pub const ReplayDetector = @import("replay_detector.zig").ReplayDetector;

const std = @import("std");
const rtp = @import("rtp");
const rtcp = @import("rtcp");
const cipher = @import("cipher.zig");

const RtpReplayDetector = ReplayDetector(256);
const RtcpReplayDetector = ReplayDetector(64);

/// E flag + SRTCP index.
const rtcp_index_size = 4;

pub const EncryptError = std.mem.Allocator.Error || rtp.Packet.ParseError || error{WriteFailed};
pub const DecryptError = std.mem.Allocator.Error || rtp.Packet.ParseError || RtpReplayDetector.Error || error{ AuthenticationFailed, WriteFailed };
pub const RtcpEncryptError = error{ MalformedPacket, WriteFailed } || std.mem.Allocator.Error;
pub const RtcpDecryptError = error{
    AuthenticationFailed,
    MalformedPacket,
    WriteFailed,
} || RtcpReplayDetector.Error || std.mem.Allocator.Error;

/// An enum describing the list of supported SRTP profiles.
pub const Profile = enum {
    AesCm128HmacSha1_80,
    AesCm128HmacSha1_32,

    pub fn keysSize(profile: Profile) struct { u8, u8 } {
        return switch (profile) {
            .AesCm128HmacSha1_80, .AesCm128HmacSha1_32 => .{ 16, 14 },
        };
    }

    pub fn rtpTagLength(profile: *const Profile) u8 {
        return switch (profile.*) {
            .AesCm128HmacSha1_80 => 10,
            .AesCm128HmacSha1_32 => 4,
        };
    }

    pub fn rtcpTagLength(profile: *const Profile) u8 {
        return switch (profile.*) {
            .AesCm128HmacSha1_80, .AesCm128HmacSha1_32 => 10,
        };
    }

    /// Bytes added to an RTP packet when protected.
    pub fn rtpOverhead(profile: *const Profile) u8 {
        return profile.rtpTagLength();
    }

    /// Bytes added to an RTCP packet when protected.
    pub fn rtcpOverhead(profile: *const Profile) u8 {
        return rtcp_index_size + profile.rtcpTagLength();
    }
};

const Cipher = union(Profile) {
    AesCm128HmacSha1_80: cipher.AesCm,
    AesCm128HmacSha1_32: cipher.AesCm,

    pub fn init(profile: Profile, master_key: []const u8, master_salt: []const u8) Cipher {
        return switch (profile) {
            .AesCm128HmacSha1_80 => .{ .AesCm128HmacSha1_80 = cipher.AesCm.init(profile, master_key, master_salt) },
            .AesCm128HmacSha1_32 => .{ .AesCm128HmacSha1_32 = cipher.AesCm.init(profile, master_key, master_salt) },
        };
    }
};

const RtpSsrcState = struct {
    const SEQ_NUM_MEDIAN: u16 = 0x8000;
    const SEQ_NUM_MODULO: i32 = 1 << 16;

    /// Highest packet index seen (RFC 3711: ROC << 16 | SEQ).
    index: u48 = 0,
    rollover_has_processed: bool = false,
    replay_detector: RtpReplayDetector,

    pub fn getRoc(state: *const RtpSsrcState, sequence_number: u16) struct { u32, i32 } {
        const local_roc: u32 = @intCast(state.index >> 16);
        const local_seq: u16 = @truncate(state.index);

        var guess_roc = local_roc;
        const diff: i32 = if (state.rollover_has_processed) blk: {
            var seq: i32 = @as(i32, sequence_number) - @as(i32, local_seq);
            if (local_seq < SEQ_NUM_MEDIAN) {
                if (seq > SEQ_NUM_MEDIAN) {
                    guess_roc = local_roc -% 1;
                    seq -= SEQ_NUM_MODULO;
                }
            } else if (local_seq - SEQ_NUM_MEDIAN > sequence_number) {
                guess_roc = local_roc +% 1;
                seq += SEQ_NUM_MODULO;
            }

            break :blk seq;
        } else 0;

        return .{ guess_roc, diff };
    }

    pub fn updateRolloverCount(state: *RtpSsrcState, sequence_number: u16, diff: i32) void {
        if (!state.rollover_has_processed) {
            state.index = sequence_number;
            state.rollover_has_processed = true;
        } else if (diff > 0) {
            // Only advance on newer packets, late ones must not move the reference point.
            state.index += @intCast(diff);
        }
    }

    test "rollover count" {
        const Step = struct { u16, u32, i32 }; // seq, expected roc, expected diff
        const scenarios = [_][]const Step{
            // Wrap, late packets across the wrap and RFC 3711 window boundaries.
            &.{
                .{ 65530, 0, 0 },       .{ 0, 1, 6 },      .{ 65530, 0, -6 },      .{ 5, 1, 5 },
                .{ 6, 1, 1 },           .{ 7, 1, 1 },      .{ 0x4000, 1, 0x3FF9 }, .{ 0x8000, 1, 0x4000 },
                .{ 0xFFFF, 1, 0x7FFF }, .{ 0, 2, 1 },      .{ 0x8001, 1, -32767 }, .{ 0x8000, 2, 32768 },
                .{ 0, 2, -32768 },      .{ 0x8001, 2, 1 }, .{ 0, 3, 32767 },
            },
            // Late packet before ROC 0 doesn't underflow the index.
            &.{ .{ 5, 0, 0 }, .{ 65530, 0xFFFFFFFF, -11 }, .{ 6, 0, 1 } },
            // Late packet doesn't shift the reference point.
            &.{ .{ 1000, 0, 0 }, .{ 30000, 0, 29000 }, .{ 33000, 0, 3000 }, .{ 10000, 0, -23000 }, .{ 45000, 0, 12000 } },
        };

        for (scenarios) |steps| {
            var state: RtpSsrcState = .{ .replay_detector = undefined };
            for (steps) |step| {
                const seq, const expected_roc, const expected_diff = step;
                const roc, const diff = state.getRoc(seq);
                try std.testing.expectEqual(expected_roc, roc);
                try std.testing.expectEqual(expected_diff, diff);
                state.updateRolloverCount(seq, diff);
            }
        }
    }
};

const RtcpSsrcState = struct {
    index: u31 = 1,
    replay_detector: RtcpReplayDetector,
};

/// A struct representing an SRTP session, which holds the master key, salt, cipher, and state for RTP and RTCP SSRCs.
pub const Session = struct {
    master_key: []const u8,
    salt: []const u8,
    cipher: Cipher,
    rtp_ssrc_states: std.AutoHashMapUnmanaged(u32, RtpSsrcState),
    rtcp_ssrc_states: std.AutoHashMapUnmanaged(u32, RtcpSsrcState),

    pub fn init(keying_material: []const u8, profile: Profile) error{InvalidKeyingMaterial}!Session {
        const master_size, const salt_size = Profile.keysSize(profile);
        if (master_size + salt_size != keying_material.len) return error.InvalidKeyingMaterial;

        const master_key = keying_material[0..master_size];
        const master_salt = keying_material[master_size..];

        return .{
            .master_key = master_key,
            .salt = master_salt,
            .cipher = Cipher.init(profile, master_key, master_salt),
            .rtp_ssrc_states = .empty,
            .rtcp_ssrc_states = .empty,
        };
    }

    pub fn deinit(session: *Session, allocator: std.mem.Allocator) void {
        session.rtp_ssrc_states.deinit(allocator);
        session.rtcp_ssrc_states.deinit(allocator);
    }

    /// Bytes `encryptRtp` adds to a packet, `dst` must hold the packet plus this.
    pub fn rtpOverhead(session: *const Session) u8 {
        return @as(Profile, session.cipher).rtpOverhead();
    }

    /// Bytes `encryptRtcp` adds to a packet, `dst` must hold the packet plus this.
    pub fn rtcpOverhead(session: *const Session) u8 {
        return @as(Profile, session.cipher).rtcpOverhead();
    }

    /// Registers `ssrc` so encrypting and decrypting its packets never allocates.
    pub fn addSsrc(session: *Session, allocator: std.mem.Allocator, ssrc: u32) std.mem.Allocator.Error!void {
        try session.rtp_ssrc_states.ensureUnusedCapacity(allocator, 1);
        try session.rtcp_ssrc_states.ensureUnusedCapacity(allocator, 1);

        const rtp_entry = session.rtp_ssrc_states.getOrPutAssumeCapacity(ssrc);
        if (!rtp_entry.found_existing) rtp_entry.value_ptr.* = .{ .replay_detector = .init() };

        const rtcp_entry = session.rtcp_ssrc_states.getOrPutAssumeCapacity(ssrc);
        if (!rtcp_entry.found_existing) rtcp_entry.value_ptr.* = .{ .replay_detector = .init() };
    }

    /// Encrypts an RTP packet using the SRTP session's cipher.
    pub fn encryptRtp(session: *Session, allocator: std.mem.Allocator, rtp_data: []const u8, dst: []u8) EncryptError![]const u8 {
        return try processRtp(session, allocator, rtp_data, dst, true);
    }

    /// Encrypts an RTCP packet using the SRTP session's cipher.
    pub fn encryptRtcp(session: *Session, allocator: std.mem.Allocator, rtcp_data: []const u8, dst: []u8) RtcpEncryptError![]const u8 {
        return try processRtcp(session, allocator, rtcp_data, dst, true);
    }

    /// Decrypts an RTP packet using the SRTP session's cipher.
    pub fn decryptRtp(session: *Session, allocator: std.mem.Allocator, rtp_data: []const u8, dst: []u8) DecryptError![]const u8 {
        return try processRtp(session, allocator, rtp_data, dst, false);
    }

    /// Decrypts an RTCP packet using the SRTP session's cipher.
    pub fn decryptRtcp(session: *Session, allocator: std.mem.Allocator, rtcp_data: []const u8, dst: []u8) RtcpDecryptError![]const u8 {
        return try session.processRtcp(allocator, rtcp_data, dst, false);
    }

    fn processRtp(session: *Session, allocator: std.mem.Allocator, rtp_data: []const u8, dst: []u8, comptime encrypt: bool) ![]const u8 {
        const overhead = session.rtpOverhead();
        // On decrypt, the header must not overlap the auth tag.
        const header_size = try rtp.Packet.getHeaderSize(if (encrypt) rtp_data else rtp_data[0..rtp_data.len -| overhead]);
        const out_size = if (encrypt) rtp_data.len + overhead else rtp_data.len - overhead;
        if (dst.len < out_size) {
            @branchHint(.cold);
            return error.WriteFailed;
        }

        const ssrc = std.mem.readInt(u32, rtp_data[8..12], .big);
        const seq_num = std.mem.readInt(u16, rtp_data[2..4], .big);

        const entry = session.rtp_ssrc_states.getPtr(ssrc);

        var new_state: RtpSsrcState = undefined;
        const rtp_ssrc_state = entry orelse blk: {
            try session.rtp_ssrc_states.ensureUnusedCapacity(allocator, 1);
            new_state = .{ .replay_detector = .init() };
            break :blk &new_state;
        };

        const roc, const diff = rtp_ssrc_state.getRoc(seq_num);
        const packet_index = @as(u64, roc) << 16 | seq_num;
        if (!encrypt) try rtp_ssrc_state.replay_detector.check(packet_index);

        switch (session.cipher) {
            .AesCm128HmacSha1_32, .AesCm128HmacSha1_80 => |*c| {
                const result = if (encrypt)
                    c.encryptRtp(roc, header_size, rtp_data, dst)
                else
                    try c.decryptRtp(roc, header_size, rtp_data, dst);
                rtp_ssrc_state.updateRolloverCount(seq_num, diff);
                if (!encrypt) rtp_ssrc_state.replay_detector.accept(packet_index);

                if (entry == null) {
                    @branchHint(.cold);
                    session.rtp_ssrc_states.putAssumeCapacity(ssrc, rtp_ssrc_state.*);
                }
                return result;
            },
        }
    }

    fn processRtcp(session: *Session, allocator: std.mem.Allocator, rtcp_data: []const u8, dst: []u8, comptime encrypt: bool) ![]const u8 {
        const tag_size = @as(Profile, session.cipher).rtcpTagLength();
        const overhead = session.rtcpOverhead();
        // 8 = header + ssrc
        const min_size: usize = if (encrypt) 8 else 8 + overhead;
        if (rtcp_data.len < min_size) {
            @branchHint(.cold);
            return error.MalformedPacket;
        }

        const out_size = if (encrypt) rtcp_data.len + overhead else rtcp_data.len - overhead;
        if (dst.len < out_size) {
            @branchHint(.cold);
            return error.WriteFailed;
        }

        const ssrc = std.mem.readInt(u32, rtcp_data[4..8], .big);
        const entry = session.rtcp_ssrc_states.getPtr(ssrc);

        var new_state: RtcpSsrcState = undefined;
        const rtcp_ssrc_state = entry orelse blk: {
            try session.rtcp_ssrc_states.ensureUnusedCapacity(allocator, 1);
            new_state = .{ .replay_detector = .init() };
            break :blk &new_state;
        };

        const index, const encrypted = if (encrypt) .{ rtcp_ssrc_state.index, false } else getRtcpIndex(rtcp_data, tag_size);
        if (!encrypt) try rtcp_ssrc_state.replay_detector.check(index);

        const result = switch (session.cipher) {
            .AesCm128HmacSha1_80, .AesCm128HmacSha1_32 => |*c| blK: {
                const result = if (encrypt)
                    c.encryptRtcp(rtcp_data, dst, index)
                else
                    try c.decryptRtcp(rtcp_data, dst, encrypted, index);

                break :blK result;
            },
        };

        if (!encrypt) {
            rtcp_ssrc_state.replay_detector.accept(index);
        } else rtcp_ssrc_state.index +%= 1;

        if (entry == null) {
            @branchHint(.cold);
            session.rtcp_ssrc_states.putAssumeCapacity(ssrc, rtcp_ssrc_state.*);
        }

        return result;
    }

    fn getRtcpIndex(rtcp_data: []const u8, tag_size: u8) struct { u32, bool } {
        var index = std.mem.readInt(u32, rtcp_data[rtcp_data.len - tag_size - rtcp_index_size ..][0..rtcp_index_size], .big);
        const encrypted = (index & 0x80000000) != 0;
        index &= 0x7FFFFFFF;

        return .{ index, encrypted };
    }
};

const testing = std.testing;

const test_keying_material = "mysecretkey12345mysaltvalue123";
const encrypted_rtp_aes_128_cm_hmac1_80 = [_]u8{
    0x80, 0x0E, 0x0F, 0x8F, 0x62, 0x91, 0x7F, 0xF7,
    0xE9, 0xA4, 0x91, 0x8C, 0x50, 0x81, 0x66, 0x9A,
    0xB9, 0xA3, 0x44, 0xB3, 0x0E, 0xB7, 0x99, 0x0C,
    0x8D, 0x1E, 0x71, 0x48, 0x9C, 0x8E, 0xB8, 0x98,
};

const plain_rtp_aes_128_cm_hmac1_80 = [_]u8{
    0x80, 0x0E, 0x0F, 0x8F, 0x62, 0x91, 0x7F, 0xF7,
    0xE9, 0xA4, 0x91, 0x8C, 0x87, 0x9C, 0xF1, 0xE2,
    0x8F, 0x08, 0x0B, 0x33, 0xC1, 0xA4,
};

const encrypted_rtcp_aes_128_cm_hmac1_80 = [_]u8{
    128, 200, 0,   6,  137, 161, 255, 135, 235, 3,  169, 113, 236, 134, 217, 36,  127,
    210, 78,  156, 66, 244, 203, 218, 58,  80,  24, 60,  28,  171, 30,  89,  192, 155,
    19,  59,  128, 0,  0,   1,   139, 226, 152, 17, 40,  71,  251, 110, 11,  235,
};

const plain_rtcp_aes_128_cm_hmac1_80 = [_]u8{
    128, 200, 0,   6,   137, 161, 255, 135, 18,  52,  86,  120,
    144, 171, 205, 239, 0,   1,   226, 64,  0,   0,   0,   100,
    0,   0,   0,   200, 129, 203, 0,   1,   137, 161, 255, 135,
};

test {
    testing.refAllDecls(@This());
    _ = @import("kdf.zig");
    _ = @import("replay_detector.zig");
    _ = @import("cipher.zig");
}

test "Session.init: session" {
    var srtp_session = try Session.init(test_keying_material, .AesCm128HmacSha1_80);
    defer srtp_session.deinit(testing.allocator);
}

test "Session.init: wrong keys size" {
    try testing.expectError(
        error.InvalidKeyingMaterial,
        Session.init("shortkeyhere", .AesCm128HmacSha1_80),
    );
}

test "Session.decryptRtp: Aes128CmHmacSha1_80" {
    var session = try Session.init(test_keying_material, .AesCm128HmacSha1_80);
    defer session.deinit(testing.allocator);

    var dest: [1024]u8 = @splat(0);
    const decrypted = try session.decryptRtp(testing.allocator, &encrypted_rtp_aes_128_cm_hmac1_80, &dest);
    try testing.expectEqualSlices(u8, &plain_rtp_aes_128_cm_hmac1_80, decrypted);
    try testing.expectEqual(1, session.rtp_ssrc_states.count());

    try testing.expectError(error.Replayed, session.decryptRtp(testing.allocator, &encrypted_rtp_aes_128_cm_hmac1_80, &dest));
}

test "Session.decryptRtcp: Aes128CmHmacSha1_80" {
    var session = try Session.init(test_keying_material, .AesCm128HmacSha1_80);
    defer session.deinit(testing.allocator);

    var dest: [1024]u8 = @splat(0);
    const decrypted = try session.decryptRtcp(testing.allocator, &encrypted_rtcp_aes_128_cm_hmac1_80, &dest);
    try testing.expectEqualSlices(u8, &plain_rtcp_aes_128_cm_hmac1_80, decrypted);
    try testing.expectEqual(1, session.rtcp_ssrc_states.count());

    try testing.expectError(error.Replayed, session.decryptRtcp(testing.allocator, &encrypted_rtcp_aes_128_cm_hmac1_80, &dest));
}

test "Session.encryptRtcp: Aes128CmHmacSha1_80" {
    var session = try Session.init(test_keying_material, .AesCm128HmacSha1_80);
    defer session.deinit(testing.allocator);

    var dest: [1024]u8 = @splat(0);
    const encrypted = try session.encryptRtcp(testing.allocator, &plain_rtcp_aes_128_cm_hmac1_80, &dest);
    try testing.expectEqualSlices(u8, &encrypted_rtcp_aes_128_cm_hmac1_80, encrypted);
}

test "Session.addSsrc: encrypt does not allocate for a registered ssrc" {
    var session = try Session.init(test_keying_material, .AesCm128HmacSha1_80);
    defer session.deinit(testing.allocator);

    const rtp_plain = &plain_rtp_aes_128_cm_hmac1_80;
    const rtcp_plain = &plain_rtcp_aes_128_cm_hmac1_80;
    const rtp_ssrc = std.mem.readInt(u32, rtp_plain[8..12], .big);
    const rtcp_ssrc = std.mem.readInt(u32, rtcp_plain[4..8], .big);

    var dest: [1024]u8 = undefined;
    try testing.expectError(error.OutOfMemory, session.encryptRtp(testing.failing_allocator, rtp_plain, &dest));

    try session.addSsrc(testing.allocator, rtp_ssrc);
    try session.addSsrc(testing.allocator, rtp_ssrc);
    try session.addSsrc(testing.allocator, rtcp_ssrc);
    try testing.expectEqual(2, session.rtp_ssrc_states.count());
    try testing.expectEqual(2, session.rtcp_ssrc_states.count());

    var lazy = try Session.init(test_keying_material, .AesCm128HmacSha1_80);
    defer lazy.deinit(testing.allocator);
    var lazy_dest: [1024]u8 = undefined;

    for (0..2) |_| {
        const encrypted = try session.encryptRtp(testing.failing_allocator, rtp_plain, &dest);
        try testing.expectEqualSlices(u8, try lazy.encryptRtp(testing.allocator, rtp_plain, &lazy_dest), encrypted);
    }

    const encrypted_rtcp = try session.encryptRtcp(testing.failing_allocator, rtcp_plain, &dest);
    try testing.expectEqualSlices(u8, &encrypted_rtcp_aes_128_cm_hmac1_80, encrypted_rtcp);
}

test "Session: short packets and small destination buffers are rejected without state change" {
    var session = try Session.init(test_keying_material, .AesCm128HmacSha1_80);
    defer session.deinit(testing.allocator);

    var dest: [1024]u8 = undefined;
    const short_rtcp = [_]u8{ 0x80, 0xC8, 0x00 };
    try testing.expectError(error.MalformedPacket, session.encryptRtcp(testing.allocator, &short_rtcp, &dest));
    try testing.expectError(error.MalformedPacket, session.decryptRtcp(testing.allocator, &short_rtcp, &dest));
    try testing.expectError(error.MalformedPacket, session.decryptRtcp(testing.allocator, &[_]u8{}, &dest));
    try testing.expectError(error.MalformedPacket, session.decryptRtp(testing.allocator, plain_rtp_aes_128_cm_hmac1_80[0..12], &dest));

    // Destination one byte short of the output size.
    const rtp_overhead = session.rtpOverhead();
    const rtcp_overhead = session.rtcpOverhead();
    const rtp_plain = &plain_rtp_aes_128_cm_hmac1_80;
    const rtcp_plain = &plain_rtcp_aes_128_cm_hmac1_80;
    try testing.expectError(error.WriteFailed, session.encryptRtp(testing.allocator, rtp_plain, dest[0 .. rtp_plain.len + rtp_overhead - 1]));
    try testing.expectError(error.WriteFailed, session.encryptRtcp(testing.allocator, rtcp_plain, dest[0 .. rtcp_plain.len + rtcp_overhead - 1]));
    try testing.expectError(error.WriteFailed, session.decryptRtp(testing.allocator, &encrypted_rtp_aes_128_cm_hmac1_80, dest[0 .. rtp_plain.len - 1]));
    try testing.expectError(error.WriteFailed, session.decryptRtcp(testing.allocator, &encrypted_rtcp_aes_128_cm_hmac1_80, dest[0 .. rtcp_plain.len - 1]));
    try testing.expectEqual(0, session.rtp_ssrc_states.count());
    try testing.expectEqual(0, session.rtcp_ssrc_states.count());

    // Exact output size succeeds.
    _ = try session.decryptRtp(testing.allocator, &encrypted_rtp_aes_128_cm_hmac1_80, dest[0..rtp_plain.len]);
    _ = try session.decryptRtcp(testing.allocator, &encrypted_rtcp_aes_128_cm_hmac1_80, dest[0..rtcp_plain.len]);
    _ = try session.encryptRtp(testing.allocator, rtp_plain, dest[0 .. rtp_plain.len + rtp_overhead]);
    _ = try session.encryptRtcp(testing.allocator, rtcp_plain, dest[0 .. rtcp_plain.len + rtcp_overhead]);
}

test "Session.encrypt/decrypt rtp: csrcs, extension and padding" {
    var sender = try Session.init(test_keying_material, .AesCm128HmacSha1_80);
    defer sender.deinit(testing.allocator);
    var receiver = try Session.init(test_keying_material, .AesCm128HmacSha1_80);
    defer receiver.deinit(testing.allocator);

    // 2 csrcs, 1-word extension, 4-byte payload, 4 bytes of padding.
    const plain = [_]u8{ 0xB2, 0x60, 0x00, 0x01, 0, 0, 0, 1, 0, 0, 0, 2 } ++ [_]u8{ 0, 0, 0, 3, 0, 0, 0, 4 } ++
        [_]u8{ 0xBE, 0xDE, 0x00, 0x01, 0x10, 0xAA, 0, 0 } ++ "ABCD".* ++ [_]u8{ 0, 0, 0, 4 };

    var enc_dst: [64]u8 = undefined;
    var dec_dst: [64]u8 = undefined;
    const encrypted = try sender.encryptRtp(testing.allocator, &plain, &enc_dst);
    // Header is authenticated but sent in the clear, payload and padding are encrypted.
    try testing.expectEqualSlices(u8, plain[0..28], encrypted[0..28]);
    try testing.expect(!std.mem.eql(u8, plain[28..], encrypted[28..plain.len]));

    const decrypted = try receiver.decryptRtp(testing.allocator, encrypted, &dec_dst);
    try testing.expectEqualSlices(u8, &plain, decrypted);
}

test "Session.encrypt/decrypt rtcp: advancing indices round-trip" {
    var sender = try Session.init(test_keying_material, .AesCm128HmacSha1_80);
    defer sender.deinit(testing.allocator);

    var receiver = try Session.init(test_keying_material, .AesCm128HmacSha1_80);
    defer receiver.deinit(testing.allocator);

    var enc_dst: [1024]u8 = @splat(0);
    var dec_dst: [1024]u8 = @splat(0);

    for (0..10) |_| {
        const encrypted = try sender.encryptRtcp(testing.allocator, &plain_rtcp_aes_128_cm_hmac1_80, &enc_dst);
        const decrypted = try receiver.decryptRtcp(testing.allocator, encrypted, &dec_dst);
        try testing.expectEqualSlices(u8, &plain_rtcp_aes_128_cm_hmac1_80, decrypted);
    }
}

test "Session.encrypt/decrypt rtp" {
    const assert_enc_dec = struct {
        pub fn encrypt_decrypt(profile: Profile) !void {
            // Separate sessions so ROC is tracked independently on each side.
            var sender = try Session.init(test_keying_material, profile);
            defer sender.deinit(testing.allocator);
            var receiver = try Session.init(test_keying_material, profile);
            defer receiver.deinit(testing.allocator);

            var header = rtp.Packet.Header{
                .extension = false,
                .marker = false,
                .padding = false,
                .payload_type = 99,
                .sequence_number = 0xFF90,
                .ssrc = 0xFE1A8988,
                .timestamp = 1000,
            };

            var dst_dec: [1000]u8 = @splat(0);

            // Batch size must not exceed the replay window size,
            // otherwise we'll get `error.TooOld` when decrypting.
            var batch: [64][1000]u8 = @splat(@splat(0));
            var dst_enc: [64][1024]u8 = undefined;
            var encrypted: [64][]const u8 = undefined;
            var order: [64]usize = undefined;
            var r = std.Random.DefaultPrng.init(testing.random_seed);
            var random = r.random();

            var idx: usize = 0;
            while (idx < 1000) : (idx += batch.len) {
                // Encrypt in order, decrypt out of order.
                for (&batch, &dst_enc, &encrypted) |*payload, *dst, *enc| {
                    testing.io.random(payload[12..]);
                    std.mem.writeInt(u96, payload[0..12], @bitCast(header), .big);
                    header.sequence_number +%= 1;
                    enc.* = try sender.encryptRtp(testing.allocator, payload, dst);
                }

                for (&order, 0..) |*o, i| o.* = i;
                random.shuffle(usize, &order);

                for (order) |i| {
                    const decrypted = try receiver.decryptRtp(testing.allocator, encrypted[i], &dst_dec);
                    try testing.expectEqualSlices(u8, &batch[i], decrypted);
                }
            }
        }
    }.encrypt_decrypt;

    try assert_enc_dec(.AesCm128HmacSha1_80);
    try assert_enc_dec(.AesCm128HmacSha1_32);
}
