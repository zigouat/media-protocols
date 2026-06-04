const std = @import("std");
const rtp = @import("rtp");
const rtcp = @import("rtcp");
const cipher = @import("cipher.zig");
const ReplayDetector = @import("replay_detector.zig");

const default_replay_detection_window = 64;

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

    index: u64 = 0,
    rollover_has_processed: bool = false,
    replay_detector: ReplayDetector,

    pub fn deinit(state: *RtpSsrcState, allocator: std.mem.Allocator) void {
        state.replay_detector.deinit(allocator);
    }

    pub fn getRoc(state: *const RtpSsrcState, sequence_number: u16) struct { u32, i32 } {
        const local_roc: u32 = @intCast(state.index >> 16);
        const local_seq: u16 = @intCast(state.index & 0xFFFF);

        var guess_roc = local_roc;
        const diff: i32 = if (state.rollover_has_processed) blk: {
            var seq: i32 = @as(i32, sequence_number) -% @as(i32, local_seq);
            if (local_seq < SEQ_NUM_MEDIAN) {
                if (seq > SEQ_NUM_MEDIAN) {
                    guess_roc = local_roc -% 1;
                    seq -%= @as(i32, std.math.maxInt(u16)) + 1;
                }
            } else if (local_seq - SEQ_NUM_MEDIAN > sequence_number) {
                guess_roc = local_roc +% 1;
                seq +%= @as(i32, std.math.maxInt(u16)) + 1;
            }

            break :blk seq;
        } else 0;

        return .{ guess_roc, diff };
    }

    pub fn updateRolloverCount(state: *RtpSsrcState, sequence_number: u16, diff: i32) void {
        if (!state.rollover_has_processed) {
            state.index = sequence_number;
            state.rollover_has_processed = true;
        } else {
            state.index +%= @as(u64, @bitCast(@as(i64, diff)));
        }
    }

    test "rollover count" {
        var rtp_ssrc_state: RtpSsrcState = .{ .replay_detector = undefined };

        var roc, var diff = rtp_ssrc_state.getRoc(65530);
        try std.testing.expectEqual(0, roc);
        try std.testing.expectEqual(0, diff);

        rtp_ssrc_state.updateRolloverCount(65530, diff);
        roc, diff = rtp_ssrc_state.getRoc(0);
        try std.testing.expectEqual(1, roc);
        try std.testing.expect(diff != 0);

        rtp_ssrc_state.updateRolloverCount(0, diff);
        roc, diff = rtp_ssrc_state.getRoc(65530);
        try std.testing.expectEqual(0, roc);
        try std.testing.expect(diff != 0);

        rtp_ssrc_state.updateRolloverCount(65530, diff);
        roc, diff = rtp_ssrc_state.getRoc(5);
        try std.testing.expectEqual(1, roc);
        try std.testing.expect(diff != 0);

        roc, diff = rtp_ssrc_state.getRoc(6);
        rtp_ssrc_state.updateRolloverCount(6, diff);
        roc, diff = rtp_ssrc_state.getRoc(7);
        rtp_ssrc_state.updateRolloverCount(7, diff);
        try std.testing.expectEqual(1, roc);

        roc, diff = rtp_ssrc_state.getRoc(0x4000);
        try std.testing.expectEqual(1, roc);
        rtp_ssrc_state.updateRolloverCount(0x4000, diff);

        roc, diff = rtp_ssrc_state.getRoc(0x8000);
        try std.testing.expectEqual(1, roc);
        rtp_ssrc_state.updateRolloverCount(0x8000, diff);

        roc, diff = rtp_ssrc_state.getRoc(0xFFFF);
        try std.testing.expectEqual(1, roc);
        rtp_ssrc_state.updateRolloverCount(0xFFFF, diff);

        roc, diff = rtp_ssrc_state.getRoc(0);
        try std.testing.expectEqual(2, roc);
        rtp_ssrc_state.updateRolloverCount(0, diff);
    }
};

const RtcpSsrcState = struct {
    index: u31 = 1,
    replay_detector: ReplayDetector,

    pub fn deinit(state: *RtcpSsrcState, allocator: std.mem.Allocator) void {
        state.replay_detector.deinit(allocator);
    }
};

pub const Session = struct {
    master_key: []const u8,
    salt: []const u8,
    cipher: Cipher,
    rtp_ssrc_states: std.AutoHashMap(u32, RtpSsrcState),
    rtcp_ssrc_states: std.AutoHashMap(u32, RtcpSsrcState),

    pub fn init(allocator: std.mem.Allocator, keying_material: []const u8, profile: Profile) !Session {
        const master_size, const salt_size = Profile.keysSize(profile);
        if (master_size + salt_size != keying_material.len) return error.InvalidKeyingMaterial;

        const master_key = keying_material[0..master_size];
        const master_salt = keying_material[master_size..];

        return .{
            .master_key = master_key,
            .salt = master_salt,
            .cipher = Cipher.init(profile, master_key, master_salt),
            .rtp_ssrc_states = .init(allocator),
            .rtcp_ssrc_states = .init(allocator),
        };
    }

    pub fn deinit(session: *Session) void {
        var it = session.rtp_ssrc_states.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(session.rtp_ssrc_states.allocator);
        session.rtp_ssrc_states.deinit();

        var rtcp_it = session.rtcp_ssrc_states.iterator();
        while (rtcp_it.next()) |entry| entry.value_ptr.deinit(session.rtcp_ssrc_states.allocator);
        session.rtcp_ssrc_states.deinit();
    }

    pub fn encryptRtcp(session: *Session, rtcp_data: []const u8, dst: []u8) ![]const u8 {
        const ssrc = std.mem.readInt(u32, rtcp_data[4..8], .big);

        const entry = session.rtcp_ssrc_states.getPtr(ssrc);
        var rtcp_ssrc_state = entry orelse blk: {
            var state: RtcpSsrcState = .{
                .replay_detector = try .init(session.rtcp_ssrc_states.allocator, 128),
            };

            break :blk &state;
        };
        errdefer if (entry == null) rtcp_ssrc_state.deinit(session.rtcp_ssrc_states.allocator);

        switch (session.cipher) {
            .AesCm128HmacSha1_80, .AesCm128HmacSha1_32 => |*c| {
                const result = try c.encryptRtcp(rtcp_data, dst, rtcp_ssrc_state.index);
                rtcp_ssrc_state.index +%= 1;
                if (entry == null) {
                    @branchHint(.cold);
                    try session.rtcp_ssrc_states.put(ssrc, rtcp_ssrc_state.*);
                }

                return result;
            },
        }
    }

    pub fn decryptRtp(session: *Session, packet: []const u8, dst: []u8) ![]const u8 {
        const rtp_packet = try rtp.Packet.parse(packet);
        const header_size = packet.len - rtp_packet.payload.len - rtp_packet.padding_size;

        const entry = session.rtp_ssrc_states.getPtr(rtp_packet.header.ssrc);
        var rtp_ssrc_state = entry orelse blk: {
            var state = RtpSsrcState{
                .replay_detector = try .init(session.rtp_ssrc_states.allocator, default_replay_detection_window),
            };
            break :blk &state;
        };
        errdefer if (entry == null) rtp_ssrc_state.deinit(session.rtp_ssrc_states.allocator);

        const roc, const diff = rtp_ssrc_state.getRoc(rtp_packet.header.sequence_number);
        const packet_index = @as(u64, roc) << 16 | rtp_packet.header.sequence_number;
        try rtp_ssrc_state.replay_detector.check(packet_index);

        switch (session.cipher) {
            .AesCm128HmacSha1_32, .AesCm128HmacSha1_80 => |*c| {
                const result = try c.decryptRtp(roc, header_size, packet, dst);
                rtp_ssrc_state.updateRolloverCount(rtp_packet.header.sequence_number, diff);
                rtp_ssrc_state.replay_detector.accept(packet_index);
                if (entry == null) {
                    @branchHint(.cold);
                    try session.rtp_ssrc_states.put(rtp_packet.header.ssrc, rtp_ssrc_state.*);
                }
                return result;
            },
        }
    }

    pub fn decryptRtcp(session: *Session, rtcp_data: []const u8, dst: []u8) ![]const u8 {
        const profile = @as(Profile, session.cipher);
        const tag_size = profile.rtcpTagLength();

        const min_size = tag_size + 12; // 12 = header size + ssrc + index
        if (rtcp_data.len < min_size) return error.InvalidRtcp;

        const ssrc = std.mem.readInt(u32, rtcp_data[4..8], .big);
        var index = std.mem.readInt(u32, rtcp_data[rtcp_data.len - tag_size - 4 ..][0..4], .big);
        const encrypted = (index & 0x80000000) != 0;
        index &= 0x7FFFFFFF;

        const entry = session.rtcp_ssrc_states.getPtr(ssrc);
        var rtcp_ssrc_state = entry orelse blk: {
            var state: RtcpSsrcState = .{
                .replay_detector = try .init(session.rtcp_ssrc_states.allocator, 128),
            };

            break :blk &state;
        };
        errdefer if (entry == null) rtcp_ssrc_state.deinit(session.rtcp_ssrc_states.allocator);

        try rtcp_ssrc_state.replay_detector.check(index);

        switch (session.cipher) {
            .AesCm128HmacSha1_80, .AesCm128HmacSha1_32 => |*c| {
                const result = try c.decryptRtcp(rtcp_data, dst, encrypted, index);
                rtcp_ssrc_state.replay_detector.accept(index);

                if (entry == null) {
                    @branchHint(.cold);
                    try session.rtcp_ssrc_states.put(ssrc, rtcp_ssrc_state.*);
                }
                return result;
            },
        }

        return dst[0..];
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

const encrypted_rtp_aes_128_cm_hmac1_32 = [_]u8{};
const plain_rtp_aes_128_cm_hmac1_32 = [_]u8{};

test {
    std.testing.refAllDecls(@This());
    _ = @import("kdf.zig");
    _ = @import("replay_detector.zig");
    _ = @import("cipher.zig");
}

test "init session" {
    var srtp_session = try Session.init(testing.allocator, test_keying_material, .AesCm128HmacSha1_80);
    defer srtp_session.deinit();
}

test "init session: wrong keys size" {
    try testing.expectError(error.InvalidKeyingMaterial, Session.init(testing.allocator, "shortkeyhere", .AesCm128HmacSha1_80));
}

test "decrypt rtp: Aes128CmHmacSha1_80" {
    var session = try Session.init(std.testing.allocator, test_keying_material, .AesCm128HmacSha1_80);
    defer session.deinit();

    var dest: [1024]u8 = @splat(0);
    const decrypted = try session.decryptRtp(&encrypted_rtp_aes_128_cm_hmac1_80, &dest);
    try testing.expectEqualSlices(u8, &plain_rtp_aes_128_cm_hmac1_80, decrypted);
    try testing.expectEqual(1, session.rtp_ssrc_states.count());

    try testing.expectError(error.Replayed, session.decryptRtp(&encrypted_rtp_aes_128_cm_hmac1_80, &dest));
}

test "decrypt rtcp: Aes128CmHmacSha1_80" {
    var session = try Session.init(std.testing.allocator, test_keying_material, .AesCm128HmacSha1_80);
    defer session.deinit();

    var dest: [1024]u8 = @splat(0);
    const decrypted = try session.decryptRtcp(&encrypted_rtcp_aes_128_cm_hmac1_80, &dest);
    try testing.expectEqualSlices(u8, &plain_rtcp_aes_128_cm_hmac1_80, decrypted);
    try testing.expectEqual(1, session.rtcp_ssrc_states.count());

    try testing.expectError(error.Replayed, session.decryptRtcp(&encrypted_rtcp_aes_128_cm_hmac1_80, &dest));
}

test "encrypt rtcp: Aes128CmHmacSha1_80" {
    var session = try Session.init(std.testing.allocator, test_keying_material, .AesCm128HmacSha1_80);
    defer session.deinit();

    var dest: [1024]u8 = @splat(0);
    const decrypted = try session.encryptRtcp(&plain_rtcp_aes_128_cm_hmac1_80, &dest);
    try testing.expectEqualSlices(u8, &encrypted_rtcp_aes_128_cm_hmac1_80, decrypted);
}
