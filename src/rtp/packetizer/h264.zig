const std = @import("std");
const media = @import("media");
const Packet = @import("../rtp.zig").Packet;
const RtpConfig = @import("../packetizer.zig").RtpConfig;
const Packetizer = @This();

rtp_config: RtpConfig,

const FuState = struct {
    nalu: []const u8,
    first_byte: u8,
    nal_type: u8,
    first_fragment: bool = true,

    fn init(nalu: []const u8) FuState {
        return .{
            .nalu = nalu[1..],
            .first_byte = (nalu[0] & 0xE0) | 0x1C,
            .nal_type = nalu[0] & 0x1F,
        };
    }

    /// Gets the next fragment from the NALu.
    fn next(state: *FuState, buffer: []u8) []const u8 {
        const offset: usize = @min(buffer.len - 2, state.nalu.len);
        const last_fragment = offset == state.nalu.len;

        @memcpy(buffer[2 .. offset + 2], state.nalu[0..offset]);

        buffer[0] = state.first_byte;
        buffer[1] = (@as(u8, @intFromBool(state.first_fragment)) << 7) | (@as(u8, @intFromBool(last_fragment)) << 6) | state.nal_type;

        state.nalu = state.nalu[offset..];
        state.first_fragment = false;
        return buffer[0 .. offset + 2];
    }

    fn empty(state: *const FuState) bool {
        return state.nalu.len == 0;
    }
};

pub fn init(rtp_config: RtpConfig) Packetizer {
    return .{ .rtp_config = rtp_config };
}

pub fn packetize(packetizer: *Packetizer, packet: *const media.Packet) Iterator {
    return .{ .packetizer = packetizer, .packet = packet };
}

pub const Iterator = struct {
    packetizer: *Packetizer,
    packet: *const media.Packet,
    fu_state: ?FuState = null,
    pos: usize = 0,
    marker: bool = false,

    pub fn next(it: *Iterator, out: []u8) !?Packet {
        if (it.marker) return null;

        if (it.fu_state) |*fu_state| {
            const payload = fu_state.next(out);

            if (fu_state.empty()) {
                it.fu_state = null;
                it.marker = it.pos == it.packet.data.len;
            }

            return it.packetizer.rtp_config.newRtpPacket(it.marker, it.packet.pts, payload);
        }

        var reader: std.Io.Reader = .fixed(it.packet.data[it.pos..]);
        const nalu_size = try reader.takeInt(u32, .big);
        const nalu = try reader.take(nalu_size);
        defer it.pos += nalu_size + 4;

        if (nalu_size > out.len) {
            // FU unit
            it.fu_state = .init(nalu);
            const payload = it.fu_state.?.next(out);
            return it.packetizer.rtp_config.newRtpPacket(false, it.packet.pts, payload);
        }

        // Single nalu
        it.marker = reader.seek == reader.end;
        return it.packetizer.rtp_config.newRtpPacket(it.marker, it.packet.pts, nalu);
    }
};

test "h264 packetizer: single nalu" {
    var packetizer: Packetizer = .init(.{
        .payload_type = 96,
        .ssrc = 0xDEADBEEF,
        .seq_number = 1000,
    });

    var out: [1500]u8 = @splat(0);

    const nalu1 = [_]u8{ 0x67, 0x42, 0xC0, 0x1E };
    const nalu2 = [_]u8{ 0x65, 0x88, 0x84, 0x21, 0xA0 };
    const avc_data = [_]u8{ 0x00, 0x00, 0x00, nalu1.len } ++ nalu1 ++
        [_]u8{ 0x00, 0x00, 0x00, nalu2.len } ++ nalu2;

    var media_packet: media.Packet = .fromSlice(&avc_data);
    media_packet.pts = 90000;

    var it = packetizer.packetize(&media_packet);

    const first = try it.next(&out) orelse return error.TestUnexpectedNull;
    try std.testing.expectEqual(96, first.header.payload_type);
    try std.testing.expectEqual(0xDEADBEEF, first.header.ssrc);
    try std.testing.expectEqual(1001, first.header.sequence_number);
    try std.testing.expectEqual(90000, first.header.timestamp);
    try std.testing.expect(!first.header.marker);
    try std.testing.expectEqualSlices(u8, &nalu1, first.payload);

    const second = try it.next(&out) orelse return error.TestUnexpectedNull;
    try std.testing.expectEqual(96, second.header.payload_type);
    try std.testing.expectEqual(0xDEADBEEF, second.header.ssrc);
    try std.testing.expectEqual(1002, second.header.sequence_number);
    try std.testing.expectEqual(90000, second.header.timestamp);
    try std.testing.expect(second.header.marker);
    try std.testing.expectEqualSlices(u8, &nalu2, second.payload);

    try std.testing.expectEqual(1002, packetizer.rtp_config.seq_number);

    try std.testing.expectEqual(null, try it.next(&out));
}

test "h264 packetizer: fu-a fragmentation" {
    var packetizer: Packetizer = .init(.{
        .payload_type = 96,
        .ssrc = 0xCAFEBABE,
        .seq_number = 2000,
    });

    var out: [1400]u8 = @splat(0);

    // Header byte 0x65: F=0, NRI=3, Type=5 (IDR slice).
    const nalu_size: usize = 3000;
    var avc_data: [4 + nalu_size]u8 = undefined;
    std.mem.writeInt(u32, avc_data[0..4], @intCast(nalu_size), .big);
    avc_data[4] = 0x65;
    for (avc_data[5..], 0..) |*b, i| b.* = @intCast(i & 0xFF);

    var media_packet: media.Packet = .fromSlice(&avc_data);
    media_packet.pts = 180_000;
    var it = packetizer.packetize(&media_packet);

    var packet = try it.next(out[0..1400]) orelse unreachable;
    try std.testing.expectEqual(2001, packet.header.sequence_number);
    try std.testing.expectEqual(180_000, packet.header.timestamp);
    try std.testing.expect(!packet.header.marker);
    try std.testing.expectEqual(1400, packet.payload.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x7c, 0x85 }, packet.payload[0..2]);
    var idx: u8 = 0;
    for (packet.payload[2..]) |*b| {
        try std.testing.expectEqual(idx, b.*);
        idx +%= 1;
    }

    packet = try it.next(out[0..1350]) orelse unreachable;
    try std.testing.expectEqual(2002, packet.header.sequence_number);
    try std.testing.expectEqual(180_000, packet.header.timestamp);
    try std.testing.expect(!packet.header.marker);
    try std.testing.expectEqual(1350, packet.payload.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x7c, 0x05 }, packet.payload[0..2]);
    for (packet.payload[2..]) |*b| {
        try std.testing.expectEqual(idx, b.*);
        idx +%= 1;
    }

    packet = try it.next(out[0..1000]) orelse unreachable;
    try std.testing.expectEqual(2003, packet.header.sequence_number);
    try std.testing.expectEqual(180_000, packet.header.timestamp);
    try std.testing.expect(packet.header.marker);
    try std.testing.expectEqual(255, packet.payload.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x7c, 0x45 }, packet.payload[0..2]);
    for (packet.payload[2..]) |*b| {
        try std.testing.expectEqual(idx, b.*);
        idx +%= 1;
    }

    try std.testing.expectEqual(null, try it.next(&out));
}
