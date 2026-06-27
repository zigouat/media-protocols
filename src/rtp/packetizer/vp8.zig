const std = @import("std");
const media = @import("media");
const Packet = @import("../rtp.zig").Packet;
const RtpConfig = @import("../packetizer.zig").RtpConfig;
const Packetizer = @This();

rtp_config: RtpConfig,

pub fn init(rtp_config: RtpConfig) Packetizer {
    return .{ .rtp_config = rtp_config };
}

pub fn packetize(packetizer: *Packetizer, packet: *const media.Packet) Iterator {
    return .{ .packetizer = packetizer, .packet = packet };
}

pub const Iterator = struct {
    packetizer: *Packetizer,
    packet: *const media.Packet,
    pos: usize = 0,
    marker: bool = false,

    pub fn next(it: *Iterator, out: []u8) ?Packet {
        if (it.marker or it.packet.data.len == 0) return null;

        // payload descriptor
        out[0] = if (it.pos == 0) 0x10 else 0;
        const slice = it.packet.data[it.pos..];
        it.marker = slice.len <= out.len - 1;
        if (it.marker) {
            @memcpy(out[1 .. slice.len + 1], slice);
        } else {
            @memcpy(out[1..], slice[0 .. out.len - 1]);
            it.pos += out.len - 1;
        }

        const payload = if (it.marker) out[0 .. slice.len + 1] else out;
        return it.packetizer.rtp_config.newRtpPacket(it.marker, it.packet.pts, payload);
    }
};

test "packetize" {
    const data: [64]u8 = undefined;
    for (&data, 0..) |*b, idx| {
        b.* = @intCast(idx);
    }

    const packet: media.Packet = .{
        .dts = 67584930000,
        .pts = 67584930000,
        .duration = 3003,
        .stream_id = 1,
        .data = data,
    };

    var depacketer = Packetizer.init(RtpConfig{
        .ssrc = 0x12345678,
        .payload_type = 96,
        .sequence_number = 0x1234,
    });
    var it = depacketer.packetize(&packet);

    var buf: [20]u8 = undefined;
    var rtp_packet = it.next(&buf) orelse return error.FailedTest;
    try std.testing.expect(!rtp_packet.marker);
    try std.testing.expectEqual(3160420560, rtp_packet.pts);
    try std.testing.expectEqual(0x1235, rtp_packet.sequence_number);
    try std.testing.expectEqual(0x12345678, rtp_packet.ssrc);
    try std.testing.expectEqual(20, rtp_packet.payload.len);
    try std.testing.expectEqualSlice(u8, [20]u8{ 0x10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 }, rtp_packet.payload);

    rtp_packet = it.next(&buf) orelse return error.FailedTest;
    try std.testing.expect(!rtp_packet.marker);
    try std.testing.expectEqual(3160420560, rtp_packet.pts);
    try std.testing.expectEqual(0x1236, rtp_packet.sequence_number);
    try std.testing.expectEqual(0x12345678, rtp_packet.ssrc);
    try std.testing.expectEqual(20, rtp_packet.payload.len);
    try std.testing.expectEqualSlice(u8, [20]u8{ 0, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37 }, rtp_packet.payload);

    rtp_packet = it.next(buf[0..15]) orelse return error.FailedTest;
    try std.testing.expect(!rtp_packet.marker);
    try std.testing.expectEqual(3160420560, rtp_packet.pts);
    try std.testing.expectEqual(0x1236, rtp_packet.sequence_number);
    try std.testing.expectEqual(0x12345678, rtp_packet.ssrc);
    try std.testing.expectEqual(15, rtp_packet.payload.len);
    try std.testing.expectEqualSlice(u8, [15]u8{ 0, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 }, rtp_packet.payload);

    rtp_packet = it.next(buf) orelse return error.FailedTest;
    try std.testing.expect(rtp_packet.marker);
    try std.testing.expectEqual(3160420560, rtp_packet.pts);
    try std.testing.expectEqual(0x1237, rtp_packet.sequence_number);
    try std.testing.expectEqual(0x12345678, rtp_packet.ssrc);
    try std.testing.expectEqual(14, rtp_packet.payload.len);
    try std.testing.expectEqualSlice(u8, [14]u8{ 0, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63 }, rtp_packet.payload);

    try std.testing.expect(it.next(buf) == null);
}
