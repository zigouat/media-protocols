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
    marker: bool = false,

    pub fn next(it: *Iterator, out: []u8) ?Packet {
        if (it.marker) return null;
        const len = it.packet.data.len;
        std.debug.assert(len <= out.len);
        @memcpy(out[0..len], it.packet.data);
        it.marker = true;
        return it.packetizer.rtp_config.newRtpPacket(it.marker, it.packet.pts, out[0..len]);
    }
};

test "Opus Packetize" {
    var data: [64]u8 = undefined;
    for (&data, 0..) |*b, idx| {
        b.* = @intCast(idx);
    }

    var buffer: [128]u8 = undefined;

    const packet: media.Packet = .{
        .dts = 67584930000,
        .pts = 67584930000,
        .duration = 3003,
        .stream_id = 1,
        .data = &data,
    };

    var packetizer = Packetizer.init(RtpConfig{
        .ssrc = 0x12345678,
        .payload_type = 96,
        .seq_number = 0x1234,
    });
    var it = packetizer.packetize(&packet);

    const rtp_packet = it.next(&buffer) orelse return error.FailedTest;
    try std.testing.expect(rtp_packet.header.marker);
    try std.testing.expectEqual(3160420560, rtp_packet.header.timestamp);
    try std.testing.expectEqual(0x1235, rtp_packet.header.sequence_number);
    try std.testing.expectEqual(0x12345678, rtp_packet.header.ssrc);
    try std.testing.expectEqual(64, rtp_packet.payload.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    }, rtp_packet.payload);

    try std.testing.expect(it.next(&buffer) == null);
}
