pub const H264 = @import("packetizer/h264.zig");
pub const VP8 = @import("packetizer/vp8.zig");
pub const Opus = @import("packetizer/opus.zig");

const std = @import("std");
const Packet = @import("packet.zig");
const media = @import("media");

const Packetizer = @This();

const max_timestamp: u64 = std.math.maxInt(u32) + 1;

pub const RtpConfig = struct {
    payload_type: u7,
    ssrc: u32,
    seq_number: u16,
    fragment_size: u16,

    fn incrementSeqNumber(self: *RtpConfig) void {
        self.seq_number +%= 1;
    }
};

pub const Codec = enum {
    h264,
    vp8,
    opus,
};

pub const Error = error{
    /// Malformed media packet.
    InvalidPacket,
    /// The codec can't fragment the payload into `fragment_size`.
    PayloadTooLarge,
    /// The output buffer is too small, retry with at least `fragment_size` bytes.
    WriteFailed,
};

/// A codec payload written into the output buffer. `last` marks the end of the media packet.
pub const Fragment = struct {
    payload: []const u8,
    last: bool,
};

rtp_config: RtpConfig,
codec: Codec,

const State = union(Codec) {
    h264: H264,
    vp8: VP8,
    opus: Opus,
};

pub fn init(codec: Codec, rtp_config: RtpConfig) Packetizer {
    return .{ .rtp_config = rtp_config, .codec = codec };
}

pub fn packetize(self: *Packetizer, media_packet: *const media.Packet) Iterator {
    return .{
        .packetizer = self,
        .timestamp = media_packet.pts,
        .done = media_packet.data.len == 0,
        .state = switch (self.codec) {
            inline else => |tag| @unionInit(State, @tagName(tag), .init(media_packet.data)),
        },
    };
}

pub const Iterator = struct {
    packetizer: *Packetizer,
    timestamp: i64,
    done: bool,
    state: State,

    pub fn next(it: *Iterator, out: []u8) Error!?Packet {
        if (it.done) return null;

        const fragment = try switch (it.state) {
            inline else => |*s| s.next(out, it.packetizer.rtp_config.fragment_size),
        };
        it.done = fragment.last;
        it.packetizer.rtp_config.incrementSeqNumber();
        return it.newRtpPacket(fragment);
    }

    fn newRtpPacket(it: *Iterator, framgent: Fragment) Packet {
        const config = &it.packetizer.rtp_config;
        return Packet{
            .header = .{
                .extension = false,
                .marker = framgent.last,
                .padding = false,
                .payload_type = config.payload_type,
                .sequence_number = config.seq_number,
                .ssrc = config.ssrc,
                .timestamp = @truncate(@as(u64, @bitCast(it.timestamp))),
            },
            .payload = framgent.payload,
        };
    }
};

test {
    _ = @import("packetizer/h264.zig");
    _ = @import("packetizer/vp8.zig");
    _ = @import("packetizer/opus.zig");
}

test "Packetizer" {
    var data: [64]u8 = @splat(0xAB);
    var packet: media.Packet = .fromSlice(&data);
    packet.pts = 67584930000;

    var buffer: [1500]u8 = undefined;

    var packetizer: Packetizer = .init(.vp8, .{
        .ssrc = 0x12345678,
        .payload_type = 96,
        .seq_number = 0xFFFF,
        .fragment_size = 32,
    });
    var it = packetizer.packetize(&packet);

    var count: u16 = 0;
    while (try it.next(&buffer)) |rtp_packet| : (count += 1) {
        try std.testing.expectEqual(96, rtp_packet.header.payload_type);
        try std.testing.expectEqual(0x12345678, rtp_packet.header.ssrc);
        try std.testing.expectEqual(count, rtp_packet.header.sequence_number);
        try std.testing.expectEqual(3160420560, rtp_packet.header.timestamp);
        try std.testing.expectEqual(count == 2, rtp_packet.header.marker);
    }
    try std.testing.expectEqual(3, count);
    try std.testing.expectEqual(2, packetizer.rtp_config.seq_number);

    packet.data = &.{};
    it = packetizer.packetize(&packet);
    try std.testing.expectEqual(null, try it.next(&buffer));
}
