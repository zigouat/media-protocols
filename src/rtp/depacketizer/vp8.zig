const std = @import("std");
const vp8 = @import("media").codecs.vp8;
const Depacketizer = @import("../depacketizer.zig");

const VP8 = @This();

pub const Config = struct {};

const PayloadDescriptor = struct {
    non_reference: bool,
    partition_start: bool,
    partition_id: u3,
    picture_id: ?u15 = null,
    // temporal_level_idx: ?u8 = null,
    // temporal_layer_idx: ?u2 = null,
    // key_idx: ?u5 = null,

    fn parse(r: *std.Io.Reader) !PayloadDescriptor {
        var pd: PayloadDescriptor = .{
            .non_reference = false,
            .partition_start = false,
            .partition_id = 0,
        };

        const first_byte = try r.takeByte();
        pd.partition_id = @intCast(first_byte & 0x07);
        pd.partition_start = (first_byte & 0x10) != 0;
        pd.non_reference = (first_byte & 0x20) != 0;

        if ((first_byte & 0x80) == 0) return pd;

        const second_byte = try r.takeByte();
        if ((second_byte & 0x80) != 0) {
            const third_byte = try r.takeByte();
            pd.picture_id = third_byte & 0x07;
            if ((third_byte & 0x80) != 0) pd.picture_id = (pd.picture_id.? << 8) | try r.takeByte();
        }

        const l = (second_byte & 0x40) != 0;
        const t = (second_byte & 0x20) != 0;
        const k = (second_byte & 0x10) != 0;
        if (l) try r.discardAll(2) else if (t or k) _ = try r.takeByte();

        return pd;
    }
};

/// Initializes a new VP8 depacketizer.
pub fn init(config: Config) VP8 {
    _ = config;
    return .{};
}

/// Depacketizes a VP8 RTP packet and writes it to the destination buffer.
pub fn depacketize(self: *VP8, payload: []const u8, w: *std.Io.Writer) Depacketizer.Error!?Depacketizer.FrameInfo {
    _ = self;
    var reader = std.Io.Reader.fixed(payload);

    const pd = PayloadDescriptor.parse(&reader) catch return error.InvalidPacket;

    const keyframe = blk: {
        if (!pd.partition_start or pd.partition_id != 0) break :blk false;
        const byte = reader.peekByte() catch return error.InvalidPacket;
        break :blk (byte & 0x1) == 0;
    };

    try w.writeAll(reader.buffered());
    return .{ .keyframe = keyframe };
}

test "VP8 Depacktize: simple packet" {
    var depack: VP8 = .{};

    const data = [_]u8{
        0x90, 0x80, 0xf4, 0xc3, 0x90, 0xd8,
        0x00, 0x9d, 0x01, 0x2a, 0x80, 0x02,
        0xe0, 0x01, 0x39, 0x6b, 0x00, 0x27,
        0x1c, 0x22, 0xd1, 0x61, 0x62, 0x26,
        0x61, 0x22, 0x0d,
    };

    var writer_alloc = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer writer_alloc.deinit();

    const frame_info = try depack.depacketize(&data, &writer_alloc.writer);
    try std.testing.expect(frame_info != null);
    try std.testing.expect(frame_info.?.keyframe);
    try std.testing.expectEqual(23, writer_alloc.writer.buffered().len);
}
