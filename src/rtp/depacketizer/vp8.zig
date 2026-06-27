const std = @import("std");
const vp8 = @import("media").codecs.vp8;
const FrameInfo = @import("frame_info.zig");

const Depacketizer = @This();

pub const Config = struct {};

pub const Error = error{
    /// The destination buffer is too small to hold the depacketized frame.
    ShortBuffer,
    /// The payload descriptor extension is not supported.
    UnsupportedPayloadDescriptorExtension,
} || std.Io.Reader.Error;

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
pub fn init(config: Config) Depacketizer {
    _ = config;
    return .{};
}

/// Depacketizes a VP8 RTP packet and writes it to the destination buffer.
pub fn depacketize(self: *Depacketizer, payload: []const u8, dest: []u8) Error!?FrameInfo {
    _ = self;
    var reader = std.Io.Reader.fixed(payload);

    const pd = try PayloadDescriptor.parse(&reader);

    const size = reader.bufferedLen();
    const keyframe = blk: {
        if (!pd.partition_start or pd.partition_id != 0) break :blk false;
        break :blk ((try reader.peekByte()) & 0x1) == 0;
    };

    if (size > dest.len) return Error.ShortBuffer;
    @memcpy(dest[0..size], reader.buffered());
    return .{ .written = size, .keyframe = keyframe };
}

test "depacketize" {
    var depack: Depacketizer = .{};

    const data = [_]u8{
        0x90, 0x80, 0xf4, 0xc3, 0x90, 0xd8,
        0x00, 0x9d, 0x01, 0x2a, 0x80, 0x02,
        0xe0, 0x01, 0x39, 0x6b, 0x00, 0x27,
        0x1c, 0x22, 0xd1, 0x61, 0x62, 0x26,
        0x61, 0x22, 0x0d,
    };

    var dest: [1024]u8 = undefined;
    const frame_info = try depack.depacketize(&data, &dest);
    try std.testing.expect(frame_info != null);
    try std.testing.expect(frame_info.?.keyframe);
    try std.testing.expectEqual(23, frame_info.?.written);
}
