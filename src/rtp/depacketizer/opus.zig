const std = @import("std");
const vp8 = @import("media").codecs.vp8;
const Depacketizer = @import("../depacketizer.zig");

const Opus = @This();

pub const Config = struct {};

/// Initializes a new Opus depacketizer.
pub fn init(config: Config) Opus {
    _ = config;
    return .{};
}

/// Depacketizes an Opus rtp packet.
pub fn depacketize(self: *Opus, payload: []const u8, w: *std.Io.Writer) Depacketizer.Error!?Depacketizer.FrameInfo {
    _ = self;
    try w.writeAll(payload);
    return .{ .keyframe = false };
}
