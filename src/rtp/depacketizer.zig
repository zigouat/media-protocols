pub const H264 = @import("depacketizer/h264.zig");
pub const VP8 = @import("depacketizer/vp8.zig");
pub const Opus = @import("depacketizer/opus.zig");

const std = @import("std");
const media = @import("media");
const Packet = @import("packet.zig");

const Depacketizer = @This();

pub const Error = error{ InvalidPacket, WriteFailed };

pub const FrameInfo = struct { keyframe: bool };

allocator: std.mem.Allocator,
media_allocator: std.mem.Allocator,
impl: *anyopaque,
vtable: *const VTable,
writer: std.Io.Writer.Allocating,

last_timestamp: ?u32 = null,
keyframe: bool = false,

pub const InitOptions = struct {
    initial_capacity: usize = 8192,
};

pub const VTable = struct {
    /// Depacketize an rtp packet payload into a buffer.
    ///
    /// This function should return frame info which contains the number of written bytes into
    /// the slice and if the packet contains a keyframe.
    ///
    /// If the buffer is not enough for the whole frame, the implementation should return `error.ShortBuffer`.
    depacketize: *const fn (*anyopaque, []const u8, *std.Io.Writer) anyerror!?FrameInfo,
};

pub fn init(
    allocator: std.mem.Allocator,
    media_allocator: std.mem.Allocator,
    impl: anytype,
    init_options: InitOptions,
) std.mem.Allocator.Error!Depacketizer {
    const T = std.meta.Child(@TypeOf(impl));

    return .{
        .impl = impl,
        .allocator = allocator,
        .media_allocator = media_allocator,
        .writer = try .initCapacity(allocator, init_options.initial_capacity),
        .vtable = &.{
            .depacketize = @ptrCast(&@field(T, "depacketize")),
        },
    };
}

pub fn deinit(self: *Depacketizer) void {
    self.writer.deinit();
}

pub fn depacketize(self: *Depacketizer, rtp: *const Packet) !?media.Packet {
    const frame_info = try self.vtable.depacketize(self.impl, rtp.payload, &self.writer.writer);

    if (frame_info) |info| self.keyframe |= info.keyframe;

    if (rtp.header.marker) {
        defer self.writer.clearRetainingCapacity();
        var media_packet = try media.Packet.dupe(self.media_allocator, self.writer.written());
        media_packet.dts = rtp.header.timestamp;
        media_packet.pts = rtp.header.timestamp;
        media_packet.flags.keyframe = self.keyframe;

        self.keyframe = false;
        return media_packet;
    }

    return null;
}

test {
    _ = @import("depacketizer/h264.zig");
    _ = @import("depacketizer/vp8.zig");
    _ = @import("depacketizer/opus.zig");
}
