pub const H264 = @import("depacketizer/h264.zig");
pub const VP8 = @import("depacketizer/vp8.zig");

const std = @import("std");
const media = @import("media");
const Packet = @import("packet.zig");
const FrameInfo = @import("depacketizer/frame_info.zig");

const Depacketizer = @This();
const initial_capacity = 8192;

allocator: std.mem.Allocator,
media_allocator: std.mem.Allocator,
impl: *anyopaque,
vtable: *const VTable,
buffer: []u8,

last_timestamp: ?u32 = null,
offset: usize = 0,
keyframe: bool = false,

pub const InitOptions = struct {
    initial_capacity: usize = initial_capacity,
};

pub const VTable = struct {
    /// Depacketize an rtp packet payload into a buffer.
    ///
    /// This function should return frame info which contains the number of written bytes into
    /// the slice and if the packet contains a keyframe.
    ///
    /// If the buffer is not enough for the whole frame, the implementation should return `error.ShortBuffer`.
    depacketize: *const fn (*anyopaque, []const u8, []u8) anyerror!?FrameInfo,
};

pub fn init(
    allocator: std.mem.Allocator,
    media_allocator: std.mem.Allocator,
    impl: anytype,
    init_options: InitOptions,
) !Depacketizer {
    const T = std.meta.Child(@TypeOf(impl));

    return .{
        .impl = impl,
        .allocator = allocator,
        .media_allocator = media_allocator,
        .buffer = try allocator.alloc(u8, init_options.initial_capacity),
        .vtable = &.{
            .depacketize = @ptrCast(&@field(T, "depacketize")),
        },
    };
}

pub fn deinit(self: *Depacketizer) void {
    self.allocator.free(self.buffer);
}

pub fn depacketize(self: *Depacketizer, rtp: *const Packet) !?media.Packet {
    while (true) {
        const frame_info = self.vtable.depacketize(self.impl, rtp.payload, self.buffer[self.offset..]) catch |err| switch (err) {
            error.ShortBuffer => {
                self.buffer = try self.allocator.realloc(self.buffer, self.buffer.len * 2);
                continue;
            },
            else => return err,
        };

        if (frame_info) |info| {
            self.offset += info.written;
            self.keyframe |= info.keyframe;
        }

        if (rtp.header.marker) {
            var media_packet = try media.Packet.dupe(self.media_allocator, self.buffer[0..self.offset]);
            media_packet.dts = rtp.header.timestamp;
            media_packet.pts = rtp.header.timestamp;
            media_packet.flags.keyframe = self.keyframe;

            self.offset = 0;
            self.keyframe = false;
            return media_packet;
        }

        break;
    }

    return null;
}

test {
    _ = @import("depacketizer/h264.zig");
    _ = @import("depacketizer/vp8.zig");
}
