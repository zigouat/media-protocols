const std = @import("std");
const FixedBigInt = @import("replay_detector/fixed_big_int.zig");

const ReplayDetector = @This();

pub const Error = error{ Replayed, TooOld };

last_seq: u64,
window_size: u16,
mask: FixedBigInt,

pub fn init(allocator: std.mem.Allocator, window_size: u16) std.mem.Allocator.Error!ReplayDetector {
    return .{
        .last_seq = 0,
        .window_size = window_size,
        .mask = try FixedBigInt.init(allocator, window_size),
    };
}

pub fn deinit(replay_detector: *ReplayDetector, allocator: std.mem.Allocator) void {
    replay_detector.mask.deinit(allocator);
}

pub fn check(replay_detector: *ReplayDetector, seq: u64) Error!void {
    if (seq <= replay_detector.last_seq) {
        if (replay_detector.last_seq > seq + replay_detector.window_size) return error.TooOld;
        switch (replay_detector.mask.bit(replay_detector.last_seq - seq)) {
            true => return error.Replayed,
            false => {},
        }
    }
}

pub fn accept(replay_detector: *ReplayDetector, seq: u64) void {
    if (seq > replay_detector.last_seq) {
        replay_detector.mask.shiftLeft(seq - replay_detector.last_seq);
        replay_detector.last_seq = seq;
    }

    replay_detector.mask.setBit(replay_detector.last_seq - seq);
}

test {
    _ = @import("replay_detector/fixed_big_int.zig");
}

test "init" {
    var replay_detector = try ReplayDetector.init(std.testing.allocator, 64);
    defer replay_detector.deinit(std.testing.allocator);
}

test "accept" {
    var replay_detector = try ReplayDetector.init(std.testing.allocator, 64);
    defer replay_detector.deinit(std.testing.allocator);

    for (1..100) |idx| replay_detector.accept(idx);
    try std.testing.expectError(error.Replayed, replay_detector.check(94));

    replay_detector.accept(0xFF99);
    try std.testing.expectError(error.TooOld, replay_detector.check(101));

    for (0xFFA0..0xFFFF) |seq| replay_detector.accept(seq);
    try replay_detector.check(0x0AFFF06765780000);
    replay_detector.accept(0x0AFFF06765780000);
}
