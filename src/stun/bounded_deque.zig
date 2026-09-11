const std = @import("std");

pub fn BoundedDeque(comptime T: type, comptime capacity: usize) type {
    return struct {
        buffer: [capacity]T = undefined,
        head: usize = 0,
        len: usize = 0,

        const Self = @This();

        pub const empty: Self = .{ .buffer = undefined, .head = 0, .len = 0 };

        pub fn pushBack(self: *Self, value: T) error{Overflow}!void {
            if (self.len == capacity) return error.Overflow;
            self.buffer[(self.head + self.len) % capacity] = value;
            self.len += 1;
        }

        pub fn popFront(self: *Self) ?T {
            if (self.len == 0) return null;
            const value = self.buffer[self.head];
            self.head = (self.head + 1) % capacity;
            self.len -= 1;
            return value;
        }

        pub fn clear(self: *Self) void {
            self.head = 0;
            self.len = 0;
        }
    };
}

test "pushBack/popFront: preserves FIFO order" {
    var deque: BoundedDeque(u32, 4) = .empty;
    try deque.pushBack(1);
    try deque.pushBack(2);
    try deque.pushBack(3);

    try std.testing.expectEqual(@as(?u32, 1), deque.popFront());
    try std.testing.expectEqual(@as(?u32, 2), deque.popFront());
    try std.testing.expectEqual(@as(?u32, 3), deque.popFront());
}

test "pushBack: returns error.Overflow when full" {
    var deque: BoundedDeque(u32, 2) = .empty;
    try deque.pushBack(1);
    try deque.pushBack(2);
    try std.testing.expectError(error.Overflow, deque.pushBack(3));
}

test "popFront: returns null when empty" {
    var deque: BoundedDeque(u32, 2) = .empty;
    try std.testing.expectEqual(null, deque.popFront());
}

test "pushBack/popFront: wraps around the ring buffer" {
    var deque: BoundedDeque(u32, 3) = .empty;
    try deque.pushBack(1);
    try deque.pushBack(2);
    try deque.pushBack(3);

    try std.testing.expectEqual(1, deque.popFront());
    try std.testing.expectEqual(2, deque.popFront());

    try deque.pushBack(4);
    try deque.pushBack(5);

    try std.testing.expectEqual(3, deque.popFront());
    try std.testing.expectEqual(4, deque.popFront());
    try std.testing.expectEqual(5, deque.popFront());
    try std.testing.expectEqual(null, deque.popFront());
}
