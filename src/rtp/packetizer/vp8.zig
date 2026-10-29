const std = @import("std");
const Fragment = @import("../packetizer.zig").Fragment;
const VP8 = @This();

data: []const u8,
first: bool = true,

pub fn init(data: []const u8) VP8 {
    return .{ .data = data };
}

pub fn next(self: *VP8, out: []u8, fragment_size: usize) error{WriteFailed}!Fragment {
    const size = @min(self.data.len + 1, fragment_size);
    if (out.len < size) return error.WriteFailed;

    // payload descriptor
    out[0] = if (self.first) 0x10 else 0;
    self.first = false;

    const len = size - 1;
    @memcpy(out[1..size], self.data[0..len]);
    self.data = self.data[len..];

    return .{ .payload = out[0..size], .last = self.data.len == 0 };
}

test "VP8 Packetize" {
    var data: [64]u8 = undefined;
    for (&data, 0..) |*b, idx| {
        b.* = @intCast(idx);
    }

    var vp8: VP8 = .init(&data);
    var buf: [20]u8 = undefined;

    // Too small buffer leaves the state untouched.
    try std.testing.expectError(error.WriteFailed, vp8.next(buf[0..19], 20));

    var fragment = try vp8.next(&buf, 20);
    try std.testing.expect(!fragment.last);
    try std.testing.expectEqualSlices(u8, &[20]u8{ 0x10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 }, fragment.payload);

    fragment = try vp8.next(&buf, 20);
    try std.testing.expect(!fragment.last);
    try std.testing.expectEqualSlices(u8, &[20]u8{ 0, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37 }, fragment.payload);

    fragment = try vp8.next(&buf, 15);
    try std.testing.expect(!fragment.last);
    try std.testing.expectEqualSlices(u8, &[15]u8{ 0, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 }, fragment.payload);

    // Remaining data fits in a buffer smaller than the fragment size.
    fragment = try vp8.next(buf[0..13], 20);
    try std.testing.expect(fragment.last);
    try std.testing.expectEqualSlices(u8, &[13]u8{ 0, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63 }, fragment.payload);
}
