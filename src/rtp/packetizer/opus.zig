const std = @import("std");
const Fragment = @import("../packetizer.zig").Fragment;
const Opus = @This();

data: []const u8,

pub fn init(data: []const u8) Opus {
    return .{ .data = data };
}

pub fn next(self: *Opus, out: []u8, fragment_size: usize) error{ PayloadTooLarge, WriteFailed }!Fragment {
    const len = self.data.len;
    if (len > fragment_size) return error.PayloadTooLarge;
    if (out.len < len) return error.WriteFailed;
    @memcpy(out[0..len], self.data);
    return .{ .payload = out[0..len], .last = true };
}

test "Opus Packetize" {
    var data: [64]u8 = undefined;
    for (&data, 0..) |*b, idx| {
        b.* = @intCast(idx);
    }

    var buffer: [128]u8 = undefined;
    var opus: Opus = .init(&data);

    try std.testing.expectError(error.PayloadTooLarge, opus.next(&buffer, 63));
    try std.testing.expectError(error.WriteFailed, opus.next(buffer[0..63], 1200));

    const fragment = try opus.next(&buffer, 1200);
    try std.testing.expect(fragment.last);
    try std.testing.expectEqualSlices(u8, &data, fragment.payload);
}
