const std = @import("std");

const FixedBigInt = @This();

bits: []u64,
n: u16,
msb_mask: u64,

pub fn init(allocator: std.mem.Allocator, n: u16) !FixedBigInt {
    const bits = try allocator.alloc(u64, @divFloor(n, 64) + 1);
    @memset(bits, 0);

    return .{
        .bits = bits,
        .n = n,
        .msb_mask = switch (@rem(n, 64)) {
            0 => std.math.maxInt(u64),
            else => |rem| blk: {
                const shift: u6 = @intCast(64 - rem);
                break :blk (@as(u64, 1) << shift) - 1;
            },
        },
    };
}

pub fn deinit(self: *FixedBigInt, allocator: std.mem.Allocator) void {
    allocator.free(self.bits);
}

pub fn shiftLeft(self: *FixedBigInt, n: usize) void {
    if (n == 0) {
        @branchHint(.unlikely);
        return;
    }

    const n_chunk: isize = @bitCast(n / 64);
    const n_n: u6 = @intCast(@rem(n, 64));

    var idx: isize = @bitCast(self.bits.len - 1);
    while (idx >= 0) : (idx -= 1) {
        var carry: u64 = 0;
        if (idx - n_chunk >= 0) {
            carry = self.bits[@bitCast(idx - n_chunk)] << n_n;

            if (idx - n_chunk > 0) {
                carry |= if (n_n == 0) 0 else self.bits[@bitCast(idx - n_chunk - 1)] >> (63 - n_n + 1);
            }
        }

        self.bits[@bitCast(idx)] = if (n >= 64) carry else (self.bits[@bitCast(idx)] << @intCast(n)) | carry;
    }

    self.bits[self.bits.len - 1] &= self.msb_mask;
}

pub fn bit(self: *const FixedBigInt, i: usize) bool {
    if (i >= self.n) {
        @branchHint(.unlikely);
        return false;
    }

    const chunk = i / 64;
    return self.bits[chunk] & (@as(u64, 1) << @intCast(i % 64)) != 0;
}

pub fn setBit(self: *FixedBigInt, i: usize) void {
    if (i >= self.n) {
        @branchHint(.unlikely);
        return;
    }

    const chunk = i / 64;
    self.bits[chunk] |= @as(u64, 1) << @intCast(i % 64);
}

pub fn format(self: @This(), writer: *std.Io.Writer) std.Io.Writer.Error!void {
    var idx = self.bits.len;
    while (idx > 0) : (idx -= 1) {
        try writer.print("{X:0>16}", .{self.bits[idx - 1]});
    }
}

test "init" {
    var fixed_set = try init(std.testing.allocator, 114);
    defer fixed_set.deinit(std.testing.allocator);

    try std.testing.expectEqual(2, fixed_set.bits.len);
    try std.testing.expectEqual(114, fixed_set.n);
    try std.testing.expectEqual(0x3FFF, fixed_set.msb_mask);
}

test "shiftLeft" {
    var fbi = try init(std.testing.allocator, 224);
    defer fbi.deinit(std.testing.allocator);

    const assertEquals = struct {
        fn assertEquals(fixed_big_int: *FixedBigInt, expectd: []const u8) !void {
            var buffer: [1024]u8 = @splat(0);
            var w = std.Io.Writer.fixed(&buffer);

            try w.print("{f}", .{fixed_big_int});
            try std.testing.expectEqualStrings(expectd, w.buffered());
        }
    }.assertEquals;

    fbi.setBit(0);
    try assertEquals(&fbi, "0000000000000000000000000000000000000000000000000000000000000001");

    fbi.shiftLeft(1);
    try assertEquals(&fbi, "0000000000000000000000000000000000000000000000000000000000000002");

    fbi.shiftLeft(0);
    try assertEquals(&fbi, "0000000000000000000000000000000000000000000000000000000000000002");

    fbi.setBit(10);
    try assertEquals(&fbi, "0000000000000000000000000000000000000000000000000000000000000402");

    fbi.shiftLeft(20);
    try assertEquals(&fbi, "0000000000000000000000000000000000000000000000000000000040200000");

    fbi.setBit(80);
    try assertEquals(&fbi, "0000000000000000000000000000000000000000000100000000000040200000");

    fbi.shiftLeft(4);
    try assertEquals(&fbi, "0000000000000000000000000000000000000000001000000000000402000000");

    fbi.setBit(130);
    try assertEquals(&fbi, "0000000000000000000000000000000400000000001000000000000402000000");

    fbi.shiftLeft(64);
    try assertEquals(&fbi, "0000000000000004000000000010000000000004020000000000000000000000");

    fbi.setBit(7);
    try assertEquals(&fbi, "0000000000000004000000000010000000000004020000000000000000000080");

    fbi.shiftLeft(129);
    try assertEquals(&fbi, "0000000004000000000000000000010000000000000000000000000000000000");

    for (0..256) |_| {
        fbi.shiftLeft(1);
        fbi.setBit(0);
    }
    try assertEquals(&fbi, "00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
}
