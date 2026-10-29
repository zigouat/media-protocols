const std = @import("std");
const Fragment = @import("../packetizer.zig").Fragment;
const H264 = @This();

/// Remaining AVC data (4 bytes big endian length prefixed NALus).
data: []const u8,
fu_state: ?FuState = null,

const FuState = struct {
    nalu: []const u8,
    first_byte: u8,
    nal_type: u8,
    first_fragment: bool = true,

    fn init(nalu: []const u8) FuState {
        return .{
            .nalu = nalu[1..],
            .first_byte = (nalu[0] & 0xE0) | 0x1C,
            .nal_type = nalu[0] & 0x1F,
        };
    }

    /// Gets the next fragment from the NALu.
    fn next(state: *FuState, buffer: []u8) []const u8 {
        const offset: usize = @min(buffer.len - 2, state.nalu.len);
        const last_fragment = offset == state.nalu.len;

        @memcpy(buffer[2 .. offset + 2], state.nalu[0..offset]);

        buffer[0] = state.first_byte;
        buffer[1] = (@as(u8, @intFromBool(state.first_fragment)) << 7) | (@as(u8, @intFromBool(last_fragment)) << 6) | state.nal_type;

        state.nalu = state.nalu[offset..];
        state.first_fragment = false;
        return buffer[0 .. offset + 2];
    }

    fn empty(state: *const FuState) bool {
        return state.nalu.len == 0;
    }
};

pub fn init(data: []const u8) H264 {
    return .{ .data = data };
}

pub fn next(self: *H264, out: []u8, fragment_size: usize) error{ InvalidPacket, WriteFailed }!Fragment {
    if (self.fu_state) |*fu_state| {
        if (out.len < @min(fu_state.nalu.len + 2, fragment_size)) return error.WriteFailed;
        const payload = fu_state.next(out[0..@min(out.len, fragment_size)]);
        if (fu_state.empty()) self.fu_state = null;
        return .{ .payload = payload, .last = self.fu_state == null and self.data.len == 0 };
    }

    if (self.data.len < 4) return error.InvalidPacket;
    const nalu_size = std.mem.readInt(u32, self.data[0..4], .big);
    if (self.data.len - 4 < nalu_size) return error.InvalidPacket;
    const nalu = self.data[4..][0..nalu_size];
    if (out.len < @min(nalu.len, fragment_size)) return error.WriteFailed;
    self.data = self.data[4 + nalu_size ..];

    if (nalu.len > fragment_size) {
        // FU unit
        self.fu_state = .init(nalu);
        return .{ .payload = self.fu_state.?.next(out[0..fragment_size]), .last = false };
    }

    // Single nalu
    @memcpy(out[0..nalu.len], nalu);
    return .{ .payload = out[0..nalu.len], .last = self.data.len == 0 };
}

test "h264 packetizer: single nalu" {
    var out: [1500]u8 = @splat(0);

    const nalu1 = [_]u8{ 0x67, 0x42, 0xC0, 0x1E };
    const nalu2 = [_]u8{ 0x65, 0x88, 0x84, 0x21, 0xA0 };
    const avc_data = [_]u8{ 0x00, 0x00, 0x00, nalu1.len } ++ nalu1 ++
        [_]u8{ 0x00, 0x00, 0x00, nalu2.len } ++ nalu2;

    var h264: H264 = .init(&avc_data);

    const first = try h264.next(&out, 1200);
    try std.testing.expect(!first.last);
    try std.testing.expectEqualSlices(u8, &nalu1, first.payload);
    try std.testing.expectEqual(&out, first.payload.ptr);

    const second = try h264.next(&out, 1200);
    try std.testing.expect(second.last);
    try std.testing.expectEqualSlices(u8, &nalu2, second.payload);
    try std.testing.expectEqual(&out, second.payload.ptr);
}

test "h264 packetizer: fu-a fragmentation" {
    var out: [1400]u8 = @splat(0);

    // Header byte 0x65: F=0, NRI=3, Type=5 (IDR slice).
    const nalu_size: usize = 3000;
    var avc_data: [4 + nalu_size]u8 = undefined;
    std.mem.writeInt(u32, avc_data[0..4], @intCast(nalu_size), .big);
    avc_data[4] = 0x65;
    for (avc_data[5..], 0..) |*b, i| b.* = @intCast(i & 0xFF);

    var h264: H264 = .init(&avc_data);

    const expected = [_]struct { fragment_size: usize, len: usize, header: [2]u8, last: bool }{
        .{ .fragment_size = 1400, .len = 1400, .header = .{ 0x7c, 0x85 }, .last = false },
        .{ .fragment_size = 1350, .len = 1350, .header = .{ 0x7c, 0x05 }, .last = false },
        .{ .fragment_size = 1000, .len = 255, .header = .{ 0x7c, 0x45 }, .last = true },
    };

    var idx: u8 = 0;
    for (expected) |e| {
        // Too small buffer leaves the state untouched.
        try std.testing.expectError(error.WriteFailed, h264.next(out[0 .. e.len - 1], e.fragment_size));

        const fragment = try h264.next(&out, e.fragment_size);
        try std.testing.expectEqual(e.last, fragment.last);
        try std.testing.expectEqual(e.len, fragment.payload.len);
        try std.testing.expectEqualSlices(u8, &e.header, fragment.payload[0..2]);
        for (fragment.payload[2..]) |b| {
            try std.testing.expectEqual(idx, b);
            idx +%= 1;
        }
    }
}
