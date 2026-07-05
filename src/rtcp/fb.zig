//! Describes the RTCP Feedback (FB) packet format as defined in RFC 4585.
const std = @import("std");
const rtcp = @import("rtcp.zig");

pub const Nack = struct {
    sender_ssrc: u32,
    media_ssrc: u32,
    fci: []const u8,

    pub fn parse(data: []const u8) rtcp.Error!Nack {
        if (data.len < 12 or @rem(data.len, 4) != 0) return error.MalformedPacket;
        const sender_ssrc = std.mem.readInt(u32, data[0..4], .big);
        const source_ssrc = std.mem.readInt(u32, data[4..8], .big);

        return Nack{
            .sender_ssrc = sender_ssrc,
            .media_ssrc = source_ssrc,
            .fci = data[8..],
        };
    }

    pub fn iterateSequenceNumbers(nack: *const Nack) Iterator {
        return .{ .fci = nack.fci };
    }

    pub const Iterator = struct {
        fci: []const u8,
        pid: u16 = 0,
        blp: u16 = 0,

        pub fn next(it: *Iterator) ?u16 {
            if (it.blp != 0) {
                const tr_zeroes = @ctz(it.blp) + 1;
                it.pid +%= tr_zeroes;
                it.blp = if (tr_zeroes == 16) 0 else it.blp >> @intCast(tr_zeroes);
                return it.pid;
            }

            if (it.fci.len < 4) return null;
            it.pid = std.mem.readInt(u16, it.fci[0..2], .big);
            it.blp = std.mem.readInt(u16, it.fci[2..4], .big);
            it.fci = it.fci[4..];
            return it.pid;
        }
    };
};

test "Nack: parse" {
    const data = [_]u8{ 0, 1, 225, 185, 0, 1, 182, 103, 0, 100, 144, 4, 0, 117, 0, 128, 0, 153, 0, 0 };
    const fb = try Nack.parse(&data);

    try std.testing.expectEqual(123_321, fb.sender_ssrc);
    try std.testing.expectEqual(112_231, fb.media_ssrc);
    try std.testing.expectEqualSlices(u8, data[8..], fb.fci);
}

test "NACK: iterate sequence numbers" {
    // [100, 103, 113, 116, 117, 125, 153, 169, 400]
    const data = [_]u8{ 0, 1, 225, 185, 0, 1, 182, 103, 0, 100, 144, 4, 0, 117, 0, 128, 0, 153, 128, 0, 1, 144, 0, 0 };
    const fb = try Nack.parse(&data);
    var it = fb.iterateSequenceNumbers();

    try std.testing.expectEqual(100, it.next().?);
    try std.testing.expectEqual(103, it.next().?);
    try std.testing.expectEqual(113, it.next().?);
    try std.testing.expectEqual(116, it.next().?);
    try std.testing.expectEqual(117, it.next().?);
    try std.testing.expectEqual(125, it.next().?);
    try std.testing.expectEqual(153, it.next().?);
    try std.testing.expectEqual(169, it.next().?);
    try std.testing.expectEqual(400, it.next().?);
    try std.testing.expect(it.next() == null);
}
