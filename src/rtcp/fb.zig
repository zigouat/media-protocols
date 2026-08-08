//! Describes the RTCP Feedback (FB) packet format as defined in RFC 4585.
const std = @import("std");
const rtcp = @import("rtcp.zig");
const Io = std.Io;

pub const pli_size = 8;

pub const Nack = struct {
    sender_ssrc: u32,
    media_ssrc: u32,
    fci: []const u8,

    pub fn decode(data: []const u8) rtcp.Error!Nack {
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

/// Describes a payload specific feedback (PSFB) packet for Picture Loss Indication (PLI) as defined in RFC 4585.
///
/// PLI is used by decoder to inform encoder that it has lost an undefined amount of pictures and requests a new keyframe to be sent.
pub const PLI = struct {
    /// The SSRC of the sender of this feedback packet.
    sender_ssrc: u32,
    /// The SSRC of the remote media source.
    media_ssrc: u32,

    /// Decodes a PLI packet from the given data slice.
    pub fn decode(data: []const u8) rtcp.Error!PLI {
        if (data.len != pli_size) return error.MalformedPacket;
        const sender_ssrc = std.mem.readInt(u32, data[0..4], .big);
        const source_ssrc = std.mem.readInt(u32, data[4..8], .big);
        return PLI{ .sender_ssrc = sender_ssrc, .media_ssrc = source_ssrc };
    }

    /// Encodes a PLI packet into the given buffer.
    pub fn encode(pli: *const PLI, buffer: *[pli_size]u8) void {
        std.mem.writeInt(u32, buffer[0..4], pli.sender_ssrc, .big);
        std.mem.writeInt(u32, buffer[4..8], pli.media_ssrc, .big);
    }

    /// Writes a PLI packet to the given writer.
    pub fn writerEncode(pli: *const PLI, writer: *Io.Writer) Io.Writer.Error!void {
        try writer.writeInt(u32, pli.sender_ssrc, .big);
        try writer.writeInt(u32, pli.media_ssrc, .big);
    }
};

/// Describes a payload specific feedback (PSFB) packet for Application layer Feedback (AFB) as defined in RFC 4585.
pub const AFB = struct {
    sender_ssrc: u32,
    media_ssrc: u32,
    data: []const u8,

    pub fn decode(data: []const u8) rtcp.Error!AFB {
        if (data.len < 8) return error.MalformedPacket;

        const sender_ssrc = std.mem.readInt(u32, data[0..4], .big);
        const source_ssrc = std.mem.readInt(u32, data[4..8], .big);
        return AFB{
            .sender_ssrc = sender_ssrc,
            .media_ssrc = source_ssrc,
            .data = data[8..],
        };
    }
};

test "Nack: decode" {
    const data = [_]u8{ 0, 1, 225, 185, 0, 1, 182, 103, 0, 100, 144, 4, 0, 117, 0, 128, 0, 153, 0, 0 };
    const fb = try Nack.decode(&data);

    try std.testing.expectEqual(123_321, fb.sender_ssrc);
    try std.testing.expectEqual(112_231, fb.media_ssrc);
    try std.testing.expectEqualSlices(u8, data[8..], fb.fci);
}

test "NACK: iterate sequence numbers" {
    // [100, 103, 113, 116, 117, 125, 153, 169, 400]
    const data = [_]u8{ 0, 1, 225, 185, 0, 1, 182, 103, 0, 100, 144, 4, 0, 117, 0, 128, 0, 153, 128, 0, 1, 144, 0, 0 };
    const fb = try Nack.decode(&data);
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

test "PLI: decode" {
    const data = [_]u8{ 0, 1, 225, 185, 0, 1, 182, 103 };
    const fb = try PLI.decode(&data);

    try std.testing.expectEqual(123_321, fb.sender_ssrc);
    try std.testing.expectEqual(112_231, fb.media_ssrc);
}

test "PLI: encode" {
    var expected = [_]u8{ 0, 1, 225, 185, 0, 1, 182, 103 };
    var buffer: [pli_size]u8 = undefined;

    const pli = PLI{ .sender_ssrc = 123_321, .media_ssrc = 112_231 };
    PLI.encode(&pli, &buffer);
    try std.testing.expectEqualSlices(u8, &expected, buffer[0..]);
}

test "PLI: writer encode" {
    var expected = [_]u8{ 0, 1, 225, 185, 0, 1, 182, 103 };
    var buffer: [pli_size]u8 = undefined;
    const pli = PLI{ .sender_ssrc = 123_321, .media_ssrc = 112_231 };

    var writer = Io.Writer.fixed(&buffer);
    try PLI.writerEncode(&pli, &writer);
    try std.testing.expectEqualSlices(u8, &expected, buffer[0..]);
}

test "AFB: decode" {
    const data = [_]u8{ 0, 1, 225, 185, 0, 1, 182, 103, 'R', 'E', 'M', 'B' };
    const fb = try AFB.decode(&data);

    try std.testing.expectEqual(123_321, fb.sender_ssrc);
    try std.testing.expectEqual(112_231, fb.media_ssrc);
    try std.testing.expectEqualSlices(u8, data[8..], fb.data);
}

test "AFB: decode with empty data" {
    const data = [_]u8{ 0, 1, 225, 185, 0, 1, 182, 103 };
    const fb = try AFB.decode(&data);

    try std.testing.expectEqual(123_321, fb.sender_ssrc);
    try std.testing.expectEqual(112_231, fb.media_ssrc);
    try std.testing.expectEqual(0, fb.data.len);
}

test "AFB: decode malformed packet" {
    const data = [_]u8{ 0, 1, 225, 185, 0, 1, 182 };
    try std.testing.expectError(error.MalformedPacket, AFB.decode(&data));
}
