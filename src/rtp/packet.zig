//! Describes an RTP packet.
const std = @import("std");

const Reader = std.Io.Reader;
const Self = @This();

pub const ParseError = error{EndOfStream};
pub const WriteError = error{WriteFailed};

/// Describes an RTP header.
pub const Header = packed struct {
    ssrc: u32,
    timestamp: u32,
    sequence_number: u16,
    payload_type: u7,
    marker: bool,
    csrc_count: u4 = 0,
    extension: bool,
    padding: bool,
    version: u2 = 2,
};

/// Describes an RTP Extension
pub const Extension = struct {
    profile: u16,
    data: []const u8,

    fn parse(reader: *Reader) !Extension {
        const profile = reader.takeInt(u16, .big) catch return error.EndOfStream;
        const extension_size = (reader.takeInt(u16, .big) catch return error.EndOfStream) * 4;
        const ext_data = reader.take(extension_size) catch return error.EndOfStream;

        return .{
            .profile = profile,
            .data = ext_data,
        };
    }

    fn write(ext: *const Extension, writer: *std.Io.Writer) !void {
        try writer.writeInt(u16, ext.profile, .big);
        try writer.writeInt(u16, @intCast(@divExact(ext.data.len, 4)), .big);
        try writer.writeAll(ext.data);
    }

    inline fn size(ext: *const Extension) usize {
        return ext.data.len + 4;
    }
};

header: Header,
csrc_list: []align(1) const u32 = &.{},
extension: ?Extension = null,
payload: []const u8,
padding_size: u8 = 0,

/// Parses RTP Packet from slice
pub fn parse(data: []const u8) ParseError!Self {
    var reader = std.Io.Reader.fixed(data);
    var packet: Self = .{
        .header = undefined,
        .payload = &.{},
    };

    packet.header = reader.takeStruct(Header, .big) catch return error.EndOfStream;
    const csrc_count = reader.take(@as(usize, packet.header.csrc_count) * 4) catch return error.EndOfStream;
    packet.csrc_list = std.mem.bytesAsSlice(u32, csrc_count);

    if (packet.header.extension) packet.extension = try .parse(&reader);

    if (packet.header.padding) {
        if (reader.seek >= data.len or data[data.len - 1] + reader.seek > data.len) {
            @branchHint(.unlikely);
            return error.EndOfStream;
        }

        packet.padding_size = data[data.len - 1];
    }
    packet.payload = data[reader.seek .. reader.end - packet.padding_size];

    return packet;
}

/// Serializes the rtp packet.
pub fn write(packet: *const Self, writer: *std.Io.Writer) WriteError!void {
    try writer.writeStruct(packet.header, .big);

    const csrc_list: []const u8 = std.mem.sliceAsBytes(packet.csrc_list);
    try writer.writeAll(csrc_list);

    if (packet.extension) |ext| try ext.write(writer);

    try writer.writeAll(packet.payload);
    if (packet.header.padding) {
        const pad: u8 = @intCast(4 - @rem(packet.payload.len, 4));
        for (0..pad - 1) |_| try writer.writeByte(0);
        try writer.writeByte(pad);
    }
}

pub fn format(self: Self, writer: *std.Io.Writer) !void {
    try writer.writeAll("RTP Packet:\n");
    try writer.writeAll("\tVersion: ");
    try writer.print("{d}\n", .{self.header.version});
    try writer.writeAll("\tMarker: ");
    try writer.print("{}\n", .{self.header.marker});
    try writer.writeAll("\tPayload Type: ");
    try writer.print("{d}\n", .{self.header.payload_type});
    try writer.writeAll("\tSequence Number: ");
    try writer.print("{d}\n", .{self.header.sequence_number});
    try writer.writeAll("\tTimestamp: ");
    try writer.print("{d}\n", .{self.header.timestamp});
    try writer.writeAll("\tSSRC: ");
    try writer.print("{d}\n", .{self.header.ssrc});
    try writer.writeAll("\tPayload Size: ");
    try writer.print("{d} bytes\n", .{self.payload.len});
}

const header_size = @divExact(@bitSizeOf(Header), 8);

pub fn size(packet: *const Self) usize {
    const ext_size = if (packet.extension) |ext| ext.size() else 0;
    const padding_size = if (packet.header.padding) 4 - @rem(packet.payload.len + ext_size, 4) else 0;
    return header_size + packet.csrc_list.len * 4 + ext_size + packet.payload.len + padding_size;
}

test "parse packet" {
    const rtp_packet: [16]u8 = [_]u8{
        0x80, 0xE0, 0x51, 0xA4, 0x00, 0x0D, 0xDF,
        0x22, 0x54, 0xA7, 0xD4, 0xF3, 0x01, 0x02,
        0x03, 0x04,
    };

    const packet = try Self.parse(rtp_packet[0..]);

    try std.testing.expect(packet.header.version == 2);
    try std.testing.expect(!packet.header.padding);
    try std.testing.expect(!packet.header.extension);
    try std.testing.expect(packet.header.csrc_count == 0);
    try std.testing.expect(packet.header.marker);
    try std.testing.expect(packet.header.payload_type == 96);
    try std.testing.expect(packet.header.sequence_number == 0x51A4);
    try std.testing.expect(packet.header.timestamp == 0x000DDF22);
    try std.testing.expect(packet.header.ssrc == 0x54A7D4F3);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03, 0x04 }, packet.payload);

    try std.testing.expectEqual(16, packet.size());
}

test "packet too short" {
    const short_packet: [10]u8 = [_]u8{ 0x80, 0xE0, 0x51, 0xA4, 0x00, 0x0D, 0xDF, 0x22, 0x54, 0xA7 };

    const result = Self.parse(short_packet[0..]);
    try std.testing.expectError(ParseError.EndOfStream, result);
}

test "packet with csrc" {
    const packet = [_]u8{
        0x83, 0x6F, 0x41, 0xFF, 0xD2,
        0x14, 0x8B, 0xBA, 0x37, 0xB8,
        0x30, 0x7F, 0x37, 0xB8, 0x30,
        0x7F, 0x37, 0xB8, 0x30, 0x7E,
        0x37, 0xB8, 0x30, 0x73, 0x00,
        0x00, 0x05, 0x00, 0x09,
    };

    const csrc_list: []align(1) const u32 = std.mem.bytesAsSlice(u32, packet[12..24]);

    const parsed_packet = try Self.parse(packet[0..]);
    try std.testing.expect(parsed_packet.header.csrc_count == 3);

    for (csrc_list, parsed_packet.csrc_list) |csrc, parsed_csrc| {
        try std.testing.expect(csrc == parsed_csrc);
    }

    try std.testing.expectEqual(29, parsed_packet.size());
}

test "packet with extension" {
    const packet = [_]u8{
        0x90, 0x6F, 0x41, 0xFF, 0xD2, 0x14,
        0x8B, 0xBA, 0x37, 0xB8, 0x30, 0x7F,
        0xBD, 0xDE, 0x00, 0x03, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x09,
    };

    const parsed_packet = try Self.parse(packet[0..]);
    try std.testing.expect(parsed_packet.header.extension);
    try std.testing.expect(parsed_packet.extension.?.profile == 0xBDDE);
    try std.testing.expectEqualSlices(u8, packet[16..28], parsed_packet.extension.?.data);
}

test "packet with padding" {
    const packet = [_]u8{
        0xB3, 0x6F, 0x41, 0xFF, 0xD2, 0x14, 0x8B,
        0xBA, 0x37, 0xB8, 0x30, 0x7F, 0x37, 0xB8,
        0x30, 0x7F, 0x37, 0xB8, 0x30, 0x7E, 0x37,
        0xB8, 0x30, 0x73, 0xBD, 0xDE, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x00, 0x00, 0x00, 0x04,
    };

    const parsed_packet = try Self.parse(packet[0..]);
    try std.testing.expect(parsed_packet.header.padding);
    try std.testing.expect(parsed_packet.padding_size == 4);

    try std.testing.expectEqual(48, parsed_packet.size());
}

test "write packet" {
    const expected = [_]u8{
        0x80, 0xE0, 0x51, 0xA4, 0x00, 0x0D, 0xDF,
        0x22, 0x54, 0xA7, 0xD4, 0xF3, 0x01, 0x02,
        0x03, 0x04,
    };

    const packet: Self = .{
        .header = .{
            .padding = false,
            .extension = false,
            .payload_type = 96,
            .csrc_count = 0,
            .sequence_number = 0x51A4,
            .marker = true,
            .timestamp = 0x000DDF22,
            .ssrc = 0x54A7D4F3,
        },
        .payload = &[_]u8{ 0x01, 0x02, 0x03, 0x04 },
    };

    var buffer: [1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packet.write(&writer);
    try std.testing.expectEqualSlices(u8, &expected, writer.buffered());
}

test "write packet with csrc" {
    const expected = [_]u8{
        0x83, 0x6F, 0x41, 0xFF, 0xD2,
        0x14, 0x8B, 0xBA, 0x37, 0xB8,
        0x30, 0x7F, 0x37, 0xB8, 0x30,
        0x7F, 0x37, 0xB8, 0x30, 0x7E,
        0x37, 0xB8, 0x30, 0x73, 0x00,
        0x00, 0x05, 0x00, 0x09,
    };

    const packet: Self = .{
        .header = .{
            .padding = false,
            .extension = false,
            .payload_type = 111,
            .csrc_count = 3,
            .sequence_number = 0x41FF,
            .marker = false,
            .timestamp = 0xD2148BBA,
            .ssrc = 0x37B8307F,
        },
        .csrc_list = std.mem.bytesAsSlice(u32, expected[12..24]),
        .payload = &[_]u8{ 0x00, 0x00, 0x05, 0x00, 0x09 },
    };

    var buffer: [1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packet.write(&writer);
    try std.testing.expectEqualSlices(u8, &expected, writer.buffered());
}

test "write packet with extension" {
    const expected = [_]u8{
        0x90, 0x6F, 0x41, 0xFF, 0xD2, 0x14,
        0x8B, 0xBA, 0x37, 0xB8, 0x30, 0x7F,
        0xBD, 0xDE, 0x00, 0x03, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x09,
    };

    const packet: Self = .{
        .header = .{
            .padding = false,
            .extension = true,
            .payload_type = 111,
            .csrc_count = 0,
            .sequence_number = 0x41FF,
            .marker = false,
            .timestamp = 0xD2148BBA,
            .ssrc = 0x37B8307F,
        },
        .extension = .{
            .profile = 0xBDDE,
            .data = expected[16..28],
        },
        .payload = expected[28..33],
    };

    var buffer: [1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packet.write(&writer);
    try std.testing.expectEqualSlices(u8, &expected, writer.buffered());
}

test "write packet with padding" {
    const expected = [_]u8{
        0xB3, 0x6F, 0x41, 0xFF, 0xD2, 0x14, 0x8B,
        0xBA, 0x37, 0xB8, 0x30, 0x7F, 0x37, 0xB8,
        0x30, 0x7F, 0x37, 0xB8, 0x30, 0x7E, 0x37,
        0xB8, 0x30, 0x73, 0xBD, 0xDE, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x00, 0x04,
    };

    const packet: Self = .{
        .header = .{
            .padding = true,
            .extension = true,
            .payload_type = 111,
            .csrc_count = 3,
            .sequence_number = 0x41FF,
            .marker = false,
            .timestamp = 0xD2148BBA,
            .ssrc = 0x37B8307F,
        },
        .csrc_list = std.mem.bytesAsSlice(u32, expected[12..24]),
        .extension = .{
            .profile = 0xBDDE,
            .data = expected[28..40],
        },
        .payload = expected[40..44],
    };

    var buffer: [1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packet.write(&writer);
    try std.testing.expectEqualSlices(u8, &expected, writer.buffered());
}
