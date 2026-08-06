//! Describes an RTP packet.
const std = @import("std");

const Reader = std.Io.Reader;
const Self = @This();

pub const ParseError = error{MalformedPacket};
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
    profile: Profile,
    data: []const u8,

    pub const Profile = enum(u16) {
        one_byte = 0xBEDE,
        // When parsing, all values between 0x1000 and 0x100F are mapped to two bytes extension
        two_bytes = 0x1000,
        _,

        pub inline fn fromInt(profile: u16) Profile {
            return switch (profile) {
                0x1000...0x100F => .two_bytes,
                else => |v| @enumFromInt(v),
            };
        }
    };

    /// Item describes a one byte and two bytes extension item.
    pub const Item = struct {
        id: u8,
        value: []const u8,
    };

    pub const Iterator = struct {
        profile: Profile,
        reader: Reader,

        pub fn init(ext: Extension) !Iterator {
            return switch (ext.profile) {
                .one_byte, .two_bytes => .{ .profile = ext.profile, .reader = .fixed(ext.data) },
                else => error.UnsupportedProfile,
            };
        }

        pub fn next(it: *Iterator) !?Item {
            return switch (it.profile) {
                .one_byte => it.parseOneByteExt() catch error.InvalidExtension,
                .two_bytes => it.parseTwoBytesExt() catch error.InvalidExtension,
                else => unreachable,
            };
        }

        fn parseOneByteExt(it: *Iterator) !?Item {
            var reader = &it.reader;

            while (true) {
                const byte = reader.takeByte() catch return null;
                const id = byte >> 4;
                if (id == 0) continue;
                if (id == 15) return null;

                const len = (byte & 0x0F) + 1;
                const value = try reader.take(len);

                return .{ .id = id, .value = value };
            }
        }

        fn parseTwoBytesExt(it: *Iterator) !?Item {
            var reader = &it.reader;

            while (true) {
                const id = reader.takeByte() catch return null;
                if (id == 0) continue;
                const len = try reader.takeByte();
                return .{ .id = id, .value = try reader.take(len) };
            }
        }
    };

    /// RTP extension writer. It contains helper methods to write one byte and two bytes extension items.
    ///
    /// Note that the writer reserves two bytes for the extension size, which is written when flush is called.
    /// Make sure the IO.Writer's buffer is large enough to accommodate the whole extension data.
    pub const Writer = struct {
        profile: Profile,
        size_slice: *[2]u8,
        size: u16,
        w: *std.Io.Writer,

        pub fn init(profile: Profile, w: *std.Io.Writer) !Writer {
            try w.writeInt(u16, @intFromEnum(profile), .big);
            return .{
                .profile = profile,
                .w = w,
                .size_slice = try w.writableArray(2),
                .size = 0,
            };
        }

        pub fn writeItem(self: *Writer, item: Item) !void {
            switch (self.profile) {
                .one_byte => try self.writeOneByteItem(item),
                .two_bytes => try self.writeTwoBytesItem(item),
                else => unreachable,
            }
        }

        pub fn writeRaw(self: *Writer, data: []const u8) !void {
            try self.w.writeAll(data);
            self.size += @intCast(data.len);
        }

        pub fn flush(self: *Writer) !void {
            const pad: u8 = switch (@rem(self.size, 4)) {
                0 => 0,
                else => |rem| @intCast(4 - rem),
            };
            self.size += pad;
            try self.w.splatByteAll(0, pad);
            std.mem.writeInt(u16, self.size_slice, @divExact(self.size, 4), .big);
        }

        fn writeOneByteItem(self: *Writer, item: Item) !void {
            std.debug.assert(item.id > 0 and item.id < 15);
            std.debug.assert(item.value.len > 0 and item.value.len <= 16);

            const len: u8 = @intCast(item.value.len);
            const byte: u8 = (item.id << 4) | (len - 1);
            try self.w.writeByte(byte);
            try self.w.writeAll(item.value);

            self.size += @intCast(len + 1);
        }

        fn writeTwoBytesItem(self: *Writer, item: Item) !void {
            std.debug.assert(item.id > 0);
            std.debug.assert(item.value.len <= 255);

            try self.w.writeByte(item.id);
            try self.w.writeByte(@intCast(item.value.len));
            try self.w.writeAll(item.value);

            self.size += @intCast(item.value.len + 2);
        }
    };

    fn parse(reader: *Reader) !Extension {
        const profile: Profile = .fromInt(try reader.takeInt(u16, .big));
        const extension_size = (try reader.takeInt(u16, .big)) * 4;
        const ext_data = try reader.take(extension_size);

        return .{
            .profile = profile,
            .data = ext_data,
        };
    }

    fn parseSlice(buffer: []const u8) !Extension {
        var reader = Reader.fixed(buffer);
        return try Extension.parse(&reader);
    }

    fn write(ext: *const Extension, writer: *std.Io.Writer) !void {
        try writer.writeInt(u16, @intFromEnum(ext.profile), .big);
        try writer.writeInt(u16, @intCast(@divExact(ext.data.len, 4)), .big);
        try writer.writeAll(ext.data);
    }

    fn size(ext: *const Extension) usize {
        return ext.data.len + 4;
    }

    test "Iterator: init fails with extensions other than ony byte or two bytes" {
        var ext: Extension = .{ .profile = .one_byte, .data = &.{} };
        _ = try Iterator.init(ext);

        ext.profile = .two_bytes;
        _ = try Iterator.init(ext);

        ext.profile = @enumFromInt(0x9090);
        try std.testing.expectError(error.UnsupportedProfile, Iterator.init(ext));
    }

    test "Iterator: one byte extension" {
        var ext: Extension = .{
            .profile = .one_byte,
            .data = &[_]u8{
                0x10, 0x1F, 0x00, 0x00,
                0xA2, 0x01, 0x02, 0x03,
                0xF0, 0x00, 0x00, 0x00,
            },
        };

        {
            var it = try Iterator.init(ext);
            var item = (try it.next()).?;
            try std.testing.expectEqual(1, item.id);
            try std.testing.expectEqualSlices(u8, &[_]u8{0x1F}, item.value);

            item = (try it.next()).?;
            try std.testing.expectEqual(10, item.id);
            try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, item.value);

            try std.testing.expectEqual(null, it.next());
        }

        // no padding
        {
            ext.data = &[_]u8{ 0x32, 0x01, 0x02, 0x03 };
            var it = try Iterator.init(ext);

            const item = (try it.next()).?;
            try std.testing.expectEqual(3, item.id);
            try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, item.value);

            try std.testing.expectEqual(null, it.next());
        }
    }

    test "Iterator: Invalid extension" {
        const ext: Extension = .{
            .profile = .one_byte,
            .data = &[_]u8{ 0x1A, 0x01, 0x02, 0x03 },
        };

        var it = try Iterator.init(ext);
        try std.testing.expectError(error.InvalidExtension, it.next());
    }

    test "Iterator: two bytes extension" {
        var ext: Extension = .{
            .profile = .two_bytes,
            .data = &[_]u8{
                0x01, 0x01, 0x1F, 0x02,
                0x03, 0x01, 0x02, 0x03,
                0x00, 0x00, 0x0F, 0x00,
                0xC0, 0x01, 0xFF, 0x00,
            },
        };

        {
            var it = try Iterator.init(ext);
            var item = (try it.next()).?;
            try std.testing.expectEqual(1, item.id);
            try std.testing.expectEqualSlices(u8, &[_]u8{0x1F}, item.value);

            item = (try it.next()).?;
            try std.testing.expectEqual(2, item.id);
            try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, item.value);

            item = (try it.next()).?;
            try std.testing.expectEqual(15, item.id);
            try std.testing.expectEqualSlices(u8, &[_]u8{}, item.value);

            item = (try it.next()).?;
            try std.testing.expectEqual(192, item.id);
            try std.testing.expectEqualSlices(u8, &[_]u8{0xFF}, item.value);

            try std.testing.expectEqual(null, it.next());
        }

        // no padding
        {
            ext.data = &[_]u8{ 0x01, 0x02, 0x02, 0x03 };
            var it = try Iterator.init(ext);

            const item = (try it.next()).?;
            try std.testing.expectEqual(1, item.id);
            try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x03 }, item.value);

            try std.testing.expectEqual(null, it.next());
        }
    }

    test "Iterator: two bytes invalid extension" {
        var ext: Extension = .{
            .profile = .two_bytes,
            .data = &[_]u8{ 0x01, 0x03, 0x02, 0x03 },
        };

        {
            var it = try Iterator.init(ext);
            try std.testing.expectError(error.InvalidExtension, it.next());
        }

        {
            ext.data = &[_]u8{ 0x00, 0x00, 0x00, 0x03 };
            var it = try Iterator.init(ext);
            try std.testing.expectError(error.InvalidExtension, it.next());
        }
    }

    test "Writer: one byte extension" {
        var buffer: [64]u8 = undefined;
        var w = std.Io.Writer.fixed(&buffer);

        var writer = try Writer.init(.one_byte, &w);
        try writer.writeItem(.{ .id = 1, .value = &[_]u8{0x1F} });
        try writer.writeItem(.{ .id = 10, .value = &[_]u8{ 0x01, 0x02, 0x03 } });
        try writer.flush();

        const expected = [_]u8{
            0xBE, 0xDE, 0x00, 0x02,
            0x10, 0x1F, 0xA2, 0x01,
            0x02, 0x03, 0x00, 0x00,
        };
        try std.testing.expectEqualSlices(u8, &expected, w.buffered());

        const ext: Extension = try .parseSlice(w.buffered());
        var it = try Iterator.init(ext);

        var item = (try it.next()).?;
        try std.testing.expectEqual(1, item.id);
        try std.testing.expectEqualSlices(u8, &[_]u8{0x1F}, item.value);

        item = (try it.next()).?;
        try std.testing.expectEqual(10, item.id);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, item.value);

        try std.testing.expectEqual(null, it.next());
    }

    test "Writer: one byte extension no padding" {
        var buffer: [64]u8 = undefined;
        var w = std.Io.Writer.fixed(&buffer);

        var writer = try Writer.init(.one_byte, &w);
        try writer.writeItem(.{ .id = 3, .value = &[_]u8{ 0x01, 0x02, 0x03 } });
        try writer.flush();

        const expected = [_]u8{ 0xBE, 0xDE, 0x00, 0x01, 0x32, 0x01, 0x02, 0x03 };
        try std.testing.expectEqualSlices(u8, &expected, w.buffered());
    }

    test "Writer: two bytes extension" {
        var buffer: [64]u8 = undefined;
        var w = std.Io.Writer.fixed(&buffer);

        var writer = try Writer.init(.two_bytes, &w);
        try writer.writeItem(.{ .id = 1, .value = &[_]u8{0x1F} });
        try writer.writeItem(.{ .id = 2, .value = &[_]u8{ 0x01, 0x02, 0x03 } });
        try writer.writeItem(.{ .id = 15, .value = &[_]u8{} });
        try writer.writeItem(.{ .id = 192, .value = &[_]u8{0xFF} });
        try writer.flush();

        const ext: Extension = try .parseSlice(w.buffered());
        var it = try Iterator.init(ext);

        var item = (try it.next()).?;
        try std.testing.expectEqual(1, item.id);
        try std.testing.expectEqualSlices(u8, &[_]u8{0x1F}, item.value);

        item = (try it.next()).?;
        try std.testing.expectEqual(2, item.id);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, item.value);

        item = (try it.next()).?;
        try std.testing.expectEqual(15, item.id);
        try std.testing.expectEqualSlices(u8, &[_]u8{}, item.value);

        item = (try it.next()).?;
        try std.testing.expectEqual(192, item.id);
        try std.testing.expectEqualSlices(u8, &[_]u8{0xFF}, item.value);

        try std.testing.expectEqual(null, it.next());
    }

    test "Writer: two bytes extension no padding" {
        var buffer: [64]u8 = undefined;
        var w = std.Io.Writer.fixed(&buffer);

        var writer = try Writer.init(.two_bytes, &w);
        try writer.writeItem(.{ .id = 1, .value = &[_]u8{ 0x02, 0x03 } });
        try writer.flush();

        const expected = [_]u8{ 0x10, 0x00, 0x00, 0x01, 0x01, 0x02, 0x02, 0x03 };
        try std.testing.expectEqualSlices(u8, &expected, w.buffered());
    }

    test "Writer: writeRaw" {
        var buffer: [64]u8 = undefined;
        var w = std.Io.Writer.fixed(&buffer);

        var writer = try Writer.init(.one_byte, &w);
        try writer.writeRaw(&[_]u8{ 0x10, 0x1F });
        try writer.flush();

        const expected = [_]u8{ 0xBE, 0xDE, 0x00, 0x01, 0x10, 0x1F, 0x00, 0x00 };
        try std.testing.expectEqualSlices(u8, &expected, w.buffered());
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

    packet.header = reader.takeStruct(Header, .big) catch return error.MalformedPacket;
    const csrc_count = reader.take(@as(usize, packet.header.csrc_count) * 4) catch return error.MalformedPacket;
    packet.csrc_list = std.mem.bytesAsSlice(u32, csrc_count);

    if (packet.header.extension) packet.extension = Extension.parse(&reader) catch return error.MalformedPacket;

    if (packet.header.padding) {
        if (reader.seek >= data.len or data[data.len - 1] != data.len - reader.seek) {
            @branchHint(.unlikely);
            return error.MalformedPacket;
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

// Size assumes a paddinng of 4 bytes at max.
pub fn size(packet: *const Self) usize {
    const ext_size = if (packet.extension) |ext| ext.size() else 0;
    const padding_size = if (packet.header.padding) 4 - @rem(packet.payload.len + ext_size, 4) else 0;
    return header_size + packet.csrc_list.len * 4 + ext_size + packet.payload.len + padding_size;
}

test {
    std.testing.refAllDecls(@This());
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
    try std.testing.expectError(ParseError.MalformedPacket, result);
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
    try std.testing.expectEqual(@as(Extension.Profile, @enumFromInt(0xBDDE)), parsed_packet.extension.?.profile);
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
        0x00, 0x04,
    };

    const parsed_packet = try Self.parse(packet[0..]);
    try std.testing.expect(parsed_packet.header.padding);
    try std.testing.expect(parsed_packet.padding_size == 4);

    try std.testing.expectEqual(44, parsed_packet.size());
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
            .profile = @enumFromInt(0xBDDE),
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
        0xB8, 0x30, 0x73, 0xBE, 0xDE, 0x00, 0x03,
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
            .profile = .one_byte,
            .data = expected[28..40],
        },
        .payload = expected[40..44],
    };

    var buffer: [1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try packet.write(&writer);
    try std.testing.expectEqualSlices(u8, &expected, writer.buffered());
}
