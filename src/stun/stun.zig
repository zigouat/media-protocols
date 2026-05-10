const std = @import("std");

const Io = std.Io;

pub const magic_cookie: u32 = 0x2112A442;
pub const header_size = 20;
const fingerprint_xor: u32 = 0x5354554e;

pub const Class = enum(u2) {
    request,
    indication,
    success_response,
    error_response,
};

pub const Method = enum(u12) {
    binding = 1,
    _,
};

pub const MessageType = packed struct {
    m1: u4,
    c1: u1,
    m2: u3,
    c2: u1,
    m3: u5,

    pub fn fromClassAndMethod(c: Class, m: Method) MessageType {
        const m_int = @intFromEnum(m);
        const cl_int = @intFromEnum(c);

        return MessageType{
            .m1 = @intCast(m_int & 0x0F),
            .c1 = @intCast(cl_int & 1),
            .m2 = @intCast((m_int >> 4) & 0x07),
            .c2 = @intCast(cl_int >> 1),
            .m3 = @intCast((m_int >> 7) & 0x1F),
        };
    }

    pub fn method(self: MessageType) Method {
        const method_int = @as(u12, self.m3) << 7 | @as(u12, self.m2) << 4 | self.m1;
        return @enumFromInt(method_int);
    }

    pub fn class(self: MessageType) Class {
        return @enumFromInt((@as(u2, self.c2) << 1) | self.c1);
    }
};

pub const Header = packed struct {
    transaction_id: u96,
    magic_cookie: u32 = magic_cookie,
    message_length: u16,
    message_type: MessageType,
    _pad: u2 = 0,
};

/// Describes a Stun message.
pub const Message = struct {
    header: Header,
    bytes: []const u8,

    pub const Error = error{
        /// Magic cookie in the header doesn't match the Stun defined one.
        WrongMagicCookie,
        /// The length reported in the header is not equal to the body of the stun message.
        InvalidLength,
    };

    pub fn iterateAttributes(message: *const Message, passwd: []const u8) AttributeIterator {
        var reader = std.Io.Reader.fixed(message.bytes);
        reader.toss(header_size);
        return .{ .reader = reader, .password = passwd };
    }

    pub fn parse(msg: []const u8) Error!Message {
        std.debug.assert(msg.len >= header_size);

        const header_int = std.mem.readInt(@typeInfo(Header).@"struct".backing_integer.?, msg[0..header_size], .big);
        const header: Header = @bitCast(header_int);
        if (header.magic_cookie != magic_cookie) {
            return error.WrongMagicCookie;
        }

        if (header.message_length != msg.len - header_size) {
            return error.InvalidLength;
        }

        return .{
            .header = header,
            .bytes = msg,
        };
    }
};

pub const StunError = struct {
    code: u16,
    reason: []const u8,
};

pub const AttributeType = enum(u16) {
    mapped_address = 0x0001,
    username = 0x0006,
    message_integrity = 0x0008,
    error_code = 0x0009,
    xor_mapped_address = 0x0020,
    use_candidate = 0x0025,
    userhash = 0x001E,
    priority = 0x0024,
    software = 0x8022,
    fingerprint = 0x8028,
    ice_controlled = 0x8029,
    ice_controlling = 0x802A,
    unknown = 0xFFFF,
    _,
};

pub const Attribute = union(AttributeType) {
    mapped_address: Io.net.IpAddress,
    username: []const u8,
    message_integrity: []const u8,
    error_code: StunError,
    xor_mapped_address: Io.net.IpAddress,
    use_candidate: void,
    userhash: []const u8,
    priority: u32,
    software: []const u8,
    fingerprint: void,
    ice_controlled: u64,
    ice_controlling: u64,
    unknown: struct { AttributeType, []const u8 },

    pub fn size(attribute: Attribute) u16 {
        return switch (attribute) {
            .priority, .fingerprint => 4,
            .ice_controlled, .ice_controlling => 8,
            .message_integrity => 20,
            .use_candidate => 0,
            .software, .username, .userhash => |slice| @intCast(slice.len),
            .mapped_address, .xor_mapped_address => |ip| switch (ip) {
                .ip4 => 8,
                .ip6 => 20,
            },
            .error_code => |err| @intCast(err.reason.len + 4),
            else => 0,
        };
    }
};

pub const AttributeIterator = struct {
    reader: Io.Reader,
    password: []const u8,

    pub const Error = error{
        InvalidAttribute,
        MessageIntegrityCheckFailed,
        FingerprintCheckFailed,
    };

    pub fn next(it: *AttributeIterator) Error!?Attribute {
        if (it.reader.bufferedLen() == 0) return null;

        const attr_type = it.reader.takeEnum(AttributeType, .big) catch return error.InvalidAttribute;
        const attr_len = it.reader.takeInt(u16, .big) catch return error.InvalidAttribute;

        const padding = switch (@rem(attr_len, 4)) {
            0 => 0,
            else => |v| 4 - v,
        };
        const attr_value = it.reader.take(attr_len + padding) catch return error.InvalidAttribute;

        return switch (attr_type) {
            .mapped_address => try parseMappedAddress(attr_value),
            .xor_mapped_address => try parseXorMappedAddress(attr_value, it.reader.buffer[8..20]),
            .username => .{ .username = attr_value[0..attr_len] },
            .software => .{ .software = attr_value[0..attr_len] },
            .error_code => blk: {
                if (attr_value.len < 4) return error.InvalidAttribute;
                const class = attr_value[2] & 0x07;
                if (class < 3 or class > 6 or attr_value[3] > 99) return error.InvalidAttribute;
                break :blk .{ .error_code = .{
                    .code = (@as(u16, class) << 8) | attr_value[3],
                    .reason = attr_value[4..attr_len],
                } };
            },
            .userhash => blk: {
                if (attr_len != 32) break :blk error.InvalidAttribute;
                break :blk .{ .userhash = attr_value[0..attr_len] };
            },
            .priority => blk: {
                if (attr_len != 4) return error.InvalidAttribute;
                break :blk .{ .priority = std.mem.readInt(u32, attr_value[0..4], .big) };
            },
            .ice_controlled, .ice_controlling => blk: {
                if (attr_len != 8) return error.InvalidAttribute;
                const tie_breaker = std.mem.readInt(u64, attr_value[0..8], .big);
                break :blk if (attr_type == .ice_controlled) .{ .ice_controlled = tie_breaker } else .{ .ice_controlling = tie_breaker };
            },
            .use_candidate => blk: {
                if (attr_value.len != 0) return error.InvalidAttribute;
                break :blk .use_candidate;
            },
            .message_integrity => blk: {
                if (attr_len != 20) break :blk error.InvalidAttribute;
                try it.verifyMessageIntegrity(attr_value);
                break :blk .{ .message_integrity = attr_value };
            },
            .fingerprint => blk: {
                if (attr_len != 4) break :blk error.InvalidAttribute;
                const fingerprint = std.mem.readInt(u32, attr_value[0..4], .big);
                try it.verifyFingerprint(fingerprint);
                break :blk .fingerprint;
            },
            else => .{ .unknown = .{ attr_type, attr_value } },
        };
    }

    fn parseMappedAddress(value: []const u8) !Attribute {
        if (value.len < 8) return error.InvalidAttribute;

        const family = switch (value[1]) {
            1 => Io.net.IpAddress.Family.ip4,
            2 => Io.net.IpAddress.Family.ip6,
            else => return error.InvalidAttribute,
        };

        if (family == .ip4 and value.len != 8 or family == .ip6 and value.len != 20) {
            return error.InvalidAttribute;
        }

        const port = std.mem.readInt(u16, value[2..4], .big);
        const ip = blk: switch (family) {
            .ip4 => {
                var ip = Io.net.IpAddress{ .ip4 = .unspecified(port) };
                @memcpy(&ip.ip4.bytes, value[4..8]);
                break :blk ip;
            },
            .ip6 => {
                var ip = Io.net.IpAddress{ .ip6 = .unspecified(port) };
                @memcpy(&ip.ip6.bytes, value[4..]);
                break :blk ip;
            },
        };

        return .{ .mapped_address = ip };
    }

    fn parseXorMappedAddress(value: []const u8, tx_id: []const u8) !Attribute {
        if (value.len < 8) return error.InvalidAttribute;
        const family = switch (value[1]) {
            1 => Io.net.IpAddress.Family.ip4,
            2 => Io.net.IpAddress.Family.ip6,
            else => return error.InvalidAttribute,
        };

        if (family == .ip4 and value.len != 8 or family == .ip6 and value.len != 20) {
            return error.InvalidAttribute;
        }

        const cookie = std.mem.toBytes(std.mem.nativeToBig(u32, magic_cookie));
        const port: u16 = std.mem.readInt(u16, &[_]u8{ value[2] ^ cookie[0], value[3] ^ cookie[1] }, .big);
        const ip = blk: switch (family) {
            .ip4 => {
                var ip = Io.net.IpAddress{ .ip4 = .unspecified(port) };
                for (&ip.ip4.bytes, 0..) |*b, idx| b.* = value[4 + idx] ^ cookie[idx];
                break :blk ip;
            },
            .ip6 => {
                var ip = Io.net.IpAddress{ .ip6 = .unspecified(port) };
                for (ip.ip6.bytes[0..4], 0..) |*b, idx| b.* = value[4 + idx] ^ cookie[idx];
                for (ip.ip4.bytes[4..], 0..) |*b, idx| b.* = value[8 + idx] ^ tx_id[idx];
                break :blk ip;
            },
        };

        return .{ .xor_mapped_address = ip };
    }

    fn verifyMessageIntegrity(it: *const AttributeIterator, expected_hash: []u8) !void {
        var hash: [20]u8 = undefined;
        const msg = it.reader.buffer[0..it.reader.seek];
        const msg_size = msg.len - header_size;

        var hasher: std.crypto.auth.hmac.HmacSha1 = .init(it.password);
        hasher.update(msg[0..2]);
        hasher.update(&std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(msg_size))));
        hasher.update(msg[4 .. msg_size - 4]);
        hasher.final(&hash);

        if (!std.mem.eql(u8, &hash, expected_hash)) {
            return error.MessageIntegrityCheckFailed;
        }
    }

    fn verifyFingerprint(it: *const AttributeIterator, expected_value: u32) !void {
        const msg = it.reader.buffer;

        var hasher: std.hash.Crc32 = .init();
        hasher.update(msg[0 .. msg.len - 8]);
        if (hasher.final() ^ fingerprint_xor != expected_value) {
            return error.FingerprintCheckFailed;
        }
    }
};

pub const Writer = struct {
    writer: Io.Writer,
    options: WriterOptions,

    pub const WriterOptions = struct {
        password: ?[]const u8 = null,
        padding_byte: u8 = 0,
    };

    pub fn init(buffer: []u8, options: WriterOptions) Writer {
        return .{ .writer = .fixed(buffer), .options = options };
    }

    pub fn writeHeader(msg_writer: *Writer, header: Header) !void {
        try msg_writer.writer.writeStruct(header, .big);
    }

    pub fn writeRaw(msg_writer: *Writer, attr_type: AttributeType, content: []const []const u8) !void {
        var w = &msg_writer.writer;

        try w.writeInt(u16, @intFromEnum(attr_type), .big);
        const length = try w.writableArray(2);
        const pos = w.end;
        try msg_writer.writer.writeVecAll(@constCast(content));

        const attr_size: u16 = @intCast(w.end - pos);
        const padding = switch (@rem(attr_size, 4)) {
            0 => 0,
            else => |v| 4 - v,
        };
        @memset(try w.writableSlice(padding), msg_writer.options.padding_byte);
        std.mem.writeInt(u16, length, attr_size, .big);
    }

    pub fn writeAttribute(msg_writer: *Writer, attribute: Attribute) !void {
        var out = &msg_writer.writer;

        try out.writeInt(u16, @intFromEnum(attribute), .big);
        try out.writeInt(u16, attribute.size(), .big);
        switch (attribute) {
            .priority => |p| try out.writeInt(u32, p, .big),
            .ice_controlled, .ice_controlling => |tie_breaker| try out.writeInt(u64, tie_breaker, .big),
            .message_integrity => try msg_writer.writeMessageIntegrity(),
            .fingerprint => try writeFingerprint(&msg_writer.writer),
            .software, .username, .userhash => |slice| try out.writeAll(slice),
            .mapped_address => |addr| try msg_writer.writeIpAddress(addr, false),
            .xor_mapped_address => |addr| try msg_writer.writeIpAddress(addr, true),
            .error_code => |err| {
                try msg_writer.writer.writeInt(u32, @as(u24, err.code / 100) << 16 | (err.code % 100), .big);
                try msg_writer.writer.writeAll(err.reason);
            },
            else => return error.UnknownAttribute,
        }

        const padding = switch (@rem(out.end, 4)) {
            0 => 0,
            else => |v| 4 - v,
        };
        @memset(try out.writableSlice(padding), msg_writer.options.padding_byte);
    }

    pub fn final(msg_writer: *Writer) []const u8 {
        const result = msg_writer.writer.buffered();
        const msg_length: u16 = @intCast(result.len - header_size);
        std.mem.writeInt(u16, result[2..4], msg_length, .big);
        return result;
    }

    fn writeMessageIntegrity(msg_writer: *Writer) !void {
        var w = &msg_writer.writer;

        const buf = w.buffered();
        const hash = try w.writableArray(20);
        const msg_length: u16 = @intCast(w.end - header_size); // 4 bytes of already written attribute header

        var hasher = std.crypto.auth.hmac.HmacSha1.init(msg_writer.options.password.?);
        hasher.update(buf[0..2]);
        hasher.update(&std.mem.toBytes(std.mem.nativeToBig(u16, msg_length)));
        hasher.update(buf[4 .. buf.len - 4]);
        hasher.final(hash);
    }

    fn writeFingerprint(w: *Io.Writer) !void {
        const buf = w.buffered();
        const msg_size: u16 = @intCast(buf.len - header_size + 4);

        var hasher: std.hash.Crc32 = .init();
        hasher.update(buf[0..2]);
        hasher.update(&std.mem.toBytes(std.mem.nativeToBig(u16, msg_size)));
        hasher.update(buf[4 .. buf.len - 4]);

        try w.writeInt(u32, hasher.final() ^ fingerprint_xor, .big);
    }

    fn writeIpAddress(msg_writer: *Writer, addr: Io.net.IpAddress, xor: bool) !void {
        var out = &msg_writer.writer;
        const cookie = std.mem.toBytes(std.mem.nativeToBig(u32, magic_cookie));
        switch (addr) {
            .ip4 => |ipv4| {
                try out.writeInt(u16, 1, .big);
                if (xor) {
                    const xor_port: u16 = ipv4.port ^ @as(u16, magic_cookie >> 16);
                    try out.writeAll(&std.mem.toBytes(std.mem.nativeToBig(u16, xor_port)));

                    const slice = try out.writableSlice(cookie.len);
                    for (slice, 0..) |*b, idx| b.* = cookie[idx] ^ ipv4.bytes[idx];
                } else {
                    try out.writeInt(u16, ipv4.port, .big);
                    try out.writeAll(&ipv4.bytes);
                }
            },
            .ip6 => |ipv6| {
                try out.writeInt(u16, 2, .big);
                if (xor) {
                    const xor_port: u16 = ipv6.port ^ @as(u16, magic_cookie >> 16);
                    try out.writeAll(&std.mem.toBytes(std.mem.nativeToBig(u16, xor_port)));

                    const slice = try out.writableSlice(ipv6.bytes.len);
                    const txid = out.buffer[8..20];

                    for (slice, 0..) |*b, idx| b.* = cookie[idx] ^ ipv6.bytes[idx];
                    for (slice[4..], 0..) |*b, idx| b.* = txid[idx] ^ ipv6.bytes[idx];
                } else {
                    try out.writeInt(u16, ipv6.port, .big);
                    try out.writeAll(&ipv6.bytes);
                }
            },
        }
    }
};

const testing = std.testing;

test "MessageType: round-trip all classes" {
    const classes = [_]Class{ .request, .indication, .success_response, .error_response };
    for (classes) |c| {
        const mt = MessageType.fromClassAndMethod(c, .binding);
        try testing.expectEqual(c, mt.class());
        try testing.expectEqual(Method.binding, mt.method());
    }
}

test "Header: size matches STUN spec" {
    try testing.expectEqual(@as(usize, 20), @divExact(@bitSizeOf(Header), 8));
}

test "Message.parse: binding request header" {
    const bytes = [_]u8{
        0x00, 0x01, 0x00, 0x00,
        0x21, 0x12, 0xA4, 0x42,
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
    };

    const msg = try Message.parse(&bytes);
    try testing.expectEqual(Class.request, msg.header.message_type.class());
    try testing.expectEqual(Method.binding, msg.header.message_type.method());
    try testing.expectEqual(@as(u16, 0), msg.header.message_length);
    try testing.expectEqual(@as(u32, magic_cookie), msg.header.magic_cookie);
    try testing.expectEqual(@as(u96, 0x000102030405060708090A0B), msg.header.transaction_id);

    var it = msg.iterateAttributes(&.{});
    try testing.expect((try it.next()) == null);
}

test "Message.parse: binding success response header" {
    const bytes = [_]u8{
        0x01, 0x01, 0x00, 0x00,
        0x21, 0x12, 0xA4, 0x42,
        0xB7, 0xE7, 0xA7, 0x01,
        0xBC, 0x34, 0xD6, 0x86,
        0xFA, 0x87, 0xDF, 0xAE,
    };

    const msg = try Message.parse(&bytes);
    try testing.expectEqual(Class.success_response, msg.header.message_type.class());
    try testing.expectEqual(Method.binding, msg.header.message_type.method());
}

test "Message.iterateAttributes" {
    const bytes = [_]u8{
        0x01, 0x01, 0x00, 0x38,
        0x21, 0x12, 0xA4, 0x42,
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        // MAPPED-ADDRESS IPv4
        0x00, 0x01, 0x00, 0x08,
        0x00, 0x01, 0x80, 0x55,
        192,  0,    2,    1,
        // MAPPED-ADDRESS IPv6
        0x00, 0x01, 0x00, 0x14,
        0x00, 0x02, 0x80, 0x55,
        0x20, 0x01, 0x0D, 0xB8,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        // XOR-MAPPED-ADDRESS IPv4
        0x00, 0x20, 0x00, 0x08,
        0x00, 0x01, 0xA1, 0x47,
        0xE1, 0x12, 0xA6, 0x43,
        // SOFTWARE (unknown)
        0x80, 0x22, 0x00, 0x04,
        't',  'e',  's',  't',
    };

    const expected_v4 = Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 32853 } };
    const expected_v6 = Io.net.IpAddress{ .ip6 = .{
        .bytes = .{
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        },
        .port = 32853,
    } };

    const msg = try Message.parse(&bytes);
    var it = msg.iterateAttributes(&.{});

    const a1 = try it.next();
    try testing.expect(a1.?.mapped_address.eql(&expected_v4));

    const a2 = (try it.next()) orelse return error.MissingAttribute;
    try testing.expect(a2.mapped_address.eql(&expected_v6));

    const a3 = (try it.next()) orelse return error.MissingAttribute;
    try testing.expect(a3.xor_mapped_address.eql(&expected_v4));

    const a4 = (try it.next()) orelse return error.MissingAttribute;
    try testing.expectEqualStrings("test", a4.software);

    try testing.expectEqual(null, try it.next());
}

test "Message.iterateAttributes: invalid attribute length zero" {
    const bytes = [_]u8{
        0x00, 0x01, 0x00, 0x04,
        0x21, 0x12, 0xA4, 0x42,
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x00, 0x01, 0x00, 0x00,
    };

    const msg = try Message.parse(&bytes);
    var it = msg.iterateAttributes(&.{});
    try testing.expectError(error.InvalidAttribute, it.next());
}

const rfc_5769_test_vector = [_]u8{
    0x00, 0x01, 0x00, 0x58,
    0x21, 0x12, 0xa4, 0x42,
    0xb7, 0xe7, 0xa7, 0x01,
    0xbc, 0x34, 0xd6, 0x86,
    0xfa, 0x87, 0xdf, 0xae,
    0x80, 0x22, 0x00, 0x10,
    0x53, 0x54, 0x55, 0x4e,
    0x20, 0x74, 0x65, 0x73,
    0x74, 0x20, 0x63, 0x6c,
    0x69, 0x65, 0x6e, 0x74,
    0x00, 0x24, 0x00, 0x04,
    0x6e, 0x00, 0x01, 0xff,
    0x80, 0x29, 0x00, 0x08,
    0x93, 0x2f, 0xf9, 0xb1,
    0x51, 0x26, 0x3b, 0x36,
    0x00, 0x06, 0x00, 0x09,
    0x65, 0x76, 0x74, 0x6a,
    0x3a, 0x68, 0x36, 0x76,
    0x59, 0x20, 0x20, 0x20,
    0x00, 0x08, 0x00, 0x14,
    0x9a, 0xea, 0xa7, 0x0c,
    0xbf, 0xd8, 0xcb, 0x56,
    0x78, 0x1e, 0xf2, 0xb5,
    0xb2, 0xd3, 0xf2, 0x49,
    0xc1, 0xb5, 0x71, 0xa2,
    0x80, 0x28, 0x00, 0x04,
    0xe5, 0x7a, 0x3b, 0xcf,
};

// test vectors (RFC 5769)
test "Message: iterator attributes" {
    const message = try Message.parse(&rfc_5769_test_vector);
    try testing.expectEqual(.request, message.header.message_type.class());
    try testing.expectEqual(.binding, message.header.message_type.method());

    var it = message.iterateAttributes("VOkJxbRl1RmTxUk/WvJxBt");
    var attribute = try it.next() orelse return error.ExpectedAttribute;
    try testing.expectEqualStrings("STUN test client", attribute.software);

    attribute = try it.next() orelse return error.ExpectedAttribute;
    try testing.expectEqual(0x6E0001FF, attribute.priority);

    attribute = try it.next() orelse return error.ExpectedAttribute;
    try testing.expectEqual(0x932FF9B151263B36, attribute.ice_controlled);

    attribute = try it.next() orelse return error.ExpectedAttribute;
    try testing.expectEqualStrings("evtj:h6vY", attribute.username);

    _ = try it.next() orelse return error.ExpectedAttribute; // Message Integrity
    _ = try it.next() orelse return error.ExpectedAttribute; // Fingerprint
    try testing.expectEqual(null, try it.next());
}

test "Message.iterateAttributes: invalid attribute length not multiple of 4" {
    const bytes = [_]u8{
        0x00, 0x01, 0x00, 0x08,
        0x21, 0x12, 0xA4, 0x42,
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x00, 0x01, 0x00, 0x07,
        0xAA, 0xBB, 0xCC, 0xDD,
    };

    const msg = try Message.parse(&bytes);
    var it = msg.iterateAttributes(&.{});
    try testing.expectError(error.InvalidAttribute, it.next());
}

test "Writer: write rfc message" {
    var buffer: [1024]u8 = undefined;

    var out = Writer.init(&buffer, .{
        .password = "VOkJxbRl1RmTxUk/WvJxBt",
        .padding_byte = 0x20,
    });

    try out.writeHeader(.{
        .message_type = .fromClassAndMethod(.request, .binding),
        .transaction_id = std.mem.readInt(u96, rfc_5769_test_vector[8..20], .big),
        .message_length = 0,
    });

    try out.writeAttribute(.{ .software = "STUN test client" });
    try out.writeAttribute(.{ .priority = 0x6E0001FF });
    try out.writeAttribute(.{ .ice_controlled = 0x932FF9B151263B36 });
    try out.writeRaw(.username, &[_][]const u8{"evtj:h6vY"});
    try out.writeAttribute(.{ .message_integrity = &.{} });
    try out.writeAttribute(.fingerprint);

    try std.testing.expectEqualSlices(u8, &rfc_5769_test_vector, out.final());
}

test "Writer: write mapped and xor mapped addresses" {
    const expected = [_]u8{
        0x01, 0x01, 0x00, 0x30,
        0x21, 0x12, 0xA4, 0x42,
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        // MAPPED-ADDRESS IPv4
        0x00, 0x01, 0x00, 0x08,
        0x00, 0x01, 0x80, 0x55,
        192,  0,    2,    1,
        // MAPPED-ADDRESS IPv6
        0x00, 0x01, 0x00, 0x14,
        0x00, 0x02, 0x80, 0x55,
        0x20, 0x01, 0x0D, 0xB8,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        // XOR-MAPPED-ADDRESS IPv4
        0x00, 0x20, 0x00, 0x08,
        0x00, 0x01, 0xA1, 0x47,
        0xE1, 0x12, 0xA6, 0x43,
    };

    const ipv4 = Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 32853 } };
    const ipv6 = Io.net.IpAddress{ .ip6 = .{
        .bytes = .{
            0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        },
        .port = 32853,
    } };

    var buffer: [1024]u8 = undefined;
    var writer: Writer = .init(&buffer, .{});
    try writer.writeHeader(.{
        .message_type = .fromClassAndMethod(.success_response, .binding),
        .transaction_id = std.mem.readInt(u96, expected[8..20], .big),
        .message_length = 0,
    });

    try writer.writeAttribute(.{ .mapped_address = ipv4 });
    try writer.writeAttribute(.{ .mapped_address = ipv6 });
    try writer.writeAttribute(.{ .xor_mapped_address = ipv4 });
    try testing.expectEqualSlices(u8, &expected, writer.final());
}
