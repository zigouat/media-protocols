const std = @import("std");

const Io = std.Io;

pub const magic_cookie: u32 = 0x2112A442;
pub const header_size = 20;

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

pub const Message = struct {
    header: Header,
    bytes: []const u8,

    pub fn iterateAttributes(message: *const Message) AttributeIterator {
        var reader = std.Io.Reader.fixed(message.bytes);
        reader.toss(header_size);
        return .{ .reader = reader };
    }

    pub fn parse(msg: []const u8) Message {
        std.debug.assert(msg.len >= header_size);

        const header_int = std.mem.readInt(@typeInfo(Header).@"struct".backing_integer.?, msg[0..header_size], .big);

        return .{
            .header = @bitCast(header_int),
            .bytes = msg,
        };
    }
};

pub const AttributeType = enum(u16) {
    mapped_address = 0x0001,
    xor_mapped_address = 0x0020,
    unknown = 0xFFFF,
    _,
};

pub const Attribute = union(AttributeType) {
    mapped_address: Io.net.IpAddress,
    xor_mapped_address: Io.net.IpAddress,
    unknown: struct { AttributeType, []const u8 },
};

pub const AttributeIterator = struct {
    reader: Io.Reader,

    pub fn next(it: *AttributeIterator) !?Attribute {
        if (it.reader.bufferedLen() == 0) return null;

        const attr_type = try it.reader.takeEnum(AttributeType, .big);
        const attr_len = try it.reader.takeInt(u16, .big);

        if (attr_len == 0 or @rem(attr_len, 4) != 0) {
            @branchHint(.cold);
            return error.InvalidAttribute;
        }

        const attr_value = try it.reader.take(attr_len);

        switch (attr_type) {
            .mapped_address => return try parseMappedAddress(attr_value),
            .xor_mapped_address => return try parseXorMappedAddress(attr_value, it.reader.buffer[8..20]),
            else => return .{ .unknown = .{ attr_type, attr_value } },
        }
    }

    fn parseMappedAddress(value: []const u8) !Attribute {
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

    const msg = Message.parse(&bytes);
    try testing.expectEqual(Class.request, msg.header.message_type.class());
    try testing.expectEqual(Method.binding, msg.header.message_type.method());
    try testing.expectEqual(@as(u16, 0), msg.header.message_length);
    try testing.expectEqual(@as(u32, magic_cookie), msg.header.magic_cookie);
    try testing.expectEqual(@as(u96, 0x000102030405060708090A0B), msg.header.transaction_id);

    var it = msg.iterateAttributes();
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

    const msg = Message.parse(&bytes);
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

    const msg = Message.parse(&bytes);
    var it = msg.iterateAttributes();

    const a1 = try it.next();
    try testing.expect(a1.?.mapped_address.eql(&expected_v4));

    const a2 = (try it.next()) orelse return error.MissingAttribute;
    try testing.expect(a2.mapped_address.eql(&expected_v6));

    const a3 = (try it.next()) orelse return error.MissingAttribute;
    try testing.expect(a3.xor_mapped_address.eql(&expected_v4));

    const a4 = (try it.next()) orelse return error.MissingAttribute;
    switch (a4) {
        .unknown => |u| {
            try testing.expectEqual(@as(AttributeType, @enumFromInt(0x8022)), u[0]);
            try testing.expectEqualSlices(u8, "test", u[1]);
        },
        else => return error.UnexpectedAttribute,
    }

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

    const msg = Message.parse(&bytes);
    var it = msg.iterateAttributes();
    try testing.expectError(error.InvalidAttribute, it.next());
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

    const msg = Message.parse(&bytes);
    var it = msg.iterateAttributes();
    try testing.expectError(error.InvalidAttribute, it.next());
}
