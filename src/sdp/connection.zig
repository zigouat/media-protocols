const std = @import("std");

const IpAddress = std.Io.net.IpAddress;
const Connection = @This();

pub const NetType = enum { in };

net_type: NetType,
address: IpAddress,

/// Parses a connection string in the format: "<net_type> <addr_type> <address>"
pub fn parse(buffer: []const u8) !Connection {
    var parts = std.mem.tokenizeScalar(u8, buffer, ' ');

    const net_type_str = parts.next() orelse return error.InvalidConnection;
    const addr_type_str = parts.next() orelse return error.InvalidConnection;
    const address_str = parts.next() orelse return error.InvalidConnection;

    const net_type = try parseNetType(net_type_str);

    const address = if (std.ascii.eqlIgnoreCase(addr_type_str, "ip4"))
        try IpAddress.parseIp4(address_str, 0)
    else if (std.ascii.eqlIgnoreCase(addr_type_str, "ip6"))
        try IpAddress.parseIp6(address_str, 0)
    else
        return error.InvalidConnection;

    return Connection{
        .net_type = net_type,
        .address = address,
    };
}

pub fn write(c: *const Connection, w: *std.Io.Writer) !void {
    try w.writeAll("c=IN ");
    switch (c.address) {
        .ip4 => |addr| try w.print("IP4 {}.{}.{}.{}\r\n", .{ addr.bytes[0], addr.bytes[1], addr.bytes[2], addr.bytes[3] }),
        .ip6 => |addr| {
            const u: std.Io.net.Ip6Address.Unresolved = .{ .bytes = addr.bytes, .interface_name = null };
            try w.print("IP6 {f}\r\n", .{u});
        },
    }
}

pub fn parseNetType(input: []const u8) !NetType {
    if (std.mem.eql(u8, "IN", input)) {
        return .in;
    } else {
        return error.InvalidNetType;
    }
}

test "parseNetType: valid IN" {
    const result = try parseNetType("IN");
    try std.testing.expectEqual(NetType.in, result);
}

test "parseNetType: invalid returns error" {
    try std.testing.expectError(error.InvalidNetType, parseNetType("OUT"));
    try std.testing.expectError(error.InvalidNetType, parseNetType(""));
    try std.testing.expectError(error.InvalidNetType, parseNetType("in"));
}

test "parse: IPv4 connection" {
    const result = try parse("IN IP4 192.168.1.1");
    try std.testing.expectEqual(NetType.in, result.net_type);
    try std.testing.expect(result.address.eql(&.{ .ip4 = .{ .bytes = [_]u8{ 192, 168, 1, 1 }, .port = 0 } }));
}

test "parse: IPv6 connection" {
    const expected_addr: IpAddress = .{ .ip6 = .loopback(0) };

    const result = try parse("IN IP6 ::1");
    try std.testing.expectEqual(NetType.in, result.net_type);
    try std.testing.expect(result.address.eql(&expected_addr));
}

test "parse: missing fields returns error" {
    try std.testing.expectError(error.InvalidConnection, parse("IN IP4"));
    try std.testing.expectError(error.InvalidConnection, parse("IN"));
    try std.testing.expectError(error.InvalidConnection, parse(""));
}

test "parse: invalid net_type returns error" {
    try std.testing.expectError(error.InvalidNetType, parse("OUT IP4 192.168.1.1"));
}

test "parse: invalid addr_type returns error" {
    try std.testing.expectError(error.InvalidConnection, parse("IN IP5 192.168.1.1"));
}

test "write connection" {
    var buf: [1024]u8 = @splat(0);
    var w: std.Io.Writer = .fixed(&buf);

    const ip4: Connection = .{ .net_type = .in, .address = .{ .ip4 = .loopback(0) } };
    const ip6: Connection = .{ .net_type = .in, .address = try .parseIp6("2a01:4f8:2220:3128::2", 0) };

    try ip4.write(&w);
    try std.testing.expectEqualStrings("c=IN IP4 127.0.0.1\r\n", w.buffered());
    _ = w.consumeAll();

    try ip6.write(&w);
    try std.testing.expectEqualStrings("c=IN IP6 2a01:4f8:2220:3128::2\r\n", w.buffered());
}
