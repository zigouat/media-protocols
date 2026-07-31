const std = @import("std");

const ParsedServerUrl = @This();

pub const Scheme = enum { stun, stuns, turn, turns };
pub const Transport = enum { udp, tcp };

scheme: Scheme,
host: []const u8,
port: u16,
transport: Transport,

pub const ParseError = error{
    InvalidUrl,
    UnsupportedScheme,
    UnsupportedTransport,
};

pub fn parse(url: []const u8) ParseError!ParsedServerUrl {
    var top_it = std.mem.splitScalar(u8, url, ':');
    const scheme_str = top_it.next() orelse return error.InvalidUrl;

    const scheme = if (std.ascii.eqlIgnoreCase(scheme_str, "stun"))
        Scheme.stun
    else if (std.ascii.eqlIgnoreCase(scheme_str, "stuns"))
        Scheme.stuns
    else if (std.ascii.eqlIgnoreCase(scheme_str, "turn"))
        Scheme.turn
    else if (std.ascii.eqlIgnoreCase(scheme_str, "turns"))
        Scheme.turns
    else
        return error.InvalidUrl;

    switch (scheme) {
        .stuns, .turns => return error.UnsupportedScheme,
        .stun, .turn => {},
    }

    var query_it = std.mem.splitScalar(u8, top_it.rest(), '?');
    const host_port = query_it.next() orelse return error.InvalidUrl;
    const query = query_it.next();

    var host_it = std.mem.splitScalar(u8, host_port, ':');
    const host = host_it.next() orelse return error.InvalidUrl;
    const port: u16 = blk: {
        const port_str = host_it.next() orelse break :blk 3478;
        break :blk std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidUrl;
    };

    var transport: Transport = .udp;
    if (query) |q| {
        const prefix = "transport=";
        if (!std.mem.startsWith(u8, q, prefix)) return error.InvalidUrl;
        transport = std.meta.stringToEnum(Transport, q[prefix.len..]) orelse return error.InvalidUrl;
    }

    if (scheme == .turn and transport == .tcp) return error.UnsupportedTransport;

    return .{ .scheme = scheme, .host = host, .port = port, .transport = transport };
}

const testing = std.testing;

test "parse: stun url with default port" {
    const parsed = try parse("stun:stun.example.org");
    try testing.expectEqual(Scheme.stun, parsed.scheme);
    try testing.expectEqualStrings("stun.example.org", parsed.host);
    try testing.expectEqual(3478, parsed.port);
    try testing.expectEqual(Transport.udp, parsed.transport);
}

test "parse: stun url with explicit port" {
    const parsed = try parse("stun:stun.example.org:19302");
    try testing.expectEqual(Scheme.stun, parsed.scheme);
    try testing.expectEqualStrings("stun.example.org", parsed.host);
    try testing.expectEqual(19302, parsed.port);
}

test "parse: scheme is case-insensitive" {
    const parsed = try parse("STuN:stun.example.org");
    try testing.expectEqual(Scheme.stun, parsed.scheme);
}

test "parse: turn url defaults to udp transport" {
    const parsed = try parse("turn:turn.example.org:3478");
    try testing.expectEqual(Scheme.turn, parsed.scheme);
    try testing.expectEqual(Transport.udp, parsed.transport);
}

test "parse: turn url with explicit udp transport" {
    const parsed = try parse("turn:turn.example.org:3478?transport=udp");
    try testing.expectEqual(Transport.udp, parsed.transport);
    try testing.expectEqual(3478, parsed.port);
    try testing.expectEqualStrings("turn.example.org", parsed.host);
}

test "parse: turn url without explicit port but with transport" {
    const parsed = try parse("turn:turn.example.org?transport=udp");
    try testing.expectEqualStrings("turn.example.org", parsed.host);
    try testing.expectEqual(3478, parsed.port);
    try testing.expectEqual(Transport.udp, parsed.transport);
}

test "parse: transport value is case-sensitive" {
    try testing.expectError(error.InvalidUrl, parse("turn:turn.example.org?transport=UDP"));
}

test "parse: rejects turn over tcp" {
    try testing.expectError(error.UnsupportedTransport, parse("turn:turn.example.org?transport=tcp"));
}

test "parse: rejects stuns scheme" {
    try testing.expectError(error.UnsupportedScheme, parse("stuns:stun.example.org"));
}

test "parse: rejects turns scheme" {
    try testing.expectError(error.UnsupportedScheme, parse("turns:turn.example.org"));
}

test "parse: rejects unknown scheme" {
    try testing.expectError(error.InvalidUrl, parse("http:example.org"));
}

test "parse: rejects unknown transport value" {
    try testing.expectError(error.InvalidUrl, parse("turn:turn.example.org?transport=sctp"));
}

test "parse: rejects query without transport prefix" {
    try testing.expectError(error.InvalidUrl, parse("turn:turn.example.org?foo=bar"));
}

test "parse: rejects non-numeric port" {
    try testing.expectError(error.InvalidUrl, parse("stun:stun.example.org:notaport"));
}

test "parse: rejects empty url" {
    try testing.expectError(error.InvalidUrl, parse(""));
}
