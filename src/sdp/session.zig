const std = @import("std");
const Connection = @import("connection.zig");
const Media = @import("media.zig");
const Attribute = @import("attribute.zig");

const Io = std.Io;
const Self = @This();

pub const Error = error{ InvalidSDP, InvalidOrigin, InvalidSessionName, InvalidMedia };

version: u8,
origin: Origin,
session_name: []const u8,
session_info: ?[]const u8 = null,
uri: ?[]const u8 = null,
connection: ?Connection = null,
attributes: []const u8 = &.{},
medias: []const u8 = &.{},

const State = enum { V, O, S, I, U, E, P, C, B, K, A, T, R, Z, M };

/// Struct representing an Origin field in an SDP message.
pub const Origin = struct {
    username: []const u8,
    session_id: u64,
    session_version: u64,
    nettype: Connection.NetType,
    unicast_address: std.Io.net.IpAddress,
};

/// Parses an SDP message from the given buffer
pub fn parse(buffer: []const u8) !Self {
    var reader = Io.Reader.fixed(buffer);
    var state: State = .V;

    var version: u8 = 0;
    var origin: Origin = undefined;
    var session_name: []const u8 = undefined;
    var session_info: ?[]const u8 = null;
    var uri: ?[]const u8 = null;
    var connection: ?Connection = null;
    var media: []const u8 = &.{};
    var attributes: []const u8 = &.{};

    return read: while (true) {
        const line_offset = reader.seek;
        var line = readLine(&reader) catch |err| switch (err) {
            error.EndOfStream => {
                return .{
                    .version = version,
                    .origin = origin,
                    .session_name = session_name,
                    .session_info = session_info,
                    .uri = uri,
                    .connection = connection,
                    .medias = media,
                    .attributes = attributes,
                };
            },
            else => return err,
        };

        _ = parse: switch (state) {
            .V => {
                if (!std.mem.startsWith(u8, line, "v=")) {
                    return error.InvalidSDP;
                }
                const ver_str = line[2..];
                version = try std.fmt.parseInt(u8, ver_str, 10);
                state = .O;
                continue :read;
            },
            .O => {
                if (!std.mem.startsWith(u8, line, "o=")) {
                    return error.InvalidSDP;
                }
                origin = try parseOrigin(line[2..]);
                state = .S;
                continue :read;
            },
            .S => {
                if (!std.mem.startsWith(u8, line, "s=")) {
                    return error.InvalidSDP;
                }

                session_name = line[2..];
                if (session_name.len == 0) {
                    return error.InvalidSessionName;
                }

                state = .I;
                continue :read;
            },
            .I => {
                state = .U;
                if (std.mem.startsWith(u8, line, "i=")) {
                    session_info = line[2..];
                    continue :read;
                }

                continue :parse .U;
            },
            .U => {
                state = .E;
                if (std.mem.startsWith(u8, line, "u=")) {
                    uri = line[2..];
                    continue :read;
                }
                continue :parse .E;
            },
            .E => {
                state = .P;
                if (std.mem.startsWith(u8, line, "e=")) {
                    // optional
                    continue :read;
                }
                // else skip to P
                continue :parse .P;
            },
            .P => {
                state = .C;
                if (std.mem.startsWith(u8, line, "p=")) {
                    // optional
                    continue :read;
                }
                continue :parse .C;
            },
            .C => {
                state = .B;
                if (std.mem.startsWith(u8, line, "c=")) {
                    connection = try Connection.parse(line[2..]);
                    continue :read;
                }
                continue :parse .B;
            },
            .B => {
                if (std.mem.startsWith(u8, line, "b=")) {
                    // optional
                    state = .B;
                    continue :read;
                }

                continue :parse .T;
            },
            .K => {
                if (std.mem.startsWith(u8, line, "k=")) {
                    // optional
                    continue :read;
                }
                continue :parse .A;
            },
            .A => {
                if (std.mem.startsWith(u8, line, "a=")) {
                    attributes = if (attributes.len == 0) buffer[line_offset..] else attributes;
                    state = .A;
                    continue :read;
                }
                continue :parse .M;
            },
            .T => {
                if (!std.mem.startsWith(u8, line, "t=")) {
                    return error.InvalidSDP;
                }

                state = .R;
                continue :read;
            },
            .R => {
                if (std.mem.startsWith(u8, line, "r=")) {
                    // optional
                    state = .R;
                    continue :read;
                } else if (std.mem.startsWith(u8, line, "t=")) {
                    continue :parse .T;
                }

                continue :parse .Z;
            },
            .Z => {
                if (std.mem.startsWith(u8, line, "z=")) {
                    // optional
                    state = .K;
                    continue :read;
                }

                continue :parse .K;
            },
            .M => {
                if (std.mem.startsWith(u8, line, "m=")) {
                    media = buffer[line_offset..];
                    if (attributes.len != 0) {
                        const len = attributes.len - media.len;
                        attributes = attributes[0..len];
                    }

                    _ = try reader.discardRemaining();

                    state = .M;
                    continue :read;
                }

                return error.InvalidSDP;
            },
        };
    };
}

/// Gets an iterator over the media descriptions in this session.
pub fn mediaIterator(session: *const Self) Media.Iterator {
    return Media.Iterator{ .buffer = session.medias };
}

/// Gets an iterator over the session-level attributes in this session.
pub fn attributeIterator(session: *const Self) Attribute.AttributeIterator {
    return Attribute.AttributeIterator{ .reader = Io.Reader.fixed(session.attributes) };
}

fn parseOrigin(line: []const u8) !Origin {
    // o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
    var parts = std.mem.splitAny(u8, line, " ");

    const username = parts.next() orelse return Error.InvalidOrigin;
    const session_id_str = parts.next() orelse return Error.InvalidOrigin;
    const session_id = try std.fmt.parseInt(u64, session_id_str, 10);
    const session_version_str = parts.next() orelse return Error.InvalidOrigin;
    const session_version = try std.fmt.parseInt(u64, session_version_str, 10);

    const nettype_str = parts.next() orelse return Error.InvalidOrigin;
    const nettype = try Connection.parseNetType(nettype_str);

    const addrtype_str = parts.next() orelse return Error.InvalidOrigin;
    const unicast_address_str = parts.next() orelse return Error.InvalidOrigin;

    const unicast_address = if (std.ascii.eqlIgnoreCase(addrtype_str, "ip4"))
        try std.Io.net.IpAddress.parseIp4(unicast_address_str, 0)
    else if (std.ascii.eqlIgnoreCase(addrtype_str, "ip6"))
        try std.Io.net.IpAddress.parseIp6(unicast_address_str, 0)
    else
        return error.InvalidOrigin;

    return Origin{
        .username = username,
        .session_id = session_id,
        .session_version = session_version,
        .nettype = nettype,
        .unicast_address = unicast_address,
    };
}

fn readLine(reader: *Io.Reader) ![]const u8 {
    const buffer = try reader.takeDelimiterInclusive('\n');
    return std.mem.trimEnd(u8, buffer, "\r\n");
}

test "parse minimal SDP" {
    const sdp_text =
        \\v=0
        \\o=jdoe 3724394400 3724394405 IN IP4 198.51.100.1
        \\s=Call to John Smith
        \\i=SDP Offer #1
        \\u=http://www.jdoe.example.com/home.html
        \\e=Jane Doe <jane@jdoe.example.com>
        \\p=+1 617 555-6011
        \\c=IN IP4 198.51.100.1
        \\t=0 0
        \\k=prompt
        \\a=candidate:0 1 UDP 2113667327 203.0.113.1 54400 typ host
        \\a=recvonly
        \\m=audio 49170 RTP/AVP 0
        \\m=audio 49180 RTP/AVPF 0
        \\m=video 51372 RTP/SAVP 99
        \\c=IN IP6 2001:db8::2
        \\a=rtpmap:99 h263-1998/90000
        \\
    ;

    const sdp = try parse(sdp_text);
    try std.testing.expect(sdp.version == 0);

    const origin = sdp.origin;
    try std.testing.expectEqualStrings(origin.username, "jdoe");
    try std.testing.expectEqual(3724394400, origin.session_id);
    try std.testing.expectEqual(3724394405, origin.session_version);
    try std.testing.expect(origin.nettype == Connection.NetType.in);

    var expected_addr: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = [_]u8{ 198, 51, 100, 1 }, .port = 0 } };
    try std.testing.expect(origin.unicast_address.eql(&expected_addr));

    try std.testing.expectEqualStrings(sdp.session_name, "Call to John Smith");

    try std.testing.expect(sdp.session_info != null);
    try std.testing.expectEqualStrings(sdp.session_info.?, "SDP Offer #1");

    try std.testing.expect(sdp.uri != null);
    try std.testing.expectEqualStrings(sdp.uri.?, "http://www.jdoe.example.com/home.html");

    try std.testing.expect(sdp.connection != null);
    const conn = sdp.connection.?;
    try std.testing.expect(conn.net_type == Connection.NetType.in);

    expected_addr = .{ .ip4 = .{ .bytes = [_]u8{ 198, 51, 100, 1 }, .port = 0 } };
    try std.testing.expect(conn.address.eql(&expected_addr));

    // Session Attributes
    var attributes_iter = sdp.attributeIterator();
    var attribute = try attributes_iter.next() orelse unreachable;
    try std.testing.expectEqualStrings("candidate", attribute.key);
    try std.testing.expectEqualStrings("0 1 UDP 2113667327 203.0.113.1 54400 typ host", attribute.value.?);

    attribute = try attributes_iter.next() orelse unreachable;
    try std.testing.expectEqualStrings("recvonly", attribute.key);
    try std.testing.expect(attribute.value == null);

    try std.testing.expect(try attributes_iter.next() == null);

    // Media Descriptions
    var media_iterator = sdp.mediaIterator();

    var media = try media_iterator.next() orelse unreachable;
    try std.testing.expect(media.media_type == .audio);
    try std.testing.expect(media.port_range.port == 49170);
    try std.testing.expect(media.port_range.count == 1);
    try std.testing.expectEqual(.RTP_AVP, media.proto);
    try std.testing.expectEqualStrings(media.formats, "0");
    try std.testing.expect(media.connection == null);
    try std.testing.expect(media.attributes.len == 0);

    media = try media_iterator.next() orelse unreachable;
    try std.testing.expect(media.media_type == .audio);
    try std.testing.expect(media.port_range.port == 49180);
    try std.testing.expect(media.port_range.count == 1);
    try std.testing.expectEqual(.RTP_AVPF, media.proto);
    try std.testing.expectEqualStrings(media.formats, "0");
    try std.testing.expect(media.connection == null);
    try std.testing.expect(media.attributes.len == 0);

    media = try media_iterator.next() orelse unreachable;
    try std.testing.expect(media.media_type == .video);
    try std.testing.expect(media.port_range.port == 51372);
    try std.testing.expect(media.port_range.count == 1);
    try std.testing.expectEqual(.RTP_SAVP, media.proto);
    try std.testing.expectEqualStrings(media.formats, "99");
    try std.testing.expect(media.connection != null);
    try std.testing.expect(media.attributes.len != 0);

    // Media-level attributes
    attributes_iter = media.attributeIterator();
    attribute = try attributes_iter.next() orelse unreachable;
    try std.testing.expectEqualStrings(attribute.key, "rtpmap");
    try std.testing.expectEqualStrings(attribute.value.?, "99 h263-1998/90000");
    try std.testing.expect(try attributes_iter.next() == null);

    try std.testing.expect(try media_iterator.next() == null);
}

test "parse invalid origin" {
    const sdp_text =
        \\v=0
        \\o=jdoe 1989782 3724394405
        \\s=Call to John Smith
        \\
    ;

    try std.testing.expectError(Error.InvalidOrigin, parse(sdp_text));
}

test "parse invalid session name" {
    const sdp_text =
        \\v=0
        \\o=jdoe 3724394400 3724394405 IN IP4 198.51.100.1
        \\s=
        \\
    ;

    try std.testing.expectError(Error.InvalidSessionName, parse(sdp_text));
}
