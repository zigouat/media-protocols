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
attributes: ?[]const u8 = null,
medias: ?[]const u8 = null,

const State = enum { V, O, S, I, U, E, P, C, B, K, A, T, R, Z, M };

/// Struct representing an Origin field in an SDP message.
pub const Origin = struct {
    username: []const u8,
    session_id: u64,
    session_version: u64,
    nettype: Connection.NetType,
    addrtype: Connection.AddrType,
    unicast_address: []const u8,
};

pub const MediaIterator = struct {
    const MediaState = enum { M, I, C, B, K, A };

    buffer: []const u8,

    pub fn next(self: *MediaIterator) !?Media {
        var reader = Io.Reader.fixed(self.buffer);
        var state: MediaState = .M;
        var result: ?Media = null;

        return read: while (true) {
            const offset = reader.seek;
            const line = readLine(&reader) catch |err| switch (err) {
                error.EndOfStream => {
                    self.buffer = reader.buffered();
                    return result;
                },
                else => return err,
            };

            _ = parse: switch (state) {
                .M => {
                    result = try parseMediaLine(line[2..]);
                    state = .I;
                    continue :read;
                },
                .I => {
                    if (std.mem.startsWith(u8, line, "i=")) {
                        // optional
                        state = .C;
                        continue :read;
                    }
                    // else skip to C
                    continue :parse .C;
                },
                .C => {
                    state = .B;
                    if (std.mem.startsWith(u8, line, "c=")) {
                        result.?.connection = try Connection.parse(line[2..]);
                        continue :read;
                    }
                    continue :parse .B;
                },
                .B => {
                    if (std.mem.startsWith(u8, line, "b=")) {
                        // optional
                        continue :read;
                    }
                    state = .K;
                    continue :parse .K;
                },
                .K => {
                    state = .A;
                    if (std.mem.startsWith(u8, line, "k=")) {
                        continue :read;
                    }
                    continue :parse .A;
                },
                .A => {
                    if (std.mem.startsWith(u8, line, "a=")) {
                        result.?.attributes = result.?.attributes orelse self.buffer[offset..];
                        state = .A;
                        continue :read;
                    }

                    if (result.?.attributes) |attr| {
                        const len = attr.len - self.buffer[offset..].len;
                        result.?.attributes = attr[0..len];
                    }

                    self.buffer = self.buffer[offset..];
                    return result;
                },
            };
        };
    }

    fn parseMediaLine(line: []const u8) !Media {
        // m=<media> <port> <proto> <fmt> ...
        var parts = std.mem.splitAny(u8, line, " ");

        const media_str = parts.next() orelse return Error.InvalidMedia;
        const port_str = parts.next() orelse return Error.InvalidMedia;
        const proto = parts.next() orelse return Error.InvalidMedia;

        var media_type: Media.MediaType = undefined;
        var port_range: Media.PortRange = undefined;

        if (std.mem.eql(u8, "audio", media_str)) {
            media_type = .audio;
        } else if (std.mem.eql(u8, "video", media_str)) {
            media_type = .video;
        } else if (std.mem.eql(u8, "application", media_str)) {
            media_type = .application;
        } else if (std.mem.eql(u8, "text", media_str)) {
            media_type = .text;
        } else {
            return Error.InvalidMedia;
        }

        const index = std.mem.indexOf(u8, port_str, "/");
        if (index) |i| {
            const port = try std.fmt.parseInt(u16, port_str[0..i], 10);
            const count = try std.fmt.parseInt(u16, port_str[i + 1 ..], 10);
            port_range = .{ .port = port, .count = count };
        } else {
            const port = try std.fmt.parseInt(u16, port_str, 10);
            port_range = .{ .port = port, .count = 1 };
        }

        return Media{
            .media_type = media_type,
            .port_range = port_range,
            .protocol = proto,
            .formats = parts.rest(),
        };
    }
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
    var media: ?[]const u8 = null;
    var attributes: ?[]const u8 = null;

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
                    attributes = attributes orelse buffer[line_offset..];
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
                    if (attributes) |attr| {
                        const len = attr.len - media.?.len;
                        attributes = attr[0..len];
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
pub fn mediaIterator(session: *const Self) MediaIterator {
    return MediaIterator{
        .buffer = session.medias orelse &[_]u8{},
    };
}

/// Gets an iterator over the session-level attributes in this session.
pub fn attributeIterator(session: *const Self) Attribute.AttributeIterator {
    return Attribute.AttributeIterator{
        .reader = Io.Reader.fixed(session.attributes orelse &[_]u8{}),
    };
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
    const addr_type = try Connection.parseAddrType(addrtype_str);

    const unicast_address = parts.next() orelse return Error.InvalidOrigin;

    return Origin{
        .username = username,
        .session_id = session_id,
        .session_version = session_version,
        .nettype = nettype,
        .addrtype = addr_type,
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
        \\m=audio 49180 RTP/AVP 0
        \\m=video 51372 RTP/AVP 99
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
    try std.testing.expect(origin.addrtype == Connection.AddrType.ip4);
    try std.testing.expectEqualStrings(origin.unicast_address, "198.51.100.1");

    try std.testing.expectEqualStrings(sdp.session_name, "Call to John Smith");

    try std.testing.expect(sdp.session_info != null);
    try std.testing.expectEqualStrings(sdp.session_info.?, "SDP Offer #1");

    try std.testing.expect(sdp.uri != null);
    try std.testing.expectEqualStrings(sdp.uri.?, "http://www.jdoe.example.com/home.html");

    try std.testing.expect(sdp.connection != null);
    const conn = sdp.connection.?;
    try std.testing.expect(conn.net_type == Connection.NetType.in);
    try std.testing.expect(conn.addr_type == Connection.AddrType.ip4);
    try std.testing.expectEqualStrings("198.51.100.1", conn.address);

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
    try std.testing.expectEqualStrings(media.protocol, "RTP/AVP");
    try std.testing.expectEqualStrings(media.formats, "0");
    try std.testing.expect(media.connection == null);
    try std.testing.expect(media.attributes == null);

    media = try media_iterator.next() orelse unreachable;
    try std.testing.expect(media.media_type == .audio);
    try std.testing.expect(media.port_range.port == 49180);
    try std.testing.expect(media.port_range.count == 1);
    try std.testing.expectEqualStrings(media.protocol, "RTP/AVP");
    try std.testing.expectEqualStrings(media.formats, "0");
    try std.testing.expect(media.connection == null);
    try std.testing.expect(media.attributes == null);

    media = try media_iterator.next() orelse unreachable;
    try std.testing.expect(media.media_type == .video);
    try std.testing.expect(media.port_range.port == 51372);
    try std.testing.expect(media.port_range.count == 1);
    try std.testing.expectEqualStrings(media.protocol, "RTP/AVP");
    try std.testing.expectEqualStrings(media.formats, "99");
    try std.testing.expect(media.connection != null);
    try std.testing.expect(media.attributes != null);

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
