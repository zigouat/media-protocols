const std = @import("std");
const Connection = @import("connection.zig");
const AttributeIterator = @import("attribute.zig").AttributeIterator;
const Io = std.Io;

const Media = @This();

const proto_mapping: std.StaticStringMap(Proto) = .initComptime(&.{
    .{ "RTP/AVP", .RTP_AVP },
    .{ "RTP/AVPF", .RTP_AVPF },
    .{ "RTP/SAVP", .RTP_SAVP },
    .{ "RTP/SAVPF", .RTP_SAVPF },
    .{ "TCP/DTLS/RTP/SAVP", .TCP_DTLS_RTP_SAVP },
    .{ "TCP/DTLS/RTP/SAVPF", .TCP_DTLS_RTP_SAVPF },
    .{ "TCP/DTLS/SCTP", .TCP_DTLS_SCTP },
    .{ "TCP/RTP/AVP", .TCP_RTP_AVP },
    .{ "TCP/RTP/AVPF", .TCP_RTP_AVPF },
    .{ "TCP/RTP/SAVP", .TCP_RTP_SAVP },
    .{ "TCP/RTP/SAVPF", .TCP_RTP_SAVPF },
    .{ "TCP/TLS/RTP/AVP", .TCP_TLS_RTP_AVP },
    .{ "TCP/TLS/RTP/AVPF", .TCP_TLS_RTP_AVPF },
    .{ "UDP/FEC", .UDP_FEC },
    .{ "UDP/DTLS/SCTP", .UDP_DTLS_SCTP },
    .{ "UDP/TLS/RTP/SAVP", .UDP_TLS_RTP_SAVP },
    .{ "UDP/TLS/RTP/SAVPF", .UDP_TLS_RTP_SAVPF },
});

pub const Error = error{InvalidMedia};

pub const MediaType = enum {
    audio,
    video,
    text,
    application,
    message,
    image,
};

pub const Proto = enum {
    RTP_AVP,
    RTP_AVPF,
    RTP_SAVP,
    RTP_SAVPF,
    TCP_DTLS_RTP_SAVP,
    TCP_DTLS_RTP_SAVPF,
    TCP_DTLS_SCTP,
    TCP_RTP_AVP,
    TCP_RTP_AVPF,
    TCP_RTP_SAVP,
    TCP_RTP_SAVPF,
    TCP_TLS_RTP_AVP,
    TCP_TLS_RTP_AVPF,
    UDP_FEC,
    UDP_DTLS_SCTP,
    UDP_TLS_RTP_SAVP,
    UDP_TLS_RTP_SAVPF,

    pub fn fromSlice(proto: []const u8) !Proto {
        return proto_mapping.get(proto) orelse error.UnknownProto;
    }

    pub fn toSlice(proto: *const Proto) []const u8 {
        return switch (proto.*) {
            .RTP_AVP => "RTP/AVP",
            .RTP_AVPF => "RTP/AVPF",
            .RTP_SAVP => "RTP/SAVP",
            .RTP_SAVPF => "RTP/SAVPF",
            .TCP_DTLS_RTP_SAVP => "TCP/DTLS/RTP/SAVP",
            .TCP_DTLS_RTP_SAVPF => "TCP/DTLS/RTP/SAVPF",
            .TCP_DTLS_SCTP => "TCP/DTLS/SCTP",
            .TCP_RTP_AVP => "TCP/RTP/AVP",
            .TCP_RTP_AVPF => "TCP/RTP/AVPF",
            .TCP_RTP_SAVP => "TCP/RTP/SAVP",
            .TCP_RTP_SAVPF => "TCP/RTP/SAVPF",
            .TCP_TLS_RTP_AVP => "TCP/TLS/RTP/AVP",
            .TCP_TLS_RTP_AVPF => "TCP/TLS/RTP/AVPF",
            .UDP_FEC => "UDP/FEC",
            .UDP_DTLS_SCTP => "UDP/DTLS/SCTP",
            .UDP_TLS_RTP_SAVP => "UDP/TLS/RTP/SAVP",
            .UDP_TLS_RTP_SAVPF => "UDP/TLS/RTP/SAVPF",
        };
    }
};

pub const PortRange = struct {
    port: u16,
    count: u16,
};

media_type: MediaType,
port_range: PortRange,
proto: Proto,
formats: []const u8,
connection: ?Connection = null,
attributes: ?[]const u8 = null,

pub const Iterator = struct {
    const MediaState = enum { M, I, C, B, K, A };

    buffer: []const u8,

    pub fn next(self: *Iterator) !?Media {
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
        const proto = try Proto.fromSlice(parts.next() orelse return Error.InvalidMedia);

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
            .proto = proto,
            .formats = parts.rest(),
        };
    }

    fn readLine(reader: *Io.Reader) ![]const u8 {
        const buffer = try reader.takeDelimiterInclusive('\n');
        return std.mem.trimEnd(u8, buffer, "\r\n");
    }
};

/// Get an iterator over the media attributes.
pub fn attributeIterator(self: *const Media) Media.AttributeIterator {
    return AttributeIterator{
        .reader = Io.Reader.fixed(self.attributes orelse ""),
    };
}
