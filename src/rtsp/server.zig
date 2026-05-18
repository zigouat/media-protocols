//! Handles a single client session
const std = @import("std");
const rtsp = @import("rtsp.zig");
const rtp = @import("rtp");

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const Server = @This();

reader: *Reader,
writer: *Writer,

pub const Request = struct {
    server: *Server,
    head: Head,

    pub const Head = struct {
        method: rtsp.Method,
        uri: []const u8,
        cseq: u32,
        session: ?[]const u8,
        authenticate: ?[]const u8,
        transport: ?rtsp.Header.Transport,
        content_length: u32,

        pub const Error = error{
            UnknownRtspMethod,
            RtspHeadersInvalid,
            RtspVersionInvalid,
            MissingSequenceHeader,
            /// A request body is not expected for this METHOD.
            BodyUnexpected,
        } || rtsp.Header.Transport.Error;

        pub fn parse(buffer: []const u8) !Head {
            var it = std.mem.splitSequence(u8, buffer, "\r\n");

            const first_line = it.next().?;
            var it2 = std.mem.splitScalar(u8, first_line, ' ');

            const method_str = it2.next() orelse return error.RtspHeadersInvalid;
            const method = std.meta.stringToEnum(rtsp.Method, method_str) orelse return error.UnknownRtspMethod;

            const uri = it2.next() orelse return error.RtspHeadersInvalid;
            const version = std.mem.trim(u8, it2.rest(), " \t");

            if (!std.ascii.eqlIgnoreCase(version, "rtsp/1.0")) return error.RtspVersionInvalid;

            var head = Head{
                .method = method,
                .uri = std.mem.trim(u8, uri, " \t"),
                .cseq = std.math.maxInt(u32),
                .session = null,
                .authenticate = null,
                .transport = null,
                .content_length = 0,
            };

            // Parse headers
            while (it.next()) |line| {
                if (line.len == 0) {
                    if (head.cseq == std.math.maxInt(u32)) return error.MissingSequenceHeader;
                    return head;
                }

                var line_it = std.mem.splitScalar(u8, line, ':');
                const header_name = line_it.next().?;
                const header_value = std.mem.trim(u8, line_it.rest(), " \t");
                if (header_name.len == 0) return error.RtspHeadersInvalid;

                if (std.ascii.eqlIgnoreCase(header_name, "cseq")) {
                    head.cseq = std.fmt.parseInt(u32, header_value, 10) catch return error.RtspHeadersInvalid;
                } else if (std.ascii.eqlIgnoreCase(header_name, "session")) {
                    head.session = header_name;
                } else if (std.ascii.eqlIgnoreCase(header_name, "www-authenticate")) {
                    head.authenticate = header_name;
                } else if (std.ascii.eqlIgnoreCase(header_name, "content-length")) {
                    head.content_length = std.fmt.parseInt(u32, header_name, 10) catch return error.RtspHeadersInvalid;
                    if (head.content_length > 0 and !head.method.expectBody()) {
                        return error.ContentLengthUnexpected;
                    }
                } else if (std.ascii.eqlIgnoreCase(header_name, "transport")) {
                    head.transport = try .parse(header_value);
                }
            }

            return error.MissingFinalNewLine;
        }

        test "parse" {
            const request_bytes =
                \\ANNOUNCE  rtsp://localhost/ISAPI/Streaming/Channels/101 RTSP/1.0
                \\CSeq: 5   
                \\Accept: application/sdp
                \\Content-Length: 140
                \\Session: 34F4545A
                \\
            ;

            const head = try parse(request_bytes);
            try std.testing.expectEqual(.ANNOUNCE, head.method);
            try std.testing.expectEqual(5, head.cseq);
            try std.testing.expectEqual(140, head.content_length);
            try std.testing.expectEqual(null, head.transport);
            try std.testing.expectEqual(null, head.authenticate);
            try std.testing.expectEqualStrings("rtsp://localhost/ISAPI/Streaming/Channels/101", head.uri);
            try std.testing.expectEqualStrings("34F454A", head.session.?);
        }
    };

    pub const RespondOptions = struct {
        status: rtsp.Status = .success,
        reason: ?[]const u8 = null,
        extra_headers: []const rtsp.Header = &.{},
    };

    /// Send a entire rtsp response to the client.
    ///
    /// If the METHOD does not expect body, the `body` is ignored.
    pub fn respond(
        request: *Request,
        body: []const u8,
        options: RespondOptions,
    ) Writer.Error!void {
        var out = request.server.writer;
        try out.print("RTSP/1.0 {} {s}\r\n", .{
            @intFromEnum(options.status),
            options.reason orelse options.status.phrase() orelse "",
        });

        try out.print("CSeq: {}\r\n", .{request.head.cseq});
        try out.writeAll("Server: Zig RTSP/0.1.0\r\n");

        if (request.head.method == .OPTIONS) {
            try out.writeAll("Public: DESCRIBE, SETUP, PLAY, ANNOUNCE, RECORD, GET_PARAMETER, TEARDOWN\r\n");
        }

        for (options.extra_headers) |header| {
            try out.print("{s}: {s}\r\n", .{ header.name, header.value });
        }

        if (request.head.method.responseExpectBody()) {
            try out.print("Content-Length: {}\r\n\r\n", .{body.len});
            try out.writeAll(body);
        } else {
            try out.writeAll("\r\n");
        }

        try out.flush();
    }
};

/// Initialize a server that handle a single client session.
pub fn init(r: *Reader, w: *Writer) Server {
    return .{ .reader = r, .writer = w };
}

pub fn receiveHead(s: *Server) !Request {
    const head_buffer = try receiveHeadFromReader(s.reader);
    return .{
        .head = Request.Head.parse(head_buffer) catch return error.RtspHeadersInvalid,
        .server = s,
    };
}

/// Writes rtp packet interleaved with RTSP/RTCP packets.
pub fn writeRtpPacket(s: *Server, channel: u8, packet: rtp.Packet) !void {
    try s.writer.writeByte('$');
    try s.writer.writeInt(u8, channel, .big);
    try s.writer.writeInt(u16, @intCast(packet.size()), .big);
    try packet.write(s.writer);
}

fn receiveHeadFromReader(r: *Reader) ![]const u8 {
    const max_head_size = r.buffer.len;
    var head_len: usize = 0;
    var hp = std.http.HeadParser{};
    while (true) {
        if (head_len >= max_head_size) return error.RtspHeadersOversize;
        const remaining = r.buffered()[head_len..];
        if (remaining.len == 0) {
            r.fillMore() catch |err| switch (err) {
                error.EndOfStream => return error.RtspRequestTruncated,
                error.ReadFailed => return err,
            };
            continue;
        }

        head_len += hp.feed(remaining);
        if (hp.state == .finished) {
            const result = r.buffered()[0..head_len];
            r.toss(head_len);
            return result;
        }
    }
}
