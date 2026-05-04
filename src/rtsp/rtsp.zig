const std = @import("std");
const rtp = @import("rtp");

const Reader = std.Io.Reader;

const methods = std.StaticStringMap(Method).initComptime(&.{
    .{ "OPTIONS", Method.options },
    .{ "DESCRIBE", Method.describe },
    .{ "ANNOUNCE", Method.announce },
    .{ "SETUP", Method.setup },
    .{ "PLAY", Method.play },
    .{ "PAUSE", Method.pause },
    .{ "TEARDOWN", Method.teardown },
    .{ "GET_PARAMETER", Method.get_parameter },
    .{ "SET_PARAMETER", Method.set_parameter },
    .{ "REDIRECT", Method.redirect },
    .{ "RECORD", Method.record },
});

pub const uri_flags: std.Uri.Format.Flags = .{
    .authentication = false,
    .scheme = true,
    .authority = true,
    .path = true,
    .query = true,
    .fragment = true,
};

pub const Error = error{
    ParseError,
} || std.mem.Allocator.Error || Reader.Error;

pub const Method = enum {
    options,
    describe,
    announce,
    setup,
    play,
    pause,
    teardown,
    get_parameter,
    set_parameter,
    redirect,
    record,

    pub fn toString(self: *const Method) []const u8 {
        return switch (self.*) {
            .options => "OPTIONS",
            .describe => "DESCRIBE",
            .announce => "ANNOUNCE",
            .setup => "SETUP",
            .play => "PLAY",
            .pause => "PAUSE",
            .teardown => "TEARDOWN",
            .get_parameter => "GET_PARAMETER",
            .set_parameter => "SET_PARAMETER",
            .redirect => "REDIRECT",
            .record => "RECORD",
        };
    }

    test "toString" {
        try std.testing.expectEqualStrings("OPTIONS", Method.options.toString());
        try std.testing.expectEqualStrings("DESCRIBE", Method.describe.toString());
        try std.testing.expectEqualStrings("ANNOUNCE", Method.announce.toString());
        try std.testing.expectEqualStrings("SETUP", Method.setup.toString());
        try std.testing.expectEqualStrings("PLAY", Method.play.toString());
        try std.testing.expectEqualStrings("PAUSE", Method.pause.toString());
        try std.testing.expectEqualStrings("TEARDOWN", Method.teardown.toString());
        try std.testing.expectEqualStrings("GET_PARAMETER", Method.get_parameter.toString());
        try std.testing.expectEqualStrings("SET_PARAMETER", Method.set_parameter.toString());
        try std.testing.expectEqualStrings("REDIRECT", Method.redirect.toString());
        try std.testing.expectEqualStrings("RECORD", Method.record.toString());
    }
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,

    pub fn parse(line: []const u8) Error!Header {
        const colon_index = std.mem.indexOfScalar(u8, line, ':') orelse return error.ParseError;

        return Header{
            .name = line[0..colon_index],
            .value = std.mem.trim(u8, line[colon_index + 1 ..], " \t\r\n"),
        };
    }

    pub fn write(self: *const Header, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        _ = try writer.write(self.name);
        _ = try writer.write(": ");
        _ = try writer.write(self.value);
        _ = try writer.write("\r\n");
    }

    test "parseHeader normal" {
        const header = try Header.parse("CSeq: 2\r\n");
        try std.testing.expectEqualStrings("CSeq", header.name);
        try std.testing.expectEqualStrings("2", header.value);
    }

    test "parseHeader trims whitespace" {
        const header = try Header.parse("Session:  abc123 \r\n");
        try std.testing.expectEqualStrings("Session", header.name);
        try std.testing.expectEqualStrings("abc123", header.value);
    }

    test "parseHeader no colon" {
        try std.testing.expectError(error.ParseError, Header.parse("InvalidHeader\r\n"));
    }

    test "write" {
        var buf: [32]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buf);
        const header = Header{ .name = "CSeq", .value = "2" };
        try header.write(&writer);
        try std.testing.expectEqualStrings("CSeq: 2\r\n", writer.buffer[0..writer.end]);
    }
};

pub const TransportHeader = struct {
    proto: enum { tcp, udp } = .udp,
    unicast: bool = true,
    interleaved: ?struct { u8, u8 } = null,

    pub fn write(self: *const TransportHeader, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll(if (self.proto == .tcp) "RTP/AVP/TCP" else "RTP/AVP");
        if (self.unicast) {
            try writer.writeAll(";unicast");
        } else {
            try writer.writeAll(";multicast");
        }
        if (self.interleaved) |interleaved| {
            try writer.print(";interleaved={}-{}", .{ interleaved.@"0", interleaved.@"1" });
        }
    }
};

pub const StatusLine = struct {
    version: []const u8,
    status_code: u16,
    reason_phrase: []const u8,

    fn parse(line: []const u8) error{ParseError}!StatusLine {
        var parts = std.mem.splitScalar(u8, line, ' ');

        const version = parts.next() orelse return error.ParseError;
        const status_code_str = parts.next() orelse return error.ParseError;
        const reason_phrase = parts.next() orelse return error.ParseError;

        const status_code = std.fmt.parseUnsigned(u16, status_code_str, 10) catch {
            return error.ParseError;
        };

        return StatusLine{
            .version = version,
            .status_code = status_code,
            .reason_phrase = std.mem.trimEnd(u8, reason_phrase, "\r\n"),
        };
    }

    fn write(status_line: *const StatusLine, writer: *std.Io.Writer) !void {
        try writer.print("RTSP/1.0 {} {s}\r\n", .{ status_line.status_code, status_line.reason_phrase });
    }
};

pub const RequestLine = struct {
    method: Method,
    uri: std.Uri,

    pub fn parse(line: []const u8) !RequestLine {
        var iterator = std.mem.tokenizeScalar(u8, line, ' ');
        const method = blk: {
            if (iterator.next()) |str| {
                if (methods.get(str)) |method| break :blk method else return error.ParseError;
            } else return error.ParseError;
        };
        const uri = iterator.next() orelse return error.ParseError;
        if (!std.mem.eql(u8, iterator.rest(), "RTSP/1.0")) return error.ParseError;

        return .{ .method = method, .uri = std.Uri.parse(uri) catch return error.ParseError };
    }

    pub fn write(self: *const RequestLine, path: ?[]const u8, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        _ = try writer.write(self.method.toString());
        _ = try writer.writeByte(' ');

        const absolute_path = if (path) |p| std.mem.startsWith(u8, p, "rtsp") else false;

        if (!absolute_path) {
            try std.Uri.writeToStream(&self.uri, writer, uri_flags);
        }

        if (path) |p| {
            if (!std.mem.startsWith(u8, p, "/")) {
                _ = try writer.writeByte('/');
            }
            _ = try writer.write(p);
        }

        _ = try writer.write(" RTSP/1.0\r\n");
    }
};

/// A lazy parser for RTSP messages.
pub const Parser = struct {
    reader: *Reader,
    content_length: usize = 0,
    parse_state: ParseState = .first_line,

    const ParseState = enum { first_line, header, body };

    pub fn init(reader: *Reader) Parser {
        return Parser{ .reader = reader };
    }

    pub fn getRequestLine(parser: *Parser) Error!RequestLine {
        if (parser.parse_state != .first_line) return error.ParseError;
        const line = try readLine(parser.reader);

        const result = try RequestLine.parse(line);
        parser.parse_state = .header;
        return result;
    }

    pub fn getResponseStatus(parser: *Parser) Error!StatusLine {
        if (parser.parse_state != .first_line) return error.ParseError;
        const line = parser.reader.takeDelimiterInclusive('\n') catch return error.ParseError;
        const result = try StatusLine.parse(line);
        parser.parse_state = .header;
        return result;
    }

    pub fn nextHeader(parser: *Parser) Error!?Header {
        if (parser.parse_state != .header) return error.ParseError;
        const line = parser.reader.takeDelimiterInclusive('\n') catch return error.ParseError;
        if (line[0] == '\r') {
            parser.parse_state = .body;
            return null;
        }
        const header = try Header.parse(line);
        if (std.mem.eql(u8, header.name, "Content-Length")) {
            parser.content_length = std.fmt.parseUnsigned(usize, header.value, 10) catch return error.ParseError;
        }
        return header;
    }

    pub fn getBody(parser: *Parser) Error!?[]const u8 {
        switch (parser.parse_state) {
            .first_line => return error.ParseError,
            .header => {
                while (try parser.nextHeader()) |_| {}
            },
            else => {},
        }

        return if (parser.content_length > 0) try parser.reader.take(parser.content_length) else null;
    }

    pub fn consume(parser: *Parser) Error!void {
        loop: switch (parser.parse_state) {
            .first_line => {
                _ = try parser.getResponseStatus();
                continue :loop .header;
            },
            .header => {
                while (try parser.nextHeader()) |_| {}
                continue :loop .body;
            },
            .body => {
                _ = try parser.getBody();
                return;
            },
        }
    }

    fn readLine(reader: *Reader) ![]const u8 {
        const line = reader.takeDelimiterInclusive('\n') catch return error.ParseError;
        return std.mem.trimEnd(u8, line, "\r\n");
    }
};

pub const Writer = struct {
    writer: *std.Io.Writer,

    pub fn init(writer: *std.Io.Writer) Writer {
        return Writer{ .writer = writer };
    }

    pub fn writeRequestLine(self: *Writer, path: ?[]const u8, request_line: RequestLine) std.Io.Writer.Error!void {
        try request_line.write(path, self.writer);
    }

    pub fn writeStatusLine(self: *Writer, status_line: StatusLine) std.Io.Writer.Error!void {
        try status_line.write(self.writer);
    }

    pub fn writeHeader(self: *Writer, header: Header) std.Io.Writer.Error!void {
        try header.write(self.writer);
    }

    pub fn writeCSeq(self: *Writer, cseq: u64) std.Io.Writer.Error!void {
        _ = try self.writer.write("CSeq: ");
        try self.writer.print("{}\r\n", .{cseq});
    }

    pub fn writeContentLength(self: *Writer, size: usize) std.Io.Writer.Error!void {
        _ = try self.writer.write("Content-Length: ");
        try self.writer.print("{}\r\n", .{size});
    }

    pub fn writeTransportHeader(self: *Writer, header: TransportHeader) std.Io.Writer.Error!void {
        try self.writer.writeAll("Transport: ");
        try header.write(self.writer);
        try self.writeLineFeed();
    }

    pub inline fn writeLineFeed(self: *Writer) std.Io.Writer.Error!void {
        try self.writer.writeAll("\r\n");
    }

    pub inline fn writeBody(self: *Writer, body: []const u8) std.Io.Writer.Error!void {
        try self.writer.writeAll(body);
    }
};

pub fn DigestAuthParams(comptime buf_size: usize) type {
    return struct {
        raw: [buf_size]u8,
        realm: []const u8,
        nonce: []const u8,

        pub fn parse(self: *@This(), header_value: []const u8) !void {
            if (!std.mem.startsWith(u8, header_value, "Digest ")) {
                return error.ParseError;
            }
            var iterator = std.mem.splitSequence(u8, header_value[7..], ",");
            var slice: []u8 = self.raw[0..];

            while (iterator.next()) |part| {
                if (std.mem.indexOf(u8, part, "=")) |idx| {
                    const key = std.mem.trim(u8, part[0..idx], " \"");
                    const value = std.mem.trim(u8, part[idx + 1 ..], " \"");

                    if (std.mem.eql(u8, key, "realm") or std.mem.eql(u8, key, "nonce")) {
                        if (slice.len < value.len) return error.Underflow;
                        @memcpy(slice[0..value.len], value);
                        if (std.mem.eql(u8, key, "realm")) {
                            self.realm = slice[0..value.len];
                        } else {
                            self.nonce = slice[0..value.len];
                        }
                        slice = slice[value.len..];
                    }
                }
            }

            if (self.realm.len == 0 or self.nonce.len == 0) {
                return error.ParseError;
            }
        }
    };
}

/// A parser for RTSP interleaved frames that can contain RTP, RTCP, or RTSP messages.
pub const TcpDemuxer = struct {
    const header_size = 4;
    reader: *Reader,

    pub const Message = union(enum) {
        rtp: rtp.Packet,
        rtcp: []const u8,
        rtsp: u16,
    };

    pub fn init(reader: *Reader) TcpDemuxer {
        return TcpDemuxer{ .reader = reader };
    }

    pub fn next(self: *TcpDemuxer) error{ ParseError, InvalidRtpPacket }!?Message {
        var reader = self.reader;
        const h = reader.peek(header_size) catch |err| switch (err) {
            Reader.Error.EndOfStream => return null,
            else => return error.ParseError,
        };

        if (h[0] == '$') {
            @branchHint(.likely);
            const channel = h[1];
            const length = std.mem.readInt(u16, h[2..4], .big);

            reader.toss(header_size);
            const payload = reader.take(length) catch |err| switch (err) {
                Reader.Error.EndOfStream => {
                    reader.seek -= header_size;
                    return null;
                },
                else => return error.ParseError,
            };

            if (channel % 2 == 0) {
                @branchHint(.likely);
                const rtp_packet = rtp.Packet.parse(payload) catch return error.InvalidRtpPacket;
                return .{ .rtp = rtp_packet };
            } else {
                return .{ .rtcp = payload };
            }
        } else if (std.mem.eql(u8, h, "RTSP")) {
            var parser = Parser.init(reader);

            const resp_status = parser.getResponseStatus() catch |err| switch (err) {
                error.EndOfStream => return null,
                else => return error.ParseError,
            };

            parser.consume() catch |err| switch (err) {
                error.EndOfStream => return null,
                else => return error.ParseError,
            };

            return .{ .rtsp = resp_status.status_code };
        } else {
            return error.ParseError;
        }
    }

    test "next returns rtp message for even channel" {
        // Interleaved frame: $ channel=0 length=16, followed by a valid RTP packet
        const data = [_]u8{
            0x24, 0x00, 0x00, 0x10, // '$', channel=0, length=16
            0x80, 0xE0, 0x51, 0xA4,
            0x00, 0x0D, 0xDF, 0x22,
            0x54, 0xA7, 0xD4, 0xF3,
            0x01, 0x02, 0x03, 0x04,
        };
        var r = Reader.fixed(&data);
        var demuxer = TcpDemuxer.init(&r);
        const msg = try demuxer.next();
        try std.testing.expect(msg != null);
        try std.testing.expect(msg.? == .rtp);
        try std.testing.expectEqual(@as(u7, 96), msg.?.rtp.header.payload_type);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03, 0x04 }, msg.?.rtp.payload);
    }

    test "next returns rtcp message for odd channel" {
        const data = [_]u8{
            0x24, 0x01, 0x00, 0x08, // '$', channel=1, length=8
            0x81, 0xC8, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01,
        };
        var r = Reader.fixed(&data);
        var demuxer = TcpDemuxer.init(&r);
        const msg = try demuxer.next();
        try std.testing.expect(msg != null);
        try std.testing.expect(msg.? == .rtcp);
        try std.testing.expectEqualSlices(u8, data[4..], msg.?.rtcp);
    }

    test "next skips rtsp response and returns null" {
        var r = Reader.fixed("RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n");
        var demuxer = TcpDemuxer.init(&r);
        const msg = try demuxer.next();
        try std.testing.expect(msg != null);
        try std.testing.expectEqual(200, msg.?.rtsp);
    }

    test "next returns null and rewinds seek for incomplete payload" {
        // Header claims 255 bytes but only 2 bytes follow
        const data = [_]u8{ 0x24, 0x00, 0x00, 0xFF, 0x01, 0x02 };
        var r = Reader.fixed(&data);
        var demuxer = TcpDemuxer.init(&r);
        const msg = try demuxer.next();
        try std.testing.expectEqual(null, msg);
    }

    test "next returns ParseError for invalid leading byte" {
        const data = [_]u8{ 0x00, 0x01, 0x02, 0x03 };
        var r = Reader.fixed(&data);
        var demuxer = TcpDemuxer.init(&r);
        try std.testing.expectError(error.ParseError, demuxer.next());
    }

    test "next parses two sequential interleaved frames" {
        const data = [_]u8{
            0x24, 0x01, 0x00, 0x02, 0xAA, 0xBB, // RTCP on channel 1
            0x24, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03, // RTCP on channel 3
        };
        var r = Reader.fixed(&data);
        var demuxer = TcpDemuxer.init(&r);

        const msg1 = try demuxer.next();
        try std.testing.expect(msg1 != null);
        try std.testing.expect(msg1.? == .rtcp);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, msg1.?.rtcp);

        const msg2 = try demuxer.next();
        try std.testing.expect(msg2 != null);
        try std.testing.expect(msg2.? == .rtcp);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, msg2.?.rtcp);
    }

    // Incomplete RTSP response cases

    test "next returns error for truncated rtsp status line" {
        // No \r\n — ResponseParser.init cannot finish reading the status line
        var r = Reader.fixed("RTSP/1.0 200 OK");
        var demuxer = TcpDemuxer.init(&r);
        try std.testing.expectError(error.ParseError, demuxer.next());
    }

    test "next returns error for truncated rtsp headers" {
        // Status line complete but header line cut off before \r\n
        var r = Reader.fixed("RTSP/1.0 200 OK\r\nCSeq: 1");
        var demuxer = TcpDemuxer.init(&r);
        try std.testing.expectError(error.ParseError, demuxer.next());
    }

    test "next returns null for rtsp response with truncated body" {
        // Content-Length claims 10 bytes but only 2 arrive — EndOfStream on take()
        var r = Reader.fixed("RTSP/1.0 200 OK\r\nContent-Length: 10\r\n\r\nhi");
        var demuxer = TcpDemuxer.init(&r);
        const msg = try demuxer.next();
        try std.testing.expectEqual(null, msg);
    }

    // Mixed-message buffers: all three frame types in one contiguous buffer

    test "next parses rtp then rtsp then rtcp from same buffer" {
        // RTP (ch=0, 16-byte payload) | RTSP 200 response | RTCP (ch=1)
        const data =
            "\x24\x00\x00\x10" ++ // '$' ch=0 len=16
            "\x80\xE0\x51\xA4\x00\x0D\xDF\x22\x54\xA7\xD4\xF3\x01\x02\x03\x04" ++ // RTP packet
            "RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n" ++ // RTSP response (28 bytes)
            "\x24\x01\x00\x04\x81\xC8\x00\x01"; // '$' ch=1 len=4, RTCP payload

        var r = Reader.fixed(data);
        var demuxer = TcpDemuxer.init(&r);

        const msg1 = try demuxer.next();
        try std.testing.expect(msg1 != null);
        try std.testing.expect(msg1.? == .rtp);
        try std.testing.expectEqualSlices(u8, "\x01\x02\x03\x04", msg1.?.rtp.payload);

        const msg2 = try demuxer.next(); // RTSP response → 200
        try std.testing.expect(msg2 != null);
        try std.testing.expectEqual(200, msg2.?.rtsp);

        const msg3 = try demuxer.next();
        try std.testing.expect(msg3 != null);
        try std.testing.expect(msg3.? == .rtcp);
        try std.testing.expectEqualSlices(u8, "\x81\xC8\x00\x01", msg3.?.rtcp);
    }

    test "next parses rtsp then rtp then rtcp from same buffer" {
        // RTSP response first — exercises reader advancing past a full RTSP exchange
        const data =
            "RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Basic realm=\"cam\"\r\n\r\n" ++
            "\x24\x00\x00\x10" ++ // '$' ch=0 len=16
            "\x80\xE0\x51\xA4\x00\x0D\xDF\x22\x54\xA7\xD4\xF3\x05\x06\x07\x08" ++ // RTP packet
            "\x24\x01\x00\x03\xAA\xBB\xCC"; // '$' ch=1 len=3, RTCP payload

        var r = Reader.fixed(data);
        var demuxer = TcpDemuxer.init(&r);

        const msg1 = try demuxer.next(); // RTSP → 401
        try std.testing.expect(msg1 != null);
        try std.testing.expectEqual(401, msg1.?.rtsp);

        const msg2 = try demuxer.next();
        try std.testing.expect(msg2 != null);
        try std.testing.expect(msg2.? == .rtp);
        try std.testing.expectEqualSlices(u8, "\x05\x06\x07\x08", msg2.?.rtp.payload);

        const msg3 = try demuxer.next();
        try std.testing.expect(msg3 != null);
        try std.testing.expect(msg3.? == .rtcp);
        try std.testing.expectEqualSlices(u8, "\xAA\xBB\xCC", msg3.?.rtcp);
    }
};

test "DigestAuthParams: parse" {
    const DigestAuthParams256 = DigestAuthParams(256);
    var auth_params: DigestAuthParams256 = .{ .raw = undefined, .realm = "", .nonce = "" };
    try auth_params.parse("Digest realm=\"RTSP\", nonce=\"abc123\"");
    try std.testing.expectEqualStrings("RTSP", auth_params.realm);
    try std.testing.expectEqualStrings("abc123", auth_params.nonce);
}

test "request line: invalid request" {
    try std.testing.expectError(error.ParseError, RequestLine.parse("METHOD /url RTSP/1.0"));
    try std.testing.expectError(error.ParseError, RequestLine.parse("DESCRIBE /hello RTSP/1.0"));
    try std.testing.expectError(error.ParseError, RequestLine.parse("DESCRIBE rtsp://example.com/hello RTSP/1.1"));
}

test "response parser" {
    const response_text = "RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: 12345678\r\nContent-Length: 13\r\n\r\nHello, World!";
    var reader = Reader.fixed(response_text);
    var parser = Parser.init(&reader);

    const response_status = try parser.getResponseStatus();

    try std.testing.expectEqual(200, response_status.status_code);

    var header = try parser.nextHeader();
    try std.testing.expect(header != null);
    try std.testing.expectEqualStrings("CSeq", header.?.name);
    try std.testing.expectEqualStrings("2", header.?.value);

    header = try parser.nextHeader();
    try std.testing.expect(header != null);
    try std.testing.expectEqualStrings("Session", header.?.name);
    try std.testing.expectEqualStrings("12345678", header.?.value);

    header = try parser.nextHeader();
    try std.testing.expect(header != null);
    try std.testing.expectEqualStrings("Content-Length", header.?.name);
    try std.testing.expectEqualStrings("13", header.?.value);

    header = try parser.nextHeader();
    try std.testing.expect(header == null);

    const body = try parser.getBody();
    try std.testing.expect(body != null);
    try std.testing.expectEqualStrings("Hello, World!", body.?);
}

test "request parser" {
    const response_text = "ANNOUNCE  rtsp://example.com/my/stream RTSP/1.0\nCSeq: 2\r\nSession: 12345678\r\nContent-Length: 13\r\n\r\nHello, World!";
    var reader = Reader.fixed(response_text);
    var parser = Parser.init(&reader);

    const request_line = try parser.getRequestLine();

    try std.testing.expectEqual(.announce, request_line.method);
    try std.testing.expectEqualStrings("/my/stream", request_line.uri.path.percent_encoded);

    var header = try parser.nextHeader();
    try std.testing.expect(header != null);
    try std.testing.expectEqualStrings("CSeq", header.?.name);
    try std.testing.expectEqualStrings("2", header.?.value);

    header = try parser.nextHeader();
    try std.testing.expect(header != null);
    try std.testing.expectEqualStrings("Session", header.?.name);
    try std.testing.expectEqualStrings("12345678", header.?.value);

    header = try parser.nextHeader();
    try std.testing.expect(header != null);
    try std.testing.expectEqualStrings("Content-Length", header.?.name);
    try std.testing.expectEqualStrings("13", header.?.value);

    header = try parser.nextHeader();
    try std.testing.expect(header == null);

    const body = try parser.getBody();
    try std.testing.expect(body != null);
    try std.testing.expectEqualStrings("Hello, World!", body.?);
}

test {
    std.testing.refAllDecls(@This());
}
