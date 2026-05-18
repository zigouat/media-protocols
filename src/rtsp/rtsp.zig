pub const Server = @import("server.zig");

const std = @import("std");
const rtp = @import("rtp");

const Reader = std.Io.Reader;

pub const Error = error{
    ParseError,
} || std.mem.Allocator.Error || Reader.Error;

pub const Method = enum {
    OPTIONS,
    DESCRIBE,
    ANNOUNCE,
    SETUP,
    PLAY,
    PAUSE,
    TEARDOWN,
    GET_PARAMETER,
    SET_PARAMETER,
    REDIRECT,
    RECORD,

    pub fn expectBody(self: Method) bool {
        return switch (self) {
            .ANNOUNCE, .SET_PARAMETER => true,
            else => false,
        };
    }

    pub fn responseExpectBody(self: Method) bool {
        return switch (self) {
            .DESCRIBE, .GET_PARAMETER => true,
            else => false,
        };
    }
};

pub const Status = enum(u10) {
    success = 200,
    low_on_storage = 250,

    method_not_allowed = 405,
    parameter_not_understood = 451,
    conference_not_found = 452,
    not_enough_bandwidth = 453,
    session_not_found = 454,
    invalid_method = 455,
    invalid_header = 456,
    invalid_range = 457,
    parameter_readonly = 458,
    aggregate_not_allowed = 459,
    only_aggregate = 460,
    unsupported_transport = 461,
    destination_unreachable = 462,

    option_not_supported = 551,

    _,

    pub fn phrase(self: Status) ?[]const u8 {
        return switch (self) {
            .success => "SUCCESS",
            .low_on_storage => "Low on Storage Space",
            .method_not_allowed => "Method Not Allowed",
            .parameter_not_understood => "Parameter Not Understood",
            .conference_not_found => "Parameter Not Understood",
            .not_enough_bandwidth => "Not Enough Bandwidth",
            .session_not_found => "Session Not Found",
            .invalid_method => "Method Not Valid in This State",
            .invalid_header => "Header Field Not Valid for Resource",
            .invalid_range => "Invalid Range",
            .parameter_readonly => "Parameter Is Read-Only",
            .aggregate_not_allowed => "Aggregate Operation Not Allowed",
            .only_aggregate => "Only Aggregate Operation Allowed",
            .unsupported_transport => "Unsupported Transport",
            .destination_unreachable => "Destination Unreachable",
            .option_not_supported => "Option not supported",
            else => null,
        };
    }
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,

    pub const Transport = struct {
        proto: enum { tcp, udp } = .udp,
        /// False means multicast
        unicast: bool = true,
        interleaved: ?struct { u8, u8 } = null,
        client_port: ?struct { u16, u16 } = null,
        server_port: ?struct { u16, u16 } = null,
        mode: Method = .PLAY,

        pub const Error = error{InvalidTransportHeader};

        pub fn parse(header_value: []const u8) Transport.Error!Transport {
            var it = std.mem.splitScalar(u8, header_value, ';');
            var transport: Transport = .{};

            const protocol = it.next().?;
            if (std.mem.eql(u8, protocol, "RTP/AVP")) {
                transport.proto = .udp;
            } else if (std.mem.eql(u8, protocol, "RTP/AVP/UDP")) {
                transport.proto = .udp;
            } else if (std.mem.eql(u8, protocol, "RTP/AVP/TCP")) {
                transport.proto = .tcp;
            } else {
                return error.InvalidTransportHeader;
            }

            while (it.next()) |parameter| {
                if (std.mem.eql(u8, parameter, "unicast")) {
                    transport.unicast = true;
                } else if (std.mem.eql(u8, parameter, "multicast")) {
                    transport.unicast = false;
                } else if (std.mem.startsWith(u8, parameter, "interleaved=")) {
                    transport.interleaved = parseRange(u8, parameter[12..]) catch return error.InvalidTransportHeader;
                } else if (std.mem.startsWith(u8, parameter, "client_port=")) {
                    transport.client_port = parseRange(u16, parameter[12..]) catch return error.InvalidTransportHeader;
                } else if (std.mem.startsWith(u8, parameter, "server_port=")) {
                    transport.server_port = parseRange(u16, parameter[12..]) catch return error.InvalidTransportHeader;
                } else if (std.mem.startsWith(u8, parameter, "mode=")) {
                    const method = std.mem.trim(u8, parameter[5..], "\"");
                    if (std.ascii.eqlIgnoreCase(method, "play"))
                        transport.mode = .PLAY
                    else if (std.ascii.eqlIgnoreCase(method, "record"))
                        transport.mode = .RECORD
                    else
                        return error.InvalidTransportHeader;
                }
            }

            return transport;
        }

        pub fn write(self: *const Transport, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.writeAll(if (self.proto == .tcp) "RTP/AVP/TCP" else "RTP/AVP");
            if (self.unicast) try writer.writeAll(";unicast") else try writer.writeAll(";multicast");

            if (self.interleaved) |interleaved|
                try writer.print(";interleaved={}-{}", .{ interleaved.@"0", interleaved.@"1" });

            if (self.client_port) |client_port|
                try writer.print(";client_port={}-{}", .{ client_port.@"0", client_port.@"1" });

            if (self.server_port) |server_port|
                try writer.print(";server_port={}-{}", .{ server_port.@"0", server_port.@"1" });
        }

        fn parseRange(T: type, value: []const u8) !struct { T, T } {
            if (std.mem.cutScalar(u8, value, '-')) |range| {
                const left, const right = range;
                return .{ try std.fmt.parseInt(T, left, 10), try std.fmt.parseInt(T, right, 10) };
            }

            return error.ParseError;
        }
    };

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

    test "Transport: parse" {
        {
            const transport = try Transport.parse("RTP/AVP/TCP;unicast;interleaved=0-1");
            try std.testing.expect(transport.unicast);
            try std.testing.expectEqual(.tcp, transport.proto);
            try std.testing.expectEqual(.{ 0, 1 }, transport.interleaved);
        }

        {
            const transport = try Transport.parse("RTP/AVP/UDP;client_port=15000-15001;mode=\"recOrd\"");
            try std.testing.expect(transport.unicast);
            try std.testing.expectEqual(.udp, transport.proto);
            try std.testing.expectEqual(null, transport.interleaved);
            try std.testing.expectEqual(.{ 15000, 15001 }, transport.client_port);
            try std.testing.expectEqual(.RECORD, transport.mode);
        }

        {
            const transport = try Transport.parse("RTP/AVP;unicast;server_port=35000-35001");
            try std.testing.expect(transport.unicast);
            try std.testing.expectEqual(.udp, transport.proto);
            try std.testing.expectEqual(null, transport.interleaved);
            try std.testing.expectEqual(null, transport.client_port);
            try std.testing.expectEqual(.{ 35000, 35001 }, transport.server_port);
            try std.testing.expectEqual(.PLAY, transport.mode);
        }
    }
};

pub const uri_flags: std.Uri.Format.Flags = .{
    .authentication = false,
    .scheme = true,
    .authority = true,
    .path = true,
    .query = true,
    .fragment = true,
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

/// A lazy parser for RTSP messages.
pub const Parser = struct {
    reader: *Reader,
    content_length: usize = 0,
    parse_state: ParseState = .first_line,

    const ParseState = enum { first_line, header, body };

    pub fn init(reader: *Reader) Parser {
        return Parser{ .reader = reader };
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

    pub fn writeTransportHeader(self: *Writer, header: Header.Transport) std.Io.Writer.Error!void {
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

test {
    std.testing.refAllDecls(@This());
}
