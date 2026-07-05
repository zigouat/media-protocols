const fb = @import("fb.zig");
pub const SourceDescription = @import("source_description.zig");
pub const Nack = fb.Nack;

const std = @import("std");
const Reader = std.Io.Reader;

pub const header_size = @bitSizeOf(Header) / 8;
pub const sr_base_size = 24;
pub const rr_base_size = 4;
pub const reception_report_size = 24;

pub const Error = error{MalformedPacket};

/// RTP Control Protocol (RTCP) packet types.
pub const PayloadType = enum(u8) {
    /// Sender Report (SR) packet type.
    ///
    /// The SR packet is used to provide transmission and reception statistics from active senders.
    sender_report = 200,
    /// Receiver Report (RR) packet type.
    ///
    /// The RR packet is used to provide reception statistics from participants that are not active senders.
    receiver_report = 201,
    /// Source Description (SDES) packet type.
    ///
    /// The SDES packet is used to convey descriptive information about the sources in an RTP session.
    source_description = 202,
    /// Goodbye (BYE) packet type.
    ///
    /// The BYE packet is used to indicate that one or more sources are no longer active.
    bye = 203,
    /// Transport layer feedback message (RFC 4585)
    ///
    /// The RTPFB packet is used to provide feedback on the reception quality of RTP streams, such as packet loss and jitter.
    rtp_fb = 205,
    /// Payload-specific feedback message (RFC 4585)
    ///
    /// The PSFB packet is used to provide feedback on the reception quality of specific payload types, such as video codecs.
    ps_fb = 206,
    _,
};

/// The RTCP packet header structure as defined in RFC 3550.
pub const Header = packed struct {
    /// The length of the RTCP packet in 32-bit words minus one, including the header and any padding.
    length: u16,
    /// The type of RTCP packet.
    payload_type: PayloadType,
    /// The number of reception report blocks contained in the packet.
    ///
    /// In case of RTPFB and PSFB packets, this field indicates the format of the feedback message.
    rc: u5,
    /// Indicates whether the packet contains padding bytes at the end.
    ///
    /// If set to `true`, the last byte of the packet contains a count of how many padding bytes should be ignored.
    padding: bool,
    /// The version of the RTCP protocol. This field is 2 bits long and should be set to 2 for all RTCP packets.
    version: u2 = 2,
};

/// The RTCP packet structure, which consists of a header and a payload.
pub const Packet = struct {
    header: Header,
    payload: union(enum(u8)) {
        sr: SenderReport,
        rr: ReceiverReport,
        sdes: SourceDescription,
        bye: []const u8,
        nack: Nack,
        unknown: []const u8,
    },

    pub fn parse(data: []const u8) Error!Packet {
        var reader = Reader.fixed(data);
        return parseFromReader(&reader) catch return error.MalformedPacket;
    }

    fn parseFromReader(reader: *Reader) !Packet {
        var packet: Packet = undefined;

        packet.header = try reader.takeStruct(Header, .big);
        const payload = try reader.take(packet.header.length * 4);

        switch (packet.header.payload_type) {
            .sender_report => {
                if (payload.len < @as(usize, packet.header.rc) * reception_report_size + sr_base_size) return error.EndOfStream;
                packet.payload = .{ .sr = .fromSlice(payload, packet.header.rc) };
            },
            .receiver_report => {
                if (payload.len < @as(usize, packet.header.rc) * reception_report_size + rr_base_size) return error.EndOfStream;
                packet.payload = .{ .rr = .fromSlice(payload, packet.header.rc) };
            },
            .source_description => packet.payload = .{ .sdes = .{ .chunks_bytes = payload } },
            .bye => {
                if (payload.len < packet.header.rc * 4) return error.EndOfStream;
                packet.payload = .{ .bye = payload };
            },
            .rtp_fb => switch (packet.header.rc) { // FB FMT
                1 => packet.payload = .{ .nack = try Nack.parse(payload) },
                else => packet.payload = .{ .unknown = payload },
            },
            else => packet.payload = .{ .unknown = payload },
        }

        return packet;
    }

    // Get the size of the packet
    pub fn getSize(packet: *const Packet) usize {
        return (packet.header.length + 1) * 4;
    }
};

/// The Sender Report (SR) packet structure, which is used to provide transmission and reception statistics from active senders in an RTP session.
pub const SenderReport = struct {
    /// The synchronization source identifier (SSRC) of the sender.
    ssrc: u32,
    /// The NTP timestamp of the sender, which is a 64-bit value representing the time at which the report was generated.
    ntp_timestamp: u64,
    /// The RTP timestamp of the sender, which is a 32-bit value representing the time at which the report was generated in RTP timestamp units.
    rtp_timestamp: u32,
    /// The total number of RTP packets sent by the sender since the beginning of transmission.
    packet_count: u32,
    /// The total number of RTP payload octets sent by the sender since the beginning of transmission.
    octet_count: u32,
    report_bytes: []const u8 = &.{},
    profile_extensions: []const u8 = &.{},

    /// Parses a SenderReport from a byte slice, given the number of reception reports (rr_count) contained in the report.
    pub fn fromSlice(data: []const u8, rr_count: u5) SenderReport {
        const report_offset = @as(usize, reception_report_size) * rr_count + 24;

        return .{
            .ssrc = std.mem.readInt(u32, data[0..4], .big),
            .ntp_timestamp = std.mem.readInt(u64, data[4..12], .big),
            .rtp_timestamp = std.mem.readInt(u32, data[12..16], .big),
            .packet_count = std.mem.readInt(u32, data[16..20], .big),
            .octet_count = std.mem.readInt(u32, data[20..24], .big),
            .report_bytes = data[24..report_offset],
            .profile_extensions = data[report_offset..],
        };
    }

    /// Serializes the base sender report (no receiver report or profile extensions) to a buffer.
    pub fn write(sender_report: *const SenderReport, buf: *[sr_base_size]u8) void {
        std.mem.writeInt(u32, buf[0..4], sender_report.ssrc, .big);
        std.mem.writeInt(u64, buf[4..12], sender_report.ntp_timestamp, .big);
        std.mem.writeInt(u32, buf[12..16], sender_report.rtp_timestamp, .big);
        std.mem.writeInt(u32, buf[16..20], sender_report.packet_count, .big);
        std.mem.writeInt(u32, buf[20..24], sender_report.octet_count, .big);
    }

    /// Returns the reception report at the specified index.
    ///
    /// The total number of reception reports is determined by the `rc` field in the RTCP header.
    pub fn getReceptionReport(sr: *const SenderReport, index: usize) ReceptionReport {
        const offset = index * reception_report_size;
        std.debug.assert(offset + reception_report_size <= sr.report_bytes.len);
        return .fromSlice(sr.report_bytes[offset .. offset + reception_report_size]);
    }
};

/// The Receiver Report (RR) packet structure, which is used to provide reception statistics from participants that are not active senders in an RTP session.
pub const ReceiverReport = struct {
    /// The synchronization source identifier (SSRC) of the receiver.
    ssrc: u32,
    report_bytes: []const u8 = &.{},
    profile_extensions: []const u8 = &.{},

    /// Parses a ReceiverReport from a byte slice, given the number of reception reports (rr_count) contained in the report.
    pub fn fromSlice(data: []const u8, rr_count: u5) ReceiverReport {
        const report_offset = @as(usize, reception_report_size) * rr_count + 4;

        return .{
            .ssrc = std.mem.readInt(u32, data[0..4], .big),
            .report_bytes = data[4..report_offset],
            .profile_extensions = data[report_offset..],
        };
    }

    /// Returns the reception report at the specified index.
    ///
    /// The total number of reception reports is determined by the `rc` field in the RTCP header.
    pub fn getReceptionReport(sr: *const SenderReport, index: usize) ReceptionReport {
        const offset = index * reception_report_size;
        std.debug.assert(offset + reception_report_size <= sr.report_bytes.len);
        return .fromSlice(sr.report_bytes[offset .. offset + reception_report_size]);
    }
};

/// The Reception Report structure, which is used to provide reception statistics for a specific source in an RTP session.
pub const ReceptionReport = struct {
    /// The synchronization source identifier (SSRC) of the source for which the reception report is generated.
    ssrc: u32,
    /// The fraction of RTP data packets from the source lost since the previous SR or RR packet was sent.
    fraction_lost: u8,
    /// The total number of RTP data packets from the source that have been lost since the beginning of reception.
    total_lost: u24,
    /// The extended highest sequence number received from the source, which is the highest sequence number received plus the number of packets lost.
    last_sequence_number: u32,
    /// The interarrival jitter, which is an estimate of the statistical variance of the RTP data packet interarrival time.
    jitter: u32,
    /// The timestamp of the last SR packet received from the source, expressed in NTP format.
    last_sr: u32,
    /// The delay since the last SR packet was received from the source, expressed in units of 1/65536 seconds.
    delay: u32,

    /// Parses a ReceptionReport from a byte slice.
    pub fn fromSlice(data: []const u8) ReceptionReport {
        std.debug.assert(data.len == reception_report_size);

        return .{
            .ssrc = std.mem.readInt(u32, data[0..4], .big),
            .fraction_lost = data[4],
            .total_lost = std.mem.readInt(u24, data[5..8], .big),
            .last_sequence_number = std.mem.readInt(u32, data[8..12], .big),
            .jitter = std.mem.readInt(u32, data[12..16], .big),
            .last_sr = std.mem.readInt(u32, data[16..20], .big),
            .delay = std.mem.readInt(u32, data[20..24], .big),
        };
    }
};

/// An iterator over compound rtcp packet.
pub const Iterator = struct {
    reader: Reader,

    pub fn init(rtcp: []const u8) Iterator {
        return .{ .reader = .fixed(rtcp) };
    }

    pub fn next(it: *Iterator) Error!?Packet {
        if (it.reader.bufferedLen() == 0) return null;
        return Packet.parseFromReader(&it.reader) catch return error.MalformedPacket;
    }
};

const testing = std.testing;

test {
    _ = @import("source_description.zig");
    _ = @import("fb.zig");
}

test "Header: bit size is 32" {
    try testing.expectEqual(32, @bitSizeOf(Header));
}

test "Packet: parse receiver report" {
    const data = [_]u8{
        0x81, 0xC9, 0x00, 0x08,
        0x00, 0x0F, 0x1A, 0x64,
        0xAB, 0xCD, 0xEF, 0x01,
        0x05, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x12, 0x34,
        0x00, 0x00, 0x00, 0x50,
        0xE8, 0xC5, 0xF7, 0x3B,
        0x00, 0x00, 0x01, 0x00,
        0x01, 0x02, 0x03, 0x04,
    };

    const packet = try Packet.parse(&data);
    try std.testing.expectEqual(PayloadType.receiver_report, packet.header.payload_type);
    try std.testing.expectEqual(989796, packet.payload.rr.ssrc);
    try std.testing.expectEqualSlices(u8, data[32..36], packet.payload.rr.profile_extensions);
}

test "SenderReport.fromSlice: parses all fields" {
    const data = [_]u8{
        // ssrc
        0x12, 0x34, 0x56, 0x78,
        // ntp_timestamp
        0xE8, 0xC5, 0xF7, 0x3B,
        0x1A, 0x2B, 0x3C, 0x4D,
        // rtp_timestamp
        0x00, 0x0D, 0xDF, 0x22,
        // packet_count = 100
        0x00, 0x00, 0x00, 0x64,
        // octet_count = 10000
        0x00, 0x00, 0x27, 0x10,
    };

    const sr = SenderReport.fromSlice(&data, 0);

    try testing.expectEqual(0x12345678, sr.ssrc);
    try testing.expectEqual(0xE8C5F73B1A2B3C4D, sr.ntp_timestamp);
    try testing.expectEqual(0x000DDF22, sr.rtp_timestamp);
    try testing.expectEqual(100, sr.packet_count);
    try testing.expectEqual(10000, sr.octet_count);
    try testing.expectEqual(0, sr.report_bytes.len);
}

test "SenderReport.fromSlice: report_bytes contains trailing data" {
    const data = [_]u8{
        // ssrc
        0x12, 0x34, 0x56, 0x78,
        // ntp_timestamp
        0xE8, 0xC5, 0xF7, 0x3B,
        0x1A, 0x2B, 0x3C, 0x4D,
        // rtp_timestamp
        0x00, 0x0D, 0xDF, 0x22,
        // packet_count
        0x00, 0x00, 0x00, 0x64,
        // octet_count
        0x00, 0x00, 0x27, 0x10,
        // trailing reception report bytes
        0xAB, 0xCD, 0xEF, 0x01,
        0x05, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x12, 0x34,
        0x00, 0x00, 0x00, 0x50,
        0xE8, 0xC5, 0xF7, 0x3B,
        0x00, 0x00, 0x01, 0x00,
    };

    const sr = SenderReport.fromSlice(&data, 1);
    try testing.expectEqualSlices(u8, data[24..], sr.report_bytes);
}

test "ReceptionReport.fromSlice: parses all fields" {
    const data = [_]u8{
        0xAB, 0xCD, 0xEF, 0x01,
        0x05, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x12, 0x34,
        0x00, 0x00, 0x00, 0x50,
        0xE8, 0xC5, 0xF7, 0x3B,
        0x00, 0x00, 0x01, 0x00,
    };

    const rr = ReceptionReport.fromSlice(&data);

    try testing.expectEqual(0xABCDEF01, rr.ssrc);
    try testing.expectEqual(0x05, rr.fraction_lost);
    try testing.expectEqual(0x000010, rr.total_lost);
    try testing.expectEqual(0x00001234, rr.last_sequence_number);
    try testing.expectEqual(0x00000050, rr.jitter);
    try testing.expectEqual(0xE8C5F73B, rr.last_sr);
    try testing.expectEqual(0x00000100, rr.delay);
}

test "ReceptionReport.fromSlice: max values" {
    const data = [_]u8{
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
    };

    const rr = ReceptionReport.fromSlice(&data);

    try testing.expectEqual(std.math.maxInt(u32), rr.ssrc);
    try testing.expectEqual(std.math.maxInt(u8), rr.fraction_lost);
    try testing.expectEqual(std.math.maxInt(u24), rr.total_lost);
    try testing.expectEqual(std.math.maxInt(u32), rr.last_sequence_number);
    try testing.expectEqual(std.math.maxInt(u32), rr.jitter);
    try testing.expectEqual(std.math.maxInt(u32), rr.last_sr);
    try testing.expectEqual(std.math.maxInt(u32), rr.delay);
}

test "SenderReport: parse single report" {
    const data = [_]u8{
        // SenderReport
        0x12, 0x34, 0x56, 0x78,
        0xE8, 0xC5, 0xF7, 0x3B,
        0x1A, 0x2B, 0x3C, 0x4D,
        0x00, 0x0D, 0xDF, 0x22,
        0x00, 0x00, 0x00, 0x64,
        0x00, 0x00, 0x27, 0x10,
        // ReceptionReport
        0xAB, 0xCD, 0xEF, 0x01,
        0x05, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x12, 0x34,
        0x00, 0x00, 0x00, 0x50,
        0xE8, 0xC5, 0xF7, 0x3B,
        0x00, 0x00, 0x01, 0x00,
    };

    const sr = SenderReport.fromSlice(&data, 1);
    const rr = sr.getReceptionReport(0);

    try testing.expectEqual(0xABCDEF01, rr.ssrc);
    try testing.expectEqual(0x05, rr.fraction_lost);
    try testing.expectEqual(0x000010, rr.total_lost);
    try testing.expectEqual(0x00001234, rr.last_sequence_number);
    try testing.expectEqual(0x00000050, rr.jitter);
    try testing.expectEqual(0xE8C5F73B, rr.last_sr);
    try testing.expectEqual(0x00000100, rr.delay);
}

test "SenderReport: parse multiple reports indexed correctly" {
    const data = [_]u8{
        // --- SenderReport body (24 bytes) ---
        0x12, 0x34, 0x56, 0x78,
        0xE8, 0xC5, 0xF7, 0x3B,
        0x1A, 0x2B, 0x3C, 0x4D,
        0x00, 0x0D, 0xDF, 0x22,
        0x00, 0x00, 0x00, 0x64,
        0x00, 0x00, 0x27, 0x10,
        // --- ReceptionReport[0] ---
        0x11, 0x11, 0x11, 0x11,
        0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01,
        // --- ReceptionReport[1] ---
        0x22, 0x22, 0x22, 0x22,
        0x02, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x02,
    };

    const sr = SenderReport.fromSlice(&data, 2);

    const rr0 = sr.getReceptionReport(0);
    try testing.expectEqual(0x11111111, rr0.ssrc);
    try testing.expectEqual(0x01, rr0.fraction_lost);
    try testing.expectEqual(0x000001, rr0.total_lost);

    const rr1 = sr.getReceptionReport(1);
    try testing.expectEqual(0x22222222, rr1.ssrc);
    try testing.expectEqual(0x02, rr1.fraction_lost);
    try testing.expectEqual(0x000002, rr1.total_lost);
}

test "SenderReport: write" {
    const expected = [_]u8{
        0x12, 0x34, 0x56, 0x78,
        0xE8, 0xC5, 0xF7, 0x3B,
        0x1A, 0x2B, 0x3C, 0x4D,
        0x00, 0x0D, 0xDF, 0x22,
        0x00, 0x00, 0x00, 0x64,
        0x00, 0x00, 0x27, 0x10,
    };

    const sr: SenderReport = .{
        .ssrc = 305419896,
        .ntp_timestamp = 16773084220425452621,
        .rtp_timestamp = 909090,
        .packet_count = 100,
        .octet_count = 10000,
    };

    var buffer: [sr_base_size]u8 = @splat(0);
    sr.write(&buffer);
    try testing.expectEqualSlices(u8, &expected, &buffer);
}

test "Packet: parse source description" {
    const data = [_]u8{
        // header: V=2, P=0, SC=1, PT=202, length=3 (12 bytes payload)
        0x81, 0xCA, 0x00, 0x03,
        // chunk: ssrc
        0xFD, 0x8D, 0xA5, 0x3B,
        // cname item (type=1, len=4, "evca")
        0x01, 0x04, 'e',  'v',
        'c',  'a',
        // terminator + padding to 32-bit boundary
         0x00, 0x00,
    };

    const packet = try Packet.parse(&data);
    try testing.expectEqual(PayloadType.source_description, packet.header.payload_type);
    try testing.expectEqualSlices(u8, data[4..], packet.payload.sdes.chunks_bytes);
}

test "Packet: parse RTP-FB Nack" {
    const data = [_]u8{
        0x81, 0xCD, 0x00, 0x03,
        0x12, 0x34, 0x56, 0x78,
        0x9A, 0xBC, 0xDE, 0xF0,
        0x03, 0xE8, 0x00, 0x05,
    };

    const packet = try Packet.parse(&data);
    try testing.expectEqual(PayloadType.rtp_fb, packet.header.payload_type);
    try testing.expectEqual(1, packet.header.rc);
    try testing.expectEqual(305419896, packet.payload.nack.sender_ssrc);
    try testing.expectEqual(2596069104, packet.payload.nack.media_ssrc);
    try testing.expectEqualSlices(u8, data[12..], packet.payload.nack.fci);
}

test "Compound packet: iterate" {
    const rtcp = [_]u8{
        0x80, 0xc8, 0x00, 0x06, 0xb2, 0x39, 0x3f, 0x3f, 0xed, 0xdf, 0x9e,
        0x71, 0x66, 0xd1, 0x39, 0x43, 0x1b, 0x13, 0x76, 0x14, 0x00, 0x00,
        0x00, 0x92, 0x00, 0x01, 0xc5, 0x5c, 0x81, 0xca, 0x00, 0x0c, 0xb2,
        0x39, 0x3f, 0x3f, 0x01, 0x26, 0x7b, 0x64, 0x30, 0x66, 0x35, 0x63,
        0x66, 0x30, 0x30, 0x2d, 0x36, 0x63, 0x63, 0x37, 0x2d, 0x34, 0x65,
        0x35, 0x66, 0x2d, 0x61, 0x38, 0x61, 0x30, 0x2d, 0x64, 0x63, 0x36,
        0x35, 0x39, 0x38, 0x64, 0x66, 0x65, 0x31, 0x61, 0x66, 0x7d, 0x00,
        0x00, 0x00, 0x00,
    };

    const rtcp2 = [_]u8{
        0x80, 0xc9, 0x00, 0x01, 0xb2, 0x39, 0x3f, 0x3f, 0x81,
        0xca, 0x00, 0x0c, 0xb2, 0x39, 0x3f, 0x3f, 0x01, 0x26,
        0x7b, 0x64, 0x30, 0x66, 0x35, 0x63, 0x66, 0x30, 0x30,
        0x2d, 0x36, 0x63, 0x63, 0x37, 0x2d, 0x34, 0x65, 0x35,
        0x66, 0x2d, 0x61, 0x38, 0x61, 0x30, 0x2d, 0x64, 0x63,
        0x36, 0x35, 0x39, 0x38, 0x64, 0x66, 0x65, 0x31, 0x61,
        0x66, 0x7d, 0x00, 0x00, 0x00, 0x00, 0x81, 0xcb, 0x00,
        0x01, 0xb2, 0x39, 0x3f, 0x3f,
    };

    var it: Iterator = .init(&rtcp);
    var packet = try it.next();
    try testing.expect(packet != null);
    try testing.expectEqual(.sender_report, packet.?.header.payload_type);

    packet = try it.next();
    try testing.expect(packet != null);
    try testing.expectEqual(.source_description, packet.?.header.payload_type);

    var sdes = packet.?.payload.sdes;
    var chunk_it = sdes.iterateChunks();
    const chunk = (try chunk_it.next()).?;
    try std.testing.expect(try chunk_it.next() == null);

    var item_it = chunk.iterateItems();
    const item = (try item_it.next()).?;
    try testing.expectEqual(.cname, item.item_type);
    try testing.expectEqualStrings("{d0f5cf00-6cc7-4e5f-a8a0-dc6598dfe1af}", item.value);

    packet = try it.next();
    try testing.expect(try it.next() == null);
    try testing.expect(try it.next() == null);

    // Rtcp2
    it = .init(&rtcp2);

    packet = try it.next();
    try testing.expect(packet != null);
    try testing.expectEqual(.receiver_report, packet.?.header.payload_type);

    packet = try it.next();
    try testing.expect(packet != null);
    try testing.expectEqual(.source_description, packet.?.header.payload_type);

    packet = try it.next();
    try testing.expect(packet != null);
    try testing.expectEqual(.bye, packet.?.header.payload_type);

    packet = try it.next();
    try testing.expect(packet == null);
}
