pub const SourceDescription = @import("source_description.zig");

const std = @import("std");

const Reader = std.Io.Reader;

pub const header_size = @bitSizeOf(Header) / 8;
pub const sr_base_size = 24;
pub const rr_base_size = 4;
pub const reception_report_size = 24;

pub const PayloadType = enum(u8) {
    sender_report = 200,
    receiver_report = 201,
    source_description = 202,
    bye = 203,
    _,
};

pub const Header = packed struct {
    length: u16,
    payload_type: PayloadType,
    rc: u5,
    padding: bool,
    version: u2 = 2,
};

pub const Packet = struct {
    header: Header,
    payload: union(PayloadType) {
        sender_report: SenderReport,
        receiver_report: ReceiverReport,
        source_description: SourceDescription,
        bye: []const u8,
    },

    pub const Error = Reader.Error || error{UnknownPayloadType};

    pub fn parse(data: []const u8) Error!Packet {
        var reader = Reader.fixed(data);
        return parseFromReader(&reader);
    }

    fn parseFromReader(reader: *Reader) Error!Packet {
        var packet: Packet = undefined;

        packet.header = try reader.takeStruct(Header, .big);
        const payload = try reader.take(packet.header.length * 4);

        switch (packet.header.payload_type) {
            .sender_report => {
                if (payload.len < @as(usize, packet.header.rc) * reception_report_size + sr_base_size) return error.EndOfStream;
                packet.payload = .{ .sender_report = .fromSlice(payload, packet.header.rc) };
            },
            .receiver_report => {
                if (payload.len < @as(usize, packet.header.rc) * reception_report_size + rr_base_size) return error.EndOfStream;
                packet.payload = .{ .receiver_report = .fromSlice(payload, packet.header.rc) };
            },
            .source_description => packet.payload = .{ .source_description = .{ .chunks_bytes = payload } },
            .bye => {
                if (payload.len < packet.header.rc * 4) return error.EndOfStream;
                packet.payload = .{ .bye = payload };
            },
            else => return error.UnknownPayloadType,
        }

        return packet;
    }

    // Get the size of the packet
    pub fn getSize(packet: *const Packet) usize {
        return (packet.header.length + 1) * 4;
    }
};

pub const SenderReport = struct {
    ssrc: u32,
    ntp_timestamp: u64,
    rtp_timestamp: u32,
    packet_count: u32,
    octet_count: u32,
    report_bytes: []const u8 = &.{},
    profile_extensions: []const u8 = &.{},

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

    pub fn getReceptionReport(sr: *const SenderReport, index: usize) ReceptionReport {
        const offset = index * reception_report_size;
        std.debug.assert(offset + reception_report_size <= sr.report_bytes.len);
        return .fromSlice(sr.report_bytes[offset .. offset + reception_report_size]);
    }
};

pub const ReceiverReport = struct {
    ssrc: u32,
    report_bytes: []const u8 = &.{},
    profile_extensions: []const u8 = &.{},

    pub fn fromSlice(data: []const u8, rr_count: u5) ReceiverReport {
        const report_offset = @as(usize, reception_report_size) * rr_count + 4;

        return .{
            .ssrc = std.mem.readInt(u32, data[0..4], .big),
            .report_bytes = data[4..report_offset],
            .profile_extensions = data[report_offset..],
        };
    }

    pub fn getReceptionReport(sr: *const SenderReport, index: usize) ReceptionReport {
        const offset = index * reception_report_size;
        std.debug.assert(offset + reception_report_size <= sr.report_bytes.len);
        return .fromSlice(sr.report_bytes[offset .. offset + reception_report_size]);
    }
};

pub const ReceptionReport = struct {
    ssrc: u32,
    fraction_lost: u8,
    total_lost: u24,
    last_sequence_number: u32,
    jitter: u32,
    last_sr: u32,
    delay: u32,

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

    pub fn next(it: *Iterator) Packet.Error!?Packet {
        if (it.reader.bufferedLen() == 0) return null;
        return try Packet.parseFromReader(&it.reader);
    }
};

const testing = std.testing;

test {
    _ = @import("source_description.zig");
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
    try std.testing.expectEqual(989796, packet.payload.receiver_report.ssrc);
    try std.testing.expectEqualSlices(u8, data[32..36], packet.payload.receiver_report.profile_extensions);
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
    try testing.expectEqualSlices(u8, data[4..], packet.payload.source_description.chunks_bytes);
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

    var sdes = packet.?.payload.source_description;
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
