const std = @import("std");

const Reader = std.Io.Reader;

const reception_report_size = 24;
const sr_base_size = 24;
const rr_base_size = 4;

pub const PayloadType = enum(u8) {
    sender_report = 200,
    receiver_report = 201,
    source_description = 202,
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
    },

    pub fn parse(data: []const u8) Reader.Error!Packet {
        var reader = Reader.fixed(data);
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
            .source_description => packet.payload = .{ .source_description = .{ .chunk_bytes = payload } },
            else => {},
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

pub const SourceDescription = struct {
    chunk_bytes: []const u8 = &.{},

    pub const ChunkItem = union(enum(u8)) {
        cname: []const u8,
        name: []const u8,
        email: []const u8,
        phone: []const u8,
        loc: []const u8,
        tool: []const u8,
        note: []const u8,
        priv: []const u8,
    };

    pub const Chunk = struct {
        ssrc: u32,
        items: []const u8 = &.{},

        pub const ItemIterator = struct {
            data: []const u8,

            fn init(data: []const u8) ItemIterator {
                return .{ .data = data };
            }

            pub fn next(it: *ItemIterator) !?ChunkItem {
                const data = it.data;

                if (data.len == 0) return null;
                if (data.len < 2 or data.len < @as(usize, data[1]) + 2) return error.ParseError;

                const value = data[2 .. @as(usize, data[1]) + 2];

                const item: ChunkItem = switch (data[0]) {
                    1 => .{ .cname = value },
                    2 => .{ .name = value },
                    3 => .{ .email = value },
                    4 => .{ .phone = value },
                    5 => .{ .loc = value },
                    6 => .{ .tool = value },
                    7 => .{ .note = value },
                    8 => .{ .priv = value },
                    else => return error.InvalidChunkItem,
                };

                it.data = it.data[value.len + 2 ..];
                return item;
            }
        };

        pub fn iterateItems(chunk: *const Chunk) ItemIterator {
            return .init(chunk.items);
        }
    };

    pub const ChunkIterator = struct {
        bytes: []const u8,

        pub fn init(bytes: []const u8) ChunkIterator {
            return .{ .bytes = bytes };
        }

        pub fn next(it: *ChunkIterator) !?Chunk {
            const data = it.bytes;
            if (data.len == 0) return null;
            if (data.len < 4) return error.InvalidChunk;

            const ssrc = std.mem.readInt(u32, data[0..4], .big);
            const null_pos = std.mem.findScalarPos(u8, data, 4, 0) orelse return error.InvalidChunk;
            const items = data[4..null_pos];

            var skip = null_pos + 1;
            while (skip % 4 != 0) : (skip += 1) {
                if (skip >= data.len or data[skip] != 0) return error.InvalidChunk;
            }

            it.bytes = data[skip..];
            return .{ .ssrc = ssrc, .items = items };
        }
    };
};

const testing = std.testing;

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
        // ssrc
        0xAB, 0xCD, 0xEF, 0x01,
        // fraction_lost, total_lost (u24)
        0x05, 0x00, 0x00, 0x10,
        // last_sequence_number
        0x00, 0x00, 0x12, 0x34,
        // jitter
        0x00, 0x00, 0x00, 0x50,
        // last_sr
        0xE8, 0xC5, 0xF7, 0x3B,
        // delay
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

test "SenderReport.getReceptionReport: single report" {
    const data = [_]u8{
        // --- SenderReport body (24 bytes) ---
        0x12, 0x34, 0x56, 0x78,
        0xE8, 0xC5, 0xF7, 0x3B,
        0x1A, 0x2B, 0x3C, 0x4D,
        0x00, 0x0D, 0xDF, 0x22,
        0x00, 0x00, 0x00, 0x64,
        0x00, 0x00, 0x27, 0x10,
        // --- ReceptionReport[0] (24 bytes) ---
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

test "SenderReport.getReceptionReport: multiple reports indexed correctly" {
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
    try testing.expectEqualSlices(u8, data[4..], packet.payload.source_description.chunk_bytes);
}

test "SourceDescription: iterate single chunk and its items" {
    const chunk_bytes = [_]u8{
        0xFD, 0x8D, 0xA5, 0x3B,
        0x01, 0x04, 'e',  'v',
        'c',  'a',  0x00, 0x00,
    };

    var chunks = SourceDescription.ChunkIterator.init(&chunk_bytes);

    const chunk = (try chunks.next()).?;
    try testing.expectEqual(0xFD8DA53B, chunk.ssrc);

    var items = chunk.iterateItems();
    const item = (try items.next()).?;
    try testing.expectEqualStrings("evca", item.cname);
    try testing.expectEqual(null, try items.next());

    try testing.expectEqual(null, try chunks.next());
}

test "SourceDescription: item list ending on a 32-bit boundary is padded with a full word" {
    const chunk_bytes = [_]u8{
        0x12, 0x34, 0x56, 0x78,
        0x01, 0x02, 'a',  'b',
        0x00, 0x00, 0x00, 0x00,
    };

    var chunks = SourceDescription.ChunkIterator.init(&chunk_bytes);

    const chunk = (try chunks.next()).?;
    try testing.expectEqual(0x12345678, chunk.ssrc);

    var items = chunk.iterateItems();
    try testing.expectEqualStrings("ab", (try items.next()).?.cname);

    try testing.expectEqual(null, try chunks.next());
}

test "SourceDescription: multiple items in one chunk" {
    const chunk_bytes = [_]u8{
        0xAA, 0xBB, 0xCC, 0xDD,
        0x01, 0x03, 'a',  'b',
        'c',  0x06, 0x04, 'z',
        'i',  'g',  '0',  0x00,
    };

    var chunks = SourceDescription.ChunkIterator.init(&chunk_bytes);
    const chunk = (try chunks.next()).?;
    try testing.expectEqual(0xAABBCCDD, chunk.ssrc);

    var items = chunk.iterateItems();
    try testing.expectEqualStrings("abc", (try items.next()).?.cname);
    try testing.expectEqualStrings("zig0", (try items.next()).?.tool);
    try testing.expectEqual(null, try items.next());

    try testing.expectEqual(null, try chunks.next());
}

test "SourceDescription: multiple chunks" {
    const chunk_bytes = [_]u8{
        // chunk 0
        0x11, 0x11, 0x11, 0x11,
        0x01, 0x02, 'h',  'i',
        0x00, 0x00, 0x00, 0x00,
        // chunk 1
        0x22, 0x22, 0x22, 0x22,
        0x01, 0x01, 'x',  0x00,
    };

    var chunks = SourceDescription.ChunkIterator.init(&chunk_bytes);

    const c0 = (try chunks.next()).?;
    try testing.expectEqual(0x11111111, c0.ssrc);
    var it0 = c0.iterateItems();
    try testing.expectEqualStrings("hi", (try it0.next()).?.cname);

    const c1 = (try chunks.next()).?;
    try testing.expectEqual(0x22222222, c1.ssrc);
    var it1 = c1.iterateItems();
    try testing.expectEqualStrings("x", (try it1.next()).?.cname);

    try testing.expectEqual(null, try chunks.next());
}

test "SourceDescription: empty chunk (ssrc only, no items)" {
    const chunk_bytes = [_]u8{
        0xDE, 0xAD, 0xBE, 0xEF,
        0x00, 0x00, 0x00, 0x00,
    };

    var chunks = SourceDescription.ChunkIterator.init(&chunk_bytes);
    const chunk = (try chunks.next()).?;
    try testing.expectEqual(0xDEADBEEF, chunk.ssrc);
    try testing.expectEqual(0, chunk.items.len);

    var items = chunk.iterateItems();
    try testing.expectEqual(null, try items.next());

    try testing.expectEqual(null, try chunks.next());
}

test "SourceDescription: empty bytes yields no chunks" {
    var chunks = SourceDescription.ChunkIterator.init(&.{});
    try testing.expectEqual(null, try chunks.next());
}

test "SourceDescription: item with maximum length value does not overflow" {
    var chunk_bytes: [264]u8 = @splat(0);
    std.mem.writeInt(u32, chunk_bytes[0..4], 0x01020304, .big);
    chunk_bytes[4] = 1; // cname
    chunk_bytes[5] = 255; // length
    for (chunk_bytes[6 .. 6 + 255], 0..) |*b, i| b.* = @intCast('A' + (i % 26));

    var chunks = SourceDescription.ChunkIterator.init(&chunk_bytes);
    const chunk = (try chunks.next()).?;

    var items = chunk.iterateItems();
    const item = (try items.next()).?;
    try testing.expectEqual(255, item.cname.len);
    try testing.expectEqualSlices(u8, chunk_bytes[6 .. 6 + 255], item.cname);
}

test "SourceDescription: truncated chunk (no ssrc) is rejected" {
    const chunk_bytes = [_]u8{ 0x12, 0x34, 0x56 };
    var it = SourceDescription.ChunkIterator.init(&chunk_bytes);
    try testing.expectError(error.InvalidChunk, it.next());
}

test "SourceDescription: chunk with no terminator is rejected" {
    const chunk_bytes = [_]u8{
        0x12, 0x34, 0x56, 0x78,
        0x01, 0x02, 'a',  'b',
    };
    var chunks = SourceDescription.ChunkIterator.init(&chunk_bytes);
    try testing.expectError(error.InvalidChunk, chunks.next());
}

test "SourceDescription: unknown item type is rejected" {
    const chunk_bytes = [_]u8{
        0xDE, 0xAD, 0xBE, 0xEF,
        0x09, 0x01, 'x',  0x00,
    };
    var chunks = SourceDescription.ChunkIterator.init(&chunk_bytes);
    const chunk = (try chunks.next()).?;
    var items = chunk.iterateItems();
    try testing.expectError(error.InvalidChunkItem, items.next());
}

test "SourceDescription: item length running past the buffer is rejected" {
    const chunk_bytes = [_]u8{
        0xDE, 0xAD, 0xBE, 0xEF,
        // cname claims length 10, but the item list (bounded by the terminator)
        // only carries 2 value bytes
        0x01, 0x0A, 'x',  'y',
        0x00, 0x00, 0x00, 0x00,
    };
    var chunks = SourceDescription.ChunkIterator.init(&chunk_bytes);
    const chunk = (try chunks.next()).?;
    var items = chunk.iterateItems();
    try testing.expectError(error.ParseError, items.next());
}
