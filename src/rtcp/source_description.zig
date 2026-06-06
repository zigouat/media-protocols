const std = @import("std");

chunks_bytes: []const u8 = &.{},

pub const ItemType = enum(u8) { cname = 1, name, email, phone, loc, tool, note, priv, mid = 15, _ };

pub const ChunkItem = struct {
    item_type: ItemType,
    value: []const u8,
};

pub const ItemIterator = struct {
    bytes: []const u8,

    pub fn init(bytes: []const u8) ItemIterator {
        return .{ .bytes = bytes };
    }

    pub fn next(it: *ItemIterator) !?ChunkItem {
        const bytes = it.bytes;

        if (bytes.len == 0) return null;
        if (bytes.len < 2 or bytes.len < @as(usize, bytes[1]) + 2) return error.ParseError;

        const value = bytes[2 .. @as(usize, bytes[1]) + 2];
        it.bytes = it.bytes[value.len + 2 ..];
        return .{ .item_type = @enumFromInt(bytes[0]), .value = value };
    }
};

pub const Chunk = struct {
    ssrc: u32,
    items: []const u8 = &.{},

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

const testing = std.testing;

test "iterate single chunk and its items" {
    const chunk_bytes = [_]u8{
        0xFD, 0x8D, 0xA5, 0x3B,
        0x01, 0x04, 'e',  'v',
        'c',  'a',  0x00, 0x00,
    };

    var chunks = ChunkIterator.init(&chunk_bytes);

    const chunk = (try chunks.next()).?;
    try testing.expectEqual(0xFD8DA53B, chunk.ssrc);

    var items = chunk.iterateItems();
    const item = (try items.next()).?;
    try testing.expectEqual(.cname, item.item_type);
    try testing.expectEqualStrings("evca", item.value);
    try testing.expectEqual(null, try items.next());

    try testing.expectEqual(null, try chunks.next());
}

test "item list ending on a 32-bit boundary is padded with a full word" {
    const chunk_bytes = [_]u8{
        0x12, 0x34, 0x56, 0x78,
        0x01, 0x02, 'a',  'b',
        0x00, 0x00, 0x00, 0x00,
    };

    var chunks = ChunkIterator.init(&chunk_bytes);

    const chunk = (try chunks.next()).?;
    try testing.expectEqual(0x12345678, chunk.ssrc);

    var items = chunk.iterateItems();
    try testing.expectEqualStrings("ab", (try items.next()).?.value);

    try testing.expectEqual(null, try chunks.next());
}

test "multiple items in one chunk" {
    const chunk_bytes = [_]u8{
        0xAA, 0xBB, 0xCC, 0xDD,
        0x01, 0x03, 'a',  'b',
        'c',  0x06, 0x04, 'z',
        'i',  'g',  '0',  0x00,
    };

    var chunks = ChunkIterator.init(&chunk_bytes);
    const chunk = (try chunks.next()).?;
    try testing.expectEqual(0xAABBCCDD, chunk.ssrc);

    var items = chunk.iterateItems();
    var item = (try items.next()).?;

    try testing.expectEqual(.cname, item.item_type);
    try testing.expectEqualStrings("abc", item.value);

    item = (try items.next()).?;
    try testing.expectEqual(.tool, item.item_type);
    try testing.expectEqualStrings("zig0", item.value);

    try testing.expectEqual(null, try items.next());
    try testing.expectEqual(null, try chunks.next());
}

test "multiple chunks" {
    const chunk_bytes = [_]u8{
        // chunk 0
        0x11, 0x11, 0x11, 0x11,
        0x01, 0x02, 'h',  'i',
        0x00, 0x00, 0x00, 0x00,
        // chunk 1
        0x22, 0x22, 0x22, 0x22,
        0x01, 0x01, 'x',  0x00,
    };

    var chunks = ChunkIterator.init(&chunk_bytes);

    const c0 = (try chunks.next()).?;
    try testing.expectEqual(0x11111111, c0.ssrc);
    var it0 = c0.iterateItems();
    const item = (try it0.next()).?;
    try testing.expectEqual(.cname, item.item_type);
    try testing.expectEqualStrings("hi", item.value);

    const c1 = (try chunks.next()).?;
    try testing.expectEqual(0x22222222, c1.ssrc);
    var it1 = c1.iterateItems();
    try testing.expectEqualStrings("x", (try it1.next()).?.value);

    try testing.expectEqual(null, try chunks.next());
}

test "empty chunk (ssrc only, no items)" {
    const chunk_bytes = [_]u8{
        0xDE, 0xAD, 0xBE, 0xEF,
        0x00, 0x00, 0x00, 0x00,
    };

    var chunks = ChunkIterator.init(&chunk_bytes);
    const chunk = (try chunks.next()).?;
    try testing.expectEqual(0xDEADBEEF, chunk.ssrc);
    try testing.expectEqual(0, chunk.items.len);

    var items = chunk.iterateItems();
    try testing.expectEqual(null, try items.next());

    try testing.expectEqual(null, try chunks.next());
}

test "empty bytes yields no chunks" {
    var chunks = ChunkIterator.init(&.{});
    try testing.expectEqual(null, try chunks.next());
}

test "item with maximum length value does not overflow" {
    var chunk_bytes: [264]u8 = @splat(0);
    std.mem.writeInt(u32, chunk_bytes[0..4], 0x01020304, .big);
    chunk_bytes[4] = 1; // cname
    chunk_bytes[5] = 255; // length
    for (chunk_bytes[6 .. 6 + 255], 0..) |*b, i| b.* = @intCast('A' + (i % 26));

    var chunks = ChunkIterator.init(&chunk_bytes);
    const chunk = (try chunks.next()).?;

    var items = chunk.iterateItems();
    const item = (try items.next()).?;
    try testing.expectEqual(.cname, item.item_type);
    try testing.expectEqual(255, item.value.len);
    try testing.expectEqualSlices(u8, chunk_bytes[6 .. 6 + 255], item.value);
}

test "truncated chunk (no ssrc) is rejected" {
    const chunk_bytes = [_]u8{ 0x12, 0x34, 0x56 };
    var it = ChunkIterator.init(&chunk_bytes);
    try testing.expectError(error.InvalidChunk, it.next());
}

test "chunk with no terminator is rejected" {
    const chunk_bytes = [_]u8{
        0x12, 0x34, 0x56, 0x78,
        0x01, 0x02, 'a',  'b',
    };
    var chunks = ChunkIterator.init(&chunk_bytes);
    try testing.expectError(error.InvalidChunk, chunks.next());
}

test "item length running past the buffer is rejected" {
    const chunk_bytes = [_]u8{
        0xDE, 0xAD, 0xBE, 0xEF,
        // cname claims length 10, but the item list (bounded by the terminator)
        // only carries 2 value bytes
        0x01, 0x0A, 'x',  'y',
        0x00, 0x00, 0x00, 0x00,
    };
    var chunks = ChunkIterator.init(&chunk_bytes);
    const chunk = (try chunks.next()).?;
    var items = chunk.iterateItems();
    try testing.expectError(error.ParseError, items.next());
}
