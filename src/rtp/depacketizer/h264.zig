const std = @import("std");
const h264 = @import("media").codecs.h264;
// const FrameInfo = @import("frame_info.zig");
const Depacketizer = @import("../depacketizer.zig");

const Self = @This();
const Writer = std.Io.Writer;

const annexb_start_code = @import("media").codecs.h264.annexb_start_code;
const fu_header_size: usize = 2;

pub const PacketType = enum { annexb, avc };

const FuHeader = packed struct {
    nal_type: h264.NalType,
    r: bool = false,
    e: bool,
    s: bool,
};

packet_type: PacketType = .annexb,
fu_offset: ?usize = null,

/// Initializes a new H264 depacketizer with the specified packet type.
pub fn init(packet_type: PacketType) Self {
    return .{ .packet_type = packet_type };
}

/// Depacketizes an H264 RTP packet to a writer.
pub fn depacketize(self: *Self, payload: []const u8, w: *Writer) Depacketizer.Error!?Depacketizer.FrameInfo {
    const rtp_nal_header: h264.NalHeader = @bitCast(payload[0]);
    switch (@intFromEnum(rtp_nal_header.nal_type)) {
        // Single NAL Unit Packet
        1...21 => {
            const slice = try w.writableSlice(annexb_start_code.len);
            self.writePrefix(slice, payload.len);
            try w.writeAll(payload);
            return .{ .keyframe = rtp_nal_header.nal_type == .idr };
        },
        // STAP-A Packet
        @intFromEnum(h264.NalType.stap_a) => {
            @branchHint(.unlikely);
            var keyframe = false;

            var reader = std.Io.Reader.fixed(payload[1..]);
            while (reader.bufferedLen() > 0) {
                const nal_header = self.writeNal(&reader, w) catch |err| switch (err) {
                    error.EndOfStream => return error.InvalidPacket,
                    error.WriteFailed => return error.WriteFailed,
                    else => unreachable,
                };
                keyframe = keyframe or nal_header.nal_type == .idr;
            }

            return .{ .keyframe = keyframe };
        },
        // FU-A Packet
        @intFromEnum(h264.NalType.fu_a) => {
            @branchHint(.likely);
            const fu_header: FuHeader = @bitCast(payload[1]);

            if (fu_header.s and self.fu_offset != null or !fu_header.s and self.fu_offset == null) {
                return error.InvalidPacket;
            }

            if (fu_header.s) {
                // write 5 empty bytes to reserve space for the prefix and NAL header
                self.fu_offset = w.end;
                try w.splatByteAll(0, annexb_start_code.len + 1);
            }
            try w.writeAll(payload[fu_header_size..]);

            if (fu_header.e) {
                const nal_size = w.end - self.fu_offset.? - annexb_start_code.len;
                const slice = w.buffered()[self.fu_offset.?..][0 .. annexb_start_code.len + 1];
                self.writePrefix(slice, nal_size);

                slice[annexb_start_code.len] = @bitCast(h264.NalHeader{
                    .ref_idc = rtp_nal_header.ref_idc,
                    .nal_type = fu_header.nal_type,
                });

                self.fu_offset = null;

                return .{ .keyframe = fu_header.nal_type == .idr };
            }

            return null;
        },
        else => return error.InvalidPacket,
    }
}

fn writeNal(self: *Self, r: *std.Io.Reader, w: *Writer) !h264.NalHeader {
    const nal_size = try r.takeInt(u16, .big);
    const nal_header = try r.peekByte();

    const slice = try w.writableSlice(4);
    self.writePrefix(slice, nal_size);
    try r.streamExact(w, nal_size);

    return h264.NalHeader.fromByte(nal_header);
}

fn writePrefix(self: *Self, slice: []u8, nal_size: usize) void {
    switch (self.packet_type) {
        .annexb => @memcpy(slice[0..annexb_start_code.len], &annexb_start_code),
        .avc => std.mem.writeInt(u32, slice[0..annexb_start_code.len], @intCast(nal_size), .big),
    }
}

test "H264 Depacketize: Single NAL Unit Packet" {
    var depacketizer: Self = .init(.annexb);

    const nal_unit: [5]u8 = [_]u8{ 0x65, 0x88, 0x84, 0x21, 0xA0 };
    const expected = [_]u8{ 0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21, 0xA0 };

    var writer_alloc = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer writer_alloc.deinit();

    const info = try depacketizer.depacketize(&nal_unit, &writer_alloc.writer);

    try std.testing.expect(info != null);
    try std.testing.expect(info.?.keyframe);
    try std.testing.expectEqualSlices(u8, &expected, writer_alloc.writer.buffered());
}

test "H264 Depacketize: Single NAL Unit Packet non-keyframe" {
    var depacketizer: Self = .init(.annexb);
    const nal_unit: [5]u8 = [_]u8{ 0x41, 0x9A, 0x22, 0x00, 0x00 }; // NAL type 1 = non-IDR

    var writer_alloc = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer writer_alloc.deinit();

    const info = try depacketizer.depacketize(&nal_unit, &writer_alloc.writer);

    try std.testing.expect(info != null);
    try std.testing.expect(!info.?.keyframe);
}

test "H264 Depacketize: StapA" {
    var depacketizer: Self = .init(.annexb);

    const stap_a_packet: [13]u8 = [_]u8{
        24, // STAP-A NAL unit type
        0x00, 0x05, // NALU 1 size
        0x65, 0x88, 0x84, 0x21, 0xA0, // NALU 1 (IDR frame)
        0x00, 0x03, // NALU 2 size
        0x41, 0x9A, 0x22, // NALU 2 (non-IDR frame)
    };

    const expected = &[_]u8{
        0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21, 0xA0,
        0x00, 0x00, 0x00, 0x01, 0x41, 0x9A, 0x22,
    };

    var writer_alloc = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer writer_alloc.deinit();

    // Alloc
    const info = try depacketizer.depacketize(&stap_a_packet, &writer_alloc.writer);

    try std.testing.expect(info != null);
    try std.testing.expect(info.?.keyframe); // contains IDR NALU (0x65)
    try std.testing.expectEqualSlices(u8, expected, writer_alloc.writer.buffered());
}

test "H264 Depacketize: StapA non-keyframe" {
    var depacketizer: Self = .init(.annexb);

    const stap_a_packet: [9]u8 = [_]u8{
        24, // STAP-A NAL unit type
        0x00, 0x03, // NALU 1 size
        0x41, 0x9A, 0x22, // NALU 1 (non-IDR, type 1)
        0x00, 0x01, // NALU 2 size
        0x68, // NALU 2 (PPS, type 8)
    };

    var writer_alloc = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer writer_alloc.deinit();

    const info = try depacketizer.depacketize(&stap_a_packet, &writer_alloc.writer);

    try std.testing.expect(info != null);
    try std.testing.expect(!info.?.keyframe);
}

test "H264 Depacketize: Invalid StapA packet" {
    var depacketizer: Self = .init(.annexb);

    var writer_alloc = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer writer_alloc.deinit();

    const invalid_stap_a_packet: [12]u8 = [_]u8{
        24, // STAP-A NAL unit type
        0x00, 0x05, // NALU size (5 bytes)
        0x65, 0x88, 0x84, 0x21, 0xA0, // NALU 1 (IDR frame)
        0x00, 0x03, // NALU 2 size
        0x41, 0x9A, // Wrong size
    };

    const written = depacketizer.depacketize(&invalid_stap_a_packet, &writer_alloc.writer);
    try std.testing.expectError(error.InvalidPacket, written);
}

test "H264 Depacketize: FU-A" {
    const fua_start = [_]u8{ 0x7C, 0x85 } ++ [_]u8{0xAB} ** 160;
    const fua_middle = [_]u8{ 0x7C, 0x05 } ++ [_]u8{0xCD} ** 160;
    const fua_end = [_]u8{ 0x7C, 0x45 } ++ [_]u8{0xEF} ** 160;

    var depacketizer: Self = .init(.annexb);

    var writer_alloc = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer writer_alloc.deinit();

    var frame_info = try depacketizer.depacketize(&fua_start, &writer_alloc.writer);
    try std.testing.expectEqual(null, frame_info);

    frame_info = try depacketizer.depacketize(&fua_middle, &writer_alloc.writer);
    try std.testing.expectEqual(null, frame_info);

    frame_info = try depacketizer.depacketize(&fua_end, &writer_alloc.writer);
    try std.testing.expect(frame_info != null);
    try std.testing.expectEqual(485, writer_alloc.writer.buffered().len);
}
