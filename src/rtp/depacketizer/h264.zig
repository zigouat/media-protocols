const std = @import("std");
const h264 = @import("media").codecs.h264;
const FrameInfo = @import("frame_info.zig");

const Self = @This();
const Writer = std.Io.Writer;

const annexb_start_code = @import("media").codecs.h264.annexb_start_code;
const fu_header_size: usize = 2;

pub const PacketType = enum { annexb, avc };

pub const Error = error{ ShortBuffer, UnsupportedNalType, InvalidFUAPacket, InvalidStapAPacket, UnsupportedPacketType };

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

/// Depacketizes an H264 RTP packet and writes it to the destination buffer.
///
/// Returns the number of bytes written in case the whole NAL units is written, null if more packets needed
/// or an error if the packet is invalid or the buffer is too small.
pub fn depacketize(self: *Self, payload: []const u8, dest: []u8) !?FrameInfo {
    const rtp_nal_header: h264.NalHeader = @bitCast(payload[0]);
    switch (@intFromEnum(rtp_nal_header.nal_type)) {
        // Single NAL Unit Packet
        1...21 => {
            if (dest.len < payload.len + annexb_start_code.len) {
                return Error.ShortBuffer;
            }
            self.writePrefix(dest, payload.len);
            @memcpy(dest[annexb_start_code.len .. annexb_start_code.len + payload.len], payload);
            return .{ .written = payload.len + annexb_start_code.len, .keyframe = rtp_nal_header.nal_type == .idr };
        },
        // STAP-A Packet
        @intFromEnum(h264.NalType.stap_a) => {
            @branchHint(.unlikely);
            var keyframe = false;

            var reader = std.Io.Reader.fixed(payload[1..]);
            var writer = std.Io.Writer.fixed(dest);
            while (true) {
                const nal_header = self.writeNal(&reader, &writer) catch |err| switch (err) {
                    error.WriteFailed => return error.ShortBuffer,
                    error.EndOfStream => if (reader.bufferedLen() == 0) break else return error.InvalidStapAPacket,
                    else => unreachable,
                };
                keyframe = keyframe or nal_header.nal_type == .idr;
            }

            return .{ .written = writer.buffered().len, .keyframe = keyframe };
        },
        // FU-A Packet
        @intFromEnum(h264.NalType.fu_a) => {
            @branchHint(.likely);
            const fu_header: FuHeader = @bitCast(payload[1]);

            if (fu_header.s and self.fu_offset != null or !fu_header.s and self.fu_offset == null) {
                return error.InvalidFUAPacket;
            }

            const expected_size = blk: {
                const size = payload.len - fu_header_size;
                if (fu_header.s) {
                    self.fu_offset = annexb_start_code.len + 1;
                    break :blk size + annexb_start_code.len + 1;
                }
                break :blk size;
            };

            const write_pos = self.fu_offset.?;
            if (dest.len < write_pos + expected_size) {
                return error.ShortBuffer;
            }

            @memcpy(dest[write_pos .. write_pos + payload.len - fu_header_size], payload[fu_header_size..]);
            self.fu_offset = write_pos + payload.len - fu_header_size;

            if (fu_header.e) {
                defer self.fu_offset = null;

                self.writePrefix(dest[0..], self.fu_offset.? - annexb_start_code.len);
                dest[annexb_start_code.len] = @bitCast(h264.NalHeader{
                    .ref_idc = rtp_nal_header.ref_idc,
                    .nal_type = fu_header.nal_type,
                });

                return .{ .written = self.fu_offset.?, .keyframe = fu_header.nal_type == .idr };
            }

            return null;
        },
        else => return error.UnsupportedNalType,
    }
}

fn writeNal(self: *Self, r: *std.Io.Reader, w: *std.Io.Writer) !h264.NalHeader {
    const nal_size = try r.takeInt(u16, .big);
    const slice = try w.writableSlice(4);
    self.writePrefix(slice, nal_size);
    const nal = try r.take(nal_size);
    try w.writeAll(nal);

    return h264.NalHeader.fromByte(nal[0]);
}

fn writePrefix(self: *Self, slice: []u8, nal_size: usize) void {
    switch (self.packet_type) {
        .annexb => @memcpy(slice[0..annexb_start_code.len], &annexb_start_code),
        .avc => std.mem.writeInt(u32, slice[0..annexb_start_code.len], @intCast(nal_size), .big),
    }
}

test "Depacketize Single NAL Unit Packet" {
    var depacketizer: Self = .init(.annexb);

    const nal_unit: [5]u8 = [_]u8{ 0x65, 0x88, 0x84, 0x21, 0xA0 };
    const expected = [_]u8{ 0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21, 0xA0 };
    var buffer: [1024]u8 = undefined;

    const written = try depacketizer.depacketize(&nal_unit, &buffer);

    try std.testing.expect(written != null);
    try std.testing.expectEqual(expected.len, written.?.written);
    try std.testing.expect(written.?.keyframe); // 0x65 = IDR NAL type 5
    try std.testing.expectEqualSlices(u8, &expected, buffer[0..written.?.written]);
}

test "Depacketize Single NAL Unit Packet non-keyframe" {
    var depacketizer: Self = .init(.annexb);

    const nal_unit: [5]u8 = [_]u8{ 0x41, 0x9A, 0x22, 0x00, 0x00 }; // NAL type 1 = non-IDR
    var buffer: [1024]u8 = undefined;

    const written = try depacketizer.depacketize(&nal_unit, &buffer);

    try std.testing.expect(written != null);
    try std.testing.expect(!written.?.keyframe);
}

test "Depacketize StapA" {
    var buffer: [1024]u8 = undefined;
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

    // Alloc
    const written = try depacketizer.depacketize(&stap_a_packet, &buffer);

    try std.testing.expect(written != null);
    try std.testing.expectEqual(expected.len, written.?.written);
    try std.testing.expect(written.?.keyframe); // contains IDR NALU (0x65)
    try std.testing.expectEqualSlices(u8, expected, buffer[0..written.?.written]);
}

test "Depacketize StapA non-keyframe" {
    var buffer: [1024]u8 = undefined;
    var depacketizer: Self = .init(.annexb);

    const stap_a_packet: [9]u8 = [_]u8{
        24, // STAP-A NAL unit type
        0x00, 0x03, // NALU 1 size
        0x41, 0x9A, 0x22, // NALU 1 (non-IDR, type 1)
        0x00, 0x01, // NALU 2 size
        0x68, // NALU 2 (PPS, type 8)
    };

    const written = try depacketizer.depacketize(&stap_a_packet, &buffer);

    try std.testing.expect(written != null);
    try std.testing.expect(!written.?.keyframe);
}

test "Invalid StapA packet" {
    var buffer: [1024]u8 = undefined;
    var depacketizer: Self = .init(.annexb);

    const invalid_stap_a_packet: [12]u8 = [_]u8{
        24, // STAP-A NAL unit type
        0x00, 0x05, // NALU size (5 bytes)
        0x65, 0x88, 0x84, 0x21, 0xA0, // NALU 1 (IDR frame)
        0x00, 0x03, // NALU 2 size
        0x41, 0x9A, // Wrong size
    };

    const written = depacketizer.depacketize(&invalid_stap_a_packet, &buffer);
    try std.testing.expectError(Error.InvalidStapAPacket, written);
}

test "Depacketize FU-A" {
    const fua_start = [_]u8{ 0x7C, 0x85 } ++ [_]u8{0xAB} ** 160;
    const fua_middle = [_]u8{ 0x7C, 0x05 } ++ [_]u8{0xCD} ** 160;
    const fua_end = [_]u8{ 0x7C, 0x45 } ++ [_]u8{0xEF} ** 160;

    var buffer: [1024]u8 = undefined;
    var depacketizer: Self = .init(.annexb);

    var frame_info = try depacketizer.depacketize(&fua_start, &buffer);
    try std.testing.expectEqual(null, frame_info);

    frame_info = try depacketizer.depacketize(&fua_middle, &buffer);
    try std.testing.expectEqual(null, frame_info);

    frame_info = try depacketizer.depacketize(&fua_end, &buffer);
    try std.testing.expect(frame_info != null);

    try std.testing.expectEqual(485, frame_info.?.written);
}
