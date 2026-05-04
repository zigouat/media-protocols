const std = @import("std");
const media = @import("media");
const Packet = @import("../rtp.zig").Packet;
const Packetizer = @This();

const max_payload_size: usize = 1460;
const max_timestamp: u64 = std.math.maxInt(u32) + 1;

pub const InitConfig = struct {
    payload_type: u7,
    ssrc: ?u32 = null,
    seq_number: ?u16 = null,
};

const FuState = struct {
    nalu: []const u8,
    first_byte: u8,
    nal_type: u8,
    first_fragment: bool = true,

    fn init(nalu: []const u8) FuState {
        return .{
            .nalu = nalu[1..],
            .first_byte = (nalu[0] & 0xE0) | 0x1C,
            .nal_type = nalu[0] & 0x1F,
        };
    }

    /// Gets the next fragment from the NALu.
    fn next(state: *FuState, buffer: []u8) []const u8 {
        const offset: usize = @min(max_payload_size - 2, state.nalu.len);
        const last_fragment = offset == state.nalu.len;

        @memcpy(buffer[2 .. offset + 2], state.nalu[0..offset]);

        buffer[0] = state.first_byte;
        buffer[1] = (@as(u8, @intFromBool(state.first_fragment)) << 7) | (@as(u8, @intFromBool(last_fragment)) << 6) | state.nal_type;

        state.nalu = state.nalu[offset..];
        state.first_fragment = false;
        return buffer[0 .. offset + 2];
    }

    fn empty(state: *const FuState) bool {
        return state.nalu.len == 0;
    }
};

buffer: [max_payload_size]u8 = @splat(0),
ssrc: u32,
payload_type: u7,
seq_number: u16,
packet: ?*const media.Packet = null,
fu_state: ?FuState = null,
// current pos in the access unit buffer
pos: usize = 0,

pub fn init(io: std.Io, config: InitConfig) Packetizer {
    const timestamp: u64 = @bitCast(std.Io.Clock.now(.awake, io).toMilliseconds());
    var rand = std.Random.DefaultPrng.init(timestamp);
    var r = rand.random();
    return .{
        .payload_type = config.payload_type,
        .seq_number = config.seq_number orelse r.uintAtMost(u16, std.math.maxInt(u16)),
        .ssrc = config.ssrc orelse r.uintAtMost(u32, std.math.maxInt(u32)),
    };
}

pub fn consume(packetizer: *Packetizer, packet: *const media.Packet) void {
    packetizer.packet = packet;
    packetizer.pos = 0;
    packetizer.fu_state = null;
}

pub fn next(packetizer: *Packetizer) !?Packet {
    if (packetizer.packet) |packet| {
        @branchHint(.likely);
        errdefer packetizer.pos = 0;
        const timestamp: u32 = @intCast(@rem(packet.pts, max_timestamp));

        if (packetizer.fu_state) |*fu_state| {
            const buffer = fu_state.next(&packetizer.buffer);

            var marker = false;
            if (fu_state.empty()) {
                packetizer.fu_state = null;
                marker = packetizer.pos == packet.data.len;
                if (marker) packetizer.clearPacket();
            }

            return packetizer.newRtpPacket(marker, timestamp, buffer);
        }

        var reader: std.Io.Reader = .fixed(packet.data[packetizer.pos..]);
        const nalu_size = try reader.takeInt(u32, .big);
        const nalu = try reader.take(nalu_size);
        defer packetizer.pos += nalu_size + 4;

        if (nalu_size > max_payload_size) {
            // FU unit
            packetizer.fu_state = .init(nalu);
            const buffer = packetizer.fu_state.?.next(&packetizer.buffer);
            return packetizer.newRtpPacket(false, timestamp, buffer);
        }

        // Single nalu
        const marker = reader.seek == reader.end;
        if (marker) packetizer.clearPacket();
        return packetizer.newRtpPacket(marker, timestamp, nalu);
    }

    return null;
}

fn newRtpPacket(packetizer: *Packetizer, marker: bool, timestamp: u32, payload: []const u8) Packet {
    const seq_num = packetizer.seq_number;
    packetizer.seq_number +%= 1;

    return Packet{
        .header = .{
            .extension = false,
            .marker = marker,
            .padding = false,
            .payload_type = packetizer.payload_type,
            .sequence_number = seq_num,
            .ssrc = packetizer.ssrc,
            .timestamp = timestamp,
        },
        .payload = payload,
    };
}

fn clearPacket(packetizer: *Packetizer) void {
    packetizer.packet = null;
    packetizer.pos = 0;
}

test "h264 packetizer: single nalu" {
    var packetizer: Packetizer = .init(std.testing.io, .{
        .payload_type = 96,
        .ssrc = 0xDEADBEEF,
        .seq_number = 1000,
    });

    const nalu1 = [_]u8{ 0x67, 0x42, 0xC0, 0x1E };
    const nalu2 = [_]u8{ 0x65, 0x88, 0x84, 0x21, 0xA0 };
    const avc_data = [_]u8{ 0x00, 0x00, 0x00, nalu1.len } ++ nalu1 ++
        [_]u8{ 0x00, 0x00, 0x00, nalu2.len } ++ nalu2;

    var media_packet: media.Packet = .fromSlice(&avc_data);
    media_packet.pts = 90000;

    packetizer.consume(&media_packet);

    const first = try packetizer.next() orelse return error.TestUnexpectedNull;
    try std.testing.expectEqual(96, first.header.payload_type);
    try std.testing.expectEqual(0xDEADBEEF, first.header.ssrc);
    try std.testing.expectEqual(1000, first.header.sequence_number);
    try std.testing.expectEqual(90000, first.header.timestamp);
    try std.testing.expect(!first.header.marker);
    try std.testing.expectEqualSlices(u8, &nalu1, first.payload);

    const second = try packetizer.next() orelse return error.TestUnexpectedNull;
    try std.testing.expectEqual(96, second.header.payload_type);
    try std.testing.expectEqual(0xDEADBEEF, second.header.ssrc);
    try std.testing.expectEqual(1001, second.header.sequence_number);
    try std.testing.expectEqual(90000, second.header.timestamp);
    try std.testing.expect(second.header.marker);
    try std.testing.expectEqualSlices(u8, &nalu2, second.payload);

    try std.testing.expectEqual(1002, packetizer.seq_number);

    try std.testing.expectEqual(null, try packetizer.next());
}

test "h264 packetizer: fu-a fragmentation" {
    var packetizer: Packetizer = .init(std.testing.io, .{
        .payload_type = 96,
        .ssrc = 0xCAFEBABE,
        .seq_number = 2000,
    });

    // Header byte 0x65: F=0, NRI=3, Type=5 (IDR slice).
    const nalu_size: usize = 3000;
    var avc_data: [4 + nalu_size]u8 = undefined;
    std.mem.writeInt(u32, avc_data[0..4], @intCast(nalu_size), .big);
    avc_data[4] = 0x65;
    for (avc_data[5..], 0..) |*b, i| b.* = @intCast(i & 0xFF);

    var media_packet: media.Packet = .fromSlice(&avc_data);
    media_packet.pts = 180_000;
    packetizer.consume(&media_packet);

    var packet = try packetizer.next() orelse unreachable;
    try std.testing.expectEqual(2000, packet.header.sequence_number);
    try std.testing.expectEqual(180_000, packet.header.timestamp);
    try std.testing.expect(!packet.header.marker);
    try std.testing.expectEqual(max_payload_size, packet.payload.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x7c, 0x85 }, packet.payload[0..2]);
    var idx: u8 = 0;
    for (packet.payload[2..]) |*b| {
        try std.testing.expectEqual(idx, b.*);
        idx +%= 1;
    }

    packet = try packetizer.next() orelse unreachable;
    try std.testing.expectEqual(2001, packet.header.sequence_number);
    try std.testing.expectEqual(180_000, packet.header.timestamp);
    try std.testing.expect(!packet.header.marker);
    try std.testing.expectEqual(max_payload_size, packet.payload.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x7c, 0x05 }, packet.payload[0..2]);
    for (packet.payload[2..]) |*b| {
        try std.testing.expectEqual(idx, b.*);
        idx +%= 1;
    }

    packet = try packetizer.next() orelse unreachable;
    try std.testing.expectEqual(2002, packet.header.sequence_number);
    try std.testing.expectEqual(180_000, packet.header.timestamp);
    try std.testing.expect(packet.header.marker);
    try std.testing.expectEqual(85, packet.payload.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x7c, 0x45 }, packet.payload[0..2]);
    for (packet.payload[2..]) |*b| {
        try std.testing.expectEqual(idx, b.*);
        idx +%= 1;
    }

    try std.testing.expectEqual(null, try packetizer.next());
}
