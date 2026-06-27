pub const H264 = @import("packetizer/h264.zig");
pub const VP8 = @import("packetizer/vp8.zig");

const std = @import("std");
const Packet = @import("packet.zig");

const max_timestamp: u64 = std.math.maxInt(u32) + 1;

pub const RtpConfig = struct {
    payload_type: u7,
    ssrc: u32,
    seq_number: u16,

    /// Initializes a new RtpConfig with random ssrc and seq_number values.
    pub fn init(io: std.Io) RtpConfig {
        const timestamp: u64 = @bitCast(std.Io.Clock.now(.awake, io).toMilliseconds());
        var rand = std.Random.DefaultPrng.init(timestamp);
        var r = rand.random();
        return .{
            .payload_type = 0,
            .seq_number = r.uintAtMost(u16, std.math.maxInt(u16)),
            .ssrc = r.uintAtMost(u32, std.math.maxInt(u32)),
        };
    }

    pub fn newRtpPacket(config: *RtpConfig, marker: bool, timestamp: i64, payload: []const u8) Packet {
        config.seq_number +%= 1;

        return Packet{
            .header = .{
                .extension = false,
                .marker = marker,
                .padding = false,
                .payload_type = config.payload_type,
                .sequence_number = config.seq_number,
                .ssrc = config.ssrc,
                .timestamp = @truncate(@as(u64, @bitCast(timestamp))),
            },
            .payload = payload,
        };
    }
};

test {
    _ = @import("packetizer/h264.zig");
}
