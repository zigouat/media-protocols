const std = @import("std");

/// Sliding window replay detector, `size` is the window size in seqs and must be a multiple of the word size.
pub fn ReplayDetector(comptime size: u16) type {
    return struct {
        const Self = @This();
        const BitSet = std.bit_set.ArrayBitSet(usize, window_size);
        const MaskInt = BitSet.MaskInt;
        const word_bits = @bitSizeOf(MaskInt);

        pub const window_size = size;

        comptime {
            if (window_size == 0 or window_size % word_bits != 0) @compileError("window size must be a non zero multiple of the word size");
        }

        pub const Error = error{ Replayed, TooOld };

        /// Highest seq accepted.
        last_seq: u64,
        /// Every seq below this is either acked or too old.
        /// Only bits in (cumulative, last_seq] may be set.
        cumulative: u64,
        acked: BitSet,

        const WordIterator = struct {
            next_seq: u64,
            remaining: u64,

            fn init(start_seq: u64, end_seq: u64) WordIterator {
                std.debug.assert(start_seq <= end_seq and end_seq - start_seq < window_size);
                return .{ .next_seq = start_seq, .remaining = end_seq - start_seq + 1 };
            }

            /// Returns the word index, the bits of the word inside the range and the seq of the word's bit 0.
            fn next(self: *WordIterator) ?struct { usize, MaskInt, u64 } {
                if (self.remaining == 0) return null;

                const index = bitIndex(self.next_seq);
                const bit = index % word_bits;
                const len: usize = @intCast(@min(word_bits - bit, self.remaining));
                const ones = if (len == word_bits) ~@as(MaskInt, 0) else (@as(MaskInt, 1) << @intCast(len)) - 1;
                const base_seq = self.next_seq - bit;
                self.next_seq += len;
                self.remaining -= len;
                return .{ index / word_bits, ones << @intCast(bit), base_seq };
            }
        };

        pub fn init() Self {
            return .{
                .last_seq = 0,
                .cumulative = 0,
                .acked = .empty,
            };
        }

        pub fn check(replay_detector: *const Self, seq: u64) Error!void {
            if (seq > replay_detector.last_seq) return;
            if (replay_detector.last_seq - seq >= window_size) return error.TooOld;
            if (seq < replay_detector.cumulative or replay_detector.isBitSet(seq)) return error.Replayed;
        }

        pub fn accept(replay_detector: *Self, seq: u64) void {
            const cumulative = replay_detector.cumulative;
            if (seq < cumulative) return;

            if (seq == cumulative) {
                if (seq >= replay_detector.last_seq) {
                    // In order with nothing pending.
                    replay_detector.last_seq = seq;
                    replay_detector.cumulative = seq + 1;
                } else {
                    replay_detector.advanceCumulative(seq + 1);
                }
                return;
            }

            if (seq > replay_detector.last_seq) {
                replay_detector.last_seq = seq;
                // Slide the window, the new cumulative may land on an acked seq.
                if (seq - cumulative >= window_size) {
                    const lower = seq - window_size + 1;
                    replay_detector.setRange(cumulative, lower - 1, false);
                    replay_detector.acked.set(bitIndex(seq));
                    replay_detector.cumulative = lower;
                    if (replay_detector.isBitSet(lower)) replay_detector.advanceCumulative(lower);
                    return;
                }
            }

            replay_detector.acked.set(bitIndex(seq));
        }

        /// Moves the cumulative to the first unacked seq from `start_seq`, clearing the bits it passes.
        fn advanceCumulative(replay_detector: *Self, start_seq: u64) void {
            const first = replay_detector.firstUnacked(start_seq, replay_detector.last_seq) orelse replay_detector.last_seq + 1;
            if (first > start_seq) replay_detector.setRange(start_seq, first - 1, false);
            replay_detector.cumulative = first;
        }

        fn isRangeAcked(replay_detector: *const Self, start_seq: u64, end_seq: u64) bool {
            return replay_detector.firstUnacked(start_seq, end_seq) == null;
        }

        /// The lowest unset bit in an inclusive seq range.
        fn firstUnacked(replay_detector: *const Self, start_seq: u64, end_seq: u64) ?u64 {
            var it = WordIterator.init(start_seq, end_seq);
            while (it.next()) |word| {
                const index, const mask, const base_seq = word;
                const bits = ~replay_detector.acked.masks[index] & mask;
                if (bits != 0) return base_seq + @ctz(bits);
            }
            return null;
        }

        /// Sets the bits of an inclusive seq range, a range wider than the window sets all of them.
        fn setRange(replay_detector: *Self, start_seq: u64, end_seq: u64, value: bool) void {
            if (end_seq - start_seq >= window_size) {
                replay_detector.acked = if (value) .full else .empty;
                return;
            }

            var it = WordIterator.init(start_seq, end_seq);
            while (it.next()) |word| {
                const index, const mask, _ = word;
                if (value) replay_detector.acked.masks[index] |= mask else replay_detector.acked.masks[index] &= ~mask;
            }
        }

        inline fn bitIndex(seq: u64) usize {
            return @intCast(seq % window_size);
        }

        inline fn isBitSet(replay_detector: *const Self, seq: u64) bool {
            const index = bitIndex(seq);
            const mask = replay_detector.acked.masks[index / word_bits];
            return (mask >> @as(BitSet.ShiftInt, @truncate(index))) & 1 != 0;
        }
    };
}

test "accept" {
    var replay_detector = ReplayDetector(256).init();

    for (1..100) |idx| replay_detector.accept(idx);
    try std.testing.expectError(error.Replayed, replay_detector.check(94));
    try replay_detector.check(0);

    replay_detector.accept(0);
    try std.testing.expectEqual(100, replay_detector.cumulative);
    try std.testing.expectError(error.Replayed, replay_detector.check(0));

    replay_detector.accept(0xFF99);
    try std.testing.expectError(error.TooOld, replay_detector.check(101));

    for (0xFFA0..0xFFFF) |seq| replay_detector.accept(seq);
    try replay_detector.check(0x0AFFF06765780000);
    replay_detector.accept(0x0AFFF06765780000);
    try std.testing.expectError(error.Replayed, replay_detector.check(0x0AFFF06765780000));

    // Other window sizes.
    var small = ReplayDetector(64).init();
    small.accept(100);
    try std.testing.expectError(error.TooOld, small.check(36));
    try small.check(37);

    var large = ReplayDetector(1024).init();
    large.accept(2000);
    try std.testing.expectError(error.TooOld, large.check(976));
    try large.check(977);
}

test "gap and window slide" {
    var replay_detector = ReplayDetector(256).init();

    for (0..301) |seq| if (seq != 50) replay_detector.accept(seq);
    try std.testing.expectEqual(50, replay_detector.cumulative);
    try replay_detector.check(50);
    try std.testing.expect(replay_detector.isRangeAcked(51, 300));
    try std.testing.expect(!replay_detector.isRangeAcked(50, 300));

    replay_detector.accept(305);
    try replay_detector.check(50);
    try replay_detector.check(301);

    // 50 slides out, its slot is reused by 306, the cumulative skips to the 301 gap.
    replay_detector.accept(306);
    try std.testing.expectEqual(301, replay_detector.cumulative);
    try std.testing.expectError(error.TooOld, replay_detector.check(50));
    try std.testing.expectError(error.Replayed, replay_detector.check(51));
    try std.testing.expectError(error.Replayed, replay_detector.check(306));
    try replay_detector.check(301);

    for (301..305) |seq| replay_detector.accept(seq);
    try std.testing.expectEqual(307, replay_detector.cumulative);
    try std.testing.expectError(error.Replayed, replay_detector.check(300));
    try replay_detector.check(307);

    // Slide over several words.
    replay_detector.accept(400);
    replay_detector.accept(600);
    try std.testing.expectEqual(345, replay_detector.cumulative);
    try std.testing.expectError(error.TooOld, replay_detector.check(344));
    try std.testing.expectError(error.Replayed, replay_detector.check(400));
    try replay_detector.check(345);

    for (345..600) |seq| replay_detector.accept(seq);
    try std.testing.expectEqual(601, replay_detector.cumulative);
}
