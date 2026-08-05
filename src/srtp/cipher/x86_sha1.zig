const std = @import("std");
const mem = std.mem;
const simd = std.simd;

const Sha1 = @This();
const vec16 = @Vector(16, u8);
const vec4 = @Vector(4, u32);

pub const block_length = 64;
pub const digest_length = 20;
pub const Options = struct {};

s: [5]u32,
/// Streaming Cache
buf: [64]u8 = undefined,
buf_len: u8 = 0,
total_len: u64 = 0,

pub fn init(options: Options) Sha1 {
    _ = options;
    return .{
        .s = [_]u32{
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        },
    };
}

pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
    var d = Sha1.init(options);
    d.update(b);
    d.final(out);
}

pub fn update(d: *Sha1, b: []const u8) void {
    var off: usize = 0;

    // Partial buffer exists from previous update. Copy into buffer then hash.
    if (d.buf_len != 0 and d.buf_len + b.len >= 64) {
        off += 64 - d.buf_len;
        @memcpy(d.buf[d.buf_len..][0..off], b[0..off]);

        d.round(d.buf[0..]);
        d.buf_len = 0;
    }

    while (off + 64 <= b.len) : (off += 64) {
        d.round(b[off..][0..64]);
    }

    // Copy any remainder for next pass.
    @memcpy(d.buf[d.buf_len..][0 .. b.len - off], b[off..]);
    d.buf_len += @as(u8, @intCast(b[off..].len));

    d.total_len += b.len;
}

pub fn peek(d: Sha1) [digest_length]u8 {
    var copy = d;
    return copy.finalResult();
}

pub fn final(d: *Sha1, out: *[digest_length]u8) void {
    // The buffer here will never be completely full.
    @memset(d.buf[d.buf_len..], 0);

    // Append padding bits.
    d.buf[d.buf_len] = 0x80;
    d.buf_len += 1;

    // > 448 mod 512 so need to add an extra round to wrap around.
    if (64 - d.buf_len < 8) {
        d.round(d.buf[0..]);
        @memset(d.buf[0..], 0);
    }

    // Append message length.
    var i: usize = 1;
    var len = d.total_len >> 5;
    d.buf[63] = @as(u8, @intCast(d.total_len & 0x1f)) << 3;
    while (i < 8) : (i += 1) {
        d.buf[63 - i] = @as(u8, @intCast(len & 0xff));
        len >>= 8;
    }

    d.round(d.buf[0..]);

    for (d.s, 0..) |s, j| {
        mem.writeInt(u32, out[4 * j ..][0..4], s, .big);
    }
}

pub fn finalResult(d: *Sha1) [digest_length]u8 {
    var result: [digest_length]u8 = undefined;
    d.final(&result);
    return result;
}

fn round(d: *Sha1, data: *const [64]u8) void {
    var msg0: vec16 = simd.reverseOrder(data[0..16].*);
    var msg1: vec16 = simd.reverseOrder(data[16..32].*);
    var msg2: vec16 = simd.reverseOrder(data[32..48].*);
    var msg3: vec16 = simd.reverseOrder(data[48..64].*);

    var abcd: vec4 = simd.reverseOrder(d.s[0..4].*);
    var e0 = vec4{ 0, 0, 0, d.s[4] };
    var e1: vec4 = undefined;
    const e0_save: vec4 = e0;
    const abcd_save = abcd;

    // Rounds 0-3
    e0 +%= @bitCast(msg0);
    e1 = abcd;
    abcd = sha1rnds4(abcd, e0, 0);

    // Rounds 4-7
    e1 = sha1nexte(e1, msg1);
    e0 = abcd;
    abcd = sha1rnds4(abcd, e1, 0);
    msg0 = sha1msg1(msg0, msg1);

    // Rounds 8-11
    e0 = sha1nexte(e0, msg2);
    e1 = abcd;
    abcd = sha1rnds4(abcd, e0, 0);
    msg1 = sha1msg1(msg1, msg2);
    msg0 = msg0 ^ msg2;

    // Rounds 12-15
    e1 = sha1nexte(e1, msg3);
    e0 = abcd;
    msg0 = sha1msg2(msg0, msg3);
    abcd = sha1rnds4(abcd, e1, 0);
    msg2 = sha1msg1(msg2, msg3);
    msg1 = msg1 ^ msg3;

    // Rounds 16-19
    e0 = sha1nexte(e0, msg0);
    e1 = abcd;
    msg1 = sha1msg2(msg1, msg0);
    abcd = sha1rnds4(abcd, e0, 0);
    msg3 = sha1msg1(msg3, msg0);
    msg2 = msg2 ^ msg0;

    // Rounds 20-23
    e1 = sha1nexte(e1, msg1);
    e0 = abcd;
    msg2 = sha1msg2(msg2, msg1);
    abcd = sha1rnds4(abcd, e1, 1);
    msg0 = sha1msg1(msg0, msg1);
    msg3 = msg3 ^ msg1;

    // Rounds 24-27
    e0 = sha1nexte(e0, msg2);
    e1 = abcd;
    msg3 = sha1msg2(msg3, msg2);
    abcd = sha1rnds4(abcd, e0, 1);
    msg1 = sha1msg1(msg1, msg2);
    msg0 = msg0 ^ msg2;

    // Rounds 28-31
    e1 = sha1nexte(e1, msg3);
    e0 = abcd;
    msg0 = sha1msg2(msg0, msg3);
    abcd = sha1rnds4(abcd, e1, 1);
    msg2 = sha1msg1(msg2, msg3);
    msg1 = msg1 ^ msg3;

    // Rounds 32-35
    e0 = sha1nexte(e0, msg0);
    e1 = abcd;
    msg1 = sha1msg2(msg1, msg0);
    abcd = sha1rnds4(abcd, e0, 1);
    msg3 = sha1msg1(msg3, msg0);
    msg2 = msg2 ^ msg0;

    // Rounds 36-39
    e1 = sha1nexte(e1, msg1);
    e0 = abcd;
    msg2 = sha1msg2(msg2, msg1);
    abcd = sha1rnds4(abcd, e1, 1);
    msg0 = sha1msg1(msg0, msg1);
    msg3 = msg3 ^ msg1;

    // Rounds 40-43
    e0 = sha1nexte(e0, msg2);
    e1 = abcd;
    msg3 = sha1msg2(msg3, msg2);
    abcd = sha1rnds4(abcd, e0, 2);
    msg1 = sha1msg1(msg1, msg2);
    msg0 = msg0 ^ msg2;

    // Rounds 44-47
    e1 = sha1nexte(e1, msg3);
    e0 = abcd;
    msg0 = sha1msg2(msg0, msg3);
    abcd = sha1rnds4(abcd, e1, 2);
    msg2 = sha1msg1(msg2, msg3);
    msg1 = msg1 ^ msg3;

    // Rounds 48-51
    e0 = sha1nexte(e0, msg0);
    e1 = abcd;
    msg1 = sha1msg2(msg1, msg0);
    abcd = sha1rnds4(abcd, e0, 2);
    msg3 = sha1msg1(msg3, msg0);
    msg2 = msg2 ^ msg0;

    // Rounds 52-55
    e1 = sha1nexte(e1, msg1);
    e0 = abcd;
    msg2 = sha1msg2(msg2, msg1);
    abcd = sha1rnds4(abcd, e1, 2);
    msg0 = sha1msg1(msg0, msg1);
    msg3 = msg3 ^ msg1;

    // Rounds 56-59
    e0 = sha1nexte(e0, msg2);
    e1 = abcd;
    msg3 = sha1msg2(msg3, msg2);
    abcd = sha1rnds4(abcd, e0, 2);
    msg1 = sha1msg1(msg1, msg2);
    msg0 = msg0 ^ msg2;

    // Rounds 60-63
    e1 = sha1nexte(e1, msg3);
    e0 = abcd;
    msg0 = sha1msg2(msg0, msg3);
    abcd = sha1rnds4(abcd, e1, 3);
    msg2 = sha1msg1(msg2, msg3);
    msg1 = msg1 ^ msg3;

    // Rounds 64-67
    e0 = sha1nexte(e0, msg0);
    e1 = abcd;
    msg1 = sha1msg2(msg1, msg0);
    abcd = sha1rnds4(abcd, e0, 3);
    msg3 = sha1msg1(msg3, msg0);
    msg2 = msg2 ^ msg0;

    // Rounds 68-71
    e1 = sha1nexte(e1, msg1);
    e0 = abcd;
    msg2 = sha1msg2(msg2, msg1);
    abcd = sha1rnds4(abcd, e1, 3);
    msg3 = msg3 ^ msg1;

    // Rounds 72-75
    e0 = sha1nexte(e0, msg2);
    e1 = abcd;
    msg3 = sha1msg2(msg3, msg2);
    abcd = sha1rnds4(abcd, e0, 3);

    // Rounds 76-79
    e1 = sha1nexte(e1, msg3);
    e0 = abcd;
    abcd = sha1rnds4(abcd, e1, 3);

    e0 = sha1nexte(e0, @bitCast(e0_save));
    abcd +%= abcd_save;

    d.s[0..4].* = simd.reverseOrder(abcd);
    d.s[4] = e0[3];
}

fn sha1rnds4(arg0: vec4, arg1: vec4, comptime func: u8) vec4 {
    return asm volatile ("sha1rnds4 %[func], %[arg1], %[arg0]"
        : [_] "=x" (-> vec4),
        : [arg0] "0" (arg0),
          [arg1] "x" (arg1),
          [func] "i" (func),
    );
}

fn sha1nexte(arg0: vec4, arg1: vec16) vec4 {
    return asm volatile ("sha1nexte %[arg1], %[arg0]"
        : [_] "=x" (-> vec4),
        : [arg0] "0" (arg0),
          [arg1] "x" (arg1),
    );
}

fn sha1msg1(arg0: vec16, arg1: vec16) vec16 {
    return asm volatile ("sha1msg1 %[arg1], %[arg0]"
        : [_] "=x" (-> vec16),
        : [arg0] "0" (arg0),
          [arg1] "x" (arg1),
    );
}

fn sha1msg2(arg0: vec16, arg1: vec16) vec16 {
    return asm volatile ("sha1msg2 %[arg1], %[arg0]"
        : [_] "=x" (-> vec16),
        : [arg0] "0" (arg0),
          [arg1] "x" (arg1),
    );
}
