//! Key derivation function
//!
//! Given a master key and salt, generate the following keys:
//! * RTP encryption key
//! * RTP Auth key
//! * RTP Salt
//! * RTCP encryption key
//! * RTCP Auth key
//! * RTCP Salt

const std = @import("std");

const aes = std.crypto.core.aes;
const ctr = std.crypto.core.modes.ctr;

pub const Labels = struct {
    pub const RTP_ENC_KEY_LABEL: u8 = 0;
    pub const RTP_AUTH_LABEL: u8 = 1;
    pub const RTP_SALT_LABEL: u8 = 2;

    pub const RTCP_ENC_KEY_LABEL: u8 = 3;
    pub const RTCP_AUTH_LABEL: u8 = 4;
    pub const RTCP_SALT_LABEL: u8 = 5;
};

const IV_LENGTH = 16;

pub fn Kdf(comptime Aes: type) type {
    return struct {
        pub const block_length = Aes.block.block_length;
        ctx: std.crypto.core.aes.AesEncryptCtx(Aes),

        pub fn init(master_key: [block_length]u8) @This() {
            return .{ .ctx = Aes.initEnc(master_key) };
        }

        pub fn derive(kdf: *const @This(), label: u8, master_salt: []const u8, comptime out_size: usize, out: *[out_size]u8) void {
            var iv: [IV_LENGTH]u8 = @splat(0);
            @memcpy(iv[0..master_salt.len], master_salt);
            iv[7] ^= label;

            const input: [out_size]u8 = @splat(0);
            ctr(@TypeOf(kdf.ctx), kdf.ctx, out, &input, iv, .big);
        }
    };
}

test "Aes128: key derivation" {
    const master = [_]u8{
        0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0,
        0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39,
    };

    const salt = [_]u8{
        0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE,
        0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6,
    };

    const Aes128Kdf = Kdf(aes.Aes128);

    const assertDerivedKey = struct {
        pub fn assertDerivedKey(kdf: *const Aes128Kdf, T: type, comptime expected_value: T, label: u8) !void {
            const bytes = @typeInfo(T).int.bits / 8;
            var expected: [bytes]u8 = @splat(0);
            std.mem.writeInt(T, &expected, expected_value, .big);

            var out: [bytes]u8 = @splat(0);
            kdf.derive(label, &salt, bytes, &out);

            try std.testing.expectEqualSlices(u8, &expected, &out);
        }
    }.assertDerivedKey;

    const aes128_kdf = Aes128Kdf.init(master);

    const expected_rtp_enc_key: u128 = 0xC61E7A93744F39EE10734AFE3FF7A087;
    const expected_rtp_auth_key: u128 = 0xCEBE321F6FF7716B6FD4AB49AF256A15;
    const expected_rtp_salt: u112 = 0x30CBBC08863D8C85D49DB34A9AE1;

    try assertDerivedKey(&aes128_kdf, u128, expected_rtp_enc_key, Labels.RTP_ENC_KEY_LABEL);
    try assertDerivedKey(&aes128_kdf, u128, expected_rtp_auth_key, Labels.RTP_AUTH_LABEL);
    try assertDerivedKey(&aes128_kdf, u112, expected_rtp_salt, Labels.RTP_SALT_LABEL);
}
