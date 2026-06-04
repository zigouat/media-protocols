//! Implementation of the profiles:
//! * AES 128 CM HMAC SHA1 80
//! * AES 128 CM HMAC SHA1 32

const std = @import("std");
const srtp = @import("../srtp.zig");
const kdf = @import("../kdf.zig");

const AesCm = @This();
const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const aes = std.crypto.core.aes;
const ctr = std.crypto.core.modes.ctr;

const enc_key_size = 16;
const auth_key_size = 20;
const salt_size = 14;

const rtcp_index_size = 4;

pub const Error = error{AuthenticationFailed};

profile: srtp.Profile,
rtp_enc_ctx: aes.AesEncryptCtx(aes.Aes128),
rtp_auth_key: [auth_key_size]u8,
rtp_salt: [salt_size]u8,
rtcp_enc_ctx: aes.AesEncryptCtx(aes.Aes128),
rtcp_auth_key: [auth_key_size]u8,
rtcp_salt: [salt_size]u8,

pub fn init(profile: srtp.Profile, master_key: []const u8, master_salt: []const u8) AesCm {
    var cipher: AesCm = undefined;
    var aes128_kdf = kdf.Kdf(aes.Aes128).init(master_key[0..enc_key_size].*);

    cipher.profile = profile;

    var rtp_enc_key: [enc_key_size]u8 = undefined;
    aes128_kdf.derive(kdf.Labels.RTP_ENC_KEY_LABEL, master_salt, enc_key_size, &rtp_enc_key);
    cipher.rtp_enc_ctx = .init(rtp_enc_key);

    aes128_kdf.derive(kdf.Labels.RTP_AUTH_LABEL, master_salt, auth_key_size, &cipher.rtp_auth_key);
    aes128_kdf.derive(kdf.Labels.RTP_SALT_LABEL, master_salt, salt_size, &cipher.rtp_salt);

    var rtcp_enc_key: [enc_key_size]u8 = undefined;
    aes128_kdf.derive(kdf.Labels.RTCP_ENC_KEY_LABEL, master_salt, enc_key_size, &rtcp_enc_key);
    cipher.rtcp_enc_ctx = .init(rtcp_enc_key);

    aes128_kdf.derive(kdf.Labels.RTCP_AUTH_LABEL, master_salt, auth_key_size, &cipher.rtcp_auth_key);
    aes128_kdf.derive(kdf.Labels.RTCP_SALT_LABEL, master_salt, salt_size, &cipher.rtcp_salt);

    return cipher;
}

pub fn encryptRtcp(cm: *AesCm, src: []const u8, dst: []u8, index: u32) Error![]const u8 {
    const tag_size = cm.profile.rtcpTagLength();
    std.debug.assert(dst.len >= src.len + tag_size + rtcp_index_size);

    var iv: [enc_key_size]u8 = @splat(0);
    generateRtcpIV(&iv, &cm.rtcp_salt, src[4..8], index);

    ctr(@TypeOf(cm.rtcp_enc_ctx), cm.rtcp_enc_ctx, dst[8..], src[8..], iv, .big);
    @memcpy(dst[0..8], src[0..8]);
    std.mem.writeInt(u32, dst[src.len..][0..rtcp_index_size], index | 0x80000000, .big);

    var hash: [HmacSha1.mac_length]u8 = undefined;
    HmacSha1.create(&hash, dst[0 .. src.len + rtcp_index_size], &cm.rtcp_auth_key);
    @memcpy(dst[src.len + rtcp_index_size ..][0..tag_size], hash[0..tag_size]);

    return dst[0 .. src.len + rtcp_index_size + tag_size];
}

pub fn decryptRtp(cm: *AesCm, roc: u32, header_size: usize, src: []const u8, dst: []u8) Error![]const u8 {
    const tag_size = cm.profile.rtpTagLength();
    const roc_bytes: [4]u8 = std.mem.toBytes(std.mem.nativeToBig(u32, roc));

    var hash: [HmacSha1.mac_length]u8 = undefined;
    var hasher = HmacSha1.init(&cm.rtp_auth_key);
    hasher.update(src[0 .. src.len - tag_size]);
    hasher.update(&roc_bytes);
    hasher.final(&hash);

    if (std.crypto.timing_safe.compare(u8, hash[0..tag_size], src[src.len - tag_size ..], .big) != .eq) {
        @branchHint(.unlikely);
        return error.AuthenticationFailed;
    }

    // Decrypt
    var iv: [enc_key_size]u8 = @splat(0);
    @memcpy(iv[4..8], src[8..12]);
    @memcpy(iv[8..12], &roc_bytes);
    @memcpy(iv[12..14], src[2..4]);
    for (iv[0..salt_size], &cm.rtp_salt) |*b1, b2| b1.* ^= b2;

    const payload_size = src.len - tag_size - header_size;
    ctr(
        @TypeOf(cm.rtp_enc_ctx),
        cm.rtp_enc_ctx,
        dst[header_size .. src.len - tag_size],
        src[header_size .. src.len - tag_size],
        iv,
        .big,
    );

    @memcpy(dst[0..header_size], src[0..header_size]);
    return dst[0 .. payload_size + header_size];
}

pub fn decryptRtcp(cm: *AesCm, src: []const u8, dst: []u8, encrypted: bool, index: u32) Error![]const u8 {
    const tag_size = cm.profile.rtcpTagLength();
    std.debug.assert(dst.len >= src.len - tag_size - rtcp_index_size);

    var hash: [HmacSha1.mac_length]u8 = undefined;
    HmacSha1.create(&hash, src[0 .. src.len - tag_size], &cm.rtcp_auth_key);

    if (std.crypto.timing_safe.compare(u8, hash[0..tag_size], src[src.len - tag_size ..], .big) != .eq) {
        @branchHint(.unlikely);
        return error.AuthenticationFailed;
    }

    const payload_size = src.len - tag_size - rtcp_index_size;
    if (!encrypted) {
        @memcpy(dst[0..payload_size], src[0..payload_size]);
        return dst[0..payload_size];
    }

    var iv: [enc_key_size]u8 = @splat(0);
    generateRtcpIV(&iv, &cm.rtcp_salt, src[4..8], index);

    ctr(@TypeOf(cm.rtcp_enc_ctx), cm.rtcp_enc_ctx, dst[8..], src[8..payload_size], iv, .big);
    @memcpy(dst[0..8], src[0..8]);
    return dst[0..payload_size];
}

fn generateRtcpIV(iv: *[enc_key_size]u8, salt: *const [salt_size]u8, ssrc: *const [4]u8, index: u32) void {
    @memcpy(iv[4..8], ssrc);
    std.mem.writeInt(u32, iv[10..14], index, .big);
    for (iv[0..salt_size], salt) |*iv_b, salt_b| iv_b.* ^= salt_b;
}

const plain_rtp = [_]u8{
    0x80, 0x0E, 0x0F, 0x8F, 0x62, 0x91, 0x7F, 0xF7,
    0xE9, 0xA4, 0x91, 0x8C, 0x87, 0x9C, 0xF1, 0xE2,
    0x8F, 0x08, 0x0B, 0x33, 0xC1, 0xA4,
};

const plain_rtcp = [_]u8{
    128, 200, 0,   6,   137, 161, 255, 135, 18,  52,  86,  120,
    144, 171, 205, 239, 0,   1,   226, 64,  0,   0,   0,   100,
    0,   0,   0,   200, 129, 203, 0,   1,   137, 161, 255, 135,
};

const encrypted_rtp_aes_128_cm_hmac1_32 = [_]u8{};
const plain_rtp_aes_128_cm_hmac1_32 = [_]u8{};

test "encrypt/decrypt rtcp" {
    var master_key: [enc_key_size]u8 = undefined;
    var master_salt: [enc_key_size]u8 = undefined;

    std.testing.io.random(&master_key);
    std.testing.io.random(&master_salt);

    var cm = AesCm.init(.AesCm128HmacSha1_80, &master_key, &master_salt);

    var enc_dst: [200]u8 = undefined;
    var dec_dst: [200]u8 = undefined;
    for (0..1000) |idx| {
        const encrypted = try cm.encryptRtcp(&plain_rtcp, &enc_dst, @intCast(idx));
        const decrypted = try cm.decryptRtcp(encrypted, &dec_dst, true, @intCast(idx));

        try std.testing.expectEqualSlices(u8, &plain_rtcp, decrypted);
    }
}
