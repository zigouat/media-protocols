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
    @memcpy(iv[4..8], src[4..8]);
    std.mem.writeInt(u32, iv[10..14], index, .big);
    for (iv[0..salt_size], &cm.rtcp_salt) |*iv_b, salt_b| iv_b.* ^= salt_b;

    ctr(@TypeOf(cm.rtcp_enc_ctx), cm.rtcp_enc_ctx, dst[8..], src[8..payload_size], iv, .big);
    @memcpy(dst[0..8], src[0..8]);
    return dst[0..payload_size];
}
