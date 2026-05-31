const std = @import("std");
const rtp = @import("rtp");
const cipher = @import("cipher.zig");

pub const Profile = enum {
    aes_cm_128_hmac_sha1_80,
    aes_cm_128_hmac_sha1_32,

    pub fn keysSize(profile: Profile) struct { u8, u8 } {
        return switch (profile) {
            .aes_cm_128_hmac_sha1_80, .aes_cm_128_hmac_sha1_32 => .{ 16, 14 },
        };
    }

    pub fn tagSize(profile: *const Profile) u8 {
        return switch (profile.*) {
            .aes_cm_128_hmac_sha1_80 => 10,
            .aes_cm_128_hmac_sha1_32 => 4,
        };
    }
};

pub const Cipher = union(Profile) {
    AesCm128HmacSha1_80: cipher.AesCm,
    AesCm128HmacSha1_32: cipher.AesCm,

    pub fn init(profile: Profile, master_key: []const u8, master_salt: []const u8) Cipher {
        return switch (profile) {
            .aes_cm_128_hmac_sha1_80 => .{ .AesCm128HmacSha1_80 = cipher.AesCm.init(profile, master_key, master_salt) },
            .aes_cm_128_hmac_sha1_32 => .{ .AesCm128HmacSha1_32 = cipher.AesCm.init(profile, master_key, master_salt) },
        };
    }
};

pub const Session = struct {
    master_key: []const u8,
    salt: []const u8,
    profile: Profile,
    cipher: Cipher,

    pub fn init(keying_material: []const u8, profile: Profile) !Session {
        const master_size, const salt_size = Profile.keysSize(profile);
        if (master_size + salt_size != keying_material.len) return error.InvalidKeyingMaterial;

        const master_key = keying_material[0..master_size];
        const master_salt = keying_material[master_size..];

        return .{
            .profile = profile,
            .master_key = master_key,
            .salt = master_salt,
            .cipher = Cipher.init(profile, master_key, master_salt),
        };
    }

    pub fn decryptRtp(session: *Session, packet: []const u8, dst: []u8) ![]const u8 {
        const rtp_packet = try rtp.Packet.parse(packet);
        const header_size = packet.len - rtp_packet.payload.len - rtp_packet.padding_size;

        return switch (session.cipher) {
            .AesCm128HmacSha1_32, .AesCm128HmacSha1_80 => |*c| try c.decryptRtp(0, header_size, packet, dst),
        };
    }
};

test {
    _ = @import("kdf.zig");
}

test "test srtp session" {
    var session = try Session.init("mysecretkey12345mysaltvalue123", .aes_cm_128_hmac_sha1_80);

    const packet = [_]u8{
        128, 96,  0,   1,   0,   1,   226, 64,
        137, 161, 255, 135, 146, 221, 94,  142,
        7,   197, 169, 172, 155, 23,  74,  128,
        181, 142, 45,
    };

    try session.decryptRtp(&packet);
}
