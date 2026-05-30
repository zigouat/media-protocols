const std = @import("std");

pub const Profile = enum {
    aes_cm_128_hmac_sha1_80,
    aes_cm_128_hmac_sha1_32,

    pub fn keys_size(profile: Profile) struct { u8, u8 } {
        switch (profile) {
            .aes_cm_128_hmac_sha1_80, .aes_cm_128_hmac_sha1_32 => .{ 16, 14 },
        }
    }
};

pub const Session = struct {
    master_key: []const u8,
    salt: []const u8,
    profile: Profile,

    pub fn init(keying_material: []const u8, profile: Profile) !Session {
        const master_size, const salt_size = Profile.keys_size(profile);
        if (master_size + salt_size != keying_material.len) return error.InvalidKeyingMaterial;

        return .{
            .profile = profile,
            .master_key = keying_material[0..master_size],
            .salt = keying_material[master_size..],
        };
    }
};

test {
    _ = @import("kdf.zig");
}
