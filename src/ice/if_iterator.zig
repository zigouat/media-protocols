const std = @import("std");
const os = @import("builtin").os;

pub const IFF_LOOPBACK: u32 = 8;

extern fn getifaddrs([*c][*c]IfAddrs) c_int;
extern fn freeifaddrs([*c]IfAddrs) void;

const posix = std.posix;
const IfIterator = @This();

const IfAddrs = switch (os.tag) {
    .windows => void,
    else => extern struct {
        next: [*c]IfAddrs,
        name: [*c]u8,
        flags: u32,
        addr: [*c]posix.sockaddr,
    },
};

ifa: [*c]IfAddrs,

pub fn init() !IfIterator {
    var it: IfIterator = .{ .ifa = undefined };
    return switch (os.tag) {
        .windows => it,
        else => if (getifaddrs(&it.ifa) == 0) it else error.GetIfAddrsFailed,
    };
}

pub fn next(it: *IfIterator) ?std.Io.net.IpAddress {
    return switch (os.tag) {
        .windows => return null,
        else => it.nextInterafaceIpAddress(),
    };
}

pub fn deinit(iterator: *IfIterator) void {
    switch (os.tag) {
        .windows => {},
        else => freeifaddrs(iterator.ifa),
    }
}

fn nextInterafaceIpAddress(it: *IfIterator) ?std.Io.net.IpAddress {
    while (it.ifa) |ifa| {
        defer it.ifa = ifa.*.next;
        if (ifa.*.addr == null) continue;

        const sockaddr = ifa.*.addr.*;
        switch (sockaddr.family) {
            posix.AF.INET => {
                if (ifa.*.flags & IFF_LOOPBACK != 0) continue;

                const in: posix.sockaddr.in = @bitCast(sockaddr);
                return .{ .ip4 = .{ .bytes = std.mem.toBytes(in.addr), .port = 0 } };
            },
            else => {},
        }
    }

    return null;
}
