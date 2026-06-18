const std = @import("std");
const os = @import("builtin").os;
const c = @import("c");

const posix = std.posix;
const IfIterator = @This();

ifa: switch (os.tag) {
    .windows => void,
    else => [*c]c.ifaddrs,
},

pub fn init(iterator: *IfIterator) !void {
    switch (os.tag) {
        .windows => {},
        else => if (c.getifaddrs(&iterator.ifa) != 0) return error.GetIfAddrsFailed,
    }
}

pub fn next(it: *IfIterator) ?std.Io.net.IpAddress {
    return switch (os.tag) {
        .windows => return null,
        else => it.nextInterafaceIpAddress(),
    };
}

pub fn deinit(iterator: *IfIterator) void {
    switch (os.tag) {
        .linux => c.ifaddrs.freeifaddrs(iterator.ifa),
        else => {},
    }
}

fn nextInterafaceIpAddress(it: *IfIterator) ?std.Io.net.IpAddress {
    while (it.ifa) |ifa| {
        defer it.ifa = ifa.*.ifa_next;
        if (ifa.*.ifa_addr == null) continue;

        const sockaddr: posix.sockaddr = @bitCast(ifa.*.ifa_addr.*);
        switch (sockaddr.family) {
            posix.AF.INET => {
                if (ifa.*.ifa_flags & c.IFF_LOOPBACK != 0) continue;

                const in: posix.sockaddr.in = @bitCast(sockaddr);
                return .{ .ip4 = .{ .bytes = std.mem.toBytes(in.addr), .port = 0 } };
            },
            else => {},
        }
    }

    return null;
}
