const std = @import("std");
const os = @import("builtin").os;
const c = @import("c");

const linux = std.os.linux;
const IfIterator = @This();

ifa: switch (os.tag) {
    .linux => [*c]c.ifaddrs,
    else => {},
},

pub fn init(iterator: *IfIterator) !void {
    switch (os.tag) {
        .linux => if (c.getifaddrs(&iterator.ifa) != 0) return error.GetIfAddrsFailed,
        else => {},
    }
}

pub fn next(it: *IfIterator) ?std.Io.net.IpAddress {
    return switch (os.tag) {
        .linux => it.nextLinuxInteraface(),
        else => null,
    };
}

pub fn deinit(iterator: *IfIterator) void {
    switch (os.tag) {
        .linux => c.ifaddrs.freeifaddrs(iterator.ifa),
        else => {},
    }
}

fn nextLinuxInteraface(it: *IfIterator) ?std.Io.net.IpAddress {
    while (it.ifa) |ifa| {
        defer it.ifa = ifa.*.ifa_next;
        if (ifa.*.ifa_addr == null) continue;

        const sockaddr: linux.sockaddr = @bitCast(ifa.*.ifa_addr.*);
        switch (sockaddr.family) {
            linux.AF.INET => {
                const c_flags: u16 = @truncate(ifa.*.ifa_flags);
                const flags: linux.IFF = @bitCast(c_flags);
                if (flags.LOOPBACK) continue;

                const in: linux.sockaddr.in = @bitCast(sockaddr);
                return .{ .ip4 = .{ .bytes = std.mem.toBytes(in.addr), .port = 0 } };
            },
            else => {},
        }
    }

    return null;
}
