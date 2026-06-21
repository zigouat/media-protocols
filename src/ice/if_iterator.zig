const std = @import("std");
const os = @import("builtin").os;

const windows = std.os.windows;
const posix = std.posix;
const IfIterator = @This();

const IFF_LOOPBACK: u32 = 8;
const WIN_ERROR_BUFFER_OVERFLOW: windows.ULONG = 0x6F;
const IF_TYPE_SOFTWARE_LOOPBACK: windows.ULONG = 24;

extern fn getifaddrs([*c][*c]IfAddrs) callconv(.c) c_int;
extern fn freeifaddrs([*c]IfAddrs) callconv(.c) void;

extern "iphlpapi" fn GetAdaptersAddresses(
    family: windows.ULONG,
    flags: windows.ULONG,
    reserved: ?windows.PVOID,
    adapter_addresses: [*c]u8,
    size_pointer: [*c]windows.ULONG,
) callconv(.winapi) windows.ULONG;

const AdapterUnicastAddress = extern struct {
    length: windows.ULONG,
    flags: windows.DWORD,
    next: [*c]AdapterUnicastAddress,
    address: extern struct {
        sockaddr: [*c]posix.sockaddr,
        length: windows.ULONG,
    },
};

const IfAddrs = switch (os.tag) {
    .windows => extern struct {
        length: windows.ULONG,
        if_index: windows.ULONG,
        next: [*c]IfAddrs,
        adapter_name: [*c]u8,
        first_unicast_address: [*c]AdapterUnicastAddress,
        first_anycast_address: *anyopaque,
        first_multicast_address: *anyopaque,
        first_dns_server_address: *anyopaque,
        dns_suffix: [*c]windows.WCHAR,
        description: [*c]windows.WCHAR,
        friendly_name: [*c]windows.WCHAR,
        physical_address: [8]u8,
        physical_address_length: windows.ULONG,
        flags: windows.ULONG,
        mtu: windows.ULONG,
        if_type: windows.ULONG,
    },
    else => extern struct {
        next: [*c]IfAddrs,
        name: [*c]u8,
        flags: u32,
        addr: [*c]posix.sockaddr,
    },
};

ifa: [*c]IfAddrs,
buffer: []u8,

pub fn init(allocator: std.mem.Allocator) !IfIterator {
    var it: IfIterator = .{ .ifa = undefined, .buffer = &.{} };
    return switch (os.tag) {
        .windows => blk: {
            var size: windows.ULONG = 16 * 1024;
            it.buffer = try allocator.alloc(u8, size);
            while (true) {
                switch (GetAdaptersAddresses(0, 0, null, it.buffer.ptr, &size)) {
                    WIN_ERROR_BUFFER_OVERFLOW => {
                        it.buffer = try allocator.realloc(it.buffer, size);
                    },
                    0 => {
                        it.ifa = @ptrCast(@alignCast(it.buffer.ptr));
                        break :blk it;
                    },
                    else => return error.GetAdaptersAddressesFailed,
                }
            }
            break :blk it;
        },
        else => if (getifaddrs(&it.ifa) == 0) it else error.GetIfAddrsFailed,
    };
}

pub fn next(it: *IfIterator) ?std.Io.net.IpAddress {
    return switch (os.tag) {
        .windows => it.nextWindowsInterface(),
        else => it.nextInterafaceIpAddress(),
    };
}

pub fn deinit(iterator: *IfIterator, allocator: std.mem.Allocator) void {
    switch (os.tag) {
        .windows => allocator.free(iterator.buffer),
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

fn nextWindowsInterface(it: *IfIterator) ?std.Io.net.IpAddress {
    while (it.ifa != null) {
        if (it.ifa.*.if_type == IF_TYPE_SOFTWARE_LOOPBACK) {
            it.ifa = it.ifa.*.next;
            continue;
        }

        var unicast = it.ifa.*.first_unicast_address;
        while (unicast != null) {
            defer {
                unicast = unicast.*.next;
                it.ifa.*.first_unicast_address = unicast;
            }

            const sockaddr = unicast.*.address.sockaddr.*;
            switch (sockaddr.family) {
                windows.ws2_32.AF.INET => {
                    const in: posix.sockaddr.in = @bitCast(sockaddr);
                    return .{ .ip4 = .{ .bytes = std.mem.toBytes(in.addr), .port = 0 } };
                },
                else => {},
            }
        }

        it.ifa = it.ifa.*.next;
    }

    return null;
}
