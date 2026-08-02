//! A TURN client implementation. This module provides a `Client` struct that can be used to create and manage TURN allocations,
//! permissions, and data relaying.
//!
//! It handles the necessary STUN/TURN protocol interactions, including long term authentication, allocation refresh,
//! and permission management.
//!
//! When an allocation is successfully created, the client will automatically spawn background tasks to maintain the allocation
//! and refresh permissions at regular intervals.
//!
//! Receiving data from peers is done via the `receive` function, which will block until a data indication is received from the TURN server.
//! It's the caller's responsibility to call `receive` in a loop to drive the client's state machine and handle incoming data.

const std = @import("std");
const stun = @import("stun");

const Client = @This();
const Io = std.Io;
const testing = std.testing;

const refresh_margin_seconds: u32 = 60;
const refresh_permissions_interval_seconds: u32 = 120;
const rto_base_ms: u32 = 200;
const rto_max_ms: u32 = 1600;

pub const ClientConfig = struct {
    socket: Io.net.Socket,
    server: Io.net.IpAddress,
    username: []const u8,
    password: []const u8,
};

pub const Error = error{
    BadRequest,
    Unauthorized,
    Forbidden,
    UnknownAttribute,
    AllocationMismatch,
    StaleNonce,
    AddressFamilyNotSupported,
    WrongCredentials,
    UnsupportedTransportProtocol,
    AllocationQuotaReached,
    RoleConflict,
    ServerError,
    InsufficientCapacity,
    UnknownStunError,
    NoAllocation,
    BufferTooShort,
    CreatePermissionFailed,
    MissingErrorCode,
    MissingRealm,
    MissingNonce,
    MissingRelayedAddress,
    MissingMappedAddress,
    MissingLifetime,
    Timeout,
};

pub const ReceivedData = struct {
    from: Io.net.IpAddress,
    data: []const u8,
};

pub const AllocationResult = struct {
    relayed_address: Io.net.IpAddress,
    mapped_address: Io.net.IpAddress,
    lifetime: u32,
};

const Allocation = struct {
    relayed_address: Io.net.IpAddress,
    mapped_address: Io.net.IpAddress,
    lifetime: u32,
    permissions: std.ArrayList(Io.net.IpAddress) = .empty,

    fn trackPermission(allocation: *Allocation, allocator: std.mem.Allocator, peer: Io.net.IpAddress) !void {
        for (allocation.permissions.items) |existing| {
            if (sameIp(existing, peer)) return;
        }
        try allocation.permissions.append(allocator, peer);
    }

    fn sameIp(a: Io.net.IpAddress, b: Io.net.IpAddress) bool {
        return switch (a) {
            .ip4 => |a4| switch (b) {
                .ip4 => |b4| std.mem.eql(u8, &a4.bytes, &b4.bytes),
                .ip6 => false,
            },
            .ip6 => |a6| switch (b) {
                .ip6 => |b6| std.mem.eql(u8, &a6.bytes, &b6.bytes),
                .ip4 => false,
            },
        };
    }

    test "Allocation.trackPermission: dedups same ip, different port" {
        var allocation = Allocation{ .relayed_address = undefined, .mapped_address = undefined, .lifetime = 600 };
        defer allocation.permissions.deinit(testing.allocator);

        const peer_a: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 1000 } };
        const peer_a_other_port: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 2000 } };
        const peer_b: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 2 }, .port = 1000 } };

        try allocation.trackPermission(testing.allocator, peer_a);
        try allocation.trackPermission(testing.allocator, peer_a_other_port);
        try allocation.trackPermission(testing.allocator, peer_b);

        try testing.expectEqual(2, allocation.permissions.items.len);
    }

    test "Allocation.sameIp: ip4 and ip6 never match" {
        const ip4: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 1, 2, 3, 4 }, .port = 1 } };
        const ip6: Io.net.IpAddress = .{ .ip6 = .unspecified(1) };
        try testing.expect(!Allocation.sameIp(ip4, ip6));
    }

    test "Allocation.sameIp: compares address bytes, ignores port" {
        const a: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = 100 } };
        const b: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = 200 } };
        const c: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 2 }, .port = 100 } };

        try testing.expect(Allocation.sameIp(a, b));
        try testing.expect(!Allocation.sameIp(a, c));
    }
};

const Transaction = struct {
    id: u96,
    buffer: []u8,
    req: []const u8,
    resp: []const u8 = &.{},
    err: ?Error = null,
    done: Io.Event = .unset,
    mutex: Io.Mutex = .init,

    fn waitForResult(tr: *Transaction, io: Io) ![]const u8 {
        try tr.done.wait(io);
        if (tr.err) |e| return e;
        return tr.resp;
    }
};

allocator: std.mem.Allocator,
socket: Io.net.Socket,
group: Io.Group,

server: Io.net.IpAddress,
username: []const u8,
password: []const u8,
nonce: []const u8,
realm: []const u8,
key: []const u8,

allocation: ?Allocation = null,

transactions: std.AutoHashMap(u96, *Transaction),
tr_mutex: Io.Mutex = .init,

pub fn init(allocator: std.mem.Allocator, config: ClientConfig) Client {
    return Client{
        .allocator = allocator,
        .socket = config.socket,
        .group = .init,
        .server = config.server,
        .username = config.username,
        .password = config.password,
        .nonce = "",
        .realm = "",
        .key = "",
        .transactions = .init(allocator),
    };
}

pub fn deinit(client: *Client, io: Io) void {
    if (client.allocation != null) client.deleteAllocation(io);

    client.group.cancel(io);
    client.socket.close(io);
    client.transactions.deinit();
    client.allocator.free(client.realm);
    client.allocator.free(client.nonce);
    client.allocator.free(client.key);
    if (client.allocation) |*allocation| allocation.permissions.deinit(client.allocator);
}

/// Creates an allocation on the TURN server
pub fn createAllocation(client: *Client, io: Io, buffer: []u8) !AllocationResult {
    const first = try client.sendAllocateRequest(io, buffer, false);
    var msg = try stun.Message.parse(first);

    if (msg.header.message_type.class() == .error_response) {
        try client.applyChallenge(&msg);

        const second = try client.sendAllocateRequest(io, buffer, true);
        msg = try stun.Message.parse(second);
    }

    const result = try client.parseAllocation(&msg);
    client.allocation = .{
        .relayed_address = result.relayed_address,
        .mapped_address = result.mapped_address,
        .lifetime = result.lifetime,
    };
    try client.group.concurrent(io, maintainAllocation, .{ client, io });
    try client.group.concurrent(io, maintainPermissions, .{ client, io });

    return result;
}

/// Refreshes the client's allocation, extending its lifetime. Pass `lifetime = 0` to
/// explicitly delete the allocation. Returns the lifetime granted by the server.
pub fn refreshAllocation(client: *Client, io: Io, buffer: []u8, lifetime: u32) !u32 {
    const first = try client.sendRefreshRequest(io, buffer, lifetime);
    var msg = try stun.Message.parse(first);

    if (msg.header.message_type.class() == .error_response) {
        try client.applyChallenge(&msg);

        const second = try client.sendRefreshRequest(io, buffer, lifetime);
        msg = try stun.Message.parse(second);
    }

    return client.parseRefresh(&msg);
}

/// Whether a permission is already installed for `peer`'s IP (port is ignored).
pub fn hasPermission(client: *Client, peer: Io.net.IpAddress) bool {
    const allocation = client.allocation orelse return false;
    for (allocation.permissions.items) |existing| {
        if (Allocation.sameIp(existing, peer)) return true;
    }
    return false;
}

const IpAddressSliceIterator = struct {
    items: []const Io.net.IpAddress,
    index: usize = 0,

    fn next(it: *IpAddressSliceIterator) ?Io.net.IpAddress {
        if (it.index >= it.items.len) return null;
        defer it.index += 1;
        return it.items[it.index];
    }
};

/// Creates permissions for one or more peer addresses on the client's allocation.
///
/// `peers` is any type exposing `next(peers: *T) ?Io.net.IpAddress`, e.g. a slice-backed
/// iterator. See `createPermissionsSlice` for a plain `[]const Io.net.IpAddress` overload.
pub fn createPermissions(client: *Client, io: Io, buffer: []u8, peers: anytype) !void {
    const allocation = if (client.allocation) |*a| a else return error.NoAllocation;
    const previous_len = allocation.permissions.items.len;
    errdefer allocation.permissions.shrinkRetainingCapacity(previous_len);

    while (peers.next()) |peer| try allocation.trackPermission(client.allocator, peer);
    const new_peers = allocation.permissions.items[previous_len..];
    if (new_peers.len == 0) return;

    try client.performCreatePermission(io, buffer, new_peers);
}

/// Same as `createPermissions`, but takes a plain slice of peer addresses.
pub fn createPermissionsSlice(client: *Client, io: Io, buffer: []u8, peers: []const Io.net.IpAddress) !void {
    var it: IpAddressSliceIterator = .{ .items = peers };
    return client.createPermissions(io, buffer, &it);
}

/// Relays `data` to `peer` through the client's allocation. Indications are fire-and-forget:
/// no response is expected and the send is not retried.
pub fn sendIndication(client: *Client, io: Io, buffer: []u8, peer: Io.net.IpAddress, data: []const u8) !void {
    const tx_id = newTransactionId(io);

    var w = stun.Writer.init(buffer, .{});
    try writeHeader(&w, .indication, .send, tx_id);
    try w.writeAttributes(&.{
        .{ .xor_peer_address = peer },
        .{ .data = data },
    });

    try client.socket.send(io, &client.server, w.final());
}

/// Blocks until a user's data is received from the TURN server.
pub fn receive(client: *Client, io: Io, buffer: []u8) !ReceivedData {
    while (true) {
        const message = try client.socket.receive(io, buffer);
        if (!stun.isMessage(message.data)) continue;

        const s = stun.Message.parse(message.data) catch continue;
        switch (s.header.message_type.class()) {
            .request => continue,
            .indication => {
                if (s.header.message_type.method() != .data) continue;
                if (client.parseDataIndication(&s)) |received| return received;
            },
            else => {
                try client.tr_mutex.lock(io);
                defer client.tr_mutex.unlock(io);
                const entry = client.transactions.fetchRemove(s.header.transaction_id) orelse continue;

                try entry.value.mutex.lock(io);
                defer entry.value.mutex.unlock(io);
                if (message.data.len > entry.value.buffer.len) {
                    entry.value.err = error.BufferTooShort;
                    entry.value.done.set(io);
                    continue;
                }

                if (entry.value.done.isSet()) continue;

                @memcpy(entry.value.buffer[0..message.data.len], message.data);
                entry.value.resp = entry.value.buffer[0..message.data.len];
                entry.value.done.set(io);
            },
        }
    }
}

fn newTransactionId(io: Io) u96 {
    var bytes: [12]u8 = undefined;
    io.random(&bytes);
    return @bitCast(bytes);
}

fn writeHeader(w: *stun.Writer, class: stun.Class, method: stun.Method, tx_id: u96) !void {
    try w.writeHeader(.{
        .message_length = 0,
        .message_type = .fromClassAndMethod(class, method),
        .transaction_id = tx_id,
    });
}

fn sendAllocateRequest(client: *Client, io: Io, buffer: []u8, authenticated: bool) ![]const u8 {
    const tx_id = newTransactionId(io);

    var w = stun.Writer.init(buffer, .{ .password = if (authenticated) client.key else null });
    try writeHeader(&w, .request, .allocate, tx_id);
    try w.writeAttribute(.{ .requested_transport = .udp });

    if (authenticated) {
        try w.writeAttributes(&.{
            .{ .username = client.username },
            .{ .realm = client.realm },
            .{ .nonce = client.nonce },
            .{ .message_integrity = &.{} },
            .fingerprint,
        });
    }

    const msg = w.final();

    var tr = Transaction{
        .id = tx_id,
        .req = msg,
        .buffer = buffer,
        .resp = &.{},
    };

    {
        try client.tr_mutex.lock(io);
        defer client.tr_mutex.unlock(io);
        try client.transactions.put(tx_id, &tr);
    }

    return client.performTransaction(io, &tr);
}

fn sendRefreshRequest(client: *Client, io: Io, buffer: []u8, lifetime: u32) ![]const u8 {
    const tx_id = newTransactionId(io);

    var w = stun.Writer.init(buffer, .{ .password = client.key });
    try writeHeader(&w, .request, .refresh, tx_id);
    try w.writeAttributes(&.{
        .{ .lifetime = lifetime },
        .{ .username = client.username },
        .{ .realm = client.realm },
        .{ .nonce = client.nonce },
        .{ .message_integrity = &.{} },
        .fingerprint,
    });

    var tr = Transaction{ .id = tx_id, .req = w.final(), .buffer = buffer };
    {
        try client.tr_mutex.lock(io);
        defer client.tr_mutex.unlock(io);
        try client.transactions.put(tx_id, &tr);
    }

    return client.performTransaction(io, &tr);
}

fn deleteAllocation(client: *Client, io: Io) void {
    var buffer: [1500]u8 = undefined;
    var w = stun.Writer.init(&buffer, .{ .password = client.key });

    writeHeader(&w, .request, .refresh, newTransactionId(io)) catch return;
    w.writeAttributes(&.{
        .{ .lifetime = 0 },
        .{ .username = client.username },
        .{ .realm = client.realm },
        .{ .nonce = client.nonce },
        .{ .message_integrity = &.{} },
        .fingerprint,
    }) catch return;

    client.socket.send(io, &client.server, w.final()) catch {};
}

fn sendCreatePermissionRequest(client: *Client, io: Io, buffer: []u8, peers: []const Io.net.IpAddress) ![]const u8 {
    const tx_id = newTransactionId(io);

    var w = stun.Writer.init(buffer, .{ .password = client.key });
    try writeHeader(&w, .request, .create_permission, tx_id);
    for (peers) |peer| try w.writeAttribute(.{ .xor_peer_address = peer });
    try w.writeAttributes(&.{
        .{ .username = client.username },
        .{ .realm = client.realm },
        .{ .nonce = client.nonce },
        .{ .message_integrity = &.{} },
        .fingerprint,
    });

    var tr = Transaction{ .id = tx_id, .req = w.final(), .buffer = buffer };
    {
        try client.tr_mutex.lock(io);
        defer client.tr_mutex.unlock(io);
        try client.transactions.put(tx_id, &tr);
    }

    return client.performTransaction(io, &tr);
}

fn maintainAllocation(client: *Client, io: Io) !void {
    var buffer: [1500]u8 = undefined;

    while (true) {
        const lifetime = (client.allocation orelse return).lifetime;
        if (lifetime == 0) return;

        const sleep_seconds = if (lifetime > refresh_margin_seconds) lifetime - refresh_margin_seconds else lifetime;
        try io.sleep(.fromSeconds(sleep_seconds), .awake);

        const new_lifetime = client.refreshAllocation(io, &buffer, lifetime) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => {
                std.log.warn("Failed to refresh TURN allocation: {}", .{err});
                return;
            },
        };

        if (client.allocation) |*allocation| allocation.lifetime = new_lifetime;
        if (new_lifetime == 0) return;
    }
}

fn maintainPermissions(client: *Client, io: Io) !void {
    var buffer: [1500]u8 = undefined;

    while (true) {
        try io.sleep(.fromSeconds(refresh_permissions_interval_seconds), .awake);

        const allocation = client.allocation orelse return;
        if (allocation.permissions.items.len == 0) continue;

        client.performCreatePermission(io, &buffer, allocation.permissions.items) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => std.log.warn("Failed to refresh TURN permissions: {}", .{err}),
        };
    }
}

fn performCreatePermission(client: *Client, io: Io, buffer: []u8, peers: []const Io.net.IpAddress) !void {
    const first = try client.sendCreatePermissionRequest(io, buffer, peers);
    var msg = try stun.Message.parse(first);

    if (msg.header.message_type.class() == .error_response) {
        try client.applyChallenge(&msg);

        const second = try client.sendCreatePermissionRequest(io, buffer, peers);
        msg = try stun.Message.parse(second);
    }

    if (msg.header.message_type.class() != .error_response) return;

    var it = msg.iterateAttributes(client.key);
    while (try it.next()) |attr| {
        if (attr == .error_code) return errorFromCode(attr.error_code.code);
    }
    return error.CreatePermissionFailed;
}

/// Extracts REALM/NONCE from a 401/438 error response and derives the long-term credentials key.
fn applyChallenge(client: *Client, msg: *const stun.Message) !void {
    var realm: ?[]const u8 = null;
    var nonce: ?[]const u8 = null;
    var code: ?stun.StunErrorCode = null;

    var it = msg.iterateAttributes(client.key);
    while (try it.next()) |attr| switch (attr) {
        .realm => realm = attr.realm,
        .nonce => nonce = attr.nonce,
        .error_code => code = attr.error_code.code,
        else => {},
    };

    switch (code orelse return error.MissingErrorCode) {
        .unauthorized, .stale_nonce => {},
        else => |c| return errorFromCode(c),
    }

    if (realm == null) return error.MissingRealm;
    if (nonce == null) return error.MissingNonce;

    client.allocator.free(client.realm);
    client.allocator.free(client.nonce);
    client.allocator.free(client.key);

    client.realm = try client.allocator.dupe(u8, realm.?);
    client.nonce = try client.allocator.dupe(u8, nonce.?);

    const digest = stun.longTermCredentialsKey(std.crypto.hash.Md5, client.username, client.realm, client.password);
    client.key = try client.allocator.dupe(u8, &digest);
}

fn parseAllocation(client: *Client, msg: *const stun.Message) !AllocationResult {
    var relayed_address: ?Io.net.IpAddress = null;
    var mapped_address: ?Io.net.IpAddress = null;
    var lifetime: ?u32 = null;
    var code: ?stun.StunErrorCode = null;

    var it = msg.iterateAttributes(client.key);
    while (try it.next()) |attr| switch (attr) {
        .xor_relayed_address => relayed_address = attr.xor_relayed_address,
        .xor_mapped_address => mapped_address = attr.xor_mapped_address,
        .lifetime => lifetime = attr.lifetime,
        .error_code => code = attr.error_code.code,
        else => {},
    };

    if (code) |c| return errorFromCode(c);

    return .{
        .relayed_address = relayed_address orelse return error.MissingRelayedAddress,
        .mapped_address = mapped_address orelse return error.MissingMappedAddress,
        .lifetime = lifetime orelse return error.MissingLifetime,
    };
}

fn parseRefresh(client: *Client, msg: *const stun.Message) !u32 {
    var lifetime: ?u32 = null;
    var code: ?stun.StunErrorCode = null;

    var it = msg.iterateAttributes(client.key);
    while (try it.next()) |attr| switch (attr) {
        .lifetime => lifetime = attr.lifetime,
        .error_code => code = attr.error_code.code,
        else => {},
    };

    if (code) |c| return errorFromCode(c);
    return lifetime orelse error.MissingLifetime;
}

fn errorFromCode(code: stun.StunErrorCode) Error {
    return switch (code) {
        .bad_request => error.BadRequest,
        .unauthorized => error.Unauthorized,
        .forbidden => error.Forbidden,
        .unknown_attribute => error.UnknownAttribute,
        .allocation_mismatch => error.AllocationMismatch,
        .stale_nonce => error.StaleNonce,
        .address_family_not_supported => error.AddressFamilyNotSupported,
        .wrong_credentials => error.WrongCredentials,
        .unsupported_transport_protocol => error.UnsupportedTransportProtocol,
        .allocation_quota_reached => error.AllocationQuotaReached,
        .role_conflict => error.RoleConflict,
        .server_error => error.ServerError,
        .insufficient_capacity => error.InsufficientCapacity,
        _ => error.UnknownStunError,
    };
}

fn parseDataIndication(client: *Client, msg: *const stun.Message) ?ReceivedData {
    var from: ?Io.net.IpAddress = null;
    var data: ?[]const u8 = null;

    var it = msg.iterateAttributes(client.key);
    while ((it.next() catch return null)) |attr| switch (attr) {
        .xor_peer_address => from = attr.xor_peer_address,
        .data => data = attr.data,
        else => {},
    };

    return .{ .from = from orelse return null, .data = data orelse return null };
}

fn performTransaction(client: *Client, io: Io, tr: *Transaction) ![]const u8 {
    try client.socket.send(io, &client.server, tr.req);
    try client.group.concurrent(io, retry, .{ client, io, tr });
    return try tr.waitForResult(io);
}

fn retry(client: *Client, io: Io, tr: *Transaction) !void {
    var max_retries: u8 = 5;
    var rto: u32 = rto_base_ms;
    while (max_retries > 0) : (max_retries -= 1) {
        try io.sleep(.fromMilliseconds(rto), .awake);
        try tr.mutex.lock(io);
        defer tr.mutex.unlock(io);

        if (!client.transactions.contains(tr.id)) return;

        client.socket.send(io, &client.server, tr.req) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };

        rto = @min(rto * 2, rto_max_ms);
    }

    try client.tr_mutex.lock(io);
    defer client.tr_mutex.unlock(io);
    if (!client.transactions.contains(tr.id)) return;

    try tr.mutex.lock(io);
    defer tr.mutex.unlock(io);
    if (tr.done.isSet()) return;

    tr.err = error.Timeout;
    tr.done.set(io);
}

test {
    testing.refAllDecls(@This());
}
