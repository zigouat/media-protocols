const std = @import("std");
const stun = @import("stun");

const Client = @This();
const Io = std.Io;
const testing = std.testing;

const refresh_margin_seconds: u32 = 60;
const refresh_permissions_interval_seconds: u32 = 120;

pub const ClientConfig = struct {
    server: Io.net.IpAddress,
    username: []const u8,
    password: []const u8,
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
    err: ?anyerror = null,
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

pub fn init(allocator: std.mem.Allocator, io: Io, config: ClientConfig) !Client {
    const socket = try (std.Io.net.IpAddress{ .ip4 = .unspecified(0) }).bind(io, .{ .mode = .dgram });

    return Client{
        .allocator = allocator,
        .socket = socket,
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
    client.group.cancel(io);
    client.socket.close(io);
    client.transactions.deinit();
    client.allocator.free(client.realm);
    client.allocator.free(client.nonce);
    client.allocator.free(client.key);
    if (client.allocation) |*allocation| allocation.permissions.deinit(client.allocator);
}

pub fn handleData(client: *Client, io: Io) !void {
    try client.group.concurrent(io, handleReceivedData, .{ client, io });
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

/// Creates permissions for one or more peer addresses on the client's allocation.
///
/// `peers` is any type exposing `next(peers: *T) ?Io.net.IpAddress`, e.g. a slice-backed
/// iterator. See `createPermissionsSlice` for a plain `[]const Io.net.IpAddress` overload.
pub fn createPermissions(client: *Client, io: Io, buffer: []u8, peers: anytype) !void {
    const allocation = if (client.allocation) |*a| a else return error.NoAllocation;
    const previous_len = allocation.permissions.items.len;
    errdefer allocation.permissions.shrinkRetainingCapacity(previous_len);

    const tx_id = newTransactionId(io);

    var w = stun.Writer.init(buffer, .{ .password = client.key });
    try writeHeader(&w, .request, .create_permission, tx_id);

    var peer_count: usize = 0;
    while (peers.next()) |peer| : (peer_count += 1) {
        try w.writeAttribute(.{ .xor_peer_address = peer });
        try allocation.trackPermission(client.allocator, peer);
    }
    if (peer_count == 0) return error.NoPeerAddresses;

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

    const result = try client.performTransaction(io, &tr);
    const response = try stun.Message.parse(result);

    if (response.header.message_type.class() != .error_response) return;

    var it = response.iterateAttributes(client.key);
    while (try it.next()) |attr| {
        if (attr == .error_code) return errorFromCode(attr.error_code.code);
    }
    return error.CreatePermissionFailed;
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

        // Every peer here is already tracked, so this can't grow the list mid-iteration.
        client.createPermissionsSlice(io, &buffer, allocation.permissions.items) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => std.log.warn("Failed to refresh TURN permissions: {}", .{err}),
        };
    }
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

    client.allocator.free(client.realm);
    client.allocator.free(client.nonce);
    client.allocator.free(client.key);

    client.realm = try client.allocator.dupe(u8, realm orelse return error.MissingRealm);
    client.nonce = try client.allocator.dupe(u8, nonce orelse return error.MissingNonce);

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

fn errorFromCode(code: stun.StunErrorCode) anyerror {
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

fn handleReceivedData(client: *Client, io: Io) !void {
    std.log.debug("Listening for messages", .{});
    var buffer: [1500]u8 = undefined;

    while (true) {
        const message = client.socket.receive(io, &buffer) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => {
                std.log.debug("Error receiving message: {}", .{err});
                continue;
            },
        };

        if (stun.isMessage(message.data)) {
            const s = stun.Message.parse(message.data) catch continue;
            switch (s.header.message_type.class()) {
                .request => continue,
                .indication => {},
                else => {
                    if (s.header.message_type.class() == .request) continue;
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

                    // Already timed out
                    if (entry.value.done.isSet()) continue;

                    @memcpy(entry.value.buffer[0..message.data.len], message.data);
                    entry.value.resp = entry.value.buffer[0..message.data.len];
                    entry.value.done.set(io);
                },
            }
        }
    }
}

fn performTransaction(client: *Client, io: Io, tr: *Transaction) ![]const u8 {
    try client.socket.send(io, &client.server, tr.req);
    try client.group.concurrent(io, retry, .{ client, io, tr });
    return try tr.waitForResult(io);
}

fn retry(client: *Client, io: Io, tr: *Transaction) !void {
    var max_retries: u8 = 5;
    var rto: u32 = 500;
    while (max_retries > 0) : (max_retries -= 1) {
        try io.sleep(.fromMilliseconds(rto), .awake);
        try tr.mutex.lock(io);
        defer tr.mutex.unlock(io);

        if (!client.transactions.contains(tr.id)) break;

        client.socket.send(io, &client.server, tr.req) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };

        rto = rto * 2 + 500;
    }

    try tr.mutex.lock(io);
    defer tr.mutex.unlock(io);
    if (tr.done.isSet()) return;

    tr.err = error.Timeout;
    tr.done.set(io);
}

test {
    testing.refAllDecls(@This());
}
