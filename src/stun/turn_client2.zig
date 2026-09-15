const std = @import("std");
const stun = @import("stun.zig");
const BoundedDeque = @import("bounded_deque.zig").BoundedDeque;

const IpAddress = std.Io.net.IpAddress;

pub const Error = error{
    AllocationAlreadyExists,
    TooManyTransactions,
    Overflow,
} || std.Io.Writer.Error;

pub const StunError = error{
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
    TooManyPermissions,
};

pub const AllocationResult = struct {
    relayed_address: IpAddress,
    mapped_address: IpAddress,
    lifetime: u32,
};

pub const PermissionFailure = struct {
    address: IpAddress,
    err: StunError,
};

pub const Event = union(enum) {
    allocated: AllocationResult,
    allocation_failed: StunError,
    allocation_refreshed: u32,
    allocation_refresh_failed: StunError,
    permission_failed: PermissionFailure,
    permission_created: IpAddress,
};

fn AuthInfo(comptime size: u16) type {
    return struct {
        buffer: [size]u8,
        nonce_len: u32,
        realm_len: u32,
        key_len: u32,

        const empty = @This(){ .buffer = undefined, .nonce_len = 0, .realm_len = 0, .key_len = 0 };

        fn init(self: *@This(), nonce: []const u8, realm: []const u8, username: []const u8, password: []const u8) std.mem.Allocator.Error!void {
            const new_len = nonce.len + realm.len + 16; // 16 bytes for MD5 digest
            if (size < new_len) return error.OutOfMemory;

            @memcpy(self.buffer[0..nonce.len], nonce);
            @memcpy(self.buffer[nonce.len..][0..realm.len], realm);
            const digest = self.buffer[nonce.len + realm.len ..][0..16];
            digest.* = stun.longTermCredentialsKey(std.crypto.hash.Md5, username, realm, password);

            self.nonce_len = @intCast(nonce.len);
            self.realm_len = @intCast(realm.len);
            self.key_len = 16;
        }

        fn getNonce(self: *@This()) []const u8 {
            return self.buffer[0..self.nonce_len];
        }

        fn getRealm(self: *@This()) []const u8 {
            return self.buffer[self.nonce_len..][0..self.realm_len];
        }

        fn getKey(self: *@This()) []const u8 {
            return self.buffer[self.nonce_len + self.realm_len ..][0..self.key_len];
        }
    };
}

const Transaction = struct {
    id: u96,
    method: stun.Method,
    authenticated: bool,
    attempt: u8,
    payload_len: u32,
    deadline: i64,

    fn init(id: u96, method: stun.Method, deadline: i64) Transaction {
        return Transaction{
            .id = id,
            .method = method,
            .authenticated = true,
            .attempt = 0,
            .payload_len = 0,
            .deadline = deadline,
        };
    }
};

fn Transactions(comptime max_transactions: u32, comptime max_payload_size: u32) type {
    return struct {
        const Self = @This();

        items: [max_transactions]Transaction,
        req_payload: [max_payload_size * max_transactions]u8,
        current_index: u32,

        const init = Self{ .items = undefined, .req_payload = undefined, .current_index = 0 };

        fn add(self: *Self) error{TooManyTransactions}!struct { usize, []u8 } {
            if (self.current_index >= max_transactions) return error.TooManyTransactions;
            const idx = self.current_index;
            self.current_index += 1;
            return .{ idx, self.getBuffer(idx, max_payload_size) };
        }

        fn remove(self: *Self, idx: usize) void {
            self.current_index -= 1;
            const last = self.current_index;
            if (idx == last) return;

            self.items[idx] = self.items[last];
            @memcpy(self.getBuffer(idx, max_payload_size), self.getBuffer(last, max_payload_size));
        }

        fn find(self: *Self, tx_id: u96) ?usize {
            for (self.items[0..self.current_index], 0..) |tr, idx| if (tr.id == tx_id) return idx;
            return null;
        }

        fn getBuffer(self: *Self, index: usize, payload_len: u32) []u8 {
            const start = index * max_payload_size;
            return self.req_payload[start .. start + payload_len];
        }

        fn slice(self: *Self) []Transaction {
            return self.items[0..self.current_index];
        }
    };
}

fn Permissions(comptime max_permissions: u16) type {
    return struct {
        addresses: [max_permissions]IpAddress,
        current_index: u16,

        const init = @This(){ .addresses = undefined, .current_index = 0 };

        fn add(self: *@This(), address: IpAddress) error{Overflow}!bool {
            if (self.contains(address) != null) return false;
            if (self.current_index >= max_permissions) return error.Overflow;
            self.addresses[self.current_index] = address;
            self.current_index += 1;
            return true;
        }

        fn delete(self: *@This(), address: IpAddress) void {
            if (self.contains(address)) |idx| {
                self.addresses[idx] = self.addresses[self.current_index - 1];
                self.current_index -= 1;
            }
        }

        fn contains(self: *@This(), address: IpAddress) ?u16 {
            for (self.addresses[0..self.current_index], 0..) |*addr, idx| if (sameIp(addr, &address)) return @intCast(idx);
            return null;
        }

        fn slice(self: *@This()) []const IpAddress {
            return self.addresses[0..self.current_index];
        }

        fn sameIp(a: *const IpAddress, b: *const IpAddress) bool {
            if (std.meta.activeTag(a.*) != std.meta.activeTag(b.*)) return false;

            return switch (a.*) {
                .ip4 => std.mem.eql(u8, &a.ip4.bytes, &b.ip4.bytes),
                .ip6 => std.mem.eql(u8, &a.ip6.bytes, &b.ip6.bytes),
            };
        }
    };
}

pub const TurnClientConfig = struct {
    local_addr: IpAddress,
    remote_addr: IpAddress,
    random: std.Random,
    username: []const u8,
    password: []const u8,
};

pub const Config = struct {
    max_payload_size: u32 = 384,
    max_transactions: u32 = 8,
    max_permissions: u16 = 16,
};

pub fn TurnClient(comptime config: Config) type {
    return struct {
        const Self = @This();

        pub const base_rto = 200; // milliseconds
        const permission_refresh_interval = 4 * std.time.ms_per_min;
        const max_attempts = 7;

        local_addr: IpAddress,
        remote_addr: IpAddress,
        random: std.Random,
        username: []const u8,
        password: []const u8,

        auth_info: AuthInfo(128),
        transactions: Transactions(config.max_transactions, config.max_payload_size),
        events_out: BoundedDeque(Event, config.max_transactions),
        transmits: BoundedDeque(stun.TransportMessage, config.max_transactions),
        permissions: Permissions(config.max_permissions),

        allocation_lifetime: u32,
        allocation_refresh_deadline: i64,
        permission_refresh_deadline: i64,

        pub fn init(turn_config: TurnClientConfig) Self {
            return .{
                .random = turn_config.random,
                .local_addr = turn_config.local_addr,
                .remote_addr = turn_config.remote_addr,
                .username = turn_config.username,
                .password = turn_config.password,
                .auth_info = .empty,
                .transactions = .init,
                .events_out = .empty,
                .transmits = .empty,
                .permissions = .init,
                .allocation_lifetime = 0,
                .allocation_refresh_deadline = 0,
                .permission_refresh_deadline = 0,
            };
        }

        pub fn createAllocation(c: *Self, now: i64) Error!void {
            if (c.allocation_refresh_deadline != 0) return error.AllocationAlreadyExists;
            try c.newAllocateRequest(now, false);
        }

        pub fn hasAllocation(c: *Self) bool {
            return c.allocation_refresh_deadline != 0;
        }

        pub fn deleteAllocation(c: *Self, buffer: []u8) !void {
            if (c.allocation_refresh_deadline == 0) return;

            const id = c.random.int(u96);
            var w = stun.Writer.init(buffer, .{ .password = c.auth_info.getKey() });
            try writeHeader(&w, .request, .refresh, id);
            try w.writeAttributes(&.{
                .{ .lifetime = 0 },
                .{ .username = c.username },
                .{ .realm = c.auth_info.getRealm() },
                .{ .nonce = c.auth_info.getNonce() },
                .{ .message_integrity = &.{} },
                .fingerprint,
            });

            const msg = w.final();
            c.allocation_refresh_deadline = 0;

            try c.transmits.pushBack(.{
                .from = &c.local_addr,
                .to = &c.remote_addr,
                .data = msg,
            });
        }

        pub fn createPermission(c: *Self, address: IpAddress, now: i64) !void {
            if (c.permissions.contains(address) != null) return;
            try c.newCreatePermissionRequest(&.{address}, now);
        }

        pub fn handleTimeout(c: *Self, now: i64) Error!void {
            if (c.allocation_refresh_deadline != 0 and now >= c.allocation_refresh_deadline) {
                c.allocation_refresh_deadline = now + (c.allocation_lifetime / 2) * std.time.ms_per_s;
                try c.newRefreshRequest(now);
            }

            if (c.permission_refresh_deadline != 0 and now >= c.permission_refresh_deadline) {
                c.permission_refresh_deadline = now + permission_refresh_interval;
                try c.newCreatePermissionRequest(c.permissions.slice(), now);
            }

            var idx: usize = c.transactions.current_index;
            while (idx > 0) {
                idx -= 1;
                const tr = &c.transactions.items[idx];
                if (tr.deadline > now) continue;

                tr.attempt += 1;
                if (tr.attempt >= max_attempts) {
                    c.transactions.remove(idx);
                    switch (tr.method) {
                        .allocate => try c.events_out.pushBack(.{ .allocation_failed = StunError.Timeout }),
                        .refresh => try c.events_out.pushBack(.{ .allocation_refresh_failed = StunError.Timeout }),
                        .create_permission => {
                            const peer_address = c.getXorPeerAddress(idx, tr.payload_len);
                            try c.events_out.pushBack(.{ .permission_failed = .{
                                .address = peer_address,
                                .err = StunError.Timeout,
                            } });
                        },
                        else => {},
                    }
                } else {
                    tr.deadline = now + @as(i64, tr.attempt + 1) * base_rto;
                    try c.transmits.pushBack(.{
                        .from = &c.local_addr,
                        .to = &c.remote_addr,
                        .data = c.transactions.getBuffer(idx, tr.payload_len),
                    });
                }
            }
        }

        pub fn handleRead(c: *Self, buffer: []const u8, now: i64) !void {
            const msg = try stun.Message.parse(buffer);
            const idx = c.transactions.find(msg.header.transaction_id) orelse return;
            const tr = c.transactions.items[idx];
            // Read anything the handler needs from the request buffer before it's
            // overwritten by the swap-remove below.
            const peer_address = if (tr.method == .create_permission) c.getXorPeerAddress(idx, tr.payload_len) else undefined;
            c.transactions.remove(idx);

            switch (tr.method) {
                .allocate => try c.handleAllocateResponse(&tr, &msg, now),
                .refresh => try c.handleRefreshResponse(&tr, &msg, now),
                .create_permission => try c.handleCreatePermissionResponse(peer_address, &tr, &msg, now),
                else => {},
            }
        }

        /// Get the header size and the total size of a TURN message for user data.
        ///
        /// Each message to a turn server needs to be prefixed by channel number or
        /// encapsulated in send indication.
        pub fn getDataFrameSize(c: *Self, peer: *const IpAddress, payload_len: usize) struct { u32, usize } {
            _ = c;
            // When channel number is used for this peer, return 4 bytes.
            const prefix: u32 = switch (peer.*) {
                .ip4 => 36,
                .ip6 => 48,
            };

            const padding = (4 - (payload_len % 4)) % 4;
            return .{ prefix, prefix + payload_len + padding };
        }

        pub fn writeDataHeader(c: *Self, peer: *const IpAddress, buffer: []u8, payload_len: usize) void {
            const header_size, const size = c.getDataFrameSize(peer, payload_len);
            std.debug.assert(buffer.len >= header_size);

            var w = stun.Writer.init(buffer, .{});
            w.writeHeader(.{
                .message_length = @intCast(size - 20),
                .message_type = .fromClassAndMethod(.indication, .send),
                .transaction_id = 0,
            }) catch {};
            w.writeAttribute(.{ .xor_peer_address = peer.* }) catch {};

            const len = w.writer.buffered().len;
            std.mem.writeInt(u16, buffer[len..][0..2], @intFromEnum(stun.AttributeType.data), .big);
            std.mem.writeInt(u16, buffer[len + 2 ..][0..2], @intCast(payload_len), .big);
        }

        pub fn pollTimeout(c: *Self) ?i64 {
            var next_deadline: i64 = std.math.maxInt(i64);
            for (c.transactions.slice()) |tr| {
                next_deadline = @min(next_deadline, tr.deadline);
            }

            if (c.allocation_refresh_deadline != 0) next_deadline = @min(next_deadline, c.allocation_refresh_deadline);
            if (c.permission_refresh_deadline != 0) next_deadline = @min(next_deadline, c.permission_refresh_deadline);
            return if (next_deadline == std.math.maxInt(i64)) null else next_deadline;
        }

        pub fn pollEvent(c: *Self) ?Event {
            return c.events_out.popFront();
        }

        pub fn pollTransmit(c: *Self) ?stun.TransportMessage {
            return c.transmits.popFront();
        }

        fn handleAllocateResponse(c: *Self, tr: *const Transaction, msg: *const stun.Message, now: i64) !void {
            switch (msg.header.message_type.class()) {
                .error_response => {
                    if (tr.authenticated) {
                        try c.events_out.pushBack(.{ .allocation_failed = StunError.Unauthorized });
                        return;
                    }
                    try c.applyChallenge(msg);
                    try c.newAllocateRequest(now, true);
                },
                .success_response => {
                    const result = try c.parseAllocation(msg);
                    try c.events_out.pushBack(result);
                    if (result == .allocated) {
                        c.allocation_lifetime = result.allocated.lifetime;
                        c.allocation_refresh_deadline = now + (result.allocated.lifetime / 2) * std.time.ms_per_s;
                    }
                },
                else => {},
            }
        }

        fn handleRefreshResponse(c: *Self, tr: *const Transaction, msg: *const stun.Message, now: i64) !void {
            _ = tr;

            switch (msg.header.message_type.class()) {
                .error_response => {
                    c.applyChallenge(msg) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.Discard => return,
                        else => |e| {
                            try c.events_out.pushBack(.{ .allocation_refresh_failed = e });
                            return;
                        },
                    };
                    try c.newRefreshRequest(now);
                },
                .success_response => {
                    const lifetime = c.parseRefresh(msg) catch |err| switch (err) {
                        error.Discard => return,
                        else => |e| {
                            try c.events_out.pushBack(.{ .allocation_refresh_failed = e });
                            return;
                        },
                    };
                    c.allocation_lifetime = lifetime;
                    c.allocation_refresh_deadline = now + (c.allocation_lifetime / 2) * std.time.ms_per_s;

                    try c.events_out.pushBack(.{ .allocation_refreshed = lifetime });
                },
                else => {},
            }
        }

        fn handleCreatePermissionResponse(c: *Self, address: IpAddress, tr: *const Transaction, msg: *const stun.Message, now: i64) !void {
            _ = tr;

            switch (msg.header.message_type.class()) {
                .error_response => {
                    c.applyChallenge(msg) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.Discard => return,
                        else => |e| {
                            try c.events_out.pushBack(.{ .permission_failed = .{ .address = address, .err = e } });
                            return;
                        },
                    };
                    try c.newCreatePermissionRequest(&.{address}, now);
                },
                .success_response => {
                    const added = c.permissions.add(address) catch {
                        try c.events_out.pushBack(.{ .permission_failed = .{
                            .address = address,
                            .err = StunError.TooManyPermissions,
                        } });
                        return;
                    };

                    // Do not store event for permissions that were already present or refreshed.
                    if (added) {
                        try c.events_out.pushBack(.{ .permission_created = address });
                        if (c.permission_refresh_deadline == 0) c.permission_refresh_deadline = now + permission_refresh_interval;
                    }
                },
                else => {},
            }
        }

        fn newAllocateRequest(c: *Self, now: i64, authenticated: bool) !void {
            const idx, const buffer = try c.transactions.add();
            const new_tr = try c.buildAllocateRequest(buffer, now, authenticated);

            c.transactions.items[idx] = new_tr;
            try c.transmits.pushBack(.{
                .from = &c.local_addr,
                .to = &c.remote_addr,
                .data = c.transactions.getBuffer(idx, new_tr.payload_len),
            });
        }

        fn newRefreshRequest(c: *Self, now: i64) !void {
            const idx, const buffer = try c.transactions.add();
            const tr = try c.buildRefreshRequest(buffer, now);

            c.transactions.items[idx] = tr;
            try c.transmits.pushBack(.{
                .from = &c.local_addr,
                .to = &c.remote_addr,
                .data = c.transactions.getBuffer(idx, tr.payload_len),
            });
        }

        fn newCreatePermissionRequest(c: *Self, addresses: []const IpAddress, now: i64) !void {
            const idx, const buffer = try c.transactions.add();
            const tr = try c.buildCreatePermissionRequest(addresses, buffer, now);

            c.transactions.items[idx] = tr;

            try c.transmits.pushBack(.{
                .from = &c.local_addr,
                .to = &c.remote_addr,
                .data = c.transactions.getBuffer(idx, tr.payload_len),
            });
        }

        /// Extracts REALM/NONCE from a 401/438 error response and derives the long-term credentials key.
        fn applyChallenge(c: *Self, msg: *const stun.Message) !void {
            var realm: ?[]const u8 = null;
            var nonce: ?[]const u8 = null;
            var code: ?stun.StunErrorCode = null;

            var it = msg.iterateAttributes(c.auth_info.getKey());
            while (it.next() catch return error.Discard) |attr| switch (attr) {
                .realm => realm = attr.realm,
                .nonce => nonce = attr.nonce,
                .error_code => code = attr.error_code.code,
                else => {},
            };

            switch (code orelse return error.MissingErrorCode) {
                .unauthorized, .stale_nonce => {},
                else => |co| return errorFromCode(co),
            }

            if (realm == null) return error.MissingRealm;
            if (nonce == null) return error.MissingNonce;

            try c.auth_info.init(nonce.?, realm.?, c.username, c.password);
        }

        fn buildAllocateRequest(c: *Self, buffer: []u8, now: i64, authenticated: bool) !Transaction {
            const tx_id = c.random.int(u96);

            var transaction = Transaction{
                .id = tx_id,
                .method = .allocate,
                .authenticated = authenticated,
                .attempt = 0,
                .payload_len = 0,
                .deadline = now + base_rto,
            };

            var w = stun.Writer.init(buffer, .{ .password = if (authenticated) c.auth_info.getKey() else null });
            try writeHeader(&w, .request, .allocate, tx_id);
            try w.writeAttribute(.{ .requested_transport = .udp });
            try w.writeAttribute(.{ .requested_address_family = std.meta.activeTag(c.local_addr) });

            if (authenticated) {
                try w.writeAttributes(&.{
                    .{ .username = c.username },
                    .{ .realm = c.auth_info.getRealm() },
                    .{ .nonce = c.auth_info.getNonce() },
                    .{ .message_integrity = &.{} },
                    .fingerprint,
                });
            }

            transaction.payload_len = @intCast(w.final().len);
            return transaction;
        }

        fn buildRefreshRequest(c: *Self, buffer: []u8, now: i64) !Transaction {
            var tr = Transaction{
                .id = c.random.int(u96),
                .method = .refresh,
                .authenticated = true,
                .attempt = 0,
                .payload_len = 0,
                .deadline = now + base_rto,
            };

            var w = stun.Writer.init(buffer, .{ .password = c.auth_info.getKey() });
            try writeHeader(&w, .request, .refresh, tr.id);
            try w.writeAttributes(&.{
                .{ .lifetime = c.allocation_lifetime },
                .{ .username = c.username },
                .{ .realm = c.auth_info.getRealm() },
                .{ .nonce = c.auth_info.getNonce() },
                .{ .message_integrity = &.{} },
                .fingerprint,
            });

            tr.payload_len = @intCast(w.final().len);
            return tr;
        }

        fn buildCreatePermissionRequest(c: *Self, addresses: []const IpAddress, buffer: []u8, now: i64) !Transaction {
            var tr = Transaction.init(c.random.int(u96), .create_permission, now + base_rto);

            var w = stun.Writer.init(buffer, .{ .password = c.auth_info.getKey() });
            try writeHeader(&w, .request, .create_permission, tr.id);
            for (addresses) |addr| try w.writeAttribute(.{ .xor_peer_address = addr });
            try w.writeAttributes(&.{
                .{ .username = c.username },
                .{ .realm = c.auth_info.getRealm() },
                .{ .nonce = c.auth_info.getNonce() },
                .{ .message_integrity = &.{} },
                .fingerprint,
            });

            tr.payload_len = @intCast(w.final().len);
            return tr;
        }

        fn parseAllocation(client: *Self, msg: *const stun.Message) !Event {
            var relayed_address: ?IpAddress = null;
            var mapped_address: ?IpAddress = null;
            var lifetime: ?u32 = null;
            var code: ?stun.StunErrorCode = null;

            var it = msg.iterateAttributes(client.auth_info.getKey());
            while (try it.next()) |attr| switch (attr) {
                .xor_relayed_address => |addr| relayed_address = addr,
                .xor_mapped_address => |addr| mapped_address = addr,
                .lifetime => lifetime = attr.lifetime,
                .error_code => code = attr.error_code.code,
                else => {},
            };

            if (code) |c| return .{ .allocation_failed = errorFromCode(c) };

            return .{ .allocated = .{
                .relayed_address = relayed_address orelse return .{ .allocation_failed = error.MissingRelayedAddress },
                .mapped_address = mapped_address orelse return .{ .allocation_failed = error.MissingMappedAddress },
                .lifetime = lifetime orelse return .{ .allocation_failed = error.MissingLifetime },
            } };
        }

        fn parseRefresh(client: *Self, msg: *const stun.Message) !u32 {
            var lifetime: ?u32 = null;
            var code: ?stun.StunErrorCode = null;

            var it = msg.iterateAttributes(client.auth_info.getKey());
            while (it.next() catch return error.Discard) |attr| switch (attr) {
                .lifetime => lifetime = attr.lifetime,
                .error_code => code = attr.error_code.code,
                else => {},
            };

            if (code) |c| return errorFromCode(c);
            return lifetime orelse return error.MissingLifetime;
        }

        fn errorFromCode(code: stun.StunErrorCode) StunError {
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

        fn getXorPeerAddress(c: *Self, idx: usize, payload_len: u32) IpAddress {
            const request = stun.Message.parse(c.transactions.getBuffer(idx, payload_len)) catch unreachable;
            var it = request.iterateAttributes(&.{});
            while (it.next() catch unreachable) |attr| {
                if (attr == .xor_peer_address) return attr.xor_peer_address;
            }
            unreachable;
        }
    };
}

fn writeHeader(w: *stun.Writer, class: stun.Class, method: stun.Method, tx_id: u96) !void {
    try w.writeHeader(.{
        .message_length = 0,
        .message_type = .fromClassAndMethod(class, method),
        .transaction_id = tx_id,
    });
}

const TestTurnClient = TurnClient(.{});

fn testClient(random: std.Random) TestTurnClient {
    return TestTurnClient.init(.{
        .local_addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 12345 } },
        .remote_addr = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 3478 } },
        .random = random,
        .username = "user",
        .password = "pass",
    });
}

test "createAllocation: queues an unauthenticated allocate request" {
    var r = std.Random.DefaultPrng.init(std.testing.random_seed);
    var c = testClient(r.random());

    try c.createAllocation(0);

    const out = c.pollTransmit() orelse return error.ExpectedOutput;
    try std.testing.expect(out.from.eql(&c.local_addr));
    try std.testing.expect(out.to.eql(&c.remote_addr));
    try std.testing.expectEqual(null, c.pollTransmit());

    const msg = try stun.Message.parse(out.data);
    try std.testing.expectEqual(.request, msg.header.message_type.class());
    try std.testing.expectEqual(.allocate, msg.header.message_type.method());

    var it = msg.iterateAttributes(&.{});
    var attribute = try it.next() orelse return error.ExpectedAttribute;
    try std.testing.expectEqual(.udp, attribute.requested_transport);

    attribute = try it.next() orelse return error.ExpectedAttribute;
    try std.testing.expectEqual(.ip4, attribute.requested_address_family);

    try std.testing.expectEqual(null, try it.next());
}

test "createAllocation: registers a transaction with a retransmit deadline" {
    var r = std.Random.DefaultPrng.init(std.testing.random_seed);
    var c = testClient(r.random());

    try c.createAllocation(1000);

    var found: ?Transaction = null;
    for (c.transactions.slice()) |tr| {
        found = tr;
    }

    const tr = found orelse return error.ExpectedTransaction;
    try std.testing.expectEqual(.allocate, tr.method);
    try std.testing.expectEqual(false, tr.authenticated);
    try std.testing.expectEqual(0, tr.attempt);
    try std.testing.expectEqual(1000 + TestTurnClient.base_rto, tr.deadline);
    try std.testing.expectEqual(1000 + TestTurnClient.base_rto, c.pollTimeout());
}

test "createAllocation: fails when an allocation already exists" {
    var r = std.Random.DefaultPrng.init(std.testing.random_seed);
    var c = testClient(r.random());

    c.allocation_refresh_deadline = 5000;
    try std.testing.expectError(error.AllocationAlreadyExists, c.createAllocation(0));
    try std.testing.expectEqual(null, c.pollTransmit());
}

test "createAllocation: fails when no transaction slot is free" {
    var r = std.Random.DefaultPrng.init(std.testing.random_seed);
    var c = testClient(r.random());

    c.transactions.current_index = c.transactions.items.len;

    try std.testing.expectError(error.TooManyTransactions, c.createAllocation(0));
    try std.testing.expectEqual(null, c.pollTransmit());
}

test "deleteAllocation: does nothing without an active allocation" {
    var r = std.Random.DefaultPrng.init(std.testing.random_seed);
    var c = testClient(r.random());

    var buffer: [1024]u8 = undefined;
    try c.deleteAllocation(&buffer);

    try std.testing.expectEqual(null, c.pollTransmit());
}

test "deleteAllocation: queues a refresh request with lifetime zero and clears the deadline" {
    var r = std.Random.DefaultPrng.init(std.testing.random_seed);
    var c = testClient(r.random());
    c.allocation_refresh_deadline = 5000;

    var buffer: [1024]u8 = undefined;
    try c.deleteAllocation(&buffer);

    try std.testing.expectEqual(0, c.allocation_refresh_deadline);

    const out = c.pollTransmit() orelse return error.ExpectedOutput;
    try std.testing.expect(out.from.eql(&c.local_addr));
    try std.testing.expect(out.to.eql(&c.remote_addr));
    try std.testing.expectEqual(null, c.pollTransmit());

    const msg = try stun.Message.parse(out.data);
    try std.testing.expectEqual(.request, msg.header.message_type.class());
    try std.testing.expectEqual(.refresh, msg.header.message_type.method());

    var it = msg.iterateAttributes(&.{});
    const attribute = try it.next() orelse return error.ExpectedAttribute;
    try std.testing.expectEqual(0, attribute.lifetime);
}

test "createPermission: queues a create_permission request for the peer address" {
    var r = std.Random.DefaultPrng.init(std.testing.random_seed);
    var c = testClient(r.random());

    const peer = try IpAddress.parse("192.0.2.1", 3478);
    try c.createPermission(peer, 0);

    const out = c.pollTransmit() orelse return error.ExpectedOutput;
    try std.testing.expectEqual(null, c.pollTransmit());

    const msg = try stun.Message.parse(out.data);
    try std.testing.expectEqual(.request, msg.header.message_type.class());
    try std.testing.expectEqual(.create_permission, msg.header.message_type.method());

    var it = msg.iterateAttributes(&.{});
    const attribute = try it.next() orelse return error.ExpectedAttribute;
    try std.testing.expect(attribute.xor_peer_address.eql(&peer));
}

test "createPermission: success response emits permission_created" {
    var r = std.Random.DefaultPrng.init(std.testing.random_seed);
    var c = testClient(r.random());

    const peer = try IpAddress.parse("192.0.2.1", 3478);
    try c.createPermission(peer, 0);

    const out = c.pollTransmit() orelse return error.ExpectedOutput;
    const request = try stun.Message.parse(out.data);

    var response_buf: [1024]u8 = undefined;
    var w = stun.Writer.init(&response_buf, .{});
    try writeHeader(&w, .success_response, .create_permission, request.header.transaction_id);
    try c.handleRead(w.final(), 0);

    const event = c.pollEvent() orelse return error.ExpectedEvent;
    switch (event) {
        .permission_created => |addr| try std.testing.expect(addr.eql(&peer)),
        else => return error.UnexpectedEvent,
    }
    try std.testing.expectEqual(null, c.pollEvent());
}

test "createPermission: unauthorized then a hard failure emits permission_failed" {
    var r = std.Random.DefaultPrng.init(std.testing.random_seed);
    var c = testClient(r.random());

    const peer = try IpAddress.parse("192.0.2.1", 3478);
    try c.createPermission(peer, 0);

    var out = c.pollTransmit() orelse return error.ExpectedOutput;
    var request = try stun.Message.parse(out.data);

    var response_buf: [1024]u8 = undefined;
    {
        var w = stun.Writer.init(&response_buf, .{});
        try writeHeader(&w, .error_response, .create_permission, request.header.transaction_id);
        try w.writeAttributes(&.{
            .{ .error_code = .{ .code = .unauthorized, .reason = "Unauthorized" } },
            .{ .realm = "realm" },
            .{ .nonce = "nonce" },
        });
        try c.handleRead(w.final(), 0);
    }
    try std.testing.expectEqual(null, c.pollEvent());

    out = c.pollTransmit() orelse return error.ExpectedOutput;
    request = try stun.Message.parse(out.data);

    {
        var w = stun.Writer.init(&response_buf, .{});
        try writeHeader(&w, .error_response, .create_permission, request.header.transaction_id);
        try w.writeAttribute(.{ .error_code = .{ .code = .forbidden, .reason = "Forbidden" } });
        try c.handleRead(w.final(), 0);
    }

    const event = c.pollEvent() orelse return error.ExpectedEvent;
    switch (event) {
        .permission_failed => |failure| {
            try std.testing.expect(failure.address.eql(&peer));
            try std.testing.expectEqual(error.Forbidden, failure.err);
        },
        else => return error.UnexpectedEvent,
    }
}

test "hasAllocation: reflects the allocation lifecycle" {
    var r = std.Random.DefaultPrng.init(std.testing.random_seed);
    var c = testClient(r.random());

    try std.testing.expect(!c.hasAllocation());

    try c.createAllocation(0);
    const out = c.pollTransmit() orelse return error.ExpectedOutput;
    const request = try stun.Message.parse(out.data);

    var response_buf: [1024]u8 = undefined;
    var w = stun.Writer.init(&response_buf, .{});
    try writeHeader(&w, .success_response, .allocate, request.header.transaction_id);
    try w.writeAttributes(&.{
        .{ .xor_relayed_address = try IpAddress.parse("203.0.113.9", 40000) },
        .{ .xor_mapped_address = try IpAddress.parse("198.51.100.1", 5000) },
        .{ .lifetime = 600 },
    });
    try c.handleRead(w.final(), 0);

    try std.testing.expect(c.hasAllocation());

    var buffer: [1024]u8 = undefined;
    try c.deleteAllocation(&buffer);
    try std.testing.expect(!c.hasAllocation());
}

test "handleTimeout: exhausting retries emits the failure event for the transaction's method" {
    // allocate: never answered, exhausts retries as allocation_failed.
    {
        var r = std.Random.DefaultPrng.init(std.testing.random_seed);
        var c = testClient(r.random());

        try c.createAllocation(0);

        var now: i64 = 0;
        for (0..TestTurnClient.max_attempts) |_| {
            now = (c.pollTimeout() orelse return error.ExpectedTimeout) + 1;
            try c.handleTimeout(now);
        }

        const event = c.pollEvent() orelse return error.ExpectedEvent;
        try std.testing.expectEqual(StunError.Timeout, event.allocation_failed);
    }

    // refresh: active allocation whose refresh transaction times out.
    {
        var r = std.Random.DefaultPrng.init(std.testing.random_seed);
        var c = testClient(r.random());
        c.allocation_lifetime = 600;
        c.allocation_refresh_deadline = 1;

        var now: i64 = 1;
        try c.handleTimeout(now);
        _ = c.pollTransmit() orelse return error.ExpectedOutput;

        for (0..TestTurnClient.max_attempts) |_| {
            now = (c.pollTimeout() orelse return error.ExpectedTimeout) + 1;
            try c.handleTimeout(now);
        }

        const event = c.pollEvent() orelse return error.ExpectedEvent;
        try std.testing.expectEqual(StunError.Timeout, event.allocation_refresh_failed);
    }

    // create_permission: exhausts retries and reports the peer address.
    {
        var r = std.Random.DefaultPrng.init(std.testing.random_seed);
        var c = testClient(r.random());

        const peer = try IpAddress.parse("192.0.2.1", 3478);
        try c.createPermission(peer, 0);

        var now: i64 = 0;
        for (0..TestTurnClient.max_attempts) |_| {
            now = (c.pollTimeout() orelse return error.ExpectedTimeout) + 1;
            try c.handleTimeout(now);
        }

        const event = c.pollEvent() orelse return error.ExpectedEvent;
        switch (event) {
            .permission_failed => |failure| {
                try std.testing.expect(failure.address.eql(&peer));
                try std.testing.expectEqual(StunError.Timeout, failure.err);
            },
            else => return error.UnexpectedEvent,
        }
    }
}
