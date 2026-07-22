const std = @import("std");
const stun = @import("stun");
const ice = @import("ice.zig");
const CandidatePair = @import("candidate_pair.zig");
const Messages = @import("messages.zig");

const Core = @This();
const Candidate = ice.Candidate;
const IpAddress = std.Io.net.IpAddress;

/// The maximum number of binding requests sent on a pair before it is
/// considered failed.
pub const max_binding_requests: usize = 7;

allocator: std.mem.Allocator,
connection_state: ice.ConnectionState = .new,
gathering_state: ice.GatheringState = .new,

role: ice.Role,
credentials: ice.Credentials,
remote_credentials: ?ice.Credentials = null,
tie_breaker: u64,

// Candidates and sockets
candidates: std.ArrayList(Candidate) = .empty,
remote_candidates: std.ArrayList(Candidate) = .empty,
pairs: std.ArrayList(CandidatePair) = .empty,
pending_requests: std.ArrayList(PendingRequest) = .empty,
// This is a peer for which a use-candidate request is sent, but we didn't
// receive response yet.
selected_pair: ?CandidatePair = null,
// This the final pair selected by this agent or the remote one.
nominated_pair: ?CandidatePair = null,

const PendingRequest = struct {
    transaction_id: u96,
    source: IpAddress,
    target: IpAddress,
};

pub const Send = struct {
    payload: []const u8,
    from_base: IpAddress,
    to: IpAddress,
    use_candidate: bool,
};

pub const ConnectivityChecks = struct {
    core: *Core,
    nomination_done: bool = false,
    index: usize = 0,

    pub fn next(self: *ConnectivityChecks, buffer: []u8, tx_id: u96) !?Send {
        const core = self.core;

        if (!self.nomination_done) {
            self.nomination_done = true;
            if (core.selected_pair) |selected| {
                const payload = try core.buildBindingRequest(tx_id, true, buffer);
                try core.pending_requests.append(core.allocator, .{
                    .transaction_id = tx_id,
                    .source = selected.local.base,
                    .target = selected.remote.address,
                });
                return .{
                    .payload = payload,
                    .from_base = selected.local.base,
                    .to = selected.remote.address,
                    .use_candidate = true,
                };
            }
        }

        while (self.index < core.pairs.items.len) {
            const pair = &core.pairs.items[self.index];
            self.index += 1;
            switch (pair.status) {
                .waiting, .in_progress => {
                    pair.conn_check_count += 1;
                    if (pair.conn_check_count > max_binding_requests) {
                        pair.status = .failed;
                        continue;
                    }
                    const payload = try core.buildBindingRequest(tx_id, false, buffer);
                    try core.pending_requests.append(core.allocator, .{
                        .transaction_id = tx_id,
                        .source = pair.local.base,
                        .target = pair.remote.address,
                    });
                    return .{
                        .payload = payload,
                        .from_base = pair.local.base,
                        .to = pair.remote.address,
                        .use_candidate = false,
                    };
                },
                else => {},
            }
        }

        return null;
    }
};

pub fn init(allocator: std.mem.Allocator, role: ice.Role, credentials: ice.Credentials, tie_breaker: u64) Core {
    return .{
        .allocator = allocator,
        .role = role,
        .credentials = credentials,
        .tie_breaker = tie_breaker,
    };
}

pub fn deinit(core: *Core) void {
    core.candidates.deinit(core.allocator);
    core.remote_candidates.deinit(core.allocator);
    core.pairs.deinit(core.allocator);
    core.pending_requests.deinit(core.allocator);

    core.credentials.deinit(core.allocator);
    if (core.remote_credentials) |*remote| {
        remote.deinit(core.allocator);
        core.remote_credentials = null;
    }

    core.connection_state = .closed;
}

/// Release the connectivity-check bookkeeping once the connection is complete.
///
/// The nominated pair is kept (it lives in its own field); the checklist,
/// remote candidates and pending requests are no longer needed.
pub fn onComplete(core: *Core) void {
    core.remote_candidates.clearAndFree(core.allocator);
    core.pairs.clearAndFree(core.allocator);
    core.pending_requests.clearAndFree(core.allocator);
}

pub fn addHostCandidate(core: *Core, addr: std.Io.net.IpAddress) !?Candidate {
    const candidate = Candidate.initHost(addr);
    return if (try core.addLocalCandidate(candidate)) candidate else null;
}

pub fn addServerReflexiveCandidate(core: *Core, base: IpAddress, mapped: IpAddress) !?Candidate {
    for (core.candidates.items) |candidate|
        if (candidate.candidate_type == .host and ipEql(&candidate.base, &mapped)) return null;

    const candidate = Candidate.initServerReflexive(base, mapped);
    return if (try core.addLocalCandidate(candidate)) candidate else null;
}

pub fn handleConsentFreshness(core: *Core, message: std.Io.net.IncomingMessage, buffer: []u8) !?[]const u8 {
    const msg = try stun.Message.parse(message.data);
    switch (msg.header.message_type.class()) {
        .request => {
            _ = try Messages.parseAndValidateStunRequest(
                &msg,
                core.credentials,
                core.role,
                core.tie_breaker,
            );
            return try Messages.buildSuccessResponse(&msg, core.credentials.password, message.from, buffer);
        },
        else => {},
    }

    return null;
}

pub fn addRemoteCandidate(core: *Core, remote_candidate: Candidate) std.mem.Allocator.Error!void {
    try core.remote_candidates.append(core.allocator, remote_candidate);

    outer_loop: for (core.candidates.items) |candidate| {
        for (core.pairs.items) |*pair|
            if (pair.local.base.eql(&candidate.base) and pair.remote.address.eql(&remote_candidate.address))
                continue :outer_loop;

        try core.pairs.append(core.allocator, .{
            .local = candidate,
            .remote = remote_candidate,
            .priority = calculatePairPriority(candidate.priority, remote_candidate.priority, core.role),
        });
    }
}

/// Returns `false` if an identical candidate already exists.
pub fn addLocalCandidate(core: *Core, candidate: Candidate) std.mem.Allocator.Error!bool {
    for (core.candidates.items) |*existing| if (existing.eql(&candidate)) return false;

    try core.candidates.append(core.allocator, candidate);

    outer_loop: for (core.remote_candidates.items) |remote_candidate| {
        for (core.pairs.items) |*pair|
            if (pair.local.base.eql(&candidate.base) and pair.remote.address.eql(&remote_candidate.address))
                continue :outer_loop;

        try core.pairs.append(core.allocator, .{
            .local = candidate,
            .remote = remote_candidate,
            .priority = calculatePairPriority(candidate.priority, remote_candidate.priority, core.role),
        });
    }

    return true;
}

/// Compare addresses by IP only, ignoring port.
fn ipEql(a: *const IpAddress, b: *const IpAddress) bool {
    return switch (a.*) {
        .ip4 => |a_ip4| switch (b.*) {
            .ip4 => |b_ip4| std.mem.eql(u8, &a_ip4.bytes, &b_ip4.bytes),
            else => false,
        },
        .ip6 => |a_ip6| switch (b.*) {
            .ip6 => |b_ip6| std.mem.eql(u8, &a_ip6.bytes, &b_ip6.bytes),
            else => false,
        },
    };
}

/// Begin a connectivity-check round. Returns null when a pair is already
/// nominated (nothing to do). Performs the controlling-side best-pair selection.
pub fn beginConnectivityChecks(core: *Core) ?ConnectivityChecks {
    if (core.nominated_pair != null) return null;
    if (core.role == .controlling and core.selected_pair == null)
        core.selected_pair = core.selectBestPair();
    return .{ .core = core };
}

pub fn detectNominatedPair(core: *Core) ?CandidatePair {
    if (core.role == .controlling or core.nominated_pair != null) return null;
    for (core.pairs.items) |pair| if (pair.nominated) {
        core.nominated_pair = pair;
        return pair;
    };
    return null;
}

pub fn markConnected(core: *Core) bool {
    if (core.nominated_pair != null and core.connection_state != .connected) {
        core.connection_state = .connected;
        return true;
    }
    return false;
}

pub fn onConsentTimeout(core: *Core) ?ice.ConnectionState {
    switch (core.connection_state) {
        .connected, .completed => {
            core.connection_state = .disconnected;
            return .disconnected;
        },
        .disconnected => {
            core.connection_state = .failed;
            return .failed;
        },
        else => return null,
    }
}

pub fn buildBindingRequest(core: *Core, tx_id: u96, use_candidate: bool, buffer: []u8) ![]const u8 {
    var w = stun.Writer.init(buffer, .{ .password = core.remote_credentials.?.password });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.request, .binding),
        .transaction_id = tx_id,
        .message_length = 0,
    });

    var username = [_][]const u8{ core.remote_credentials.?.username, ":", core.credentials.username };
    try w.writeRaw(.username, &username);
    try w.writeAttribute(.{ .priority = ice.CandidateType.prflx.priority() });
    const role_attribute: stun.Attribute = switch (core.role) {
        .controlled => .{ .ice_controlled = core.tie_breaker },
        .controlling => .{ .ice_controlling = core.tie_breaker },
    };
    if (use_candidate) try w.writeAttribute(.use_candidate);
    try w.writeAttribute(role_attribute);
    try w.writeAttribute(.{ .message_integrity = &.{} });
    try w.writeAttribute(.fingerprint);

    return w.final();
}

pub fn handleRequest(core: *Core, msg: *const stun.Message, base_addr: IpAddress, from: IpAddress, buffer: []u8) ![]const u8 {
    const stun_req = Messages.parseAndValidateStunRequest(msg, core.credentials, core.role, core.tie_breaker) catch |err| switch (err) {
        error.RoleConflict => return try Messages.buildRoleConflictErrorMessage(msg.header.transaction_id, core.credentials.password, buffer),
        else => |e| return e,
    };

    if (core.findCandidatePair(&base_addr, &from)) |candidate_pair| {
        switch (candidate_pair.status) {
            .succeeded => candidate_pair.nominated |= stun_req.use_candidate,
            else => candidate_pair.nominate_on_binding |= stun_req.use_candidate,
        }
    } else {
        const local: Candidate = .initHost(base_addr);
        const remote: Candidate = .{
            .base = from,
            .address = from,
            .candidate_type = .prflx,
            .priority = stun_req.priority,
        };

        try core.pairs.append(core.allocator, .{
            .local = local,
            .remote = remote,
            .priority = calculatePairPriority(local.priority, remote.priority, core.role),
            .status = .in_progress,
            .nominate_on_binding = stun_req.use_candidate,
        });
    }

    return try Messages.buildSuccessResponse(msg, core.credentials.password, from, buffer);
}

pub fn handleSuccessResponse(core: *Core, msg: *const stun.Message, base_addr: IpAddress, from: IpAddress) !void {
    // Logger.debug("Handle success response on {f} from {f}", .{ base_addr, from });

    const pending_request = blk: {
        const tx_id = msg.header.transaction_id;
        for (core.pending_requests.items, 0..) |pr, i| {
            if (pr.transaction_id == tx_id) {
                const pending_request = core.pending_requests.swapRemove(i);
                break :blk pending_request;
            }
        }

        return;
    };

    if (!pending_request.source.eql(&base_addr) or !pending_request.target.eql(&from)) return;

    if (core.findCandidatePair(&base_addr, &from)) |candidate_pair| {
        const mapped_address = try Messages.parseAndValidateStunResponse(msg, core.remote_credentials.?);

        if (mapped_address.eql(&base_addr)) {
            candidate_pair.status = .succeeded;
            core.maybeSetNominatedField(candidate_pair);
            return;
        }
        candidate_pair.status = .failed;

        const local_candidate = core.findLocalCandidate(&base_addr, &mapped_address) orelse blk: {
            const prflx_candidate: Candidate = .initPeerReflexive(base_addr, mapped_address);
            try core.candidates.append(core.allocator, prflx_candidate);
            break :blk prflx_candidate;
        };

        if (core.findCandidatePairByLocalAndRemote(&local_candidate, &from)) |existing_candidate_pair| {
            existing_candidate_pair.status = .succeeded;
            core.maybeSetNominatedField(existing_candidate_pair);
            return;
        }

        try core.pairs.append(core.allocator, .{
            .local = local_candidate,
            .remote = candidate_pair.remote,
            .priority = calculatePairPriority(local_candidate.priority, candidate_pair.remote.priority, core.role),
            .status = .succeeded,
        });
    }
}

fn calculatePairPriority(l: u32, r: u32, role: ice.Role) u64 {
    var g = l;
    var d = r;
    if (role == .controlled) g, d = .{ d, g };

    const last_part: u8 = if (g > d) 1 else 0;
    return (@as(u64, 1) << 32) * @min(g, d) + 2 * @max(g, d) + last_part;
}

fn selectBestPair(core: *Core) ?CandidatePair {
    var selected_pair: ?CandidatePair = null;
    for (core.pairs.items) |candidate_pair| if (candidate_pair.status == .succeeded) {
        if (selected_pair == null or candidate_pair.priority > selected_pair.?.priority) {
            selected_pair = candidate_pair;
        }
    };

    return selected_pair;
}

fn findCandidatePair(core: *Core, local: *const IpAddress, remote: *const IpAddress) ?*CandidatePair {
    var pair: ?*CandidatePair = null;

    for (core.pairs.items) |*candidate| if (candidate.local.base.eql(local) and candidate.remote.address.eql(remote)) {
        if (pair == null or candidate.status != .failed and pair.?.status == .failed) pair = candidate;
    };

    return pair;
}

fn maybeSetNominatedField(core: *Core, candidate_pair: *CandidatePair) void {
    if (candidate_pair.nominate_on_binding) {
        candidate_pair.nominate_on_binding = false;
        candidate_pair.nominated = true;
    } else if (core.selected_pair != null and core.selected_pair.?.eql(candidate_pair)) {
        core.nominated_pair = core.selected_pair;
        core.nominated_pair.?.nominated = true;
        core.selected_pair = null;
    }
}

fn findLocalCandidate(core: *Core, base: *const IpAddress, addr: *const IpAddress) ?Candidate {
    for (core.candidates.items) |candidate| if (candidate.base.eql(base) and candidate.address.eql(addr)) return candidate;
    return null;
}

fn findCandidatePairByLocalAndRemote(core: *Core, local: *const Candidate, remote: *const IpAddress) ?*CandidatePair {
    for (core.pairs.items) |*candidate| if (candidate.local.eql(local) and candidate.remote.address.eql(remote))
        return candidate;
    return null;
}

const testing = std.testing;

fn testNewCore(role: ice.Role) !Core {
    const credentials = try (ice.Credentials{
        .username = "user",
        .password = "VOkJxbRl1RmTxUk/WvJxBt",
    }).dupe(testing.allocator);
    return Core.init(testing.allocator, role, credentials, 0x1000000);
}

fn testBuildRequest(req: Messages.StunRequest, peer_password: []const u8, buffer: []u8) !stun.Message {
    var w = stun.Writer.init(buffer, .{ .password = peer_password });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.request, .binding),
        .transaction_id = 0x000102030405060708090A0B,
        .message_length = 0,
    });
    try w.writeAttribute(.{ .username = req.username });
    try w.writeAttribute(.{ .priority = req.priority });
    if (req.ice_controlled != null) try w.writeAttribute(.{ .ice_controlled = req.ice_controlled.? });
    if (req.ice_controlling != null) try w.writeAttribute(.{ .ice_controlling = req.ice_controlling.? });
    if (req.use_candidate) try w.writeAttribute(.use_candidate);
    try w.writeAttribute(.{ .message_integrity = &.{} });
    try w.writeAttribute(.fingerprint);

    return try stun.Message.parse(w.final());
}

test "handleRequest: generate success response" {
    var core = try testNewCore(.controlled);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = core.credentials.username,
    }, core.credentials.password, &buffer);

    const resp = try core.handleRequest(&msg, base_addr, from, &resp_buffer);
    const resp_msg = try stun.Message.parse(resp);

    try testing.expectEqual(.success_response, resp_msg.header.message_type.class());
    try testing.expectEqual(.binding, resp_msg.header.message_type.method());
    try testing.expectEqual(msg.header.transaction_id, resp_msg.header.transaction_id);

    var it = resp_msg.iterateAttributes(core.credentials.password);
    var attr = try it.next() orelse return error.ExpectedAttribute;
    try testing.expect(attr.xor_mapped_address.eql(&from));

    attr = try it.next() orelse return error.ExpectedAttribute;
    try testing.expectEqual(.message_integrity, @as(stun.AttributeType, attr));

    attr = try it.next() orelse return error.ExpectedAttribute;
    try testing.expectEqual(.fingerprint, @as(stun.AttributeType, attr));
    try testing.expectEqual(null, try it.next());
}

test "handleRequest: create peer reflexive candidate" {
    var core = try testNewCore(.controlled);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = core.credentials.username,
    }, core.credentials.password, &buffer);

    _ = try core.handleRequest(&msg, base_addr, from, &resp_buffer);

    try testing.expectEqual(1, core.pairs.items.len);

    const candidate_pair = core.pairs.items[0];
    try testing.expect(candidate_pair.remote.address.eql(&from));
    try testing.expectEqual(candidate_pair.remote.priority, 0x9090);

    // Send request again
    _ = try core.handleRequest(&msg, base_addr, from, &resp_buffer);
    try testing.expectEqual(1, core.pairs.items.len); // no new peer is created
}

test "handleRequest: nominate peer" {
    var core = try testNewCore(.controlled);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    try core.pairs.append(testing.allocator, .{
        .local = .initHost(base_addr),
        .remote = .initHost(from),
        .status = .in_progress,
        .priority = 0,
    });

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = core.credentials.username,
        .use_candidate = true,
    }, core.credentials.password, &buffer);

    _ = try core.handleRequest(&msg, base_addr, from, &resp_buffer);

    const candidate_pair = &core.pairs.items[0];
    try testing.expect(candidate_pair.nominate_on_binding);
    try testing.expect(!candidate_pair.nominated);

    candidate_pair.status = .succeeded;
    _ = try core.handleRequest(&msg, base_addr, from, &resp_buffer);
    try testing.expect(candidate_pair.nominated);
}

test "handleRequest: role conflict" {
    var core = try testNewCore(.controlled);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    {
        const msg = try testBuildRequest(.{
            .ice_controlled = std.math.maxInt(u64),
            .priority = 0x9090,
            .username = core.credentials.username,
        }, core.credentials.password, &buffer);

        const resp = try core.handleRequest(&msg, base_addr, from, &resp_buffer);
        const resp_msg = try stun.Message.parse(resp);

        try testing.expectEqual(.error_response, resp_msg.header.message_type.class());
        try testing.expectEqual(.binding, resp_msg.header.message_type.method());
        try testing.expectEqual(msg.header.transaction_id, resp_msg.header.transaction_id);

        var it = resp_msg.iterateAttributes(core.credentials.password);
        const attr = (try it.next()).?;
        try testing.expectEqual(.error_code, @as(stun.AttributeType, attr));
        try testing.expectEqual(487, attr.error_code.code);
        try testing.expectEqualStrings("Role conflict", attr.error_code.reason);
    }

    {
        const msg = try testBuildRequest(.{
            .ice_controlled = 0,
            .priority = 0x9090,
            .username = core.credentials.username,
        }, core.credentials.password, &buffer);

        try testing.expectError(error.SwitchRole, core.handleRequest(&msg, base_addr, from, &resp_buffer));
    }
}

test "addLocalCandidate: forms pairs with existing remote candidates" {
    var core = try testNewCore(.controlling);
    defer core.deinit();

    try core.addRemoteCandidate(Candidate.initHost(try IpAddress.parse("192.168.1.10", 1000)));
    try core.addRemoteCandidate(Candidate.initHost(try IpAddress.parse("192.168.1.11", 1001)));

    try testing.expectEqual(2, core.remote_candidates.items.len);
    try testing.expectEqual(0, core.pairs.items.len);

    const local = try IpAddress.parse("10.0.0.1", 2000);
    _ = try core.addHostCandidate(local);

    try testing.expectEqual(1, core.candidates.items.len);
    try testing.expectEqual(2, core.pairs.items.len);
    for (core.pairs.items) |pair| try testing.expect(pair.local.base.eql(&local));

    _ = try core.addHostCandidate(local);
    try testing.expectEqual(2, core.pairs.items.len);
}

test "addRemoteCandidate: forms pairs with existing local candidates" {
    var core = try testNewCore(.controlling);
    defer core.deinit();

    _ = try core.addHostCandidate(try IpAddress.parse("10.0.0.1", 2000));
    _ = try core.addHostCandidate(try IpAddress.parse("10.0.0.2", 2001));

    try testing.expectEqual(2, core.candidates.items.len);
    try testing.expectEqual(0, core.pairs.items.len);

    const remote = try IpAddress.parse("192.168.1.10", 1000);
    try core.addRemoteCandidate(Candidate.initHost(remote));

    try testing.expectEqual(1, core.remote_candidates.items.len);
    try testing.expectEqual(2, core.pairs.items.len);
    for (core.pairs.items) |pair| try testing.expect(pair.remote.address.eql(&remote));

    try core.addRemoteCandidate(Candidate.initHost(remote));
    try testing.expectEqual(2, core.pairs.items.len);
}

test "addLocalCandidate: reports whether the candidate was added" {
    var core = try testNewCore(.controlling);
    defer core.deinit();

    const candidate = Candidate.initHost(try IpAddress.parse("10.0.0.1", 2000));
    try testing.expect(try core.addLocalCandidate(candidate));
    try testing.expect(!try core.addLocalCandidate(candidate));
    try testing.expectEqual(1, core.candidates.items.len);
}

test "addServerReflexiveCandidate: skips candidate redundant with host" {
    var core = try testNewCore(.controlling);
    defer core.deinit();

    const base = try IpAddress.parse("10.0.0.1", 2000);
    _ = try core.addHostCandidate(base);

    try testing.expectEqual(null, try core.addServerReflexiveCandidate(base, try IpAddress.parse("10.0.0.1", 3000)));
    try testing.expectEqual(1, core.candidates.items.len);

    const mapped = try IpAddress.parse("203.0.113.5", 3000);
    const srflx = try core.addServerReflexiveCandidate(base, mapped);
    try testing.expect(srflx != null);
    try testing.expect(srflx.?.address.eql(&mapped));
    try testing.expectEqual(2, core.candidates.items.len);

    try testing.expectEqual(null, try core.addServerReflexiveCandidate(base, mapped));
    try testing.expectEqual(2, core.candidates.items.len);
}
