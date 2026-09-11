const std = @import("std");
const stun = @import("stun");
const ice = @import("ice.zig");
const CandidatePair = @import("candidate_pair.zig");
const Messages = @import("messages.zig");

const Agent = @This();
const Candidate = ice.Candidate;
const IpAddress = std.Io.net.IpAddress;
const Logger = std.log.scoped(.ice);

const SelectedPair = struct {
    pair: CandidatePair,
    pair_index: u8,
    local: Candidate,
    remote: RemoteCandidate,
};

const RemoteCandidate = struct {
    address: IpAddress,
    candidate_type: ice.CandidateType,
    priority: u32,
};

fn LocalCredentials(comptime size: u8) type {
    return struct {
        buffer: [size]u8,
        user_len: u8,
        pass_len: u8,

        fn init(username: []const u8, password: []const u8) error{CredentialsTooLong}!@This() {
            if (username.len + password.len > size) return error.CredentialsTooLong;
            var credentials: @This() = undefined;
            @memcpy(credentials.buffer[0..username.len], username);
            @memcpy(credentials.buffer[username.len .. username.len + password.len], password);
            credentials.user_len = @intCast(username.len);
            credentials.pass_len = @intCast(password.len);
            return credentials;
        }

        fn getUsername(self: *const @This()) []const u8 {
            return self.buffer[0..self.user_len];
        }

        fn getPassword(self: *const @This()) []const u8 {
            return self.buffer[self.user_len .. self.user_len + self.pass_len];
        }

        fn toIceCredentials(self: *const @This()) ice.Credentials {
            return .{
                .username = self.getUsername(),
                .password = self.getPassword(),
            };
        }
    };
}

pub const Event = union(enum) {
    connection_state: ice.ConnectionState,
    gathering_state: ice.GatheringState,
    nominated: IpAddress,
    connectivity_check: void,
    consent_freshness: void,
    candidate: u8,
};

/// The maximum number of binding requests sent on a pair before it is
/// considered failed.
pub const max_binding_requests: usize = 7;
pub const connectivity_check_interval: i64 = 200;
pub const keep_alive_interval: i64 = 4 * std.time.ms_per_s;

// Comptime values
const auth_info_size: u8 = 64;
const max_transmits: u8 = 5;
const max_candidates: u8 = 16;
const max_events: u8 = 15;
const initial_pairs_capacity: usize = @as(usize, max_candidates) * max_candidates / 2; // 128
const initial_pending_requests_capacity: usize = 16;

allocator: std.mem.Allocator,
random: std.Random,

credentials: LocalCredentials(auth_info_size),
remote_credentials: ?LocalCredentials(auth_info_size),
connection_state: ice.ConnectionState,
gathering_state: ice.GatheringState,
role: ice.Role,
tie_breaker: u64,

// Candidates and sockets
candidates: [max_candidates]Candidate = undefined,
candidates_len: u8 = 0,
remote_candidates: [max_candidates]RemoteCandidate = undefined,
remote_candidates_len: u8 = 0,
pairs: std.ArrayList(CandidatePair) = .empty,
pending_requests: std.ArrayList(PendingRequest) = .empty,
// This is a peer for which a use-candidate request is sent, but we didn't
// receive response yet.
selected_pair: ?SelectedPair = null,
// This the final pair selected by this agent or the remote one.
nominated_pair: ?SelectedPair = null,

failed_timeout: u32,
disconnected_timeout: u32,

connectivity_check_deadline: i64,
disconnected_connection_deadline: i64, // used for both disconnected and failed states
keep_alive_deadline: i64,

events_out: stun.BoundedDeque(Event, max_events),
transmits: stun.BoundedDeque(stun.TransportMessage, max_transmits),

const PendingRequest = struct {
    transaction_id: [12]u8,
    pair: u8,
};

pub const ConnectivityChecks = struct {
    agent: *Agent,
    nomination_done: bool = false,
    index: usize = 0,

    pub fn next(self: *ConnectivityChecks, buffer: []u8) !?stun.TransportMessage {
        const agent = self.agent;

        if (!self.nomination_done) {
            self.nomination_done = true;
            if (agent.selected_pair) |*selected| {
                const tx_id = agent.random.int(u96);
                const payload = try agent.buildBindingRequest(tx_id, true, buffer);

                try agent.pending_requests.append(agent.allocator, .{
                    .transaction_id = @bitCast(tx_id),
                    .pair = selected.pair_index,
                });

                return stun.TransportMessage{
                    .data = payload,
                    .from = &selected.local.base,
                    .to = &selected.remote.address,
                };
            }
        }

        while (self.index < agent.pairs.items.len) {
            const idx = self.index;
            const pair = &agent.pairs.items[idx];
            self.index += 1;
            switch (pair.status) {
                .waiting, .in_progress => {
                    pair.conn_check_count += 1;
                    if (pair.conn_check_count > max_binding_requests) {
                        pair.status = .failed;
                        continue;
                    }

                    const tx_id = agent.random.int(u96);
                    const payload = try agent.buildBindingRequest(tx_id, false, buffer);
                    const local = agent.getPairLocal(pair);
                    const remote = agent.getPairRemote(pair);

                    try agent.pending_requests.append(agent.allocator, .{
                        .transaction_id = @bitCast(tx_id),
                        .pair = @intCast(idx),
                    });

                    return stun.TransportMessage{
                        .data = payload,
                        .from = &local.base,
                        .to = &remote.address,
                    };
                },
                else => {},
            }
        }

        return null;
    }
};

pub const Config = struct {
    role: ice.Role,
    credentials: ice.Credentials,
    random: std.Random,
    failed_timeout: u32 = 25000,
    disconnected_timeout: u32 = 5000,
};

pub fn init(allocator: std.mem.Allocator, config: Config) !Agent {
    return .{
        .allocator = allocator,
        .random = config.random,
        .role = config.role,
        .connection_state = .new,
        .gathering_state = .new,
        .credentials = try .init(config.credentials.username, config.credentials.password),
        .remote_credentials = null,
        .tie_breaker = config.random.int(u64),
        .connectivity_check_deadline = std.math.maxInt(i64),
        .keep_alive_deadline = std.math.maxInt(i64),
        .disconnected_connection_deadline = std.math.maxInt(i64),
        .failed_timeout = config.failed_timeout,
        .disconnected_timeout = config.disconnected_timeout,
        .events_out = .empty,
        .transmits = .empty,
        .pairs = try .initCapacity(allocator, initial_pairs_capacity),
        .pending_requests = try .initCapacity(allocator, initial_pending_requests_capacity),
    };
}

pub fn deinit(agent: *Agent) void {
    agent.close();
    agent.pairs.deinit(agent.allocator);
    agent.pending_requests.deinit(agent.allocator);
    agent.events_out.clear();
    agent.transmits.clear();
}

pub fn close(core: *Agent) void {
    core.connection_state = .closed;

    core.pairs.clearAndFree(core.allocator);
    core.pending_requests.clearAndFree(core.allocator);
    core.candidates_len = 0;
    core.remote_candidates_len = 0;
}

pub fn getRemoteCredentials(core: *const Agent) ?ice.Credentials {
    return if (core.remote_credentials) |*rc| rc.toIceCredentials() else null;
}

pub fn getLocalCredentials(core: *const Agent) ice.Credentials {
    return core.credentials.toIceCredentials();
}

pub fn addLocalAddrs(core: *Agent, addrs: []const IpAddress) !void {
    for (addrs) |addr| {
        const candidate = Candidate.initHost(addr);
        if (try core.addLocalCandidate(candidate)) |idx| {
            try core.events_out.pushBack(.{ .candidate = @intCast(idx) });
        }
    }

    // since there's no support for stun/turn servers, we can immediately transition to the "gathering done" state
    core.gathering_state = .complete;
    try core.events_out.pushBack(.{ .gathering_state = core.gathering_state });
}

pub fn setRemoteCredentials(agent: *Agent, credentials: ice.Credentials, now: i64) !void {
    agent.remote_credentials = try .init(credentials.username, credentials.password);
    try agent.setConnectionState(.checking, now);
}

pub fn addServerReflexiveCandidate(core: *Agent, base: IpAddress, mapped: IpAddress) !?Candidate {
    for (core.candidates[0..core.candidates_len]) |candidate|
        if (candidate.candidate_type == .host and ipEql(&candidate.base, &mapped)) return null;

    const candidate = Candidate.initServerReflexive(base, mapped);
    return if (try core.addLocalCandidate(candidate)) |_| candidate else null;
}

pub fn handleConsentFreshness(agent: *Agent, from: *const IpAddress, message: []const u8, buffer: []u8) !?[]const u8 {
    const msg = try stun.Message.parse(message);
    switch (msg.header.message_type.class()) {
        .request => {
            _ = try Messages.parseAndValidateStunRequest(
                &msg,
                agent.credentials.toIceCredentials(),
                agent.role,
                agent.tie_breaker,
            );
            return try Messages.buildSuccessResponse(&msg, agent.credentials.getPassword(), from, buffer);
        },
        else => {},
    }

    return null;
}

pub fn addRemoteCandidate(core: *Agent, remote_candidate: Candidate) !void {
    const remote_idx = try core.appendRemoteCandidate(remote_candidate);

    outer_loop: for (core.candidates[0..core.candidates_len], 0..) |candidate, local_idx| {
        if (std.meta.activeTag(remote_candidate.address) != std.meta.activeTag(candidate.base)) continue;
        for (core.pairs.items) |*pair| {
            const local = core.getPairLocal(pair);
            const remote = core.getPairRemote(pair);
            if (local.base.eql(&candidate.base) and remote.address.eql(&remote_candidate.address))
                continue :outer_loop;
        }

        try core.pairs.append(core.allocator, .{
            .local = @intCast(local_idx),
            .remote = @intCast(remote_idx),
            .priority = calculatePairPriority(candidate.priority, remote_candidate.priority, core.role),
        });
    }
}

/// Returns `false` if an identical candidate already exists.
pub fn addLocalCandidate(core: *Agent, candidate: Candidate) !?usize {
    for (core.candidates[0..core.candidates_len]) |*existing| if (existing.eql(&candidate)) return null;

    const idx = try core.appendCandidate(candidate);

    outer_loop: for (core.remote_candidates[0..core.remote_candidates_len], 0..) |remote_candidate, remote_idx| {
        if (std.meta.activeTag(remote_candidate.address) != std.meta.activeTag(candidate.base)) continue;

        for (core.pairs.items) |*pair| {
            const local = core.getPairLocal(pair);
            const remote = core.getPairRemote(pair);
            if (local.base.eql(&candidate.base) and remote.address.eql(&remote_candidate.address))
                continue :outer_loop;
        }

        try core.pairs.append(core.allocator, .{
            .local = @intCast(idx),
            .remote = @intCast(remote_idx),
            .priority = calculatePairPriority(candidate.priority, remote_candidate.priority, core.role),
        });
    }

    return idx;
}

/// Begin a connectivity-check round. Returns null when a pair is already
/// nominated (nothing to do). Performs the controlling-side best-pair selection.
pub fn beginConnectivityChecks(agent: *Agent) ?ConnectivityChecks {
    if (agent.nominated_pair != null) return null;
    if (agent.role == .controlling and agent.selected_pair == null)
        agent.selected_pair = agent.selectBestPair();
    return .{ .agent = agent };
}

pub fn handleTimeout(agent: *Agent, now: i64) error{Overflow}!void {
    if (agent.connection_state == .closed) return;

    if (now >= agent.connectivity_check_deadline) {
        agent.connectivity_check_deadline = now + connectivity_check_interval;
        try agent.events_out.pushBack(.connectivity_check);
    }

    if (now >= agent.keep_alive_deadline) {
        agent.keep_alive_deadline = now + keep_alive_interval;
        if (agent.connection_state == .connected) {
            try agent.setConnectionState(.completed, now);
        }
        try agent.events_out.pushBack(.consent_freshness);
    }

    if (now >= agent.disconnected_connection_deadline) {
        switch (agent.connection_state) {
            .checking, .disconnected => try agent.setConnectionState(.failed, now),
            else => try agent.setConnectionState(.disconnected, now),
        }
    }
}

pub const ReadResult = union(enum) {
    app_data: []const u8,
    consumed: void,
};

pub fn handleRead(agent: *Agent, message: stun.TransportMessage, now: i64, buffer: []u8) !ReadResult {
    if (!stun.isMessage(message.data)) {
        return try agent.handleAppData(message.from, message.data);
    }

    switch (agent.connection_state) {
        .completed, .disconnected, .failed => |state| {
            agent.disconnected_connection_deadline = now + agent.disconnected_timeout;
            if (state == .disconnected) try agent.setConnectionState(.completed, now);
            if (try agent.handleConsentFreshness(message.from, message.data, buffer)) |resp| {
                try agent.transmits.pushBack(.{
                    .data = resp,
                    .from = message.to,
                    .to = message.from,
                });
            }

            return .consumed;
        },
        else => return agent.handleStunMessage(message, now, buffer),
    }
}

pub fn pollEvent(core: *Agent) ?Event {
    return core.events_out.popFront();
}

pub fn pollTransmit(agent: *Agent) ?stun.TransportMessage {
    return agent.transmits.popFront();
}

pub fn pollTimeout(core: *Agent) ?i64 {
    if (core.connection_state == .closed) return null;
    var deadline: i64 = std.math.maxInt(i64);

    for (&[_]i64{
        core.connectivity_check_deadline,
        core.keep_alive_deadline,
        core.disconnected_connection_deadline,
    }) |d| deadline = @min(deadline, d);

    return if (deadline == std.math.maxInt(i64)) null else deadline;
}

pub fn detectNominatedPair(core: *Agent) ?CandidatePair {
    if (core.role == .controlling or core.nominated_pair != null) return null;
    for (core.pairs.items, 0..) |pair, idx| if (pair.nominated) {
        core.nominated_pair = .{
            .pair = pair,
            .pair_index = @intCast(idx),
            .local = core.getPairLocal(&pair).*,
            .remote = core.getPairRemote(&pair).*,
        };
        return pair;
    };
    return null;
}

pub fn buildBindingRequest(core: *Agent, tx_id: u96, use_candidate: bool, buffer: []u8) ![]const u8 {
    var w = stun.Writer.init(buffer, .{ .password = core.remote_credentials.?.getPassword() });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.request, .binding),
        .transaction_id = tx_id,
        .message_length = 0,
    });

    var username = [_][]const u8{ core.remote_credentials.?.getUsername(), ":", core.credentials.getUsername() };
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

pub fn toggleRole(agent: *Agent) void {
    switch (agent.role) {
        .controlling => agent.role = .controlled,
        .controlled => agent.role = .controlling,
    }
    agent.tie_breaker = agent.random.int(u64);

    for (agent.pairs.items) |*pair| {
        const local = agent.getPairLocal(pair);
        const remote = agent.getPairRemote(pair);
        pair.priority = calculatePairPriority(local.priority, remote.priority, agent.role);
    }
}

fn appendCandidate(core: *Agent, candidate: Candidate) error{Overflow}!usize {
    if (core.candidates_len >= max_candidates) return error.Overflow;
    const idx = core.candidates_len;
    core.candidates[idx] = candidate;
    core.candidates_len += 1;
    return idx;
}

fn appendRemoteCandidate(core: *Agent, candidate: Candidate) error{Overflow}!usize {
    if (core.remote_candidates_len >= max_candidates) return error.Overflow;
    const idx = core.remote_candidates_len;
    core.remote_candidates[idx] = .{ .address = candidate.address, .candidate_type = candidate.candidate_type, .priority = candidate.priority };
    core.remote_candidates_len += 1;
    return idx;
}

fn setConnectionState(agent: *Agent, state: ice.ConnectionState, now: i64) !void {
    agent.connection_state = state;
    switch (agent.connection_state) {
        .checking => {
            agent.connectivity_check_deadline = now + connectivity_check_interval;
            agent.disconnected_connection_deadline = now + agent.failed_timeout;
        },
        .connected => {
            agent.keep_alive_deadline = now + keep_alive_interval;
            agent.disconnected_connection_deadline = now + agent.disconnected_timeout;
        },
        .completed => {
            agent.connectivity_check_deadline = std.math.maxInt(i64);
            agent.remote_candidates_len = 0;
            agent.pairs.clearAndFree(agent.allocator);
            agent.pending_requests.clearAndFree(agent.allocator);
        },
        .disconnected => agent.disconnected_connection_deadline = now + agent.failed_timeout,
        .failed => {
            agent.connectivity_check_deadline = std.math.maxInt(i64);
            agent.disconnected_connection_deadline = std.math.maxInt(i64);
            agent.keep_alive_deadline = std.math.maxInt(i64);
        },
        else => {},
    }

    try agent.events_out.pushBack(.{ .connection_state = agent.connection_state });
}

fn handleStunMessage(agent: *Agent, message: stun.TransportMessage, now: i64, buffer: []u8) !ReadResult {
    const was_nominated = agent.nominated_pair != null;
    const msg = try stun.Message.parse(message.data);

    switch (msg.header.message_type.class()) {
        .request => {
            const resp = try agent.handleRequest(&msg, message.to, message.from, buffer);
            _ = agent.detectNominatedPair();
            try agent.transmits.pushBack(.{
                .data = resp,
                .from = message.to,
                .to = message.from,
            });
        },
        .success_response => {
            try agent.handleSuccessResponse(&msg, message.to, message.from);
            _ = agent.detectNominatedPair();
        },
        else => {},
    }

    if (!was_nominated) if (agent.nominated_pair) |pair| {
        try agent.setConnectionState(.connected, now);
        try agent.events_out.pushBack(.{ .nominated = pair.local.base });
    };

    return .consumed;
}

fn handleAppData(agent: *Agent, sender: *const IpAddress, data: []const u8) !ReadResult {
    switch (agent.connection_state) {
        .connected, .completed, .disconnected => return .{ .app_data = data },
        else => {
            for (agent.pairs.items) |*candidate_pair| {
                const remote = &agent.remote_candidates[candidate_pair.remote];
                if (remote.address.eql(sender)) return .{ .app_data = data };
            } else Logger.debug("Drop non stun message from unknown remote candidate: {f}", .{sender});
        },
    }

    return .consumed;
}

fn handleRequest(agent: *Agent, msg: *const stun.Message, base_addr: *const IpAddress, from: *const IpAddress, buffer: []u8) ![]const u8 {
    const stun_req = Messages.parseAndValidateStunRequest(
        msg,
        agent.credentials.toIceCredentials(),
        agent.role,
        agent.tie_breaker,
    ) catch |err| switch (err) {
        error.RoleConflict => return try Messages.buildRoleConflictErrorMessage(msg.header.transaction_id, agent.credentials.getPassword(), buffer),
        error.SwitchRole => blk: {
            agent.toggleRole();
            break :blk try Messages.parseAndValidateStunRequest(
                msg,
                agent.credentials.toIceCredentials(),
                agent.role,
                agent.tie_breaker,
            );
        },
        else => |e| return e,
    };

    if (agent.findCandidatePair(base_addr, from)) |candidate_pair| {
        switch (candidate_pair.status) {
            .succeeded => candidate_pair.nominated |= stun_req.use_candidate,
            else => candidate_pair.nominate_on_binding |= stun_req.use_candidate,
        }
    } else {
        const local_idx = agent.findLocalCandidate(base_addr, base_addr) orelse return error.NoLocalCandidate;
        const local_candidate = agent.candidates[local_idx];

        const remote_idx: u32 = agent.findRemoteCandidate(from) orelse blk: {
            const candidate = Candidate{
                .base = from.*,
                .address = from.*,
                .candidate_type = .prflx,
                .priority = stun_req.priority,
            };
            break :blk @intCast(try agent.appendRemoteCandidate(candidate));
        };

        try agent.pairs.append(agent.allocator, .{
            .local = local_idx,
            .remote = remote_idx,
            .priority = calculatePairPriority(local_candidate.priority, stun_req.priority, agent.role),
            .status = .in_progress,
            .nominate_on_binding = stun_req.use_candidate,
        });
    }

    return try Messages.buildSuccessResponse(msg, agent.credentials.getPassword(), from, buffer);
}

fn handleSuccessResponse(core: *Agent, msg: *const stun.Message, base_addr: *const IpAddress, from: *const IpAddress) !void {
    const pending_request = blk: {
        const tx_id = msg.header.transaction_id;
        for (core.pending_requests.items, 0..) |pr, i| {
            if (@as(u96, @bitCast(pr.transaction_id)) == tx_id) {
                const pending_request = core.pending_requests.swapRemove(i);
                break :blk pending_request;
            }
        }

        return;
    };

    const expected_pair = core.pairs.items[pending_request.pair];
    if (!core.getPairLocal(&expected_pair).base.eql(base_addr) or !core.getPairRemote(&expected_pair).address.eql(from)) return;

    if (core.findCandidatePair(base_addr, from)) |candidate_pair| {
        const mapped_address = try Messages.parseAndValidateStunResponse(msg, core.remote_credentials.?.getPassword());

        if (mapped_address.eql(base_addr)) {
            candidate_pair.status = .succeeded;
            core.maybeSetNominatedField(candidate_pair);
            return;
        }
        candidate_pair.status = .failed;

        const local_idx: u32 = core.findLocalCandidate(base_addr, &mapped_address) orelse blk: {
            const prflx_candidate: Candidate = .initPeerReflexive(base_addr.*, mapped_address);
            break :blk @intCast(try core.appendCandidate(prflx_candidate));
        };
        const local_candidate = core.candidates[local_idx];
        const remote_candidate = core.getPairRemote(candidate_pair);

        if (core.findCandidatePairByLocalAndRemote(&local_candidate, from)) |existing_candidate_pair| {
            existing_candidate_pair.status = .succeeded;
            core.maybeSetNominatedField(existing_candidate_pair);
            return;
        }

        try core.pairs.append(core.allocator, .{
            .local = local_idx,
            .remote = candidate_pair.remote,
            .priority = calculatePairPriority(local_candidate.priority, remote_candidate.priority, core.role),
            .status = .succeeded,
        });
    }
}

fn pairsEql(core: *Agent, pair1: *const CandidatePair, pair2: *const CandidatePair) bool {
    const local1 = core.getPairLocal(pair1);
    const remote1 = core.getPairRemote(pair1);

    const local2 = core.getPairLocal(pair2);
    const remote2 = core.getPairRemote(pair2);

    return local1.base.eql(&local2.base) and local1.address.eql(&local2.address) and
        remote1.address.eql(&remote2.address);
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

fn calculatePairPriority(l: u32, r: u32, role: ice.Role) u64 {
    var g = l;
    var d = r;
    if (role == .controlled) g, d = .{ d, g };

    const last_part: u8 = if (g > d) 1 else 0;
    return (@as(u64, 1) << 32) * @min(g, d) + 2 * @max(g, d) + last_part;
}

fn selectBestPair(core: *Agent) ?SelectedPair {
    var selected_pair: ?CandidatePair = null;
    var selected_idx: usize = 0;
    for (core.pairs.items, 0..) |candidate_pair, idx| if (candidate_pair.status == .succeeded) {
        if (selected_pair == null or candidate_pair.priority > selected_pair.?.priority) {
            selected_pair = candidate_pair;
            selected_idx = idx;
        }
    };

    return if (selected_pair) |pair| .{
        .pair = pair,
        .pair_index = @intCast(selected_idx),
        .local = core.getPairLocal(&pair).*,
        .remote = core.getPairRemote(&pair).*,
    } else null;
}

fn findCandidatePair(core: *Agent, local: *const IpAddress, remote: *const IpAddress) ?*CandidatePair {
    var pair: ?*CandidatePair = null;
    for (core.pairs.items) |*candidate| {
        const local_c = core.getPairLocal(candidate);
        const remote_c = core.getPairRemote(candidate);
        if (local_c.base.eql(local) and remote_c.address.eql(remote)) {
            if (pair == null or candidate.status != .failed and pair.?.status == .failed) pair = candidate;
        }
    }

    return pair;
}

fn maybeSetNominatedField(core: *Agent, candidate_pair: *CandidatePair) void {
    if (candidate_pair.nominate_on_binding) {
        candidate_pair.nominate_on_binding = false;
        candidate_pair.nominated = true;
    } else if (core.selected_pair != null and core.pairsEql(&core.selected_pair.?.pair, candidate_pair)) {
        core.nominated_pair = core.selected_pair;
        core.nominated_pair.?.pair.nominated = true;
        core.selected_pair = null;
    }
}

fn findLocalCandidate(core: *Agent, base: *const IpAddress, addr: *const IpAddress) ?u32 {
    for (core.candidates[0..core.candidates_len], 0..) |candidate, idx| {
        if (candidate.base.eql(base) and candidate.address.eql(addr)) return @intCast(idx);
    }
    return null;
}

fn findRemoteCandidate(core: *Agent, addr: *const IpAddress) ?u32 {
    for (core.remote_candidates[0..core.remote_candidates_len], 0..) |candidate, idx| if (candidate.address.eql(addr)) return @intCast(idx);
    return null;
}

fn findCandidatePairByLocalAndRemote(core: *Agent, local: *const Candidate, remote: *const IpAddress) ?*CandidatePair {
    for (core.pairs.items) |*candidate| {
        if (core.getPairLocal(candidate).eql(local) and core.getPairRemote(candidate).address.eql(remote))
            return candidate;
    }
    return null;
}

fn getPairLocal(core: *Agent, pair: *const CandidatePair) *const Candidate {
    return &core.candidates[pair.local];
}

fn getPairRemote(core: *Agent, pair: *const CandidatePair) *const RemoteCandidate {
    return &core.remote_candidates[pair.remote];
}

const testing = std.testing;
var rand = std.Random.DefaultPrng.init(0xDEADBEEF);

fn testRemoteCandidate(address: IpAddress) RemoteCandidate {
    return .{ .address = address, .candidate_type = .host, .priority = ice.CandidateType.host.priority() };
}

fn testNewAgent(role: ice.Role) !Agent {
    return Agent.init(testing.allocator, .{
        .role = role,
        .credentials = .{ .username = "user", .password = "VOkJxbRl1RmTxUk/WvJxBt" },
        .random = rand.random(),
    });
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

fn testBuildResponse(tx_id: u96, addr: IpAddress, password: []const u8, buffer: []u8) !stun.Message {
    var w = stun.Writer.init(buffer, .{ .password = password });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.success_response, .binding),
        .transaction_id = tx_id,
        .message_length = 0,
    });
    try w.writeAttribute(.{ .xor_mapped_address = addr });
    try w.writeAttribute(.{ .message_integrity = &.{} });
    try w.writeAttribute(.fingerprint);

    return try stun.Message.parse(w.final());
}

fn expectEvent(core: *Agent, tag: std.meta.Tag(Event)) !void {
    const event = core.pollEvent() orelse return error.ExpectedEvent;
    if (std.meta.activeTag(event) != tag) return error.UnexpectedEvent;
}

fn expectConnectionStateEvent(core: *Agent, state: ice.ConnectionState) !void {
    switch (core.pollEvent() orelse return error.ExpectedEvent) {
        .connection_state => |s| try testing.expectEqual(state, s),
        else => return error.UnexpectedEvent,
    }
}

test "handleRequest: generate success response" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    try core.addLocalAddrs(&.{base_addr});

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = core.credentials.getUsername(),
    }, core.credentials.getPassword(), &buffer);

    const resp = try core.handleRequest(&msg, &base_addr, &from, &resp_buffer);
    const resp_msg = try stun.Message.parse(resp);

    try testing.expectEqual(.success_response, resp_msg.header.message_type.class());
    try testing.expectEqual(.binding, resp_msg.header.message_type.method());
    try testing.expectEqual(msg.header.transaction_id, resp_msg.header.transaction_id);

    var it = resp_msg.iterateAttributes(core.credentials.getPassword());
    var attr = try it.next() orelse return error.ExpectedAttribute;
    try testing.expect(attr.xor_mapped_address.eql(&from));

    attr = try it.next() orelse return error.ExpectedAttribute;
    try testing.expectEqual(.message_integrity, @as(stun.AttributeType, attr));

    attr = try it.next() orelse return error.ExpectedAttribute;
    try testing.expectEqual(.fingerprint, @as(stun.AttributeType, attr));
    try testing.expectEqual(null, try it.next());
}

test "handleRequest: create peer reflexive candidate" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    try core.addLocalAddrs(&.{base_addr});

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = core.credentials.getUsername(),
    }, core.credentials.getPassword(), &buffer);

    _ = try core.handleRequest(&msg, &base_addr, &from, &resp_buffer);

    try testing.expectEqual(1, core.pairs.items.len);

    const candidate_pair = core.pairs.items[0];
    const remote = core.remote_candidates[candidate_pair.remote];
    try testing.expect(remote.address.eql(&from));
    try testing.expectEqual(remote.priority, 0x9090);

    // Send request again
    _ = try core.handleRequest(&msg, &base_addr, &from, &resp_buffer);
    try testing.expectEqual(1, core.pairs.items.len); // no new peer is created
}

test "handleRequest: nominate peer" {
    var agent = try testNewAgent(.controlled);
    defer agent.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    agent.candidates[0] = .initHost(base_addr);
    agent.candidates_len = 1;
    agent.remote_candidates[0] = testRemoteCandidate(from);
    agent.remote_candidates_len = 1;
    try agent.pairs.append(testing.allocator, .{
        .local = 0,
        .remote = 0,
        .status = .in_progress,
        .priority = 0,
    });

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = agent.credentials.getUsername(),
        .use_candidate = true,
    }, agent.credentials.getPassword(), &buffer);

    _ = try agent.handleRequest(&msg, &base_addr, &from, &resp_buffer);

    const candidate_pair = &agent.pairs.items[0];
    try testing.expect(candidate_pair.nominate_on_binding);
    try testing.expect(!candidate_pair.nominated);

    candidate_pair.status = .succeeded;
    _ = try agent.handleRequest(&msg, &base_addr, &from, &resp_buffer);
    try testing.expect(candidate_pair.nominated);
}

test "handleRequest: role conflict" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);
    try core.addLocalAddrs(&.{base_addr});

    {
        const msg = try testBuildRequest(.{
            .ice_controlled = std.math.maxInt(u64),
            .priority = 0x9090,
            .username = core.credentials.getUsername(),
        }, core.credentials.getPassword(), &buffer);

        const resp = try core.handleRequest(&msg, &base_addr, &from, &resp_buffer);
        const resp_msg = try stun.Message.parse(resp);

        try testing.expectEqual(.error_response, resp_msg.header.message_type.class());
        try testing.expectEqual(.binding, resp_msg.header.message_type.method());
        try testing.expectEqual(msg.header.transaction_id, resp_msg.header.transaction_id);
        try testing.expectEqual(.controlled, core.role);

        var it = resp_msg.iterateAttributes(core.credentials.getPassword());
        const attr = (try it.next()).?;
        try testing.expectEqual(.error_code, @as(stun.AttributeType, attr));
        try testing.expectEqual(.role_conflict, attr.error_code.code);
        try testing.expectEqualStrings("Role conflict", attr.error_code.reason);
    }

    {
        const msg = try testBuildRequest(.{
            .ice_controlled = 0,
            .priority = 0x9090,
            .username = core.credentials.getUsername(),
        }, core.credentials.getPassword(), &buffer);

        const resp = try core.handleRequest(&msg, &base_addr, &from, &resp_buffer);
        const resp_msg = try stun.Message.parse(resp);

        try testing.expectEqual(.success_response, resp_msg.header.message_type.class());
        try testing.expectEqual(.controlling, core.role);
    }
}

test "addLocalCandidate: forms pairs with existing remote candidates" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    try core.addRemoteCandidate(Candidate.initHost(try IpAddress.parse("192.168.1.10", 1000)));
    try core.addRemoteCandidate(Candidate.initHost(try IpAddress.parse("192.168.1.11", 1001)));

    try testing.expectEqual(2, core.remote_candidates_len);
    try testing.expectEqual(0, core.pairs.items.len);

    const local = try IpAddress.parse("10.0.0.1", 2000);
    try core.addLocalAddrs(&.{local});

    try testing.expectEqual(1, core.candidates_len);
    try testing.expectEqual(2, core.pairs.items.len);
    for (core.pairs.items) |pair| try testing.expect(core.candidates[pair.local].base.eql(&local));

    try core.addLocalAddrs(&.{local});
    try testing.expectEqual(2, core.pairs.items.len);
}

test "addRemoteCandidate: forms pairs with existing local candidates" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    try core.addLocalAddrs(&.{try IpAddress.parse("10.0.0.1", 2000)});
    try core.addLocalAddrs(&.{try IpAddress.parse("10.0.0.2", 2001)});

    try testing.expectEqual(2, core.candidates_len);
    try testing.expectEqual(0, core.pairs.items.len);

    const remote = try IpAddress.parse("192.168.1.10", 1000);
    try core.addRemoteCandidate(Candidate.initHost(remote));

    try testing.expectEqual(1, core.remote_candidates_len);
    try testing.expectEqual(2, core.pairs.items.len);
    for (core.pairs.items) |pair| try testing.expect(core.remote_candidates[pair.remote].address.eql(&remote));

    try core.addRemoteCandidate(Candidate.initHost(remote));
    try testing.expectEqual(2, core.pairs.items.len);
}

test "addRemoteCandidate: skips pairing across differing address families" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    try core.addLocalAddrs(&.{try IpAddress.parse("10.0.0.1", 2000)});

    try core.addRemoteCandidate(Candidate.initHost(try IpAddress.parse("2001:db8::10", 1000)));
    try testing.expectEqual(0, core.pairs.items.len);

    try core.addRemoteCandidate(Candidate.initHost(try IpAddress.parse("192.168.1.10", 1001)));
    try testing.expectEqual(1, core.pairs.items.len);
}

test "addLocalCandidate: skips pairing across differing address families" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    try core.addRemoteCandidate(Candidate.initHost(try IpAddress.parse("192.168.1.10", 1000)));

    try core.addLocalAddrs(&.{try IpAddress.parse("2001:db8::1", 2000)});
    try testing.expectEqual(0, core.pairs.items.len);

    try core.addLocalAddrs(&.{try IpAddress.parse("10.0.0.1", 2001)});
    try testing.expectEqual(1, core.pairs.items.len);
}

test "addLocalCandidate: reports whether the candidate was added" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    const candidate = Candidate.initHost(try IpAddress.parse("10.0.0.1", 2000));
    try testing.expect(try core.addLocalCandidate(candidate) != null);
    try testing.expectEqual(null, try core.addLocalCandidate(candidate));
    try testing.expectEqual(1, core.candidates_len);
}

test "addServerReflexiveCandidate: skips candidate redundant with host" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    const base = try IpAddress.parse("10.0.0.1", 2000);
    try core.addLocalAddrs(&.{base});

    try testing.expectEqual(null, try core.addServerReflexiveCandidate(base, try IpAddress.parse("10.0.0.1", 3000)));
    try testing.expectEqual(1, core.candidates_len);

    const mapped = try IpAddress.parse("203.0.113.5", 3000);
    const srflx = try core.addServerReflexiveCandidate(base, mapped);
    try testing.expect(srflx != null);
    try testing.expect(srflx.?.address.eql(&mapped));
    try testing.expectEqual(2, core.candidates_len);

    try testing.expectEqual(null, try core.addServerReflexiveCandidate(base, mapped));
    try testing.expectEqual(2, core.candidates_len);
}

test "toggleRole: flips role, tie breaker and pair priorities" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    const local_addr = try IpAddress.parse("10.0.0.1", 2000);
    const remote_addr = try IpAddress.parse("192.168.1.10", 1000);

    try core.addLocalAddrs(&.{local_addr});
    try core.addRemoteCandidate(Candidate.initServerReflexive(remote_addr, remote_addr));

    try testing.expectEqual(1, core.pairs.items.len);
    const controlling_priority = core.pairs.items[0].priority;
    const controlling_tie_breaker = core.tie_breaker;

    core.toggleRole();

    try testing.expectEqual(.controlled, core.role);
    try testing.expect(core.tie_breaker != controlling_tie_breaker);
    try testing.expect(core.pairs.items[0].priority != controlling_priority);

    const controlled_tie_breaker = core.tie_breaker;
    core.toggleRole();

    try testing.expectEqual(.controlling, core.role);
    try testing.expect(core.tie_breaker != controlled_tie_breaker);
    try testing.expectEqual(controlling_priority, core.pairs.items[0].priority);
}

test "handleInput: drops non-stun data from an unknown remote before connected" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);
    var resp_buffer: [64]u8 = undefined;

    const result = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = "hello" }, 0, &resp_buffer);

    try testing.expectEqual(.consumed, std.meta.activeTag(result));
    try testing.expectEqual(null, core.pollEvent());
}

test "handleInput: forwards non-stun data from a known remote candidate pair" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);
    var resp_buffer: [64]u8 = undefined;

    core.candidates[0] = .initHost(base_addr);
    core.candidates_len = 1;
    core.remote_candidates[0] = testRemoteCandidate(from);
    core.remote_candidates_len = 1;
    try core.pairs.append(testing.allocator, .{ .local = 0, .remote = 0, .status = .in_progress, .priority = 0 });

    const result = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = "hello" }, 0, &resp_buffer);

    switch (result) {
        .app_data => |data| try testing.expectEqualStrings("hello", data),
        else => return error.UnexpectedResult,
    }
    try testing.expectEqual(null, core.pollEvent());
}

test "handleInput: forwards non-stun data once connected regardless of sender" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();
    core.connection_state = .connected;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("10.0.0.5", 4000);
    var resp_buffer: [64]u8 = undefined;

    const result = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = "world" }, 0, &resp_buffer);

    switch (result) {
        .app_data => |data| try testing.expectEqualStrings("world", data),
        else => return error.UnexpectedResult,
    }
}

test "handleInput: completed state answers stun requests via consent freshness" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();
    core.connection_state = .completed;

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = core.credentials.getUsername(),
    }, core.credentials.getPassword(), &buffer);

    const result = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = msg.bytes }, 0, &resp_buffer);

    try testing.expectEqual(.consumed, std.meta.activeTag(result));
    try testing.expectEqual(.completed, core.connection_state);

    const resp = core.pollTransmit() orelse return error.ExpectedTransmit;
    const resp_msg = try stun.Message.parse(resp.data);
    try testing.expectEqual(.success_response, resp_msg.header.message_type.class());

    try testing.expectEqual(null, core.pollEvent());
}

test "handleInput: stun request produces a response event" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);
    try core.addLocalAddrs(&.{base_addr});

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = core.credentials.getUsername(),
    }, core.credentials.getPassword(), &buffer);

    _ = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = msg.bytes }, 0, &resp_buffer);

    const resp = core.pollTransmit() orelse return error.ExpectedTransmit;
    const resp_msg = try stun.Message.parse(resp.data);
    try testing.expectEqual(.success_response, resp_msg.header.message_type.class());

    try testing.expectEqual(null, core.pollTransmit());
    try expectEvent(&core, .candidate);
    try testing.expectEqual(1, core.pairs.items.len);
}

test "handleInput: role conflict switches role and produces a response" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);
    try core.addLocalAddrs(&.{base_addr});

    const msg = try testBuildRequest(.{
        .ice_controlled = 0,
        .priority = 0x9090,
        .username = core.credentials.getUsername(),
    }, core.credentials.getPassword(), &buffer);

    _ = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = msg.bytes }, 0, &resp_buffer);

    try testing.expectEqual(.controlling, core.role);

    const resp = core.pollTransmit() orelse return error.ExpectedTransmit;
    const resp_msg = try stun.Message.parse(resp.data);
    try testing.expectEqual(.success_response, resp_msg.header.message_type.class());

    try expectEvent(&core, .candidate);
    try expectEvent(&core, .gathering_state);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleInput: success response completes the pending request and marks the pair succeeded" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    core.remote_credentials = try .init("ruser", "peer-password-0123456789");

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    core.candidates[0] = .initHost(base_addr);
    core.candidates_len = 1;
    core.remote_candidates[0] = testRemoteCandidate(from);
    core.remote_candidates_len = 1;
    try core.pairs.append(testing.allocator, .{ .local = 0, .remote = 0, .status = .in_progress, .priority = 0 });
    try core.pending_requests.append(testing.allocator, .{
        .transaction_id = @bitCast(@as(u96, 0x2)),
        .pair = 0,
    });

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [64]u8 = undefined;
    const msg = try testBuildResponse(0x2, base_addr, core.remote_credentials.?.getPassword(), &buffer);

    _ = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = msg.bytes }, 0, &resp_buffer);

    try testing.expectEqual(null, core.pollEvent());

    try testing.expectEqual(.succeeded, core.pairs.items[0].status);
    try testing.expectEqual(0, core.pending_requests.items.len);
}

test "handleInput: success response nominates the pair and transitions to connected" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    core.remote_credentials = try .init("ruser", "peer-password-0123456789");

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    core.candidates[0] = .initHost(base_addr);
    core.candidates_len = 1;
    core.remote_candidates[0] = testRemoteCandidate(from);
    core.remote_candidates_len = 1;
    try core.pairs.append(testing.allocator, .{
        .local = 0,
        .remote = 0,
        .status = .in_progress,
        .priority = 0,
        .nominate_on_binding = true,
    });
    try core.pending_requests.append(testing.allocator, .{
        .transaction_id = @bitCast(@as(u96, 0x2)),
        .pair = 0,
    });

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [64]u8 = undefined;
    const msg = try testBuildResponse(0x2, base_addr, core.remote_credentials.?.getPassword(), &buffer);

    _ = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = msg.bytes }, 0, &resp_buffer);

    try expectConnectionStateEvent(&core, .connected);
    try expectEvent(&core, .nominated);
    try testing.expectEqual(null, core.pollEvent());

    try testing.expectEqual(.connected, core.connection_state);
    try testing.expect(core.pairs.items[0].nominated);
    try testing.expect(core.nominated_pair != null);

    try testing.expectEqual(@as(i64, keep_alive_interval), core.keep_alive_deadline);
    try testing.expectEqual(@as(i64, core.disconnected_timeout), core.disconnected_connection_deadline);
}

test "handleTimeout: new connection starts checking and schedules a connectivity check" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    const failed_timeout: i64 = core.failed_timeout;
    try core.setRemoteCredentials(.{ .username = "peer", .password = "peer-password-0123456789" }, 0);

    try testing.expectEqual(connectivity_check_interval, core.connectivity_check_deadline);
    try testing.expectEqual(failed_timeout, core.disconnected_connection_deadline);

    try expectConnectionStateEvent(&core, .checking);
    try testing.expectEqual(null, core.pollEvent());

    try core.handleTimeout(connectivity_check_interval);
    try expectEvent(&core, .connectivity_check);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleTimeout: checking sends a connectivity_check every interval" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    try core.setRemoteCredentials(.{ .username = "peer", .password = "peer-password-0123456789" }, 0);
    _ = core.pollEvent(); // .checking

    try core.handleTimeout(100);
    try testing.expectEqual(null, core.pollEvent());

    try core.handleTimeout(connectivity_check_interval);
    try testing.expectEqual(connectivity_check_interval * 2, core.connectivity_check_deadline);
    try expectEvent(&core, .connectivity_check);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleTimeout: checking fails after failed_timeout without connecting" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    const failed_timeout: i64 = core.failed_timeout;
    try core.setRemoteCredentials(.{ .username = "peer", .password = "peer-password-0123456789" }, 0);
    _ = core.pollEvent(); // .checking

    try core.handleTimeout(failed_timeout);

    try testing.expectEqual(.failed, core.connection_state);
    try testing.expectEqual(std.math.maxInt(i64), core.disconnected_connection_deadline);

    try expectEvent(&core, .connectivity_check);
    try expectConnectionStateEvent(&core, .failed);
    try testing.expectEqual(null, core.pollEvent());

    try core.handleTimeout(failed_timeout + 1000);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleTimeout: connected transitions to completed once keep_alive_deadline elapses and clears the checklist" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    core.connection_state = .connected;
    core.connectivity_check_deadline = 100_000;
    core.disconnected_connection_deadline = 100_000;
    core.keep_alive_deadline = 1000;

    const from = try IpAddress.parse("192.168.1.120", 2000);
    core.remote_candidates[0] = testRemoteCandidate(from);
    core.remote_candidates_len = 1;
    try core.pairs.append(testing.allocator, .{ .local = 0, .remote = 0, .status = .succeeded, .priority = 0 });
    try core.pending_requests.append(testing.allocator, .{ .transaction_id = @bitCast(@as(u96, 0x1)), .pair = 0 });

    try core.handleTimeout(1000);

    try testing.expectEqual(.completed, core.connection_state);
    try testing.expectEqual(0, core.remote_candidates_len);
    try testing.expectEqual(0, core.pairs.items.len);
    try testing.expectEqual(0, core.pending_requests.items.len);
    try testing.expectEqual(1000 + keep_alive_interval, core.keep_alive_deadline);

    try expectConnectionStateEvent(&core, .completed);
    try expectEvent(&core, .consent_freshness);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleTimeout: completed sends periodic consent_freshness without changing state" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    core.connection_state = .completed;
    core.disconnected_connection_deadline = 100_000;
    core.keep_alive_deadline = 1000;

    try core.handleTimeout(1000);

    try testing.expectEqual(.completed, core.connection_state);
    try testing.expectEqual(1000 + keep_alive_interval, core.keep_alive_deadline);

    try expectEvent(&core, .consent_freshness);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleTimeout: disconnected sends periodic consent_freshness without changing state" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    core.connection_state = .disconnected;
    core.disconnected_connection_deadline = 100_000;
    core.keep_alive_deadline = 1000;

    try core.handleTimeout(1000);

    try testing.expectEqual(.disconnected, core.connection_state);
    try testing.expectEqual(1000 + keep_alive_interval, core.keep_alive_deadline);

    try expectEvent(&core, .consent_freshness);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleTimeout: connected becomes disconnected after disconnected_timeout of silence and refreshes the failed deadline" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    core.connection_state = .connected;
    core.connectivity_check_deadline = 100_000;
    core.keep_alive_deadline = 100_000;
    core.disconnected_connection_deadline = 1000;

    const failed_timeout: i64 = core.failed_timeout;
    try core.handleTimeout(1000);

    try testing.expectEqual(.disconnected, core.connection_state);
    try testing.expectEqual(1000 + failed_timeout, core.disconnected_connection_deadline);

    try expectConnectionStateEvent(&core, .disconnected);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleTimeout: disconnected becomes failed after failed_timeout elapses" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    core.connection_state = .disconnected;
    core.keep_alive_deadline = 999_999;
    core.disconnected_connection_deadline = 1000;

    try core.handleTimeout(1000);

    try testing.expectEqual(.failed, core.connection_state);
    try testing.expectEqual(null, core.pollTimeout());

    try expectConnectionStateEvent(&core, .failed);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleTimeout: returns the earliest of the three schedules without firing anything" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    core.connection_state = .connected;
    core.connectivity_check_deadline = 5000;
    core.keep_alive_deadline = 3000;
    core.disconnected_connection_deadline = 8000;

    try core.handleTimeout(1000);

    try testing.expectEqual(.connected, core.connection_state);
    try testing.expectEqual(3000, core.pollTimeout());
    try testing.expectEqual(null, core.pollEvent());

    try testing.expectEqual(5000, core.connectivity_check_deadline);
    try testing.expectEqual(3000, core.keep_alive_deadline);
    try testing.expectEqual(8000, core.disconnected_connection_deadline);
}

test "setRemoteCredentials: replaces and frees the previous value" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    try core.setRemoteCredentials(.{ .username = "first", .password = "first-password-0123456789" }, 0);
    try testing.expectEqualStrings("first", core.remote_credentials.?.getUsername());

    try core.setRemoteCredentials(.{ .username = "second", .password = "second-password-0123456789" }, 0);
    try testing.expectEqualStrings("second", core.remote_credentials.?.getUsername());
    try testing.expectEqualStrings("second-password-0123456789", core.remote_credentials.?.getPassword());
}

fn testFillPairs(core: *Agent) void {
    for (0..max_pairs) |i| {
        core.pairs[i] = .{ .local = 0, .remote = 0, .priority = @intCast(i + 1), .status = .waiting };
    }
    core.pairs_len = max_pairs;
}

test "addPair: replaces a failed pair when full" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    testFillPairs(&core);
    core.pairs[3].status = .failed;

    core.addPair(.{ .local = 0, .remote = 0, .priority = 999, .status = .waiting });

    try testing.expectEqual(max_pairs, core.pairs_len);
    try testing.expectEqual(999, core.pairs[3].priority);
    try testing.expectEqual(.waiting, core.pairs[3].status);
}

test "addPair: replaces the lowest-priority pair when full and no failed pairs" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    testFillPairs(&core);
    // Lowest priority (1) is at index 0.

    core.addPair(.{ .local = 0, .remote = 0, .priority = 999, .status = .waiting });

    try testing.expectEqual(max_pairs, core.pairs_len);
    try testing.expectEqual(999, core.pairs[0].priority);
}

test "addPair: drops the new pair when full and it doesn't improve on the lowest priority" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    testFillPairs(&core);

    core.addPair(.{ .local = 0, .remote = 0, .priority = 1, .status = .waiting });

    try testing.expectEqual(max_pairs, core.pairs_len);
    try testing.expectEqual(1, core.pairs[0].priority);
}

test "addPendingRequest: evicts the oldest entry (FIFO) when full" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    const addr = try IpAddress.parse("10.0.0.1", 1000);
    for (0..max_pending_requests) |i| {
        core.pending_requests[i] = .{ .transaction_id = @intCast(i), .source = addr, .target = addr };
    }
    core.pending_requests_len = max_pending_requests;

    core.addPendingRequest(.{ .transaction_id = 999, .source = addr, .target = addr });

    try testing.expectEqual(max_pending_requests, core.pending_requests_len);
    try testing.expectEqual(1, core.pending_requests[0].transaction_id);
    try testing.expectEqual(999, core.pending_requests[max_pending_requests - 1].transaction_id);
}
