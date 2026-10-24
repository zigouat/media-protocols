//! This module implements an ICE (Interactive Connectivity Establishment) agent that can be used to establish a peer-to-peer connection.
//!
//! The implementation is based on RFC 8445.

const std = @import("std");
const stun = @import("stun");
const ice = @import("ice.zig");
const CandidatePair = @import("candidate_pair.zig");
const Messages = @import("messages.zig");

const Candidate = ice.Candidate;
const CandidateIndex = CandidatePair.CandidateIndex;
const IpAddress = std.Io.net.IpAddress;
const Logger = std.log.scoped(.ice);
const AllocError = std.mem.Allocator.Error;

pub const NominatedPair = struct {
    local: CandidateIndex,
    remote: CandidateIndex,
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
    nominated: NominatedPair,
    candidate: struct { CandidateIndex, CandidateIndex }, // range inclusive
};

pub const ReadResult = union(enum) {
    app_data: []const u8,
    consumed: void,
};

/// A resolved STUN or TURN server.
pub const Server = union(enum) {
    stun: IpAddress,
    turn: struct { address: IpAddress, username: []const u8, password: []const u8 },
};

const PendingRequest = struct {
    transaction_id: [12]u8,
    pair: u16,
};

const Response = struct {
    tx_id: [12]u8,
    local: CandidateIndex,
    remote: CandidateIndex,
    kind: enum(u2) { success, role_conflict } = .success,
};

/// The maximum number of binding requests sent on a pair before it is
/// considered failed.
pub const max_binding_requests: usize = 7;
pub const keep_alive_interval: i64 = 4 * std.time.ms_per_s;

pub const Config = struct {
    /// The role of the agent.
    role: ice.Role,
    credentials: ice.Credentials,
    /// A random number generator implementation used for generating transaction IDs and tie breakers.
    random: std.Random,
    /// The time in milliseconds after which a connection is considered failed if no data is received or no connection is established.
    failed_timeout: u32 = 25 * std.time.ms_per_s,
    /// The time in milliseconds after which a connection is considered disconnected if no data is received.
    disconnected_timeout: u32 = 5 * std.time.ms_per_s,
    /// The interval between connectivity checks in milliseconds. This is the time between sending binding requests on all pairs.
    connectivity_check_interval: u16 = 200,
};

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

pub fn Agent(comptime config: struct {
    auth_info_size: u8 = 64,
    max_candidates: CandidateIndex = 16,
    max_responses: u8 = 16,
    stun_config: stun.Client.ClientConfig = .{ .max_transactions = 1 },
    turn_config: stun.turn.Config = .{},
}) type {
    const Timers = struct {
        failed_timeout: u32,
        disconnected_timeout: u32,
        connectivity_check_interval: u16,
    };

    return struct {
        const Self = @This();
        const StunClient = stun.Client.Client(config.stun_config);
        const TurnClient = stun.turn.TurnClient(config.turn_config);

        const max_events: u8 = 5;
        const initial_pairs_capacity: usize = @as(usize, config.max_candidates) * config.max_candidates / 2;
        const initial_pending_requests_capacity: usize = 16;

        allocator: std.mem.Allocator,
        random: std.Random,

        credentials: LocalCredentials(config.auth_info_size),
        remote_credentials: ?LocalCredentials(config.auth_info_size),
        connection_state: ice.ConnectionState,
        gathering_state: ice.GatheringState,
        /// Set once addLocalAddrs is called with no addresses.
        gathering_done: bool,
        role: ice.Role,
        tie_breaker: u64,

        // Candidates and sockets
        candidates: [config.max_candidates]Candidate = undefined,
        candidates_len: CandidateIndex = 0,
        remote_candidates: [config.max_candidates]RemoteCandidate = undefined,
        remote_candidates_len: CandidateIndex = 0,
        pairs: std.ArrayList(CandidatePair) = .empty,
        pending_requests: std.ArrayList(PendingRequest) = .empty,
        stun_clients: std.ArrayList(StunClient) = .empty,
        turn_clients: std.ArrayList(TurnClient) = .empty,
        // This is a peer for which a use-candidate request is sent, but we didn't
        // receive response yet.
        selected_pair: ?u8 = null,
        // This the final pair selected by this agent or the remote one.
        nominated_pair: ?NominatedPair = null,

        timers: Timers,

        connectivity_check_deadline: i64,
        disconnected_connection_deadline: i64, // used for both disconnected and failed states
        keep_alive_deadline: i64,

        events_out: stun.BoundedDeque(Event, max_events),
        responses: stun.BoundedDeque(Response, config.max_responses) = .empty,

        connectivity_check: ConnectivityChecks = .init_done,
        consent_freshness: bool,

        const ConnectivityChecks = struct {
            index: u16,
            nomination_done: bool,
            done: bool,

            const init = ConnectivityChecks{ .index = 0, .nomination_done = false, .done = false };
            const init_done = ConnectivityChecks{ .index = 0, .nomination_done = false, .done = true };
        };

        pub fn init(allocator: std.mem.Allocator, agent_config: Config) error{ OutOfMemory, CredentialsTooLong }!Self {
            std.debug.assert(agent_config.connectivity_check_interval > 0);

            var pairs: std.ArrayList(CandidatePair) = try .initCapacity(allocator, initial_pairs_capacity);
            errdefer pairs.deinit(allocator);

            var pending_requests: std.ArrayList(PendingRequest) = try .initCapacity(allocator, initial_pending_requests_capacity);
            errdefer pending_requests.deinit(allocator);

            return .{
                .allocator = allocator,
                .random = agent_config.random,
                .role = agent_config.role,
                .connection_state = .new,
                .gathering_state = .new,
                .gathering_done = false,
                .credentials = try .init(agent_config.credentials.username, agent_config.credentials.password),
                .remote_credentials = null,
                .tie_breaker = agent_config.random.int(u64),
                .connectivity_check_deadline = std.math.maxInt(i64),
                .keep_alive_deadline = std.math.maxInt(i64),
                .disconnected_connection_deadline = std.math.maxInt(i64),
                .events_out = .empty,
                .pairs = pairs,
                .pending_requests = pending_requests,
                .consent_freshness = false,
                .timers = .{
                    .failed_timeout = agent_config.failed_timeout,
                    .disconnected_timeout = agent_config.disconnected_timeout,
                    .connectivity_check_interval = agent_config.connectivity_check_interval,
                },
            };
        }

        pub fn deinit(agent: *Self) void {
            agent.close();
            agent.events_out.clear();
            agent.responses.clear();
        }

        pub fn close(agent: *Self) void {
            agent.connection_state = .closed;

            agent.pairs.clearAndFree(agent.allocator);
            agent.pending_requests.clearAndFree(agent.allocator);
            agent.stun_clients.clearAndFree(agent.allocator);
            agent.turn_clients.clearAndFree(agent.allocator);
            agent.candidates_len = 0;
            agent.remote_candidates_len = 0;
        }

        pub fn getRemoteCredentials(core: *const Self) ?ice.Credentials {
            return if (core.remote_credentials) |*rc| rc.toIceCredentials() else null;
        }

        pub fn getLocalCredentials(core: *const Self) ice.Credentials {
            return core.credentials.toIceCredentials();
        }

        pub fn getNominatedRemoteAddress(core: *const Self) ?IpAddress {
            return if (core.nominated_pair) |nominated| core.remote_candidates[nominated.remote].address else null;
        }

        /// Add local addresses to the agent. The first call starts gathering.
        ///
        /// Adding an empty list of addresses signals the end of gathering.
        pub fn addLocalAddrs(agent: *Self, addrs: []const IpAddress, now: i64) (AllocError || error{GatheringDone})!void {
            if (agent.gathering_done) return error.GatheringDone;
            const prev_state = agent.gathering_state;
            if (agent.gathering_state == .new) {
                agent.gathering_state = .gathering;
                try agent.events_out.pushBack(.{ .gathering_state = agent.gathering_state });
            }

            var min_index: ?CandidateIndex = null;
            var max_index: ?CandidateIndex = null;
            for (addrs) |addr| {
                const candidate = Candidate.initHost(addr);
                if (try agent.addLocalCandidate(candidate)) |idx| {
                    if (min_index == null) min_index = idx;
                    max_index = idx;
                }
            }

            if (min_index) |min| try agent.events_out.pushBack(.{ .candidate = .{ min, max_index.? } });

            // Send binding requests for all stun servers and create allocations for all turn servers
            // only if this is the first call
            if (prev_state == .new) {
                for (agent.stun_clients.items) |*stun_client| {
                    try stun_client.bindingRequest(now);
                }

                for (agent.turn_clients.items) |*turn_client| try startAllocation(turn_client, now);
            }

            if (addrs.len == 0) {
                agent.gathering_done = true;
                try agent.setGatheringCompleted();
            }
        }

        /// Add a server queried from the `local` socket. Servers added while gathering
        /// is in progress are queried immediately.
        pub fn addServer(agent: *Self, local: IpAddress, server: Server, now: i64) (AllocError || error{GatheringDone})!void {
            if (agent.gathering_done) return error.GatheringDone;
            const started = agent.gathering_state == .gathering;
            switch (server) {
                .stun => |address| {
                    const stun_client = try agent.stun_clients.addOne(agent.allocator);
                    errdefer _ = agent.stun_clients.pop();
                    stun_client.* = StunClient.init(.{
                        .local_addr = local,
                        .remote_addr = address,
                        .random = agent.random,
                    });
                    if (started) try stun_client.bindingRequest(now);
                },
                .turn => |turn| {
                    const turn_client = try agent.turn_clients.addOne(agent.allocator);
                    errdefer _ = agent.turn_clients.pop();
                    turn_client.* = TurnClient.init(.{
                        .local_addr = local,
                        .remote_addr = turn.address,
                        .random = agent.random,
                        .username = turn.username,
                        .password = turn.password,
                    });
                    if (started) try startAllocation(turn_client, now);
                },
            }
        }

        fn startAllocation(turn_client: *TurnClient, now: i64) AllocError!void {
            turn_client.createAllocation(now) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.AllocationAlreadyExists => {},
            };
        }

        pub fn setRemoteCredentials(agent: *Self, credentials: ice.Credentials, now: i64) (AllocError || error{CredentialsTooLong})!void {
            agent.remote_credentials = try .init(credentials.username, credentials.password);
            try agent.setConnectionState(.checking, now);
        }

        pub fn addServerReflexiveCandidate(core: *Self, base: IpAddress, mapped: IpAddress) AllocError!?CandidateIndex {
            for (core.candidates[0..core.candidates_len]) |candidate|
                if (candidate.candidate_type == .host and ipEql(&candidate.base, &mapped)) return null;

            const candidate = Candidate.initServerReflexive(base, mapped);
            return try core.addLocalCandidate(candidate);
        }

        pub fn addRemoteCandidate(core: *Self, remote_candidate: Candidate, now: i64) AllocError!void {
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
                    .remote = remote_idx,
                    .priority = calculatePairPriority(candidate.priority, remote_candidate.priority, core.role),
                });

                if (candidate.candidate_type == .relay) {
                    if (core.findTurnClient(&candidate.base)) |turn_client| {
                        turn_client.createPermission(remote_candidate.address, now) catch |err| {
                            Logger.warn("Cannot create permissions for {f}: {}\n", .{ remote_candidate.address, err });
                        };
                    }
                }
            }

            core.resumeConnectivityChecks();
        }

        /// Returns `false` if an identical candidate already exists.
        pub fn addLocalCandidate(core: *Self, candidate: Candidate) AllocError!?CandidateIndex {
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
                    .local = idx,
                    .remote = @intCast(remote_idx),
                    .priority = calculatePairPriority(candidate.priority, remote_candidate.priority, core.role),
                });
            }

            core.resumeConnectivityChecks();
            return idx;
        }

        pub fn handleTimeout(agent: *Self, now: i64) AllocError!void {
            if (agent.connection_state == .closed) return;

            var stun_idx: usize = 0;
            while (stun_idx < agent.stun_clients.items.len) {
                const stun_server = &agent.stun_clients.items[stun_idx];
                stun_server.handleTimeout(now) catch continue;
                if (!try agent.handleStunClientEvents(stun_idx)) stun_idx += 1;
            }

            var turn_idx: usize = 0;
            while (turn_idx < agent.turn_clients.items.len) {
                const turn_server = &agent.turn_clients.items[turn_idx];
                turn_server.handleTimeout(now) catch continue;
                if (!try agent.handleTurnClientEvents(turn_idx, now)) turn_idx += 1;
            }

            if (now >= agent.connectivity_check_deadline) {
                agent.connectivity_check_deadline = now + agent.timers.connectivity_check_interval;
                if (agent.nominated_pair == null) agent.connectivity_check = .init;
                if (agent.role == .controlling and agent.nominated_pair == null and agent.selected_pair == null) {
                    agent.selected_pair = agent.selectBestPair();
                }
            }

            if (now >= agent.keep_alive_deadline) {
                agent.keep_alive_deadline = now + keep_alive_interval;
                if (agent.connection_state == .connected) {
                    try agent.setConnectionState(.completed, now);
                }
                agent.consent_freshness = true;
            }

            if (now >= agent.disconnected_connection_deadline) {
                switch (agent.connection_state) {
                    .checking, .disconnected => try agent.setConnectionState(.failed, now),
                    else => try agent.setConnectionState(.disconnected, now),
                }
            }
        }

        pub fn handleRead(agent: *Self, message: stun.TransportMessage, now: i64) !ReadResult {
            if (!stun.isMessage(message.data)) {
                return agent.handleAppData(message.from, message.data);
            }

            // Ignore malformed stun messages.
            var msg = stun.Message.parse(message.data) catch return .consumed;

            const peer, const data = if (msg.isDataIndication())
                msg.parseDataIndication() catch return .consumed
            else
                .{ message.from.*, message.data };
            if (!stun.isMessage(data)) return .{ .app_data = data };

            const new_message = stun.TransportMessage{
                .from = &peer,
                .to = message.to,
                .data = data,
            };

            for (agent.turn_clients.items, 0..) |*turn_client, i| {
                if (turn_client.local_addr.eql(new_message.to) and turn_client.remote_addr.eql(new_message.from)) {
                    // ignore malformed messages
                    turn_client.handleRead(new_message.data, now) catch return .consumed;
                    _ = try agent.handleTurnClientEvents(i, now);
                    return .consumed;
                }
            }

            switch (agent.connection_state) {
                .completed, .disconnected, .failed => |state| {
                    agent.disconnected_connection_deadline = now + agent.timers.disconnected_timeout;
                    msg = stun.Message.parse(new_message.data) catch return .consumed;
                    if (state == .disconnected) try agent.setConnectionState(.completed, now);
                    if (try agent.handleConsentFreshness(&msg, new_message.to, new_message.from)) |resp| {
                        agent.queueResponse(resp);
                    }

                    return .consumed;
                },
                else => {
                    for (agent.stun_clients.items, 0..) |*stun_server, i| {
                        if (stun_server.local_addr.eql(new_message.to)) if (try stun_server.handleRead(new_message.data)) {
                            _ = try agent.handleStunClientEvents(i);
                            return .consumed;
                        };
                    }

                    return agent.handleStunMessage(new_message, now);
                },
            }
        }

        pub fn pollEvent(core: *Self) ?Event {
            return core.events_out.popFront();
        }

        pub fn pollTransmit(agent: *Self, buffer: []u8) error{WriteFailed}!?stun.TransportMessage {
            if (agent.responses.popFront()) |resp| {
                const remote = &agent.remote_candidates[resp.remote].address;
                const password = agent.credentials.getPassword();
                const payload = switch (resp.kind) {
                    .success => try Messages.buildSuccessResponse(resp.tx_id, password, remote, buffer),
                    .role_conflict => try Messages.buildRoleConflictErrorMessage(resp.tx_id, password, buffer),
                };
                return try agent.maybeWrapInTurnMessage(
                    &agent.candidates[resp.local].base,
                    remote,
                    buffer,
                    payload.len,
                );
            }

            for (agent.stun_clients.items) |*stun_client| if (try stun_client.pollTransmit(buffer)) |msg| {
                return msg;
            };

            for (agent.turn_clients.items) |*turn_client| if (try turn_client.pollTransmit(buffer)) |msg| {
                return msg;
            };

            if (agent.consent_freshness) {
                agent.consent_freshness = false;
                const payload = try agent.buildBindingRequest(agent.newTransactionId(), false, buffer);
                const local_candidate = &agent.candidates[agent.nominated_pair.?.local];
                const remote_addr = &agent.remote_candidates[agent.nominated_pair.?.remote].address;

                return try agent.maybeWrapInTurnMessage(
                    &local_candidate.base,
                    remote_addr,
                    buffer,
                    payload.len,
                );
            }

            return try agent.nextConnectivityCheck(buffer);
        }

        pub fn pollTimeout(agent: *Self) ?i64 {
            if (agent.connection_state == .closed) return null;
            var deadline: i64 = std.math.maxInt(i64);

            for (agent.stun_clients.items) |*stun_client| if (stun_client.pollTimeout()) |d| {
                deadline = @min(deadline, d);
            };

            for (agent.turn_clients.items) |*turn_client| if (turn_client.pollTimeout()) |d| {
                deadline = @min(deadline, d);
            };

            for (&[_]i64{
                agent.connectivity_check_deadline,
                agent.keep_alive_deadline,
                agent.disconnected_connection_deadline,
            }) |d| deadline = @min(deadline, d);

            return if (deadline == std.math.maxInt(i64)) null else deadline;
        }

        pub fn detectNominatedPair(core: *Self) void {
            if (core.role == .controlling or core.nominated_pair != null) return;
            for (core.pairs.items) |pair| if (pair.nominated) {
                core.nominated_pair = .{ .local = pair.local, .remote = pair.remote };
                return;
            };
        }

        pub fn buildBindingRequest(core: *Self, tx_id: [12]u8, use_candidate: bool, buffer: []u8) error{WriteFailed}![]const u8 {
            var w = stun.Writer.init(buffer, .{ .password = core.remote_credentials.?.getPassword() });
            try w.writeHeader(.{
                .message_type = .fromClassAndMethod(.request, .binding),
                .transaction_id = tx_id,
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

        pub fn toggleRole(agent: *Self) void {
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

        fn newTransactionId(agent: *Self) [12]u8 {
            var id: [12]u8 = undefined;
            agent.random.bytes(&id);
            return id;
        }

        fn appendCandidate(core: *Self, candidate: Candidate) error{OutOfMemory}!CandidateIndex {
            if (core.candidates_len >= config.max_candidates) return error.OutOfMemory;
            const idx = core.candidates_len;
            core.candidates[idx] = candidate;
            core.candidates_len += 1;
            return idx;
        }

        fn appendRemoteCandidate(core: *Self, candidate: Candidate) AllocError!CandidateIndex {
            if (core.remote_candidates_len >= config.max_candidates) return error.OutOfMemory;
            const idx = core.remote_candidates_len;
            core.remote_candidates[idx] = .{ .address = candidate.address, .candidate_type = candidate.candidate_type, .priority = candidate.priority };
            core.remote_candidates_len += 1;
            return idx;
        }

        fn setConnectionState(agent: *Self, state: ice.ConnectionState, now: i64) !void {
            agent.connection_state = state;
            switch (agent.connection_state) {
                .checking => {
                    agent.connectivity_check = .init; // start connectivity checks immediately
                    agent.connectivity_check_deadline = now + agent.timers.connectivity_check_interval;
                    agent.disconnected_connection_deadline = now + agent.timers.failed_timeout;
                },
                .connected => {
                    agent.keep_alive_deadline = now + keep_alive_interval;
                    agent.disconnected_connection_deadline = now + agent.timers.disconnected_timeout;
                },
                .completed => {
                    agent.connectivity_check_deadline = std.math.maxInt(i64);
                    agent.connectivity_check = .init_done;
                    agent.disconnected_connection_deadline = now + agent.timers.disconnected_timeout;
                    agent.pairs.clearAndFree(agent.allocator);
                    agent.pending_requests.clearAndFree(agent.allocator);
                    agent.stun_clients.clearAndFree(agent.allocator);

                    const local_candidate = &agent.candidates[agent.nominated_pair.?.local];
                    if (agent.findTurnClient(&local_candidate.base)) |turn_client| {
                        const client = turn_client.*;
                        agent.turn_clients.shrinkAndFree(agent.allocator, 1);
                        agent.turn_clients.items[0] = client;
                    } else agent.turn_clients.clearAndFree(agent.allocator);
                },
                .disconnected => agent.disconnected_connection_deadline = now + agent.timers.failed_timeout,
                .failed => {
                    agent.connectivity_check_deadline = std.math.maxInt(i64);
                    agent.disconnected_connection_deadline = std.math.maxInt(i64);
                    agent.keep_alive_deadline = std.math.maxInt(i64);
                },
                else => {},
            }

            try agent.events_out.pushBack(.{ .connection_state = agent.connection_state });
        }

        fn handleStunMessage(agent: *Self, message: stun.TransportMessage, now: i64) !ReadResult {
            const was_nominated = agent.nominated_pair != null;
            const msg = try stun.Message.parse(message.data);

            switch (msg.header.message_type.class()) {
                .request => {
                    if (try agent.handleRequest(&msg, message.to, message.from)) |resp| agent.queueResponse(resp);
                    agent.detectNominatedPair();
                },
                .success_response => {
                    try agent.handleSuccessResponse(&msg, message.to, message.from);
                    agent.detectNominatedPair();
                },
                else => {},
            }

            if (!was_nominated) if (agent.nominated_pair) |nominated| {
                try agent.events_out.pushBack(.{ .nominated = nominated });
                try agent.setConnectionState(.connected, now);
            };

            return .consumed;
        }

        fn handleStunClientEvents(agent: *Self, idx: usize) !bool {
            const stun_client = &agent.stun_clients.items[idx];
            // There's only one event
            const event = stun_client.pollEvent() orelse return false;
            switch (event) {
                .mapped_address => {
                    const mapped_address = event.mapped_address;
                    if (try agent.addServerReflexiveCandidate(
                        stun_client.local_addr,
                        mapped_address,
                    )) |index| try agent.events_out.pushBack(.{ .candidate = .{ index, index } });

                    _ = agent.stun_clients.swapRemove(idx);
                },
                .err => {
                    Logger.debug("Stun server error for {f}: {}", .{ stun_client.remote_addr, event.err });
                    _ = agent.stun_clients.swapRemove(idx);
                },
            }

            try agent.setGatheringCompleted();
            return true;
        }

        fn handleTurnClientEvents(agent: *Self, idx: usize, now: i64) !bool {
            const turn_client = &agent.turn_clients.items[idx];
            var delete_entry: bool = false;
            while (turn_client.pollEvent()) |event| switch (event) {
                .allocated => |allocation| {
                    const relayed_address = allocation.relayed_address;
                    const index = try agent.addLocalCandidate(.initRelay(
                        turn_client.local_addr,
                        relayed_address,
                    )) orelse {
                        delete_entry = true;
                        break;
                    };
                    try agent.events_out.pushBack(.{ .candidate = .{ index, index } });

                    for (agent.pairs.items) |*pair| {
                        if (pair.local != index) continue;
                        const remote_addr = agent.getPairRemote(pair).address;
                        turn_client.createPermission(remote_addr, now) catch |err| {
                            Logger.warn("Cannot create permissions for {f}: {}\n", .{ remote_addr, err });
                        };
                    }
                },
                .allocation_failed => |err| {
                    Logger.debug("Turn server allocation failed for {f}: {}", .{ turn_client.remote_addr, err });
                    delete_entry = true;
                    break;
                },
                .allocation_refresh_failed => {},
                .permission_created => |addr| {
                    Logger.debug("Turn server permission created for {f}: {f}", .{ turn_client.remote_addr, addr });
                },
                .permission_failed => |err| {
                    Logger.debug("Turn server permission failed for {f}: {}", .{ err.address, err.err });
                    for (agent.pairs.items) |*pair| {
                        const local_addr = agent.getPairLocal(pair).base;
                        const remote_addr = agent.getPairRemote(pair).address;
                        if (local_addr.eql(&turn_client.local_addr) and remote_addr.eql(&err.address)) {
                            pair.status = .failed;
                            continue;
                        }
                    }
                },
                else => {},
            };

            if (delete_entry) _ = agent.turn_clients.swapRemove(idx);
            try agent.setGatheringCompleted();
            return delete_entry;
        }

        fn setGatheringCompleted(agent: *Self) !void {
            if (agent.gathering_state == .complete) return;
            if (!agent.gathering_done) return;
            const stun_completed = agent.stun_clients.items.len == 0;
            const turn_completed = blk: {
                for (agent.turn_clients.items) |*turn_client| if (!turn_client.hasAllocation()) break :blk false;
                break :blk true;
            };

            if (stun_completed and turn_completed) {
                agent.gathering_state = .complete;
                try agent.events_out.pushBack(.{ .gathering_state = agent.gathering_state });
            }
        }

        /// Check pairs added after the current round finished without waiting for the next interval.
        fn resumeConnectivityChecks(agent: *Self) void {
            if (agent.connection_state == .checking and agent.nominated_pair == null) agent.connectivity_check.done = false;
        }

        fn nextConnectivityCheck(agent: *Self, buffer: []u8) !?stun.TransportMessage {
            const check = &agent.connectivity_check;
            if (check.done) return null;

            if (!check.nomination_done) {
                check.nomination_done = true;
                if (agent.selected_pair) |selected_idx| {
                    const pair = &agent.pairs.items[selected_idx];
                    if (try agent.buildConnectivityCheckBindingRequest(
                        pair,
                        selected_idx,
                        buffer,
                    )) |msg| return msg;
                }
            }

            while (check.index < agent.pairs.items.len) {
                const idx = check.index;
                const pair = &agent.pairs.items[idx];
                check.index += 1;
                switch (pair.status) {
                    .waiting, .in_progress => {
                        pair.conn_check_count += 1;
                        if (pair.conn_check_count > max_binding_requests) {
                            pair.status = .failed;
                            continue;
                        }

                        const msg = (try agent.buildConnectivityCheckBindingRequest(
                            pair,
                            idx,
                            buffer,
                        )) orelse continue;
                        return msg;
                    },
                    else => {},
                }
            }

            check.done = true;
            return null;
        }

        fn buildConnectivityCheckBindingRequest(agent: *Self, pair: *const CandidatePair, idx: u16, buffer: []u8) !?stun.TransportMessage {
            const tx_id = agent.newTransactionId();
            const local = agent.getPairLocal(pair);
            const remote = &agent.getPairRemote(pair).address;

            const payload = try agent.buildBindingRequest(
                tx_id,
                agent.selected_pair != null and agent.selected_pair.? == idx,
                buffer,
            );

            const msg = try agent.maybeWrapInTurnMessage(
                &local.base,
                remote,
                buffer,
                payload.len,
            );

            agent.pending_requests.append(agent.allocator, .{
                .transaction_id = tx_id,
                .pair = idx,
            }) catch return null;

            return msg;
        }

        fn findTurnClient(agent: *Self, addr: *const IpAddress) ?*TurnClient {
            for (agent.turn_clients.items) |*turn_client| if (turn_client.local_addr.eql(addr)) return turn_client;
            return null;
        }

        fn handleAppData(agent: *Self, sender: *const IpAddress, data: []const u8) ReadResult {
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

        fn handleRequest(
            agent: *Self,
            msg: *const stun.Message,
            base_addr: *const IpAddress,
            from: *const IpAddress,
        ) !?Response {
            const stun_req = Messages.parseAndValidateStunRequest(
                msg,
                agent.credentials.toIceCredentials(),
                agent.role,
                agent.tie_breaker,
            ) catch |err| switch (err) {
                error.RoleConflict => return .{
                    .kind = .role_conflict,
                    .tx_id = msg.header.transaction_id,
                    .local = agent.findLocalBase(base_addr) orelse return error.NoLocalCandidate,
                    .remote = agent.findRemoteCandidate(from) orelse return null,
                },
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

            var local_candidate: CandidateIndex = undefined;
            var remote_candidate: CandidateIndex = undefined;
            if (agent.findCandidatePair(base_addr, from)) |candidate_pair| {
                local_candidate = candidate_pair.local;
                remote_candidate = candidate_pair.remote;
                switch (candidate_pair.status) {
                    .succeeded => candidate_pair.nominated |= stun_req.use_candidate,
                    else => candidate_pair.nominate_on_binding |= stun_req.use_candidate,
                }
            } else {
                const local_idx = agent.findLocalCandidate(base_addr, base_addr) orelse return error.NoLocalCandidate;
                local_candidate = local_idx;

                const remote_idx = agent.findRemoteCandidate(from) orelse blk: {
                    const candidate = Candidate{
                        .base = from.*,
                        .address = from.*,
                        .candidate_type = .prflx,
                        .priority = stun_req.priority,
                    };
                    break :blk try agent.appendRemoteCandidate(candidate);
                };

                try agent.pairs.append(agent.allocator, .{
                    .local = local_idx,
                    .remote = remote_idx,
                    .priority = calculatePairPriority(agent.candidates[local_idx].priority, stun_req.priority, agent.role),
                    .status = .in_progress,
                    .nominate_on_binding = stun_req.use_candidate,
                });
                remote_candidate = remote_idx;
            }

            return .{
                .tx_id = msg.header.transaction_id,
                .local = local_candidate,
                .remote = remote_candidate,
            };
        }

        fn queueResponse(agent: *Self, resp: Response) void {
            // Drop on overflow, the peer will retransmit.
            agent.responses.pushBack(resp) catch {};
        }

        /// Returns the header size and the total size of data given a payload length.
        /// This is useful to only for Turn candidates to know how much space to reserve for the header.
        pub fn getDataFrameSize(agent: *Self, local: *const IpAddress, remote: *const IpAddress, payload_len: usize) struct { u32, usize } {
            const turn_client = agent.findTurnClient(local) orelse return .{ 0, payload_len };
            return turn_client.getDataFrameSize(remote, payload_len);
        }

        pub fn getRelayServerAddress(agent: *Self, local: *const IpAddress) ?IpAddress {
            const turn_client = agent.findTurnClient(local) orelse return null;
            return turn_client.remote_addr;
        }

        /// Writes the TURN header in front of a payload already placed at the header offset
        /// returned by `getDataFrameSize` and returns the frame.
        pub fn writeDataFrame(
            agent: *Self,
            local: *const IpAddress,
            remote: *const IpAddress,
            buffer: []u8,
            payload_len: usize,
        ) error{WriteFailed}![]const u8 {
            const turn_client = agent.findTurnClient(local) orelse return buffer[0..payload_len];

            _, const size = turn_client.getDataFrameSize(remote, payload_len);
            if (size > buffer.len) return error.WriteFailed;
            turn_client.writeDataHeader(remote, buffer, payload_len);
            return buffer[0..size];
        }

        fn maybeWrapInTurnMessage(
            agent: *Self,
            local: *const IpAddress,
            remote: *const IpAddress,
            buffer: []u8,
            data_len: usize,
        ) error{WriteFailed}!stun.TransportMessage {
            const turn_client = agent.findTurnClient(local) orelse return .{
                .data = buffer[0..data_len],
                .from = local,
                .to = remote,
            };

            const offset, const size = turn_client.getDataFrameSize(remote, data_len);
            if (size > buffer.len) return error.WriteFailed;
            @memmove(buffer[offset .. offset + data_len], buffer[0..data_len]);
            turn_client.writeDataHeader(remote, buffer, data_len);

            return .{
                .data = buffer[0..size],
                .from = local,
                .to = &turn_client.remote_addr,
            };
        }

        fn handleSuccessResponse(core: *Self, msg: *const stun.Message, base_addr: *const IpAddress, from: *const IpAddress) !void {
            const pending_request = blk: {
                const tx_id = msg.header.transaction_id;
                for (core.pending_requests.items, 0..) |pr, i| {
                    if (std.mem.eql(u8, &pr.transaction_id, &tx_id)) {
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

                const local_idx = core.findLocalCandidate(base_addr, &mapped_address) orelse blk: {
                    const prflx_candidate: Candidate = .initPeerReflexive(base_addr.*, mapped_address);
                    break :blk try core.appendCandidate(prflx_candidate);
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

        fn handleConsentFreshness(agent: *Self, msg: *const stun.Message, to: *const IpAddress, from: *const IpAddress) !?Response {
            switch (msg.header.message_type.class()) {
                .request => {
                    Messages.validateConsentFreshnessRequest(msg, agent.credentials.getPassword()) catch return null;
                    return .{
                        .tx_id = msg.header.transaction_id,
                        .local = agent.findLocalBase(to) orelse return null,
                        .remote = agent.findRemoteCandidate(from) orelse return null,
                    };
                },
                else => {},
            }

            return null;
        }

        fn pairsEql(core: *Self, pair1: *const CandidatePair, pair2: *const CandidatePair) bool {
            const local1 = core.getPairLocal(pair1);
            const remote1 = core.getPairRemote(pair1);

            const local2 = core.getPairLocal(pair2);
            const remote2 = core.getPairRemote(pair2);

            return local1.base.eql(&local2.base) and local1.address.eql(&local2.address) and
                remote1.address.eql(&remote2.address);
        }

        fn selectBestPair(core: *Self) ?u8 {
            var selected_idx: ?u8 = null;
            var best_priority: u64 = 0;
            for (core.pairs.items, 0..) |candidate_pair, idx| if (candidate_pair.status == .succeeded) {
                if (selected_idx == null or candidate_pair.priority > best_priority) {
                    selected_idx = @intCast(idx);
                    best_priority = candidate_pair.priority;
                }
            };

            return selected_idx;
        }

        fn findCandidatePair(core: *Self, local: *const IpAddress, remote: *const IpAddress) ?*CandidatePair {
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

        fn maybeSetNominatedField(agent: *Self, candidate_pair: *CandidatePair) void {
            if (candidate_pair.nominate_on_binding) {
                candidate_pair.nominate_on_binding = false;
                candidate_pair.nominated = true;
            } else if (agent.selected_pair) |selected_idx| {
                if (agent.pairsEql(&agent.pairs.items[selected_idx], candidate_pair)) {
                    agent.nominated_pair = .{ .local = candidate_pair.local, .remote = candidate_pair.remote };
                    candidate_pair.nominated = true;
                    agent.selected_pair = null;
                }
            }
        }

        fn findLocalCandidate(core: *Self, base: *const IpAddress, addr: *const IpAddress) ?CandidateIndex {
            for (core.candidates[0..core.candidates_len], 0..) |candidate, idx| {
                if (candidate.base.eql(base) and candidate.address.eql(addr)) return @intCast(idx);
            }
            return null;
        }

        fn findLocalBase(core: *Self, base: *const IpAddress) ?CandidateIndex {
            for (core.candidates[0..core.candidates_len], 0..) |candidate, idx| if (candidate.base.eql(base)) return @intCast(idx);
            return null;
        }

        fn findRemoteCandidate(core: *Self, addr: *const IpAddress) ?CandidateIndex {
            for (core.remote_candidates[0..core.remote_candidates_len], 0..) |candidate, idx| if (candidate.address.eql(addr)) return @intCast(idx);
            return null;
        }

        fn findCandidatePairByLocalAndRemote(core: *Self, local: *const Candidate, remote: *const IpAddress) ?*CandidatePair {
            for (core.pairs.items) |*candidate| {
                if (core.getPairLocal(candidate).eql(local) and core.getPairRemote(candidate).address.eql(remote))
                    return candidate;
            }
            return null;
        }

        fn getPairLocal(core: *Self, pair: *const CandidatePair) *const Candidate {
            return &core.candidates[pair.local];
        }

        fn getPairRemote(core: *Self, pair: *const CandidatePair) *const RemoteCandidate {
            return &core.remote_candidates[pair.remote];
        }
    };
}

const testing = std.testing;
var rand = std.Random.DefaultPrng.init(0xDEADBEEF);

const TestAgent = Agent(.{});

fn testRemoteCandidate(address: IpAddress) RemoteCandidate {
    return .{ .address = address, .candidate_type = .host, .priority = ice.CandidateType.host.priority() };
}

fn testTurnServer(address: IpAddress) Server {
    return .{ .turn = .{ .address = address, .username = "turnuser", .password = "turnpass" } };
}

fn testNewAgent(role: ice.Role) !TestAgent {
    return TestAgent.init(testing.allocator, .{
        .role = role,
        .credentials = .{ .username = "user", .password = "VOkJxbRl1RmTxUk/WvJxBt" },
        .random = rand.random(),
    });
}

fn testBuildRequest(req: Messages.StunRequest, peer_password: []const u8, buffer: []u8) !stun.Message {
    var w = stun.Writer.init(buffer, .{ .password = peer_password });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.request, .binding),
        .transaction_id = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 },
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

fn testBuildResponse(tx_id: [12]u8, addr: IpAddress, password: []const u8, buffer: []u8) !stun.Message {
    var w = stun.Writer.init(buffer, .{ .password = password });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.success_response, .binding),
        .transaction_id = tx_id,
    });
    try w.writeAttribute(.{ .xor_mapped_address = addr });
    try w.writeAttribute(.{ .message_integrity = &.{} });
    try w.writeAttribute(.fingerprint);

    return try stun.Message.parse(w.final());
}

/// Unauthenticated STUN binding success response, as stun.Client expects.
fn testStunBindingResponse(buffer: []u8, tx_id: [12]u8, addr: IpAddress) ![]const u8 {
    var w = stun.Writer.init(buffer, .{});
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.success_response, .binding),
        .transaction_id = tx_id,
    });
    try w.writeAttribute(.{ .xor_mapped_address = addr });
    return w.final();
}

fn testTurnAllocateSuccessResponse(buffer: []u8, tx_id: [12]u8, relayed: IpAddress, mapped: IpAddress, lifetime: u32) ![]const u8 {
    var w = stun.Writer.init(buffer, .{});
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.success_response, .allocate),
        .transaction_id = tx_id,
    });
    try w.writeAttributes(&.{
        .{ .xor_relayed_address = relayed },
        .{ .xor_mapped_address = mapped },
        .{ .lifetime = lifetime },
    });
    return w.final();
}

fn testTurnChallengeResponse(buffer: []u8, tx_id: [12]u8, method: stun.Method) ![]const u8 {
    var w = stun.Writer.init(buffer, .{});
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.error_response, method),
        .transaction_id = tx_id,
    });
    try w.writeAttributes(&.{
        .{ .error_code = .{ .code = .unauthorized, .reason = "Unauthorized" } },
        .{ .realm = "realm" },
        .{ .nonce = "nonce" },
    });
    return w.final();
}

fn testTurnErrorResponse(buffer: []u8, tx_id: [12]u8, method: stun.Method, code: stun.StunErrorCode, reason: []const u8) ![]const u8 {
    var w = stun.Writer.init(buffer, .{});
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.error_response, method),
        .transaction_id = tx_id,
    });
    try w.writeAttribute(.{ .error_code = .{ .code = code, .reason = reason } });
    return w.final();
}

fn testTurnDataIndication(buffer: []u8, peer: IpAddress, data: []const u8) ![]const u8 {
    var w = stun.Writer.init(buffer, .{});
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.indication, .data),
        .transaction_id = @splat(0),
    });
    try w.writeAttribute(.{ .xor_peer_address = peer });
    try w.writeAttribute(.{ .data = data });
    return w.final();
}

fn expectEvent(core: *TestAgent, tag: std.meta.Tag(Event)) !void {
    const event = core.pollEvent() orelse return error.ExpectedEvent;
    if (std.meta.activeTag(event) != tag) return error.UnexpectedEvent;
}

fn expectConnectionStateEvent(core: *TestAgent, state: ice.ConnectionState) !void {
    switch (core.pollEvent() orelse return error.ExpectedEvent) {
        .connection_state => |s| try testing.expectEqual(state, s),
        else => return error.UnexpectedEvent,
    }
}

fn expectGatheringStateEvent(core: *TestAgent, state: ice.GatheringState) !void {
    switch (core.pollEvent() orelse return error.ExpectedEvent) {
        .gathering_state => |s| try testing.expectEqual(state, s),
        else => return error.UnexpectedEvent,
    }
}

fn testRespond(core: *TestAgent, msg: *const stun.Message, base: *const IpAddress, from: *const IpAddress, buffer: []u8) !stun.TransportMessage {
    core.queueResponse((try core.handleRequest(msg, base, from)) orelse return error.ExpectedResponse);
    return (try core.pollTransmit(buffer)) orelse error.ExpectedTransmit;
}

test "handleRequest: generate success response" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    try core.addLocalAddrs(&.{base_addr}, 0);

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = core.credentials.getUsername(),
    }, core.credentials.getPassword(), &buffer);

    const resp = try testRespond(&core, &msg, &base_addr, &from, &resp_buffer);
    const resp_msg = try stun.Message.parse(resp.data);

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

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    try core.addLocalAddrs(&.{base_addr}, 0);

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = core.credentials.getUsername(),
    }, core.credentials.getPassword(), &buffer);

    _ = try core.handleRequest(&msg, &base_addr, &from);

    try testing.expectEqual(1, core.pairs.items.len);

    const candidate_pair = core.pairs.items[0];
    const remote = core.remote_candidates[candidate_pair.remote];
    try testing.expect(remote.address.eql(&from));
    try testing.expectEqual(remote.priority, 0x9090);

    // Send request again
    _ = try core.handleRequest(&msg, &base_addr, &from);
    try testing.expectEqual(1, core.pairs.items.len); // no new peer is created
}

test "handleRequest: nominate peer" {
    var agent = try testNewAgent(.controlled);
    defer agent.deinit();

    var buffer: [1024]u8 = undefined;

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

    _ = try agent.handleRequest(&msg, &base_addr, &from);

    const candidate_pair = &agent.pairs.items[0];
    try testing.expect(candidate_pair.nominate_on_binding);
    try testing.expect(!candidate_pair.nominated);

    candidate_pair.status = .succeeded;
    _ = try agent.handleRequest(&msg, &base_addr, &from);
    try testing.expect(candidate_pair.nominated);
}

test "handleRequest: role conflict" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);
    try core.addLocalAddrs(&.{base_addr}, 0);

    {
        const msg = try testBuildRequest(.{
            .ice_controlled = std.math.maxInt(u64),
            .priority = 0x9090,
            .username = core.credentials.getUsername(),
        }, core.credentials.getPassword(), &buffer);

        // Unknown sender: no response.
        try testing.expectEqual(null, try core.handleRequest(&msg, &base_addr, &from));

        try core.addRemoteCandidate(.initHost(from), 0);
        const resp = try testRespond(&core, &msg, &base_addr, &from, &resp_buffer);
        const resp_msg = try stun.Message.parse(resp.data);

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

        const resp = try testRespond(&core, &msg, &base_addr, &from, &resp_buffer);
        const resp_msg = try stun.Message.parse(resp.data);

        try testing.expectEqual(.success_response, resp_msg.header.message_type.class());
        try testing.expectEqual(.controlling, core.role);
    }
}

test "addLocalCandidate: forms pairs with existing remote candidates" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    try core.addRemoteCandidate(Candidate.initHost(try IpAddress.parse("192.168.1.10", 1000)), 0);
    try core.addRemoteCandidate(Candidate.initHost(try IpAddress.parse("192.168.1.11", 1001)), 0);

    try testing.expectEqual(2, core.remote_candidates_len);
    try testing.expectEqual(0, core.pairs.items.len);

    const local = try IpAddress.parse("10.0.0.1", 2000);
    try core.addLocalAddrs(&.{local}, 0);

    try testing.expectEqual(1, core.candidates_len);
    try testing.expectEqual(2, core.pairs.items.len);
    for (core.pairs.items) |pair| try testing.expect(core.candidates[pair.local].base.eql(&local));

    try core.addLocalAddrs(&.{local}, 0);
    try testing.expectEqual(2, core.pairs.items.len);
}

test "addRemoteCandidate: forms pairs with existing local candidates" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    try core.addLocalAddrs(&.{try IpAddress.parse("10.0.0.1", 2000)}, 0);
    while (core.pollEvent()) |_| {}
    try core.addLocalAddrs(&.{try IpAddress.parse("10.0.0.2", 2001)}, 0);
    while (core.pollEvent()) |_| {}

    try testing.expectEqual(2, core.candidates_len);
    try testing.expectEqual(0, core.pairs.items.len);

    const remote = try IpAddress.parse("192.168.1.10", 1000);
    try core.addRemoteCandidate(Candidate.initHost(remote), 0);

    try testing.expectEqual(1, core.remote_candidates_len);
    try testing.expectEqual(2, core.pairs.items.len);
    for (core.pairs.items) |pair| try testing.expect(core.remote_candidates[pair.remote].address.eql(&remote));

    try core.addRemoteCandidate(Candidate.initHost(remote), 0);
    try testing.expectEqual(2, core.pairs.items.len);
}

test "addRemoteCandidate: skips pairing across differing address families" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    try core.addLocalAddrs(&.{try IpAddress.parse("10.0.0.1", 2000)}, 0);

    try core.addRemoteCandidate(Candidate.initHost(try IpAddress.parse("2001:db8::10", 1000)), 0);
    try testing.expectEqual(0, core.pairs.items.len);

    try core.addRemoteCandidate(Candidate.initHost(try IpAddress.parse("192.168.1.10", 1001)), 0);
    try testing.expectEqual(1, core.pairs.items.len);
}

test "addLocalCandidate: skips pairing across differing address families" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    try core.addRemoteCandidate(Candidate.initHost(try IpAddress.parse("192.168.1.10", 1000)), 0);

    try core.addLocalAddrs(&.{try IpAddress.parse("2001:db8::1", 2000)}, 0);
    while (core.pollEvent()) |_| {}
    try testing.expectEqual(0, core.pairs.items.len);

    try core.addLocalAddrs(&.{try IpAddress.parse("10.0.0.1", 2001)}, 0);
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
    try core.addLocalAddrs(&.{base}, 0);

    try testing.expectEqual(null, try core.addServerReflexiveCandidate(base, try IpAddress.parse("10.0.0.1", 3000)));
    try testing.expectEqual(1, core.candidates_len);

    const mapped = try IpAddress.parse("203.0.113.5", 3000);
    const index = try core.addServerReflexiveCandidate(base, mapped);
    try testing.expect(index != null);
    try testing.expect(core.candidates[index.?].address.eql(&mapped));
    try testing.expectEqual(2, core.candidates_len);

    try testing.expectEqual(null, try core.addServerReflexiveCandidate(base, mapped));
    try testing.expectEqual(2, core.candidates_len);
}

test "addLocalAddrs: gathering completes only on an empty list; later calls fail" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    try core.addLocalAddrs(&.{try IpAddress.parse("10.0.0.1", 2000)}, 0);
    try expectGatheringStateEvent(&core, .gathering);
    try expectEvent(&core, .candidate);
    try testing.expectEqual(null, core.pollEvent());

    try core.addLocalAddrs(&.{try IpAddress.parse("10.0.0.2", 2001)}, 0);
    try expectEvent(&core, .candidate);
    try testing.expectEqual(null, core.pollEvent());
    try testing.expectEqual(.gathering, core.gathering_state);

    try core.addLocalAddrs(&.{}, 0);
    try expectGatheringStateEvent(&core, .complete);
    try testing.expectEqual(null, core.pollEvent());

    try testing.expectError(error.GatheringDone, core.addLocalAddrs(&.{try IpAddress.parse("10.0.0.3", 2002)}, 0));
    try testing.expectError(error.GatheringDone, core.addLocalAddrs(&.{}, 0));
    try testing.expectEqual(2, core.candidates_len);
    try testing.expectEqual(null, core.pollEvent());
}

test "addServer/addLocalAddrs: queues a stun binding request per server and reports its deadline" {
    var tx_buf: [1024]u8 = undefined;
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    const local1 = try IpAddress.parse("10.0.0.10", 4000);
    const server1 = try IpAddress.parse("203.0.113.1", 3478);
    const local2 = try IpAddress.parse("10.0.0.11", 4001);
    const server2 = try IpAddress.parse("203.0.113.2", 3478);

    try core.addServer(local1, .{ .stun = server1 }, 0);
    try core.addServer(local2, .{ .stun = server2 }, 0);
    try core.addLocalAddrs(&.{}, 100);

    const tm1 = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    try testing.expect(tm1.from.eql(&local1));
    try testing.expect(tm1.to.eql(&server1));

    const tm2 = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    try testing.expect(tm2.from.eql(&local2));
    try testing.expect(tm2.to.eql(&server2));

    try testing.expectEqual(null, (try core.pollTransmit(&tx_buf)));
    try testing.expectEqual(.gathering, core.gathering_state);
    try testing.expectEqual(100 + stun.Client.Client(.{}).base_rto, core.pollTimeout());
}

test "addServer: deferred before gathering, sent during, rejected once done" {
    var tx_buf: [1024]u8 = undefined;
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    const local = try IpAddress.parse("10.0.0.10", 4000);
    const stun1 = try IpAddress.parse("203.0.113.1", 3478);
    const stun2 = try IpAddress.parse("203.0.113.2", 3478);
    const turn = try IpAddress.parse("203.0.113.3", 3478);

    try core.addServer(local, .{ .stun = stun1 }, 0);
    try testing.expectEqual(null, (try core.pollTransmit(&tx_buf)));

    try core.addLocalAddrs(&.{try IpAddress.parse("10.0.0.1", 2000)}, 0);
    const tm1 = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    try testing.expect(tm1.to.eql(&stun1));
    try testing.expectEqual(null, (try core.pollTransmit(&tx_buf)));

    try core.addServer(local, .{ .stun = stun2 }, 0);
    const tm2 = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    try testing.expect(tm2.to.eql(&stun2));

    try core.addServer(local, testTurnServer(turn), 0);
    const tm3 = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    try testing.expect(tm3.to.eql(&turn));
    try testing.expectEqual(null, (try core.pollTransmit(&tx_buf)));

    // Ending gathering doesn't resend requests to servers already queried.
    try core.addLocalAddrs(&.{}, 0);
    try testing.expectEqual(null, (try core.pollTransmit(&tx_buf)));
    try testing.expectEqual(.gathering, core.gathering_state);

    try testing.expectError(error.GatheringDone, core.addServer(local, .{ .stun = stun1 }, 0));
    try testing.expectError(error.GatheringDone, core.addServer(local, testTurnServer(turn), 0));
    try testing.expectEqual(2, core.stun_clients.items.len);
    try testing.expectEqual(1, core.turn_clients.items.len);
}

test "handleRead: stun server resolves to reflexive candidate; duplicate mapped address still completes gathering" {
    var agent = try testNewAgent(.controlling);
    defer agent.deinit();

    const host_addr = try IpAddress.parse("10.0.0.1", 2000);
    const local1 = try IpAddress.parse("10.0.0.10", 4000);
    const server1 = try IpAddress.parse("203.0.113.1", 3478);
    const local2 = try IpAddress.parse("10.0.0.11", 4001);
    const server2 = try IpAddress.parse("203.0.113.2", 3478);

    try agent.addServer(local1, .{ .stun = server1 }, 0);
    try agent.addServer(local2, .{ .stun = server2 }, 0);
    try agent.addLocalAddrs(&.{host_addr}, 0);
    try agent.addLocalAddrs(&.{}, 0);
    while (agent.pollEvent()) |_| {}

    var resp_buffer: [64]u8 = undefined;

    // Poll both requests before answering either: handleRead's swapRemove on
    // a resolved server invalidates any transmit still held for another one.
    const tm1 = (try agent.pollTransmit(&resp_buffer)) orelse return error.ExpectedTransmit;
    const tx1 = (try stun.Message.parse(tm1.data)).header.transaction_id;
    const tm2 = (try agent.pollTransmit(&resp_buffer)) orelse return error.ExpectedTransmit;
    const tx2 = (try stun.Message.parse(tm2.data)).header.transaction_id;

    var buf: [128]u8 = undefined;
    const mapped = try IpAddress.parse("198.51.100.7", 55000);
    const resp1 = try testStunBindingResponse(&buf, tx1, mapped);
    _ = try agent.handleRead(.{ .from = &server1, .to = &local1, .data = resp1 }, 0);

    try expectEvent(&agent, .candidate);
    try testing.expectEqual(null, agent.pollEvent()); // server2 still pending: gathering not complete yet
    try testing.expectEqual(1, agent.stun_clients.items.len);

    // server2 maps back to the host candidate's own address: a duplicate.
    const resp2 = try testStunBindingResponse(&buf, tx2, host_addr);
    _ = try agent.handleRead(.{ .from = &server2, .to = &local2, .data = resp2 }, 0);

    try testing.expectEqual(0, agent.stun_clients.items.len);
    try expectEvent(&agent, .gathering_state);
    try testing.expectEqual(.complete, agent.gathering_state);
    try testing.expectEqual(null, agent.pollEvent());
}

test "handleTimeout: stun server failure removes it and completes gathering" {
    var tx_buf: [1024]u8 = undefined;
    var agent = try testNewAgent(.controlling);
    defer agent.deinit();

    const local = try IpAddress.parse("10.0.0.10", 4000);
    const server = try IpAddress.parse("203.0.113.1", 3478);
    try agent.addServer(local, .{ .stun = server }, 0);
    try agent.addLocalAddrs(&.{}, 0);
    while (agent.pollEvent()) |_| {}
    _ = (try agent.pollTransmit(&tx_buf)); // drain the initial binding request

    var now: i64 = 0;
    for (0..8) |_| {
        now += 2000;
        try agent.handleTimeout(now);
        _ = (try agent.pollTransmit(&tx_buf));
    }

    try testing.expectEqual(0, agent.stun_clients.items.len);
    try testing.expectEqual(.complete, agent.gathering_state);
}

test "toggleRole: flips role, tie breaker and pair priorities" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    const local_addr = try IpAddress.parse("10.0.0.1", 2000);
    const remote_addr = try IpAddress.parse("192.168.1.10", 1000);

    try core.addLocalAddrs(&.{local_addr}, 0);
    try core.addRemoteCandidate(Candidate.initServerReflexive(remote_addr, remote_addr), 0);

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

    const result = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = "hello" }, 0);

    try testing.expectEqual(.consumed, std.meta.activeTag(result));
    try testing.expectEqual(null, core.pollEvent());
}

test "handleInput: forwards non-stun data from a known remote candidate pair" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    core.candidates[0] = .initHost(base_addr);
    core.candidates_len = 1;
    core.remote_candidates[0] = testRemoteCandidate(from);
    core.remote_candidates_len = 1;
    try core.pairs.append(testing.allocator, .{ .local = 0, .remote = 0, .status = .in_progress, .priority = 0 });

    const result = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = "hello" }, 0);

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

    const result = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = "world" }, 0);

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
    core.candidates[0] = .initHost(base_addr);
    core.candidates_len = 1;
    core.remote_candidates[0] = testRemoteCandidate(from);
    core.remote_candidates_len = 1;

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = core.credentials.getUsername(),
    }, core.credentials.getPassword(), &buffer);

    const result = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = msg.bytes }, 0);

    try testing.expectEqual(.consumed, std.meta.activeTag(result));
    try testing.expectEqual(.completed, core.connection_state);

    const resp = (try core.pollTransmit(&resp_buffer)) orelse return error.ExpectedTransmit;
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
    try core.addLocalAddrs(&.{base_addr}, 0);
    try expectEvent(&core, .gathering_state);

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = core.credentials.getUsername(),
    }, core.credentials.getPassword(), &buffer);

    _ = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = msg.bytes }, 0);

    const resp = (try core.pollTransmit(&resp_buffer)) orelse return error.ExpectedTransmit;
    const resp_msg = try stun.Message.parse(resp.data);
    try testing.expectEqual(.success_response, resp_msg.header.message_type.class());

    try testing.expectEqual(null, (try core.pollTransmit(&resp_buffer)));
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
    try core.addLocalAddrs(&.{base_addr}, 0);
    try expectEvent(&core, .gathering_state);

    const msg = try testBuildRequest(.{
        .ice_controlled = 0,
        .priority = 0x9090,
        .username = core.credentials.getUsername(),
    }, core.credentials.getPassword(), &buffer);

    _ = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = msg.bytes }, 0);

    try testing.expectEqual(.controlling, core.role);

    const resp = (try core.pollTransmit(&resp_buffer)) orelse return error.ExpectedTransmit;
    const resp_msg = try stun.Message.parse(resp.data);
    try testing.expectEqual(.success_response, resp_msg.header.message_type.class());

    try expectEvent(&core, .candidate);
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
        .transaction_id = @splat(2),
        .pair = 0,
    });

    var buffer: [1024]u8 = undefined;
    const msg = try testBuildResponse(@splat(2), base_addr, core.remote_credentials.?.getPassword(), &buffer);

    _ = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = msg.bytes }, 0);

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
        .transaction_id = @splat(2),
        .pair = 0,
    });

    var buffer: [1024]u8 = undefined;
    const msg = try testBuildResponse(@splat(2), base_addr, core.remote_credentials.?.getPassword(), &buffer);

    _ = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = msg.bytes }, 0);

    try expectEvent(&core, .nominated);
    try expectConnectionStateEvent(&core, .connected);
    try testing.expectEqual(null, core.pollEvent());

    try testing.expectEqual(.connected, core.connection_state);
    try testing.expect(core.pairs.items[0].nominated);
    try testing.expect(core.nominated_pair != null);

    try testing.expectEqual(@as(i64, keep_alive_interval), core.keep_alive_deadline);
    try testing.expectEqual(@as(i64, core.timers.disconnected_timeout), core.disconnected_connection_deadline);
}

test "handleTimeout: new connection starts checking and schedules a connectivity check" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    const failed_timeout: i64 = core.timers.failed_timeout;
    const connectivity_check_interval: i64 = core.timers.connectivity_check_interval;
    try core.setRemoteCredentials(.{ .username = "peer", .password = "peer-password-0123456789" }, 0);

    try testing.expectEqual(connectivity_check_interval, core.connectivity_check_deadline);
    try testing.expectEqual(failed_timeout, core.disconnected_connection_deadline);

    try expectConnectionStateEvent(&core, .checking);
    try testing.expectEqual(null, core.pollEvent());

    try core.handleTimeout(connectivity_check_interval);
    try testing.expect(!core.connectivity_check.done);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleTimeout: checking sends a connectivity_check every interval" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    const connectivity_check_interval: i64 = core.timers.connectivity_check_interval;
    try core.setRemoteCredentials(.{ .username = "peer", .password = "peer-password-0123456789" }, 0);
    _ = core.pollEvent(); // .checking

    try core.handleTimeout(100);
    try testing.expectEqual(null, core.pollEvent());

    try core.handleTimeout(connectivity_check_interval);
    try testing.expectEqual(connectivity_check_interval * 2, core.connectivity_check_deadline);
    try testing.expect(!core.connectivity_check.done);
    try testing.expectEqual(null, core.pollEvent());
}

test "setRemoteCredentials: connectivity checks start immediately and cover pairs added later" {
    var tx_buf: [1024]u8 = undefined;
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    const local = try IpAddress.parse("192.168.1.100", 1000);
    const remote1 = try IpAddress.parse("192.168.1.120", 2000);
    const remote2 = try IpAddress.parse("192.168.1.121", 2001);

    try core.addLocalAddrs(&.{local}, 0);
    try core.addRemoteCandidate(.initHost(remote1), 0);
    try core.setRemoteCredentials(.{ .username = "peer", .password = "peer-password-0123456789" }, 0);

    const tm1 = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    try testing.expectEqual(.request, (try stun.Message.parse(tm1.data)).header.message_type.class());
    try testing.expect(tm1.from.eql(&local));
    try testing.expect(tm1.to.eql(&remote1));
    try testing.expectEqual(null, try core.pollTransmit(&tx_buf));

    // Trickled candidate: only the new pair is checked.
    try core.addRemoteCandidate(.initHost(remote2), 50);
    const tm2 = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    try testing.expect(tm2.to.eql(&remote2));
    try testing.expectEqual(null, try core.pollTransmit(&tx_buf));
}

test "handleTimeout: checking fails after failed_timeout without connecting" {
    var agent = try testNewAgent(.controlled);
    defer agent.deinit();

    const failed_timeout: i64 = agent.timers.failed_timeout;
    try agent.setRemoteCredentials(.{ .username = "peer", .password = "peer-password-0123456789" }, 0);
    _ = agent.pollEvent(); // .checking

    try agent.handleTimeout(failed_timeout);

    try testing.expectEqual(.failed, agent.connection_state);
    try testing.expectEqual(std.math.maxInt(i64), agent.disconnected_connection_deadline);

    try testing.expect(!agent.connectivity_check.done);
    try expectConnectionStateEvent(&agent, .failed);
    try testing.expectEqual(null, agent.pollEvent());

    try agent.handleTimeout(failed_timeout + 1000);
    try testing.expectEqual(null, agent.pollEvent());
}

test "handleTimeout: connected transitions to completed once keep_alive_deadline elapses and clears the checklist" {
    var tx_buf: [1024]u8 = undefined;
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    core.connection_state = .connected;
    core.connectivity_check_deadline = 100_000;
    core.disconnected_connection_deadline = 100_000;
    core.keep_alive_deadline = 1000;
    core.remote_credentials = try .init("ruser", "peer-password-0123456789");

    core.candidates[0] = .initHost(try IpAddress.parse("192.168.1.100", 1000));
    core.candidates_len = 1;
    const from = try IpAddress.parse("192.168.1.120", 2000);
    core.remote_candidates[0] = testRemoteCandidate(from);
    core.remote_candidates_len = 1;
    core.nominated_pair = .{ .local = 0, .remote = 0 };
    try core.pairs.append(testing.allocator, .{ .local = 0, .remote = 0, .status = .succeeded, .priority = 0 });
    try core.pending_requests.append(testing.allocator, .{ .transaction_id = @splat(1), .pair = 0 });

    try core.handleTimeout(1000);

    try testing.expectEqual(.completed, core.connection_state);
    try testing.expectEqual(1, core.remote_candidates_len);
    try testing.expectEqual(0, core.pairs.items.len);
    try testing.expectEqual(0, core.pending_requests.items.len);
    try testing.expectEqual(1000 + keep_alive_interval, core.keep_alive_deadline);

    try expectConnectionStateEvent(&core, .completed);
    try testing.expectEqual(null, core.pollEvent());

    const tm = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    const msg = try stun.Message.parse(tm.data);
    try testing.expectEqual(.request, msg.header.message_type.class());
    try testing.expectEqual(.binding, msg.header.message_type.method());
    try testing.expect(tm.from.eql(&core.candidates[0].base));
    try testing.expect(tm.to.eql(&from));
    try testing.expectEqual(null, (try core.pollTransmit(&tx_buf)));
}

test "handleTimeout: completed/disconnected request consent freshness without changing state" {
    var tx_buf: [1024]u8 = undefined;
    for ([_]ice.ConnectionState{ .completed, .disconnected }) |state| {
        var core = try testNewAgent(.controlling);
        defer core.deinit();

        core.connection_state = state;
        core.disconnected_connection_deadline = 100_000;
        core.keep_alive_deadline = 1000;
        core.remote_credentials = try .init("ruser", "peer-password-0123456789");

        core.candidates[0] = .initHost(try IpAddress.parse("192.168.1.100", 1000));
        core.candidates_len = 1;
        const from = try IpAddress.parse("192.168.1.120", 2000);
        core.remote_candidates[0] = testRemoteCandidate(from);
        core.remote_candidates_len = 1;
        core.nominated_pair = .{ .local = 0, .remote = 0 };

        try core.handleTimeout(1000);

        try testing.expectEqual(state, core.connection_state);
        try testing.expectEqual(1000 + keep_alive_interval, core.keep_alive_deadline);
        try testing.expectEqual(null, core.pollEvent());

        const tm = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
        const msg = try stun.Message.parse(tm.data);
        try testing.expectEqual(.request, msg.header.message_type.class());
        try testing.expectEqual(.binding, msg.header.message_type.method());
        try testing.expect(tm.from.eql(&core.candidates[0].base));
        try testing.expect(tm.to.eql(&from));
        try testing.expectEqual(null, (try core.pollTransmit(&tx_buf)));
    }
}

test "handleTimeout: connected becomes disconnected after disconnected_timeout of silence and refreshes the failed deadline" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    core.connection_state = .connected;
    core.connectivity_check_deadline = 100_000;
    core.keep_alive_deadline = 100_000;
    core.disconnected_connection_deadline = 1000;

    const failed_timeout: i64 = core.timers.failed_timeout;
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

test "addServer/addLocalAddrs: turn server queues an allocate request and keeps gathering incomplete until it resolves" {
    var tx_buf: [1024]u8 = undefined;
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    const local = try IpAddress.parse("10.0.0.10", 4000);
    const server = try IpAddress.parse("203.0.113.1", 3478);

    try core.addServer(local, testTurnServer(server), 0);
    try core.addLocalAddrs(&.{}, 0);

    const tm = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    try testing.expect(tm.from.eql(&local));
    try testing.expect(tm.to.eql(&server));
    try testing.expectEqual(null, (try core.pollTransmit(&tx_buf)));

    try testing.expectEqual(.gathering, core.gathering_state);
}

test "handleTurnClientEvents: successful allocation adds a relay candidate, creates a permission for the paired remote, and completes gathering" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    const local = try IpAddress.parse("10.0.0.10", 4000);
    const server = try IpAddress.parse("203.0.113.1", 3478);
    const remote = try IpAddress.parse("192.168.1.10", 1000);

    try core.addServer(local, testTurnServer(server), 0);
    try core.addRemoteCandidate(Candidate.initHost(remote), 0);
    try core.addLocalAddrs(&.{}, 0);
    while (core.pollEvent()) |_| {}

    var response_buf: [1024]u8 = undefined;
    const out = (try core.pollTransmit(&response_buf)) orelse return error.ExpectedTransmit;
    const request = try stun.Message.parse(out.data);

    const relayed = try IpAddress.parse("203.0.113.9", 40000);
    const mapped = try IpAddress.parse("198.51.100.1", 5000);
    const resp = try testTurnAllocateSuccessResponse(&response_buf, request.header.transaction_id, relayed, mapped, 600);

    const result = try core.handleRead(.{ .from = &server, .to = &local, .data = resp }, 0);
    try testing.expectEqual(.consumed, std.meta.activeTag(result));

    try testing.expectEqual(1, core.candidates_len);
    try testing.expectEqual(.relay, core.candidates[0].candidate_type);

    var saw_candidate = false;
    var saw_gathering_complete = false;
    while (core.pollEvent()) |event| switch (event) {
        .candidate => saw_candidate = true,
        .gathering_state => |s| if (s == .complete) {
            saw_gathering_complete = true;
        },
        else => {},
    };
    try testing.expect(saw_candidate);
    try testing.expect(saw_gathering_complete);
    try testing.expectEqual(.complete, core.gathering_state);

    const permission_tm = (try core.pollTransmit(&response_buf)) orelse return error.ExpectedTransmit;
    const permission_msg = try stun.Message.parse(permission_tm.data);
    try testing.expectEqual(.create_permission, permission_msg.header.message_type.method());

    var it = permission_msg.iterateAttributes(&.{});
    const attr = try it.next() orelse return error.ExpectedAttribute;
    try testing.expect(attr.xor_peer_address.eql(&remote));
}

test "addRemoteCandidate: pairs with a relay candidate and creates a permission" {
    var tx_buf: [1024]u8 = undefined;
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    const local = try IpAddress.parse("10.0.0.10", 4000);
    const server = try IpAddress.parse("203.0.113.1", 3478);
    const relayed = try IpAddress.parse("203.0.113.9", 40000);

    try core.addServer(local, testTurnServer(server), 0);
    _ = try core.addLocalCandidate(.initRelay(local, relayed));

    const remote = try IpAddress.parse("192.168.1.10", 1000);
    try core.addRemoteCandidate(Candidate.initHost(remote), 0);

    try testing.expectEqual(1, core.pairs.items.len);

    const out = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    const msg = try stun.Message.parse(out.data);
    try testing.expectEqual(.create_permission, msg.header.message_type.method());

    var it = msg.iterateAttributes(&.{});
    const attr = try it.next() orelse return error.ExpectedAttribute;
    try testing.expect(attr.xor_peer_address.eql(&remote));
}

test "handleRead: unwraps a TURN data indication before further processing" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    const local = try IpAddress.parse("10.0.0.10", 4000);
    const server = try IpAddress.parse("203.0.113.1", 3478);
    const relayed = try IpAddress.parse("203.0.113.9", 40000);
    const peer = try IpAddress.parse("192.168.1.120", 2000);

    try core.addServer(local, testTurnServer(server), 0);

    core.candidates[0] = .initRelay(local, relayed);
    core.candidates_len = 1;
    core.remote_candidates[0] = testRemoteCandidate(peer);
    core.remote_candidates_len = 1;
    try core.pairs.append(testing.allocator, .{
        .local = 0,
        .remote = 0,
        .status = .in_progress,
        .priority = 0,
    });

    var buffer: [1024]u8 = undefined;
    var indication_buf: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    {
        const inner = try testBuildRequest(.{
            .ice_controlling = 0x10000,
            .priority = 0x9090,
            .username = core.credentials.getUsername(),
        }, core.credentials.getPassword(), &buffer);

        const indication = try testTurnDataIndication(&indication_buf, peer, inner.bytes);

        const result = try core.handleRead(.{ .from = &server, .to = &local, .data = indication }, 0);
        try testing.expectEqual(.consumed, std.meta.activeTag(result));

        const tm = (try core.pollTransmit(&resp_buffer)) orelse return error.ExpectedTransmit;
        try testing.expect(tm.from.eql(&local));
        try testing.expect(tm.to.eql(&server));
    }

    {
        const indication = try testTurnDataIndication(&indication_buf, peer, "hello");
        const result = try core.handleRead(.{ .from = &server, .to = &local, .data = indication }, 0);
        switch (result) {
            .app_data => |data| try testing.expectEqualStrings("hello", data),
            .consumed => return error.UnexpectedResult,
        }
    }
}

test "maybeWrapInTurnMessage: relay candidate responses are wrapped as a TURN send indication addressed to the server" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const local = try IpAddress.parse("10.0.0.10", 4000);
    const server = try IpAddress.parse("203.0.113.1", 3478);
    const relayed = try IpAddress.parse("203.0.113.9", 40000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    try core.addServer(local, testTurnServer(server), 0);

    core.candidates[0] = .initRelay(local, relayed);
    core.candidates_len = 1;
    core.remote_candidates[0] = testRemoteCandidate(from);
    core.remote_candidates_len = 1;
    try core.pairs.append(testing.allocator, .{
        .local = 0,
        .remote = 0,
        .status = .in_progress,
        .priority = 0,
    });

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = core.credentials.getUsername(),
    }, core.credentials.getPassword(), &buffer);

    _ = try core.pollTransmit(&resp_buffer); // drain the allocate request
    const resp = try testRespond(&core, &msg, &local, &from, &resp_buffer);

    try testing.expect(resp.from.eql(&local));
    try testing.expect(resp.to.eql(&server));

    const resp_msg = try stun.Message.parse(resp.data);
    try testing.expectEqual(.indication, resp_msg.header.message_type.class());
    try testing.expectEqual(.send, resp_msg.header.message_type.method());

    var it = resp_msg.iterateAttributes(&.{});
    const attr = try it.next() orelse return error.ExpectedAttribute;
    try testing.expect(attr.xor_peer_address.eql(&from));
}

test "handleTurnClientEvents: allocation_failed removes the turn client and gathering still completes" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    const local = try IpAddress.parse("10.0.0.10", 4000);
    const server = try IpAddress.parse("203.0.113.1", 3478);

    try core.addServer(local, testTurnServer(server), 0);
    try core.addLocalAddrs(&.{}, 0);
    while (core.pollEvent()) |_| {}

    var response_buf: [1024]u8 = undefined;

    // Unauthenticated request answered with a challenge: retried, authenticated this time.
    {
        const out = (try core.pollTransmit(&response_buf)) orelse return error.ExpectedTransmit;
        const request = try stun.Message.parse(out.data);
        const resp = try testTurnChallengeResponse(&response_buf, request.header.transaction_id, .allocate);
        _ = try core.handleRead(.{ .from = &server, .to = &local, .data = resp }, 0);
    }

    // Authenticated retry gets a hard failure: emits allocation_failed immediately.
    {
        const out = (try core.pollTransmit(&response_buf)) orelse return error.ExpectedTransmit;
        const request = try stun.Message.parse(out.data);
        const resp = try testTurnErrorResponse(&response_buf, request.header.transaction_id, .allocate, .server_error, "Server Error");
        _ = try core.handleRead(.{ .from = &server, .to = &local, .data = resp }, 0);
    }

    try testing.expectEqual(0, core.turn_clients.items.len);
    try testing.expectEqual(.complete, core.gathering_state);
}

test "handleTurnClientEvents: permission_failed marks the matching candidate pair as failed" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    const local = try IpAddress.parse("10.0.0.10", 4000);
    const server = try IpAddress.parse("203.0.113.1", 3478);
    const remote = try IpAddress.parse("192.168.1.10", 1000);

    try core.addServer(local, testTurnServer(server), 0);
    try core.addRemoteCandidate(Candidate.initHost(remote), 0);
    try core.addLocalAddrs(&.{}, 0);
    while (core.pollEvent()) |_| {}

    var response_buf: [1024]u8 = undefined;

    {
        const out = (try core.pollTransmit(&response_buf)) orelse return error.ExpectedTransmit;
        const request = try stun.Message.parse(out.data);
        const relayed = try IpAddress.parse("203.0.113.9", 40000);
        const mapped = try IpAddress.parse("198.51.100.1", 5000);
        const resp = try testTurnAllocateSuccessResponse(&response_buf, request.header.transaction_id, relayed, mapped, 600);
        _ = try core.handleRead(.{ .from = &server, .to = &local, .data = resp }, 0);
    }
    while (core.pollEvent()) |_| {}

    try testing.expectEqual(1, core.pairs.items.len);
    try testing.expectEqual(.waiting, core.pairs.items[0].status);

    const out = (try core.pollTransmit(&response_buf)) orelse return error.ExpectedTransmit;
    const request = try stun.Message.parse(out.data);
    const resp = try testTurnErrorResponse(&response_buf, request.header.transaction_id, .create_permission, .forbidden, "Forbidden");
    _ = try core.handleRead(.{ .from = &server, .to = &local, .data = resp }, 0);

    try testing.expectEqual(.failed, core.pairs.items[0].status);
}

test "writeDataFrame: frames relayed data in place and passes host data through" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    const local = try IpAddress.parse("10.0.0.10", 4000);
    const host = try IpAddress.parse("10.0.0.11", 4000);
    const server = try IpAddress.parse("203.0.113.1", 3478);
    const remote = try IpAddress.parse("192.168.1.10", 1000);
    try core.addServer(local, testTurnServer(server), 0);

    const payload = "hello";
    var buffer: [128]u8 = undefined;

    {
        const offset, const size = core.getDataFrameSize(&host, &remote, payload.len);
        try testing.expectEqual(0, offset);
        try testing.expectEqual(payload.len, size);

        @memcpy(buffer[0..payload.len], payload);
        const frame = try core.writeDataFrame(&host, &remote, &buffer, payload.len);
        try testing.expectEqualSlices(u8, payload, frame);
        try testing.expectEqual(null, core.getRelayServerAddress(&host));
    }

    const offset, const size = core.getDataFrameSize(&local, &remote, payload.len);
    try testing.expectEqual(36, offset);

    @memcpy(buffer[offset..][0..payload.len], payload);
    const frame = try core.writeDataFrame(&local, &remote, &buffer, payload.len);
    try testing.expectEqual(size, frame.len);
    try testing.expect(core.getRelayServerAddress(&local).?.eql(&server));
    try testing.expectEqualSlices(u8, payload, frame[offset..][0..payload.len]);

    const indication = try stun.Message.parse(frame);
    try testing.expectEqual(.send, indication.header.message_type.method());
    try testing.expectEqual(.indication, indication.header.message_type.class());

    try testing.expectError(error.WriteFailed, core.writeDataFrame(&local, &remote, buffer[0 .. size - 1], payload.len));
}

test "handleTimeout: transitioning to completed keeps only the turn client backing the nominated pair" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    core.connection_state = .connected;
    core.connectivity_check_deadline = 100_000;
    core.disconnected_connection_deadline = 100_000;
    core.keep_alive_deadline = 1000;
    core.remote_credentials = try .init("ruser", "peer-password-0123456789");

    const local1 = try IpAddress.parse("10.0.0.10", 4000);
    const server1 = try IpAddress.parse("203.0.113.1", 3478);
    const local2 = try IpAddress.parse("10.0.0.11", 4001);
    const server2 = try IpAddress.parse("203.0.113.2", 3478);

    try core.addServer(local1, testTurnServer(server1), 0);
    try core.addServer(local2, testTurnServer(server2), 0);

    core.candidates[0] = .initRelay(local1, try IpAddress.parse("203.0.113.9", 40000));
    core.candidates_len = 1;
    const from = try IpAddress.parse("192.168.1.120", 2000);
    core.remote_candidates[0] = testRemoteCandidate(from);
    core.remote_candidates_len = 1;
    core.nominated_pair = .{ .local = 0, .remote = 0 };
    try core.pairs.append(testing.allocator, .{ .local = 0, .remote = 0, .status = .succeeded, .priority = 0 });
    try core.pending_requests.append(testing.allocator, .{ .transaction_id = @splat(1), .pair = 0 });

    try core.handleTimeout(1000);

    try testing.expectEqual(.completed, core.connection_state);
    try testing.expectEqual(1, core.turn_clients.items.len);
    try testing.expect(core.turn_clients.items[0].local_addr.eql(&local1));
}
