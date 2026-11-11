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

pub const AddServerError = AllocError || error{
    GatheringDone,
    /// The TURN username exceeds `stun.turn.max_username_len`.
    UsernameTooLong,
};

pub const RestartError = error{
    Closed,
    /// The previous restart's new generation hasn't nominated a pair yet.
    RestartInProgress,
    CredentialsTooLong,
};

pub const SetRemoteCredentialsError = AllocError || error{
    CredentialsTooLong,
    /// Credentials differ from the current ones; call `restart` first.
    RestartRequired,
    /// Only one of ufrag/pwd changed; a restart changes both (RFC 8839).
    InvalidCredentials,
};

pub const NominatedPair = struct {
    local: CandidateIndex,
    remote: CandidateIndex,
};

pub const RemoteCandidate = struct {
    address: IpAddress,
    candidate_type: ice.CandidateType,
    priority: u32,
};

fn LocalCredentials(comptime size: u8) type {
    return struct {
        buffer: [size]u8,
        user_len: u8,
        pass_len: u8,

        pub fn init(username: []const u8, password: []const u8) error{CredentialsTooLong}!@This() {
            if (username.len + password.len > size) return error.CredentialsTooLong;
            var credentials: @This() = undefined;
            @memcpy(credentials.buffer[0..username.len], username);
            @memcpy(credentials.buffer[username.len .. username.len + password.len], password);
            credentials.user_len = @intCast(username.len);
            credentials.pass_len = @intCast(password.len);
            return credentials;
        }

        pub fn getUsername(self: *const @This()) []const u8 {
            return self.buffer[0..self.user_len];
        }

        pub fn getPassword(self: *const @This()) []const u8 {
            return self.buffer[self.user_len .. self.user_len + self.pass_len];
        }

        pub fn toIceCredentials(self: *const @This()) ice.Credentials {
            return .{
                .username = self.getUsername(),
                .password = self.getPassword(),
            };
        }

        pub fn clear(self: *@This()) void {
            self.user_len = 0;
            self.pass_len = 0;
            std.crypto.secureZero(u8, &self.buffer);
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
    kind: enum(u2) { success, role_conflict, success_restart } = .success,
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

pub const RestartMode = enum {
    /// The old nominated pair is kept so media and data can still flow until the new session nominates a pair.
    graceful,
    /// The whole session is dropped and restarted, which may cause a temporary disruption of media and data.
    hard,
};

pub fn Agent(comptime config: struct {
    auth_info_size: u8 = 64,
    max_candidates: CandidateIndex = 16,
    max_remote_candidates: CandidateIndex = 16,
    max_responses: u8 = 16,
    restart_mode: RestartMode = .graceful,
    stun_config: stun.Client.ClientConfig = .{ .max_transactions = 1 },
    turn_config: stun.turn.Config = .{},
}) type {
    const StunClient = stun.Client.Client(config.stun_config);
    const TurnClient = stun.turn.TurnClient(config.turn_config);

    const Timers = struct {
        failed_timeout: u32,
        disconnected_timeout: u32,
        connectivity_check_interval: u16,
    };

    const RestartState = struct {
        local_credentials: LocalCredentials(config.auth_info_size),
        remote_credentials: LocalCredentials(config.auth_info_size),
        remote_candidate: RemoteCandidate,
        nominated_pair: union(enum) {
            host: Candidate,
            relay: TurnClient,
        },

        fn deinit(self: *@This()) void {
            self.local_credentials.clear();
            self.remote_credentials.clear();
        }
    };

    return struct {
        const Self = @This();

        const max_events: u8 = 5;
        const initial_pairs_capacity: usize = @as(usize, config.max_candidates) * config.max_remote_candidates / 2;
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
        remote_candidates: [config.max_remote_candidates]RemoteCandidate = undefined,
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
        /// Only the response to this request refreshes consent (RFC 7675).
        consent_tx_id: ?[12]u8 = null,

        ice_restart: if (config.restart_mode == .graceful) ?*RestartState else void,
        /// Restart credentials advertised but not applied yet.
        pending_credentials: ?LocalCredentials(config.auth_info_size) = null,

        const ConnectivityChecks = struct {
            index: u16,
            nomination_done: bool,
            done: bool,

            pub const init = ConnectivityChecks{ .index = 0, .nomination_done = false, .done = false };
            pub const init_done = ConnectivityChecks{ .index = 0, .nomination_done = false, .done = true };
        };

        const DataPath = struct {
            local: *const IpAddress,
            remote: *const IpAddress,
            turn_client: ?*TurnClient,
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
                .ice_restart = if (config.restart_mode == .graceful) null else {},
            };
        }

        pub fn deinit(agent: *Self) void {
            agent.close();
            agent.events_out.clear();
            agent.responses.clear();
        }

        pub fn close(agent: *Self) void {
            if (agent.connection_state == .closed) return;
            agent.connection_state = .closed;
            agent.credentials.clear();
            if (agent.remote_credentials) |*rc| rc.clear();
            agent.clearRestart();
            agent.discardRestart();
            agent.events_out.clear();
            agent.responses.clear();
            agent.events_out.pushBack(.{ .connection_state = .closed }) catch unreachable;

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

        /// The credentials to advertise: the staged ones during a pending restart.
        pub fn getLocalCredentials(core: *const Self) ice.Credentials {
            const credentials = if (core.pending_credentials) |*pending| pending else &core.credentials;
            return credentials.toIceCredentials();
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
        ///
        /// `local` must be a dedicated socket: host, server reflexive and relay candidates
        /// never share the same base.
        pub fn addServer(agent: *Self, local: IpAddress, server: Server, now: i64) AddServerError!void {
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
                    if (turn.username.len > stun.turn.max_username_len) return error.UsernameTooLong;
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

        pub fn setRemoteCredentials(agent: *Self, credentials: ice.Credentials, now: i64) SetRemoteCredentialsError!void {
            if (agent.remote_credentials) |*rc| {
                const same_user = std.mem.eql(u8, rc.getUsername(), credentials.username);
                const same_pass = std.mem.eql(u8, rc.getPassword(), credentials.password);
                if (same_user and same_pass) return;
                if (same_user or same_pass) return error.InvalidCredentials;
                return error.RestartRequired;
            }

            agent.remote_credentials = try .init(credentials.username, credentials.password);
            if (agent.restarting()) {
                agent.connectivity_check = .init;
                agent.connectivity_check_deadline = now + agent.timers.connectivity_check_interval;
                return;
            }

            switch (agent.connection_state) {
                .new, .failed => try agent.setConnectionState(.checking, now),
                .checking => {
                    agent.connectivity_check = .init;
                    agent.connectivity_check_deadline = now + agent.timers.connectivity_check_interval;
                    agent.disconnected_connection_deadline = now + agent.timers.failed_timeout;
                },
                else => {},
            }
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

        /// Stages new local credentials for an ICE restart (RFC 8445 §9) without updating the current session.
        pub fn stageRestart(agent: *Self, credentials: ice.Credentials) RestartError!void {
            if (agent.connection_state == .closed) return error.Closed;
            if (agent.restarting()) return error.RestartInProgress;

            const pending: LocalCredentials(config.auth_info_size) = try .init(credentials.username, credentials.password);
            agent.discardRestart();
            agent.pending_credentials = pending;
        }

        /// Applies the staged restart; a no-op when nothing is staged.
        pub fn applyRestart(agent: *Self, now: i64) AllocError!void {
            if (agent.pending_credentials == null) return;
            std.debug.assert(!agent.restarting());

            const previous_state = agent.connection_state;
            switch (previous_state) {
                .closed => unreachable,
                .new => {
                    agent.credentials.clear();
                    agent.credentials = agent.pending_credentials.?;
                    agent.pending_credentials = null;
                    return;
                },
                .checking, .failed => {
                    agent.credentials.clear();
                    if (agent.remote_credentials) |*rc| rc.clear();
                },
                .connected, .completed, .disconnected => switch (config.restart_mode) {
                    .hard => {
                        agent.credentials.clear();
                        if (agent.remote_credentials) |*rc| rc.clear();
                    },
                    .graceful => {
                        const nominated = agent.nominated_pair.?;
                        const local_candidate = agent.candidates[nominated.local];
                        const state = try agent.allocator.create(RestartState);
                        state.* = .{
                            .local_credentials = agent.credentials,
                            .remote_credentials = agent.remote_credentials.?,
                            .remote_candidate = agent.remote_candidates[nominated.remote],
                            .nominated_pair = if (agent.findTurnClient(&local_candidate.base)) |turn_client|
                                .{ .relay = turn_client.* }
                            else
                                .{ .host = local_candidate },
                        };
                        agent.ice_restart = state;
                    },
                },
            }

            agent.credentials = agent.pending_credentials.?;
            agent.pending_credentials = null;
            agent.remote_credentials = null;
            agent.nominated_pair = null;
            agent.selected_pair = null;
            agent.connectivity_check = .init_done;
            agent.pairs.clearRetainingCapacity();
            agent.pending_requests.clearRetainingCapacity();
            agent.responses.clear();
            agent.stun_clients.clearRetainingCapacity();
            agent.turn_clients.clearRetainingCapacity();
            agent.gathering_state = .new;
            agent.gathering_done = false;
            agent.candidates_len = 0;
            agent.remote_candidates_len = 0;

            if (config.restart_mode == .hard) switch (previous_state) {
                .connected, .completed, .disconnected => {
                    agent.consent_freshness = false;
                    agent.consent_tx_id = null;
                    agent.keep_alive_deadline = std.math.maxInt(i64);
                    try agent.setConnectionState(.checking, now);
                },
                else => {},
            };
        }

        pub fn discardRestart(agent: *Self) void {
            if (agent.pending_credentials) |*pending| pending.clear();
            agent.pending_credentials = null;
        }

        /// Stages and applies a restart in one step.
        pub fn restart(agent: *Self, credentials: ice.Credentials, now: i64) (RestartError || AllocError)!void {
            try agent.stageRestart(credentials);
            try agent.applyRestart(now);
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

            if (agent.restartTurnClient()) |turn_client| {
                turn_client.handleTimeout(now) catch {};
                while (turn_client.pollEvent()) |_| {}
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
                // `completed` drops the checklist, which the new generation still needs.
                if (agent.connection_state == .connected and !agent.restarting()) {
                    try agent.setConnectionState(.completed, now);
                }
                agent.consent_freshness = true;
            }

            if (now >= agent.disconnected_connection_deadline) {
                switch (agent.connection_state) {
                    .checking => try agent.setConnectionState(.failed, now),
                    .disconnected => if (agent.restarting()) {
                        // The pre-restart pair is lost; the new generation carries on.
                        agent.clearRestart();
                        agent.consent_freshness = false;
                        agent.keep_alive_deadline = std.math.maxInt(i64);
                        try agent.setConnectionState(if (agent.remote_credentials != null) .checking else .failed, now);
                    } else try agent.setConnectionState(.failed, now),
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

            if (try agent.maybeHandleTurnMessage(&new_message, now)) return .consumed;

            if (try agent.maybeHandleConsentResponse(&new_message, now)) return .consumed;

            if (config.restart_mode == .graceful) {
                if (agent.maybeHandleOldGenerationMessage(&new_message) catch return .consumed) return .consumed;
            }

            // During a restart, everything else belongs to the new generation.
            if (!agent.restarting()) switch (agent.connection_state) {
                .completed, .disconnected, .failed => {
                    msg = stun.Message.parse(new_message.data) catch return .consumed;
                    if (try agent.handleConsentFreshness(&msg, new_message.to, new_message.from)) |resp| {
                        agent.queueResponse(resp);
                    }

                    return .consumed;
                },
                else => {},
            };

            for (agent.stun_clients.items, 0..) |*stun_server, i| {
                if (stun_server.local_addr.eql(new_message.to)) if (try stun_server.handleRead(new_message.data)) {
                    _ = try agent.handleStunClientEvents(i);
                    return .consumed;
                };
            }

            return agent.handleStunMessage(new_message, now);
        }

        /// Frames application data for the nominated pair. Must be called after nomination.
        ///
        /// The payload must already be at `buffer[header_size..]`, see `getDataFrameSize`.
        pub fn handleWrite(agent: *Self, buffer: []u8, payload_len: usize) error{WriteFailed}!stun.TransportMessage {
            std.debug.assert(agent.nominated_pair != null or agent.restarting());
            const path = agent.activePath();

            if (path.turn_client) |turn_client| {
                const header_size, const size = turn_client.getDataFrameSize(path.remote, payload_len);
                if (size > buffer.len) return error.WriteFailed;
                turn_client.writeDataHeader(path.remote, buffer, payload_len);
                const padding = buffer[header_size + payload_len .. size];
                switch (padding.len) {
                    inline 0...3 => |len| padding[0..len].* = @splat(0),
                    else => unreachable,
                }
                return .{ .data = buffer[0..size], .from = path.local, .to = &turn_client.remote_addr };
            }

            if (payload_len > buffer.len) return error.WriteFailed;
            return .{ .data = buffer[0..payload_len], .from = path.local, .to = path.remote };
        }

        pub fn pollEvent(core: *Self) ?Event {
            return core.events_out.popFront();
        }

        pub fn pollTransmit(agent: *Self, buffer: []u8) error{WriteFailed}!?stun.TransportMessage {
            while (agent.responses.peekFront()) |resp| {
                const restart_resp = config.restart_mode == .graceful and resp.kind == .success_restart;
                if (restart_resp and !agent.restarting()) {
                    _ = agent.responses.popFront();
                    continue;
                }

                const active_path = if (restart_resp)
                    agent.activePath()
                else
                    DataPath{
                        .local = &agent.candidates[resp.local].base,
                        .remote = &agent.remote_candidates[resp.remote].address,
                        .turn_client = agent.findTurnClient(&agent.candidates[resp.local].base),
                    };

                const password = if (restart_resp)
                    agent.ice_restart.?.local_credentials.getPassword()
                else
                    agent.credentials.getPassword();
                const payload = switch (resp.kind) {
                    .success, .success_restart => try Messages.buildSuccessResponse(resp.tx_id, password, active_path.remote, buffer),
                    .role_conflict => try Messages.buildRoleConflictErrorMessage(resp.tx_id, password, buffer),
                };

                const result: stun.TransportMessage = blk: {
                    if (active_path.turn_client) |turn_client| {
                        const size = try wrapInTurnMessage(turn_client, active_path.remote, buffer, payload.len);
                        break :blk .{
                            .from = active_path.local,
                            .to = &turn_client.remote_addr,
                            .data = buffer[0..size],
                        };
                    }

                    break :blk .{ .from = active_path.local, .to = active_path.remote, .data = buffer[0..payload.len] };
                };

                _ = agent.responses.popFront();
                return result;
            }

            for (agent.stun_clients.items) |*stun_client| if (try stun_client.pollTransmit(buffer)) |msg| {
                return msg;
            };

            for (agent.turn_clients.items) |*turn_client| if (try turn_client.pollTransmit(buffer)) |msg| {
                return msg;
            };

            if (agent.restartTurnClient()) |turn_client| if (try turn_client.pollTransmit(buffer)) |msg| {
                return msg;
            };

            if (agent.consent_freshness) {
                const path = agent.activePath();
                const local_credentials, const remote_credentials = agent.consentCredentials();
                const tx_id = agent.newTransactionId();

                const payload = try Messages.buildAuthenticatedBindingRequest(buffer, .{
                    .tx_id = tx_id,
                    .username = local_credentials.getUsername(),
                    .remote_username = remote_credentials.getUsername(),
                    .remote_password = remote_credentials.getPassword(),
                    .use_candidate = false,
                    .role = agent.role,
                    .tie_breaker = agent.tie_breaker,
                });

                const result: stun.TransportMessage = if (path.turn_client) |turn_client| .{
                    .from = path.local,
                    .to = &turn_client.remote_addr,
                    .data = buffer[0..try wrapInTurnMessage(turn_client, path.remote, buffer, payload.len)],
                } else .{ .from = path.local, .to = path.remote, .data = payload };

                agent.consent_freshness = false;
                agent.consent_tx_id = tx_id;
                return result;
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

            if (agent.restartTurnClient()) |turn_client| if (turn_client.pollTimeout()) |d| {
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

        /// Returns the header size and total frame size of a payload sent on the nominated pair.
        /// The header size is non-zero only for relay candidates. Must be called after nomination.
        pub fn getDataFrameSize(agent: *Self, payload_len: usize) struct { u32, usize } {
            std.debug.assert(agent.nominated_pair != null or agent.restarting());
            const path = agent.activePath();
            const turn_client = path.turn_client orelse return .{ 0, payload_len };
            return turn_client.getDataFrameSize(path.remote, payload_len);
        }

        fn newTransactionId(agent: *Self) [12]u8 {
            var id: [12]u8 = undefined;
            agent.random.bytes(&id);
            return id;
        }

        fn startAllocation(turn_client: *TurnClient, now: i64) AllocError!void {
            turn_client.createAllocation(now) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.AllocationAlreadyExists => {},
            };
        }

        fn appendCandidate(core: *Self, candidate: Candidate) error{OutOfMemory}!CandidateIndex {
            if (core.candidates_len >= config.max_candidates) return error.OutOfMemory;
            const idx = core.candidates_len;
            core.candidates[idx] = candidate;
            core.candidates_len += 1;
            return idx;
        }

        fn appendRemoteCandidate(core: *Self, candidate: Candidate) AllocError!CandidateIndex {
            if (core.remote_candidates_len >= config.max_remote_candidates) return error.OutOfMemory;
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
                agent.clearRestart();
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
            const checking = agent.connection_state == .checking or agent.restarting();
            if (checking and agent.nominated_pair == null) agent.connectivity_check.done = false;
        }

        fn nextConnectivityCheck(agent: *Self, buffer: []u8) !?stun.TransportMessage {
            const check = &agent.connectivity_check;
            // After a restart, checks wait for the peer's new credentials.
            if (check.done or agent.remote_credentials == null) return null;

            if (!check.nomination_done) {
                const msg = if (agent.selected_pair) |idx|
                    try agent.buildConnectivityCheckBindingRequest(&agent.pairs.items[idx], idx, buffer)
                else
                    null;
                check.nomination_done = true;
                if (msg) |m| return m;
            }

            while (check.index < agent.pairs.items.len) {
                const msg = try agent.checkPair(check.index, buffer);
                check.index += 1;
                if (msg) |m| return m;
            }

            check.done = true;
            return null;
        }

        /// Builds the next binding request for the pair, or null if it's not checkable.
        fn checkPair(agent: *Self, idx: u16, buffer: []u8) !?stun.TransportMessage {
            const pair = &agent.pairs.items[idx];
            if (pair.status != .waiting and pair.status != .in_progress) return null;
            if (pair.conn_check_count >= max_binding_requests) {
                pair.status = .failed;
                return null;
            }

            const msg = (try agent.buildConnectivityCheckBindingRequest(pair, idx, buffer)) orelse return null;
            pair.conn_check_count += 1;
            return msg;
        }

        fn buildConnectivityCheckBindingRequest(agent: *Self, pair: *const CandidatePair, idx: u16, buffer: []u8) !?stun.TransportMessage {
            const tx_id = agent.newTransactionId();
            const local = agent.getPairLocal(pair);
            const remote = &agent.getPairRemote(pair).address;

            const payload = try Messages.buildAuthenticatedBindingRequest(buffer, .{
                .tx_id = tx_id,
                .username = agent.credentials.getUsername(),
                .remote_username = agent.remote_credentials.?.getUsername(),
                .remote_password = agent.remote_credentials.?.getPassword(),
                .use_candidate = agent.selected_pair != null and agent.selected_pair.? == idx,
                .role = agent.role,
                .tie_breaker = agent.tie_breaker,
            });

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

        /// The nominated pair, or the pre-restart one during a restart.
        fn activePath(agent: *Self) DataPath {
            if (config.restart_mode == .graceful) if (agent.ice_restart) |ice_restart| {
                var path: DataPath = .{
                    .local = undefined,
                    .remote = &ice_restart.remote_candidate.address,
                    .turn_client = null,
                };
                switch (ice_restart.nominated_pair) {
                    .host => |*candidate| path.local = &candidate.base,
                    .relay => |*client| {
                        path.local = &client.local_addr;
                        path.turn_client = client;
                    },
                }
                return path;
            };

            const nominated = agent.nominated_pair.?;
            return .{
                .local = &agent.candidates[nominated.local].base,
                .remote = &agent.remote_candidates[nominated.remote].address,
                .turn_client = agent.nominatedTurnClient(),
            };
        }

        fn maybeHandleTurnMessage(agent: *Self, message: *const stun.TransportMessage, now: i64) !bool {
            // The pre-restart client may share its socket and server with a new one;
            // each ignores transactions it doesn't own.
            var consumed = false;
            if (agent.restartTurnClient()) |turn_client| {
                if (turn_client.local_addr.eql(message.to) and turn_client.remote_addr.eql(message.from)) {
                    turn_client.handleRead(message.data, now) catch return true;
                    while (turn_client.pollEvent()) |_| {}
                    consumed = true;
                }
            }

            for (agent.turn_clients.items, 0..) |*turn_client, i| {
                if (turn_client.local_addr.eql(message.to) and turn_client.remote_addr.eql(message.from)) {
                    // ignore malformed messages
                    turn_client.handleRead(message.data, now) catch return true;
                    _ = try agent.handleTurnClientEvents(i, now);
                    return true;
                }
            }

            return consumed;
        }

        fn restarting(agent: *const Self) bool {
            return config.restart_mode == .graceful and agent.ice_restart != null;
        }

        fn restartTurnClient(agent: *Self) ?*TurnClient {
            if (config.restart_mode == .hard) return null;
            const ice_restart = agent.ice_restart orelse return null;
            return switch (ice_restart.nominated_pair) {
                .relay => |*turn_client| turn_client,
                .host => null,
            };
        }

        fn clearRestart(agent: *Self) void {
            if (config.restart_mode == .hard) return;
            const ice_restart = agent.ice_restart orelse return;
            ice_restart.deinit();
            agent.allocator.destroy(ice_restart);
            agent.ice_restart = null;
            agent.consent_tx_id = null;
        }

        fn nominatedTurnClient(agent: *Self) ?*TurnClient {
            const local = &agent.candidates[agent.nominated_pair.?.local];
            if (local.candidate_type != .relay) return null;
            return agent.findTurnClient(&local.base) orelse unreachable;
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

            const size = try wrapInTurnMessage(turn_client, remote, buffer, data_len);
            return .{
                .data = buffer[0..size],
                .from = local,
                .to = &turn_client.remote_addr,
            };
        }

        fn wrapInTurnMessage(turn_client: *TurnClient, addr: *const IpAddress, buffer: []u8, payload_len: usize) error{WriteFailed}!usize {
            const offset, const size = turn_client.getDataFrameSize(addr, payload_len);
            if (size > buffer.len) return error.WriteFailed;
            @memmove(buffer[offset .. offset + payload_len], buffer[0..payload_len]);
            turn_client.writeDataHeader(addr, buffer, payload_len);
            @memset(buffer[offset + payload_len .. size], 0);
            return size;
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

        fn maybeHandleOldGenerationMessage(agent: *Self, message: *const stun.TransportMessage) !bool {
            const ice_restart = agent.ice_restart orelse return false;
            const msg = try stun.Message.parse(message.data);
            if (msg.header.message_type.class() != .request) return false;

            var it = msg.iterateAttributes(&.{});
            const username = blk: {
                while (try it.next()) |attr| {
                    if (attr == .username) {
                        const pos = std.mem.findScalarPos(u8, attr.username, 0, ':') orelse return true;
                        break :blk attr.username[0..pos];
                    }
                } else return true; // Each stun request must have a username attribute
            };

            if (!std.mem.eql(u8, username, ice_restart.local_credentials.getUsername())) return false;

            const path = agent.activePath();
            if (!message.to.eql(path.local) or !message.from.eql(path.remote)) return true;

            try Messages.validateConsentFreshnessRequest(&msg, ice_restart.local_credentials.getPassword());
            agent.queueResponse(.{ .kind = .success_restart, .tx_id = msg.header.transaction_id, .local = 0, .remote = 0 });
            return true;
        }

        fn maybeHandleConsentResponse(agent: *Self, message: *const stun.TransportMessage, now: i64) !bool {
            const tx_id = agent.consent_tx_id orelse return false;
            const msg = stun.Message.parse(message.data) catch return false;
            if (msg.header.message_type.class() != .success_response) return false;
            if (!std.mem.eql(u8, &tx_id, &msg.header.transaction_id)) return false;

            _, const remote_credentials = agent.consentCredentials();
            _ = Messages.parseAndValidateStunResponse(&msg, remote_credentials.getPassword()) catch return true;
            agent.consent_tx_id = null;

            switch (agent.connection_state) {
                .failed => return true,
                // `completed` would drop the new generation's checklist.
                .disconnected => if (agent.restarting()) {
                    try agent.events_out.pushBack(.{ .connection_state = .completed });
                    agent.connection_state = .completed;
                } else try agent.setConnectionState(.completed, now),
                else => {},
            }

            agent.disconnected_connection_deadline = now + agent.timers.disconnected_timeout;
            return true;
        }

        fn consentCredentials(agent: *Self) struct { *LocalCredentials(config.auth_info_size), *LocalCredentials(config.auth_info_size) } {
            if (config.restart_mode == .hard) return .{ &agent.credentials, &agent.remote_credentials.? };

            return if (agent.ice_restart) |ice_restart|
                .{ &ice_restart.local_credentials, &ice_restart.remote_credentials }
            else
                .{ &agent.credentials, &agent.remote_credentials.? };
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
        .credentials = .{ .username = "user", .password = test_local_password },
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

fn testRespond(core: *TestAgent, msg: *const stun.Message, base: *const IpAddress, from: *const IpAddress, buffer: []u8) !stun.TransportMessage {
    core.queueResponse((try core.handleRequest(msg, base, from)) orelse return error.ExpectedResponse);
    return (try core.pollTransmit(buffer)) orelse error.ExpectedTransmit;
}

const test_local_password = "VOkJxbRl1RmTxUk/WvJxBt";

const TestAddrs = struct {
    local: IpAddress,
    remote: IpAddress,
    other: IpAddress,
    server: IpAddress,
    relayed: IpAddress,
    new_local: IpAddress,
    new_remote: IpAddress,

    fn init() !TestAddrs {
        return .{
            .local = try IpAddress.parse("10.0.0.10", 4000),
            .remote = try IpAddress.parse("192.168.1.10", 1000),
            .other = try IpAddress.parse("192.168.1.66", 1000),
            .server = try IpAddress.parse("203.0.113.1", 3478),
            .relayed = try IpAddress.parse("203.0.113.9", 40000),
            .new_local = try IpAddress.parse("10.0.0.20", 4000),
            .new_remote = try IpAddress.parse("192.168.1.20", 1000),
        };
    }
};

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

test "pollTransmit: keeps the message queued on WriteFailed" {
    var small: [stun.header_size - 1]u8 = undefined;
    var tx_buf: [1024]u8 = undefined;
    var req_buf: [1024]u8 = undefined;
    var agent = try testNewAgent(.controlled);
    defer agent.deinit();

    const local = try IpAddress.parse("192.168.1.100", 1000);
    const remote = try IpAddress.parse("192.168.1.120", 2000);

    try agent.addLocalAddrs(&.{local}, 0);
    try agent.addRemoteCandidate(.initHost(remote), 0);
    try agent.setRemoteCredentials(.{ .username = "peer", .password = "peer-password-0123456789" }, 0);

    const req = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = agent.credentials.getUsername(),
    }, agent.credentials.getPassword(), &req_buf);
    agent.queueResponse((try agent.handleRequest(&req, &local, &remote)) orelse return error.ExpectedResponse);

    // Response
    try testing.expectError(error.WriteFailed, agent.pollTransmit(&small));
    const resp = (try agent.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    const resp_msg = try stun.Message.parse(resp.data);
    try testing.expectEqual(.success_response, resp_msg.header.message_type.class());
    try testing.expectEqual(req.header.transaction_id, resp_msg.header.transaction_id);

    // Connectivity check
    try testing.expectError(error.WriteFailed, agent.pollTransmit(&small));
    try testing.expectEqual(0, agent.pairs.items[0].conn_check_count);
    try testing.expectEqual(0, agent.pending_requests.items.len);
    const check = (try agent.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    try testing.expectEqual(.request, (try stun.Message.parse(check.data)).header.message_type.class());
    try testing.expect(check.to.eql(&remote));
    try testing.expectEqual(1, agent.pairs.items[0].conn_check_count);
    try testing.expectEqual(null, try agent.pollTransmit(&tx_buf));

    // Consent freshness
    agent.nominated_pair = .{ .local = 0, .remote = 0 };
    agent.consent_freshness = true;
    try testing.expectError(error.WriteFailed, agent.pollTransmit(&small));
    try testing.expect(agent.consent_freshness);

    const consent = (try agent.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    try testing.expectEqual(.request, (try stun.Message.parse(consent.data)).header.message_type.class());
    try testing.expect(consent.to.eql(&remote));
    try testing.expectEqual(null, try agent.pollTransmit(&tx_buf));
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
