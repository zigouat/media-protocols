//! Ice lite agent implementation.
//!
//! The implementation is based on RFC 8445.

const std = @import("std");
const stun = @import("stun");
const ice = @import("ice.zig");
const Messages = @import("messages.zig");
const common = @import("common.zig");

const Candidate = ice.Candidate;
const CandidateIndex = common.CandidateIndex;
const IpAddress = std.Io.net.IpAddress;
const Logger = std.log.scoped(.ice);
const AllocError = std.mem.Allocator.Error;
const LocalCredentials = common.LocalCredentials;
const Response = common.Response;

pub const RestartError = common.RestartError;
pub const SetRemoteCredentialsError = common.SetRemoteCredentialsError;
pub const NominatedPair = common.NominatedPair;
pub const RemoteCandidate = common.RemoteCandidate;
pub const Event = common.Event;
pub const ReadResult = common.ReadResult;
pub const RestartMode = common.RestartMode;
pub const keep_alive_interval = common.keep_alive_interval;
pub const Config = common.Config;

pub fn Agent(comptime config: struct {
    auth_info_size: u8 = 64,
    max_candidates: CandidateIndex = 16,
    max_remote_candidates: CandidateIndex = 16,
    max_responses: u8 = 16,
    restart_mode: RestartMode = .graceful,
}) type {
    const RestartState = struct {
        local_credentials: LocalCredentials(config.auth_info_size),
        remote_credentials: LocalCredentials(config.auth_info_size),
        remote_candidate: RemoteCandidate,
        local_candidate: Candidate,

        fn deinit(self: *@This()) void {
            self.local_credentials.clear();
            self.remote_credentials.clear();
        }
    };

    return struct {
        const Self = @This();
        const max_events: u8 = 5;

        allocator: std.mem.Allocator,
        random: std.Random,

        credentials: LocalCredentials(config.auth_info_size),
        remote_credentials: ?LocalCredentials(config.auth_info_size),
        connection_state: ice.ConnectionState,
        gathering_state: ice.GatheringState,
        role: ice.Role,
        tie_breaker: u64,

        candidates: [config.max_candidates]Candidate = undefined,
        candidates_len: CandidateIndex = 0,
        remote_candidates: [config.max_remote_candidates]RemoteCandidate = undefined,
        remote_candidates_len: CandidateIndex = 0,
        /// The pair nominated by the remote agent.
        nominated_pair: ?NominatedPair = null,

        failed_timeout: u32,
        disconnected_timeout: u32,

        disconnected_connection_deadline: i64, // used for both disconnected and failed states
        keep_alive_deadline: i64,

        events_out: stun.BoundedDeque(Event, max_events),
        responses: stun.BoundedDeque(Response, config.max_responses) = .empty,

        consent_freshness: bool,
        /// Only the response to this request refreshes consent (RFC 7675).
        consent_tx_id: ?[12]u8 = null,

        ice_restart: if (config.restart_mode == .graceful) ?*RestartState else void,
        /// Restart credentials advertised but not applied yet.
        pending_credentials: ?LocalCredentials(config.auth_info_size) = null,

        const DataPath = struct {
            local: *const IpAddress,
            remote: *const IpAddress,
        };

        pub fn init(allocator: std.mem.Allocator, agent_config: Config) error{CredentialsTooLong}!Self {
            return .{
                .allocator = allocator,
                .random = agent_config.random,
                .role = agent_config.role,
                .connection_state = .new,
                .gathering_state = .new,
                .credentials = try .init(agent_config.credentials.username, agent_config.credentials.password),
                .remote_credentials = null,
                .tie_breaker = agent_config.random.int(u64),
                .keep_alive_deadline = std.math.maxInt(i64),
                .disconnected_connection_deadline = std.math.maxInt(i64),
                .events_out = .empty,
                .consent_freshness = false,
                .failed_timeout = agent_config.failed_timeout,
                .disconnected_timeout = agent_config.disconnected_timeout,
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
            agent.candidates_len = 0;
            agent.remote_candidates_len = 0;
        }

        pub fn getRemoteCredentials(agent: *const Self) ?ice.Credentials {
            return if (agent.remote_credentials) |*rc| rc.toIceCredentials() else null;
        }

        /// The credentials to advertise: the staged ones during a pending restart.
        pub fn getLocalCredentials(agent: *const Self) ice.Credentials {
            const credentials = if (agent.pending_credentials) |*pending| pending else &agent.credentials;
            return credentials.toIceCredentials();
        }

        pub fn getNominatedRemoteAddress(agent: *const Self) ?IpAddress {
            return if (agent.nominated_pair) |nominated| agent.remote_candidates[nominated.remote].address else null;
        }

        /// Add local addresses to the agent. The first call starts gathering.
        ///
        /// Adding an empty list of addresses signals the end of gathering.
        pub fn addLocalAddrs(agent: *Self, addrs: []const IpAddress) (AllocError || error{GatheringDone})!void {
            if (agent.gathering_state == .complete) return error.GatheringDone;
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

            if (addrs.len == 0) {
                agent.gathering_state = .complete;
                try agent.events_out.pushBack(.{ .gathering_state = agent.gathering_state });
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
            if (agent.restarting()) return;

            switch (agent.connection_state) {
                .new, .failed => try agent.setConnectionState(.checking, now),
                .checking => agent.disconnected_connection_deadline = now + agent.failed_timeout,
                else => {},
            }
        }

        /// A candidate for an already known address updates its type and priority, no duplicate is added.
        pub fn addRemoteCandidate(agent: *Self, remote_candidate: Candidate) AllocError!void {
            if (agent.findRemoteCandidate(&remote_candidate.address)) |idx| {
                agent.remote_candidates[idx].candidate_type = remote_candidate.candidate_type;
                agent.remote_candidates[idx].priority = remote_candidate.priority;
                return;
            }
            _ = try agent.appendRemoteCandidate(remote_candidate);
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
                        const state = try agent.allocator.create(RestartState);
                        state.* = .{
                            .local_credentials = agent.credentials,
                            .remote_credentials = agent.remote_credentials.?,
                            .remote_candidate = agent.remote_candidates[nominated.remote],
                            .local_candidate = agent.candidates[nominated.local],
                        };
                        agent.ice_restart = state;
                    },
                },
            }

            agent.credentials = agent.pending_credentials.?;
            agent.pending_credentials = null;
            agent.remote_credentials = null;
            agent.nominated_pair = null;
            agent.responses.clear();
            agent.gathering_state = .new;
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

            if (now >= agent.keep_alive_deadline) {
                agent.keep_alive_deadline = now + keep_alive_interval;
                if (agent.connection_state == .connected) try agent.setConnectionState(.completed, now);
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

        pub fn handleRead(agent: *Self, message: stun.TransportMessage, now: i64) (AllocError || error{NoLocalCandidate})!ReadResult {
            if (!stun.isMessage(message.data)) {
                return agent.handleAppData(message.from, message.data);
            }

            // Ignore malformed stun messages.
            const msg = stun.Message.parse(message.data) catch return .consumed;

            if (try agent.maybeHandleConsentResponse(&msg, now)) return .consumed;

            if (config.restart_mode == .graceful) {
                if (agent.maybeHandleOldGenerationMessage(&msg, message.to, message.from) catch return .consumed) return .consumed;
            }

            // During a restart, everything else belongs to the new generation.
            if (!agent.restarting()) switch (agent.connection_state) {
                .completed, .disconnected, .failed => {
                    if (try agent.handleConsentFreshness(&msg, message.to, message.from)) |resp| {
                        agent.queueResponse(resp);
                    }

                    return .consumed;
                },
                else => {},
            };

            return agent.handleStunMessage(&msg, message.to, message.from, now);
        }

        pub fn handleWrite(agent: *Self, buffer: []u8, payload_len: usize) error{WriteFailed}!stun.TransportMessage {
            std.debug.assert(agent.nominated_pair != null or agent.restarting());
            if (payload_len > buffer.len) return error.WriteFailed;
            const path = agent.activePath();
            return .{ .data = buffer[0..payload_len], .from = path.local, .to = path.remote };
        }

        pub fn pollEvent(agent: *Self) ?Event {
            return agent.events_out.popFront();
        }

        pub fn pollTransmit(agent: *Self, buffer: []u8) error{WriteFailed}!?stun.TransportMessage {
            while (agent.responses.peekFront()) |resp| {
                const restart_resp = config.restart_mode == .graceful and resp.pair == null;
                if (restart_resp and !agent.restarting()) {
                    _ = agent.responses.popFront();
                    continue;
                }

                const active_path: DataPath, const password = if (restart_resp)
                    .{ agent.activePath(), agent.ice_restart.?.local_credentials.getPassword() }
                else
                    .{
                        .{
                            .local = &agent.candidates[resp.pair.?.local].base,
                            .remote = &agent.remote_candidates[resp.pair.?.remote].address,
                        },
                        agent.credentials.getPassword(),
                    };

                const payload = switch (resp.kind) {
                    .success => try Messages.buildSuccessResponse(resp.tx_id, password, active_path.remote, buffer),
                    .role_conflict => try Messages.buildRoleConflictErrorMessage(resp.tx_id, password, buffer),
                    .bad_request => try Messages.buildAuthErrorResponse(resp.tx_id, error.BadRequest, buffer),
                    .unauthorized => try Messages.buildAuthErrorResponse(resp.tx_id, error.Unauthorized, buffer),
                };

                _ = agent.responses.popFront();
                return .{ .from = active_path.local, .to = active_path.remote, .data = buffer[0..payload.len] };
            }

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

                agent.consent_freshness = false;
                agent.consent_tx_id = tx_id;
                return .{ .from = path.local, .to = path.remote, .data = payload };
            }

            return null;
        }

        pub fn pollTimeout(agent: *Self) ?i64 {
            if (agent.connection_state == .closed) return null;
            const deadline: i64 = @min(
                agent.keep_alive_deadline,
                agent.disconnected_connection_deadline,
            );

            return if (deadline == std.math.maxInt(i64)) null else deadline;
        }

        pub fn getDataFrameSize(agent: *Self, payload_len: usize) struct { u32, usize } {
            std.debug.assert(agent.nominated_pair != null or agent.restarting());
            return .{ 0, payload_len };
        }

        fn newTransactionId(agent: *Self) [12]u8 {
            var id: [12]u8 = undefined;
            agent.random.bytes(&id);
            return id;
        }

        /// Returns `null` if an identical candidate already exists.
        fn addLocalCandidate(agent: *Self, candidate: Candidate) AllocError!?CandidateIndex {
            for (agent.candidates[0..agent.candidates_len]) |*existing| if (existing.eql(&candidate)) return null;
            return try agent.appendCandidate(candidate);
        }

        fn appendCandidate(agent: *Self, candidate: Candidate) error{OutOfMemory}!CandidateIndex {
            if (agent.candidates_len >= config.max_candidates) return error.OutOfMemory;
            const idx = agent.candidates_len;
            agent.candidates[idx] = candidate;
            agent.candidates_len += 1;
            return idx;
        }

        fn appendRemoteCandidate(agent: *Self, candidate: Candidate) AllocError!CandidateIndex {
            if (agent.remote_candidates_len >= config.max_remote_candidates) return error.OutOfMemory;
            const idx = agent.remote_candidates_len;
            agent.remote_candidates[idx] = .{ .address = candidate.address, .candidate_type = candidate.candidate_type, .priority = candidate.priority };
            agent.remote_candidates_len += 1;
            return idx;
        }

        fn setConnectionState(agent: *Self, state: ice.ConnectionState, now: i64) AllocError!void {
            agent.connection_state = state;
            switch (agent.connection_state) {
                .checking => agent.disconnected_connection_deadline = now + agent.failed_timeout,
                .connected => {
                    agent.keep_alive_deadline = now + keep_alive_interval;
                    agent.disconnected_connection_deadline = now + agent.disconnected_timeout;
                },
                .completed => agent.disconnected_connection_deadline = now + agent.disconnected_timeout,
                .disconnected => agent.disconnected_connection_deadline = now + agent.failed_timeout,
                .failed => {
                    agent.disconnected_connection_deadline = std.math.maxInt(i64);
                    agent.keep_alive_deadline = std.math.maxInt(i64);
                },
                else => {},
            }

            try agent.events_out.pushBack(.{ .connection_state = agent.connection_state });
        }

        /// The nominated pair, or the pre-restart one during a restart.
        fn activePath(agent: *Self) DataPath {
            if (config.restart_mode == .graceful) if (agent.ice_restart) |ice_restart| {
                return .{
                    .local = &ice_restart.local_candidate.base,
                    .remote = &ice_restart.remote_candidate.address,
                };
            };

            const nominated = agent.nominated_pair.?;
            return .{
                .local = &agent.candidates[nominated.local].base,
                .remote = &agent.remote_candidates[nominated.remote].address,
            };
        }

        fn restarting(agent: *const Self) bool {
            return config.restart_mode == .graceful and agent.ice_restart != null;
        }

        fn clearRestart(agent: *Self) void {
            if (config.restart_mode == .hard) return;
            const ice_restart = agent.ice_restart orelse return;
            ice_restart.deinit();
            agent.allocator.destroy(ice_restart);
            agent.ice_restart = null;
            agent.consent_tx_id = null;
        }

        fn handleAppData(agent: *Self, sender: *const IpAddress, data: []const u8) ReadResult {
            switch (agent.connection_state) {
                .connected, .completed, .disconnected => return .{ .app_data = data },
                else => if (agent.findRemoteCandidate(sender) != null) {
                    return .{ .app_data = data };
                } else Logger.debug("Drop non stun message from unknown remote candidate: {f}", .{sender}),
            }

            return .consumed;
        }

        fn handleRequest(agent: *Self, msg: *const stun.Message, base_addr: *const IpAddress, from: *const IpAddress) !?Response {
            const local = agent.findLocalBase(base_addr) orelse return error.NoLocalCandidate;
            const tx_id = msg.header.transaction_id;

            const stun_req = Messages.parseAndValidateStunRequest(
                msg,
                agent.credentials.toIceCredentials(),
                agent.role,
                agent.tie_breaker,
            ) catch |err| {
                const kind: Response.Kind = switch (err) {
                    // The role comes from signaling and never flips: the peer must switch.
                    error.RoleConflict, error.SwitchRole => .role_conflict,
                    error.BadRequest, error.Unauthorized => Response.authErrorKind(err).?,
                    // Malformed request: drop it.
                    else => return null,
                };
                const remote = agent.findRemoteCandidate(from) orelse return null;
                return .{ .kind = kind, .tx_id = tx_id, .pair = .{ .local = local, .remote = remote } };
            };

            const remote = agent.findRemoteCandidate(from) orelse try agent.appendRemoteCandidate(.{
                .base = from.*,
                .address = from.*,
                .candidate_type = .prflx,
                .priority = stun_req.priority,
            });

            // No checks on our side: USE-CANDIDATE nominates the pair directly.
            if (stun_req.use_candidate and agent.nominated_pair == null) {
                agent.nominated_pair = .{ .local = local, .remote = remote };
            }

            return .{ .tx_id = tx_id, .pair = .{ .local = local, .remote = remote } };
        }

        fn handleStunMessage(agent: *Self, msg: *const stun.Message, to: *const IpAddress, from: *const IpAddress, now: i64) !ReadResult {
            if (msg.header.message_type.class() != .request) return .consumed;

            const was_nominated = agent.nominated_pair != null;
            if (try agent.handleRequest(msg, to, from)) |resp| agent.queueResponse(resp);

            if (!was_nominated) if (agent.nominated_pair) |nominated| {
                agent.clearRestart();
                try agent.events_out.pushBack(.{ .nominated = nominated });
                try agent.setConnectionState(.connected, now);
            };

            return .consumed;
        }

        fn queueResponse(agent: *Self, resp: Response) void {
            // Drop on overflow, the peer will retransmit.
            agent.responses.pushBack(resp) catch {};
        }

        fn maybeHandleOldGenerationMessage(agent: *Self, msg: *const stun.Message, to: *const IpAddress, from: *const IpAddress) !bool {
            const ice_restart = agent.ice_restart orelse return false;
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
            if (!to.eql(path.local) or !from.eql(path.remote)) return true;

            try Messages.validateConsentFreshnessRequest(msg, ice_restart.local_credentials.toIceCredentials());
            agent.queueResponse(.{ .tx_id = msg.header.transaction_id, .pair = null });
            return true;
        }

        fn maybeHandleConsentResponse(agent: *Self, msg: *const stun.Message, now: i64) !bool {
            const tx_id = agent.consent_tx_id orelse return false;
            if (msg.header.message_type.class() != .success_response) return false;
            if (!std.mem.eql(u8, &tx_id, &msg.header.transaction_id)) return false;

            _, const remote_credentials = agent.consentCredentials();
            _ = Messages.parseAndValidateStunResponse(msg, remote_credentials.getPassword()) catch return true;
            agent.consent_tx_id = null;

            switch (agent.connection_state) {
                .failed => return true,
                .disconnected => try agent.setConnectionState(.completed, now),
                else => {},
            }

            agent.disconnected_connection_deadline = now + agent.disconnected_timeout;
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
            if (msg.header.message_type.class() != .request) return null;

            const kind: Response.Kind = if (Messages.validateConsentFreshnessRequest(msg, agent.credentials.toIceCredentials()))
                .success
            else |err|
                Response.authErrorKind(err) orelse return null;

            return .{
                .kind = kind,
                .tx_id = msg.header.transaction_id,
                .pair = .{
                    .local = agent.findLocalBase(to) orelse return null,
                    .remote = agent.findRemoteCandidate(from) orelse return null,
                },
            };
        }

        fn findLocalBase(agent: *Self, base: *const IpAddress) ?CandidateIndex {
            for (agent.candidates[0..agent.candidates_len], 0..) |candidate, idx| if (candidate.base.eql(base)) return @intCast(idx);
            return null;
        }

        fn findRemoteCandidate(agent: *Self, addr: *const IpAddress) ?CandidateIndex {
            for (agent.remote_candidates[0..agent.remote_candidates_len], 0..) |candidate, idx| if (candidate.address.eql(addr)) return @intCast(idx);
            return null;
        }
    };
}

const testing = std.testing;
var rand = std.Random.DefaultPrng.init(0xDEADBEEF);

const TestAgent = Agent(.{});

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
        .username = "user:peer",
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

    try core.addLocalAddrs(&.{base_addr});

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = "user:peer",
    }, core.credentials.getPassword(), &buffer);

    _ = try core.handleRequest(&msg, &base_addr, &from);

    try testing.expectEqual(1, core.remote_candidates_len);
    const remote = core.remote_candidates[0];
    try testing.expect(remote.address.eql(&from));
    try testing.expectEqual(.prflx, remote.candidate_type);
    try testing.expectEqual(remote.priority, 0x9090);

    // Send request again
    _ = try core.handleRequest(&msg, &base_addr, &from);
    try testing.expectEqual(1, core.remote_candidates_len); // no new peer is created

    // A signaled candidate for an already known address updates its type and priority, no duplicate is added.
    try core.addRemoteCandidate(.initHost(from));
    try testing.expectEqual(1, core.remote_candidates_len);
    try testing.expectEqual(.host, core.remote_candidates[0].candidate_type);
    try testing.expectEqual(ice.CandidateType.host.priority(), core.remote_candidates[0].priority);
}

test "handleRequest: nominate peer" {
    var agent = try testNewAgent(.controlled);
    defer agent.deinit();

    var buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    try agent.addLocalAddrs(&.{base_addr});
    try agent.addRemoteCandidate(.initHost(from));

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = "user:peer",
        .use_candidate = true,
    }, agent.credentials.getPassword(), &buffer);

    _ = try agent.handleRequest(&msg, &base_addr, &from);
    try testing.expectEqual(NominatedPair{ .local = 0, .remote = 0 }, agent.nominated_pair.?);
}

test "handleRequest: role conflict" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);
    try core.addLocalAddrs(&.{base_addr});

    // Unknown sender: no response.
    const unknown = try testBuildRequest(.{ .ice_controlled = 0, .priority = 0x9090, .username = "user:peer" }, core.credentials.getPassword(), &buffer);
    try testing.expectEqual(null, try core.handleRequest(&unknown, &base_addr, &from));
    try core.addRemoteCandidate(.initHost(from));

    // Whichever side wins the tie-breaker, the role never flips.
    for ([_]u64{ std.math.maxInt(u64), 0 }) |peer_tie_breaker| {
        const msg = try testBuildRequest(.{
            .ice_controlled = peer_tie_breaker,
            .priority = 0x9090,
            .username = "user:peer",
        }, core.credentials.getPassword(), &buffer);

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
}

test "pollTransmit: keeps the message queued on WriteFailed" {
    var small: [stun.header_size - 1]u8 = undefined;
    var tx_buf: [1024]u8 = undefined;
    var req_buf: [1024]u8 = undefined;
    var agent = try testNewAgent(.controlled);
    defer agent.deinit();

    const local = try IpAddress.parse("192.168.1.100", 1000);
    const remote = try IpAddress.parse("192.168.1.120", 2000);

    try agent.addLocalAddrs(&.{local});
    try agent.addRemoteCandidate(.initHost(remote));
    try agent.setRemoteCredentials(.{ .username = "peer", .password = "peer-password-0123456789" }, 0);

    const req = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = "user:peer",
    }, agent.credentials.getPassword(), &req_buf);
    agent.queueResponse((try agent.handleRequest(&req, &local, &remote)) orelse return error.ExpectedResponse);

    // Response
    try testing.expectError(error.WriteFailed, agent.pollTransmit(&small));
    const resp = (try agent.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    const resp_msg = try stun.Message.parse(resp.data);
    try testing.expectEqual(.success_response, resp_msg.header.message_type.class());
    try testing.expectEqual(req.header.transaction_id, resp_msg.header.transaction_id);
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
