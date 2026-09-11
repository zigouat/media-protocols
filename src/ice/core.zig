const std = @import("std");
const stun = @import("stun");
const ice = @import("ice.zig");
const CandidatePair = @import("candidate_pair.zig");
const Messages = @import("messages.zig");

const Core = @This();
const Candidate = ice.Candidate;
const IpAddress = std.Io.net.IpAddress;
const Logger = std.log.scoped(.ice);

const SelectedPair = struct {
    pair: CandidatePair,
    pair_index: usize,
    local: Candidate,
    remote: Candidate,
};

pub const Message = struct {
    from: *const IpAddress,
    to: *const IpAddress,
    data: []const u8,
    timestamp: i64 = 0,

    pub fn init(from: *const IpAddress, to: *const IpAddress, data: []const u8) Message {
        return .{ .from = from, .to = to, .data = data };
    }
};

pub const Event = union(enum) {
    connection_state: ice.ConnectionState,
    nominated: void,
    message: Message,
    data: []const u8,
    connectivity_check: void,
    consent_freshness: void,
};

/// The maximum number of binding requests sent on a pair before it is
/// considered failed.
pub const max_binding_requests: usize = 7;
pub const connectivity_check_interval: i64 = 200;
pub const keep_alive_interval: i64 = 4_000;

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
selected_pair: ?SelectedPair = null,
// This the final pair selected by this agent or the remote one.
nominated_pair: ?SelectedPair = null,

connectivity_check_deadline: i64,
disconnected_connection_deadline: i64,
failed_connection_deadline: i64,
keep_alive_deadline: i64,
failed_timeout: u32,
disconnected_timeout: u32,
events_out: std.Deque(Event),

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
    pair: usize,
};

pub const ConnectivityChecks = struct {
    core: *Core,
    nomination_done: bool = false,
    index: usize = 0,

    pub fn next(self: *ConnectivityChecks, buffer: []u8, tx_id: u96) !?Send {
        const core = self.core;

        if (!self.nomination_done) {
            self.nomination_done = true;
            if (core.selected_pair) |*selected| {
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
                    .pair = selected.pair_index,
                };
            }
        }

        while (self.index < core.pairs.items.len) {
            const idx = self.index;
            const pair = &core.pairs.items[idx];
            self.index += 1;
            switch (pair.status) {
                .waiting, .in_progress => {
                    pair.conn_check_count += 1;
                    if (pair.conn_check_count > max_binding_requests) {
                        pair.status = .failed;
                        continue;
                    }
                    const payload = try core.buildBindingRequest(tx_id, false, buffer);
                    const local = core.getPairLocal(pair);
                    const remote = core.getPairRemote(pair);

                    try core.pending_requests.append(core.allocator, .{
                        .transaction_id = tx_id,
                        .source = local.base,
                        .target = remote.address,
                    });
                    return .{
                        .payload = payload,
                        .from_base = local.base,
                        .to = remote.address,
                        .use_candidate = false,
                        .pair = idx,
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
    tie_breaker: u64,
    failed_timeout: u32 = 25000,
    disconnected_timeout: u32 = 5000,
};

pub fn init(allocator: std.mem.Allocator, config: Config) Core {
    return .{
        .allocator = allocator,
        .role = config.role,
        .credentials = config.credentials,
        .tie_breaker = config.tie_breaker,
        .connectivity_check_deadline = 0,
        .keep_alive_deadline = 0,
        .failed_connection_deadline = 0,
        .disconnected_connection_deadline = 0,
        .failed_timeout = config.failed_timeout,
        .disconnected_timeout = config.disconnected_timeout,
        .events_out = .empty,
    };
}

pub fn deinit(core: *Core) void {
    core.close();
    core.pairs.deinit(core.allocator);
    core.pending_requests.deinit(core.allocator);
    core.candidates.deinit(core.allocator);
    core.remote_candidates.deinit(core.allocator);
    core.events_out.deinit(core.allocator);
}

pub fn close(core: *Core) void {
    core.connection_state = .closed;

    core.pairs.clearAndFree(core.allocator);
    core.pending_requests.clearAndFree(core.allocator);
    core.candidates.clearAndFree(core.allocator);
    core.remote_candidates.clearAndFree(core.allocator);

    core.credentials.deinit(core.allocator);
    if (core.remote_credentials) |*remote| {
        remote.deinit(core.allocator);
        core.remote_credentials = null;
    }
}

pub fn setRemoteCredentials(core: *Core, credentials: ice.Credentials) !void {
    if (core.remote_credentials) |*remote| remote.deinit(core.allocator);
    core.remote_credentials = try credentials.dupe(core.allocator);
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

pub fn handleConsentFreshness(core: *Core, from: *const IpAddress, message: []const u8, buffer: []u8) !?[]const u8 {
    const msg = try stun.Message.parse(message);
    switch (msg.header.message_type.class()) {
        .request => {
            _ = try Messages.parseAndValidateStunRequest(
                &msg,
                core.credentials,
                core.role,
                core.tie_breaker,
            );
            return try Messages.buildSuccessResponse(&msg, core.credentials.password, from, buffer);
        },
        else => {},
    }

    return null;
}

pub fn addRemoteCandidate(core: *Core, remote_candidate: Candidate) std.mem.Allocator.Error!void {
    try core.remote_candidates.append(core.allocator, remote_candidate);
    const remote_idx = core.remote_candidates.items.len - 1;

    outer_loop: for (core.candidates.items, 0..) |candidate, local_idx| {
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
pub fn addLocalCandidate(core: *Core, candidate: Candidate) std.mem.Allocator.Error!bool {
    for (core.candidates.items) |*existing| if (existing.eql(&candidate)) return false;

    try core.candidates.append(core.allocator, candidate);
    const idx = core.candidates.items.len - 1;

    outer_loop: for (core.remote_candidates.items, 0..) |remote_candidate, remote_idx| {
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

    return true;
}

/// Begin a connectivity-check round. Returns null when a pair is already
/// nominated (nothing to do). Performs the controlling-side best-pair selection.
pub fn beginConnectivityChecks(core: *Core) ?ConnectivityChecks {
    if (core.nominated_pair != null) return null;
    if (core.role == .controlling and core.selected_pair == null)
        core.selected_pair = core.selectBestPair();
    return .{ .core = core };
}

pub fn handleTimeout(core: *Core, now: i64) std.mem.Allocator.Error!i64 {
    const ck_deadline = try core.nextConnectivityCheckInterval(now);
    const ka_deadline = try core.nextKeepAliveInterval(now);
    const ct_deadline = try core.nextConnectionTimeout(now);
    return @min(@min(ck_deadline, ka_deadline), ct_deadline);
}

pub fn handleInput(core: *Core, message: Message, buffer: []u8) !void {
    if (!stun.isMessage(message.data)) {
        try core.handleAppData(message.from, message.data);
        return;
    }

    switch (core.connection_state) {
        .completed, .failed, .closed => return,
        else => {},
    }

    const msg = try stun.Message.parse(message.data);

    switch (msg.header.message_type.class()) {
        .request => {
            const resp = try core.handleRequest(&msg, message.to, message.from, buffer);
            if (core.detectNominatedPair() != null) try core.events_out.pushBack(core.allocator, .nominated);
            try core.events_out.pushBack(core.allocator, .{ .message = .init(message.to, message.from, resp) });
        },
        .success_response => {
            try core.handleSuccessResponse(&msg, message.to.*, message.from.*);
            if (core.detectNominatedPair() != null) try core.events_out.pushBack(core.allocator, .nominated);
        },
        else => {},
    }

    if (core.markConnected(message.timestamp)) try core.events_out.pushBack(core.allocator, .{ .connection_state = core.connection_state });
}

pub fn pollEvent(core: *Core) ?Event {
    return core.events_out.popFront();
}

pub fn detectNominatedPair(core: *Core) ?CandidatePair {
    if (core.role == .controlling or core.nominated_pair != null) return null;
    for (core.pairs.items, 0..) |pair, idx| if (pair.nominated) {
        core.nominated_pair = .{
            .pair = pair,
            .pair_index = idx,
            .local = core.getPairLocal(&pair).*,
            .remote = core.getPairRemote(&pair).*,
        };
        return pair;
    };
    return null;
}

pub fn markConnected(core: *Core, now: i64) bool {
    if (core.nominated_pair != null and core.connection_state != .connected) {
        core.connection_state = .connected;
        core.keep_alive_deadline = now + keep_alive_interval;
        core.disconnected_connection_deadline = now + core.disconnected_timeout;
        return true;
    }
    return false;
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

pub fn toggleRole(core: *Core, tie_breaker: u64) void {
    switch (core.role) {
        .controlling => core.role = .controlled,
        .controlled => core.role = .controlling,
    }
    core.tie_breaker = tie_breaker;

    for (core.pairs.items) |*pair| {
        const local = core.getPairLocal(pair);
        const remote = core.getPairRemote(pair);
        pair.priority = calculatePairPriority(local.priority, remote.priority, core.role);
    }
}

fn onComplete(core: *Core) void {
    core.connection_state = .completed;
    core.remote_candidates.clearAndFree(core.allocator);
    core.pairs.clearAndFree(core.allocator);
    core.pending_requests.clearAndFree(core.allocator);
}

fn nextConnectivityCheckInterval(core: *Core, now: i64) !i64 {
    switch (core.connection_state) {
        .new => {
            core.connection_state = .checking;
            core.connectivity_check_deadline = now + connectivity_check_interval;
            core.failed_connection_deadline = now + @as(i64, core.failed_timeout);
            try core.events_out.pushBack(core.allocator, .connectivity_check);
            return core.connectivity_check_deadline;
        },
        .checking, .connected => {
            if (now >= core.connectivity_check_deadline) {
                core.connectivity_check_deadline = now + connectivity_check_interval;
                try core.events_out.pushBack(core.allocator, .connectivity_check);
                return core.connectivity_check_deadline;
            }

            return core.connectivity_check_deadline;
        },
        else => return std.math.maxInt(i64),
    }
}

fn nextKeepAliveInterval(core: *Core, now: i64) !i64 {
    switch (core.connection_state) {
        .connected => {
            if (now >= core.keep_alive_deadline) {
                core.onComplete();
                core.keep_alive_deadline = now + keep_alive_interval;
                try core.events_out.pushBack(core.allocator, .{ .connection_state = core.connection_state });
                try core.events_out.pushBack(core.allocator, .consent_freshness);
            }

            return core.keep_alive_deadline;
        },
        .completed, .disconnected => {
            if (now >= core.keep_alive_deadline) {
                core.keep_alive_deadline = now + keep_alive_interval;
                try core.events_out.pushBack(core.allocator, .consent_freshness);
            }

            return core.keep_alive_deadline;
        },
        else => return std.math.maxInt(i64),
    }
}

fn nextConnectionTimeout(core: *Core, now: i64) !i64 {
    switch (core.connection_state) {
        .checking => {
            if (now >= core.failed_connection_deadline) {
                core.connection_state = .failed;
                try core.events_out.pushBack(core.allocator, .{ .connection_state = core.connection_state });
                return std.math.maxInt(i64);
            }

            return core.failed_connection_deadline;
        },
        .connected, .completed => {
            if (now >= core.disconnected_connection_deadline) {
                core.connection_state = .disconnected;
                core.failed_connection_deadline = now + @as(i64, core.failed_timeout);
                try core.events_out.pushBack(core.allocator, .{ .connection_state = core.connection_state });
                return core.failed_connection_deadline;
            }

            return core.disconnected_connection_deadline;
        },
        .disconnected => {
            if (now >= core.failed_connection_deadline) {
                core.connection_state = .failed;
                try core.events_out.pushBack(core.allocator, .{ .connection_state = core.connection_state });
                return std.math.maxInt(i64);
            }

            return core.failed_connection_deadline;
        },
        else => return std.math.maxInt(i64),
    }
}

fn handleAppData(core: *Core, sender: *const IpAddress, data: []const u8) !void {
    switch (core.connection_state) {
        .connected, .completed => try core.events_out.pushBack(core.allocator, .{ .data = data }),
        else => {
            for (core.pairs.items) |*candidate_pair| {
                const remote = &core.remote_candidates.items[candidate_pair.remote];
                if (remote.address.eql(sender)) try core.events_out.pushBack(core.allocator, .{ .data = data });
            } else {
                Logger.warn("Drop non stun message from unknown remote candidate: {f}", .{sender});
            }
        },
    }
}

fn handleRequest(core: *Core, msg: *const stun.Message, base_addr: *const IpAddress, from: *const IpAddress, buffer: []u8) ![]const u8 {
    const stun_req = Messages.parseAndValidateStunRequest(msg, core.credentials, core.role, core.tie_breaker) catch |err| switch (err) {
        error.RoleConflict => return try Messages.buildRoleConflictErrorMessage(msg.header.transaction_id, core.credentials.password, buffer),
        else => |e| return e,
    };

    if (core.findCandidatePair(base_addr, from)) |candidate_pair| {
        switch (candidate_pair.status) {
            .succeeded => candidate_pair.nominated |= stun_req.use_candidate,
            else => candidate_pair.nominate_on_binding |= stun_req.use_candidate,
        }
    } else {
        const local_idx = core.findLocalCandidate(base_addr, base_addr) orelse return error.NoLocalCandidate;
        const local_candidate = core.candidates.items[local_idx];

        const remote_idx: u32 = core.findRemoteCandidate(from) orelse blk: {
            const candidate = Candidate{
                .base = from.*,
                .address = from.*,
                .candidate_type = .prflx,
                .priority = stun_req.priority,
            };
            try core.remote_candidates.append(core.allocator, candidate);
            break :blk @intCast(core.remote_candidates.items.len - 1);
        };

        try core.pairs.append(core.allocator, .{
            .local = local_idx,
            .remote = remote_idx,
            .priority = calculatePairPriority(local_candidate.priority, stun_req.priority, core.role),
            .status = .in_progress,
            .nominate_on_binding = stun_req.use_candidate,
        });
    }

    return try Messages.buildSuccessResponse(msg, core.credentials.password, from, buffer);
}

fn handleSuccessResponse(core: *Core, msg: *const stun.Message, base_addr: IpAddress, from: IpAddress) !void {
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
        const mapped_address = try Messages.parseAndValidateStunResponse(msg, core.remote_credentials.?.password);

        if (mapped_address.eql(&base_addr)) {
            candidate_pair.status = .succeeded;
            core.maybeSetNominatedField(candidate_pair);
            return;
        }
        candidate_pair.status = .failed;

        const local_idx: u32 = core.findLocalCandidate(&base_addr, &mapped_address) orelse blk: {
            const prflx_candidate: Candidate = .initPeerReflexive(base_addr, mapped_address);
            try core.candidates.append(core.allocator, prflx_candidate);
            break :blk @intCast(core.candidates.items.len - 1);
        };
        const local_candidate = core.candidates.items[local_idx];
        const remote_candidate = core.getPairRemote(candidate_pair);

        if (core.findCandidatePairByLocalAndRemote(&local_candidate, &from)) |existing_candidate_pair| {
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

fn pairsEql(core: *Core, pair1: *const CandidatePair, pair2: *const CandidatePair) bool {
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

fn selectBestPair(core: *Core) ?SelectedPair {
    var selected_pair: ?CandidatePair = null;
    var selected_index: usize = undefined;
    for (core.pairs.items, 0..) |candidate_pair, idx| if (candidate_pair.status == .succeeded) {
        if (selected_pair == null or candidate_pair.priority > selected_pair.?.priority) {
            selected_pair = candidate_pair;
            selected_index = idx;
        }
    };

    return if (selected_pair) |pair| .{
        .pair = pair,
        .pair_index = selected_index,
        .local = core.getPairLocal(&pair).*,
        .remote = core.getPairRemote(&pair).*,
    } else null;
}

fn findCandidatePair(core: *Core, local: *const IpAddress, remote: *const IpAddress) ?*CandidatePair {
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

fn maybeSetNominatedField(core: *Core, candidate_pair: *CandidatePair) void {
    if (candidate_pair.nominate_on_binding) {
        candidate_pair.nominate_on_binding = false;
        candidate_pair.nominated = true;
    } else if (core.selected_pair != null and core.pairsEql(&core.selected_pair.?.pair, candidate_pair)) {
        core.nominated_pair = core.selected_pair;
        core.nominated_pair.?.pair.nominated = true;
        core.selected_pair = null;
    }
}

fn findLocalCandidate(core: *Core, base: *const IpAddress, addr: *const IpAddress) ?u32 {
    for (core.candidates.items, 0..) |candidate, idx| {
        if (candidate.base.eql(base) and candidate.address.eql(addr)) return @intCast(idx);
    }
    return null;
}

fn findRemoteCandidate(core: *Core, addr: *const IpAddress) ?u32 {
    for (core.remote_candidates.items, 0..) |candidate, idx| if (candidate.address.eql(addr)) return @intCast(idx);
    return null;
}

fn findCandidatePairByLocalAndRemote(core: *Core, local: *const Candidate, remote: *const IpAddress) ?*CandidatePair {
    for (core.pairs.items) |*candidate| {
        if (core.getPairLocal(candidate).eql(local) and core.getPairRemote(candidate).address.eql(remote))
            return candidate;
    }
    return null;
}

fn getPairLocal(core: *Core, pair: *const CandidatePair) *const Candidate {
    return &core.candidates.items[pair.local];
}

fn getPairRemote(core: *Core, pair: *const CandidatePair) *const Candidate {
    return &core.remote_candidates.items[pair.remote];
}

const testing = std.testing;

fn testNewCore(role: ice.Role) !Core {
    const credentials = try (ice.Credentials{
        .username = "user",
        .password = "VOkJxbRl1RmTxUk/WvJxBt",
    }).dupe(testing.allocator);
    return Core.init(testing.allocator, .{ .role = role, .credentials = credentials, .tie_breaker = 0x1000000 });
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

fn expectEvent(core: *Core, tag: std.meta.Tag(Event)) !void {
    const event = core.pollEvent() orelse return error.ExpectedEvent;
    if (std.meta.activeTag(event) != tag) return error.UnexpectedEvent;
}

fn expectConnectionStateEvent(core: *Core, state: ice.ConnectionState) !void {
    switch (core.pollEvent() orelse return error.ExpectedEvent) {
        .connection_state => |s| try testing.expectEqual(state, s),
        else => return error.UnexpectedEvent,
    }
}

test "handleRequest: generate success response" {
    var core = try testNewCore(.controlled);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    _ = try core.addHostCandidate(base_addr);

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = core.credentials.username,
    }, core.credentials.password, &buffer);

    const resp = try core.handleRequest(&msg, &base_addr, &from, &resp_buffer);
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

    _ = try core.addHostCandidate(base_addr);

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = core.credentials.username,
    }, core.credentials.password, &buffer);

    _ = try core.handleRequest(&msg, &base_addr, &from, &resp_buffer);

    try testing.expectEqual(1, core.pairs.items.len);

    const candidate_pair = core.pairs.items[0];
    const remote = core.remote_candidates.items[candidate_pair.remote];
    try testing.expect(remote.address.eql(&from));
    try testing.expectEqual(remote.priority, 0x9090);

    // Send request again
    _ = try core.handleRequest(&msg, &base_addr, &from, &resp_buffer);
    try testing.expectEqual(1, core.pairs.items.len); // no new peer is created
}

test "handleRequest: nominate peer" {
    var core = try testNewCore(.controlled);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    try core.candidates.append(testing.allocator, .initHost(base_addr));
    try core.remote_candidates.append(testing.allocator, .initHost(from));
    try core.pairs.append(testing.allocator, .{
        .local = 0,
        .remote = 0,
        .status = .in_progress,
        .priority = 0,
    });

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = core.credentials.username,
        .use_candidate = true,
    }, core.credentials.password, &buffer);

    _ = try core.handleRequest(&msg, &base_addr, &from, &resp_buffer);

    const candidate_pair = &core.pairs.items[0];
    try testing.expect(candidate_pair.nominate_on_binding);
    try testing.expect(!candidate_pair.nominated);

    candidate_pair.status = .succeeded;
    _ = try core.handleRequest(&msg, &base_addr, &from, &resp_buffer);
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

        const resp = try core.handleRequest(&msg, &base_addr, &from, &resp_buffer);
        const resp_msg = try stun.Message.parse(resp);

        try testing.expectEqual(.error_response, resp_msg.header.message_type.class());
        try testing.expectEqual(.binding, resp_msg.header.message_type.method());
        try testing.expectEqual(msg.header.transaction_id, resp_msg.header.transaction_id);

        var it = resp_msg.iterateAttributes(core.credentials.password);
        const attr = (try it.next()).?;
        try testing.expectEqual(.error_code, @as(stun.AttributeType, attr));
        try testing.expectEqual(.role_conflict, attr.error_code.code);
        try testing.expectEqualStrings("Role conflict", attr.error_code.reason);
    }

    {
        const msg = try testBuildRequest(.{
            .ice_controlled = 0,
            .priority = 0x9090,
            .username = core.credentials.username,
        }, core.credentials.password, &buffer);

        try testing.expectError(error.SwitchRole, core.handleRequest(&msg, &base_addr, &from, &resp_buffer));
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
    for (core.pairs.items) |pair| try testing.expect(core.candidates.items[pair.local].base.eql(&local));

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
    for (core.pairs.items) |pair| try testing.expect(core.remote_candidates.items[pair.remote].address.eql(&remote));

    try core.addRemoteCandidate(Candidate.initHost(remote));
    try testing.expectEqual(2, core.pairs.items.len);
}

test "addRemoteCandidate: skips pairing across differing address families" {
    var core = try testNewCore(.controlling);
    defer core.deinit();

    _ = try core.addHostCandidate(try IpAddress.parse("10.0.0.1", 2000));

    try core.addRemoteCandidate(Candidate.initHost(try IpAddress.parse("2001:db8::10", 1000)));
    try testing.expectEqual(0, core.pairs.items.len);

    try core.addRemoteCandidate(Candidate.initHost(try IpAddress.parse("192.168.1.10", 1001)));
    try testing.expectEqual(1, core.pairs.items.len);
}

test "addLocalCandidate: skips pairing across differing address families" {
    var core = try testNewCore(.controlling);
    defer core.deinit();

    try core.addRemoteCandidate(Candidate.initHost(try IpAddress.parse("192.168.1.10", 1000)));

    _ = try core.addHostCandidate(try IpAddress.parse("2001:db8::1", 2000));
    try testing.expectEqual(0, core.pairs.items.len);

    _ = try core.addHostCandidate(try IpAddress.parse("10.0.0.1", 2001));
    try testing.expectEqual(1, core.pairs.items.len);
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

test "toggleRole: flips role, tie breaker and pair priorities" {
    var core = try testNewCore(.controlling);
    defer core.deinit();

    const local_addr = try IpAddress.parse("10.0.0.1", 2000);
    const remote_addr = try IpAddress.parse("192.168.1.10", 1000);

    _ = try core.addHostCandidate(local_addr);
    try core.addRemoteCandidate(Candidate.initServerReflexive(remote_addr, remote_addr));

    try testing.expectEqual(1, core.pairs.items.len);
    const controlling_priority = core.pairs.items[0].priority;

    core.toggleRole(0xDEADBEEF);

    try testing.expectEqual(.controlled, core.role);
    try testing.expectEqual(0xDEADBEEF, core.tie_breaker);
    try testing.expect(core.pairs.items[0].priority != controlling_priority);

    core.toggleRole(0x1000000);

    try testing.expectEqual(.controlling, core.role);
    try testing.expectEqual(0x1000000, core.tie_breaker);
    try testing.expectEqual(controlling_priority, core.pairs.items[0].priority);
}

test "handleInput: drops non-stun data from an unknown remote before connected" {
    var core = try testNewCore(.controlled);
    defer core.deinit();

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);
    var resp_buffer: [64]u8 = undefined;

    try core.handleInput(.init(&from, &base_addr, "hello"), &resp_buffer);

    try testing.expectEqual(null, core.pollEvent());
}

test "handleInput: forwards non-stun data from a known remote candidate pair" {
    var core = try testNewCore(.controlled);
    defer core.deinit();

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);
    var resp_buffer: [64]u8 = undefined;

    try core.candidates.append(testing.allocator, .initHost(base_addr));
    try core.remote_candidates.append(testing.allocator, .initHost(from));
    try core.pairs.append(testing.allocator, .{ .local = 0, .remote = 0, .status = .in_progress, .priority = 0 });

    try core.handleInput(.init(&from, &base_addr, "hello"), &resp_buffer);

    const event = core.pollEvent() orelse return error.ExpectedEvent;
    switch (event) {
        .data => |data| try testing.expectEqualStrings("hello", data),
        else => return error.UnexpectedEvent,
    }
    try testing.expectEqual(null, core.pollEvent());
}

test "handleInput: forwards non-stun data once connected regardless of sender" {
    var core = try testNewCore(.controlled);
    defer core.deinit();
    core.connection_state = .connected;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("10.0.0.5", 4000);
    var resp_buffer: [64]u8 = undefined;

    try core.handleInput(.init(&from, &base_addr, "world"), &resp_buffer);

    const event = core.pollEvent() orelse return error.ExpectedEvent;
    switch (event) {
        .data => |data| try testing.expectEqualStrings("world", data),
        else => return error.UnexpectedEvent,
    }
}

test "handleInput: ignores stun messages once the connection is completed" {
    var core = try testNewCore(.controlled);
    defer core.deinit();
    core.connection_state = .completed;

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = core.credentials.username,
    }, core.credentials.password, &buffer);

    try core.handleInput(.init(&from, &base_addr, msg.bytes), &resp_buffer);

    try testing.expectEqual(null, core.pollEvent());
}

test "handleInput: stun request produces a response event" {
    var core = try testNewCore(.controlled);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);
    _ = try core.addHostCandidate(base_addr);

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = core.credentials.username,
    }, core.credentials.password, &buffer);

    try core.handleInput(.init(&from, &base_addr, msg.bytes), &resp_buffer);

    const event = core.pollEvent() orelse return error.ExpectedEvent;
    switch (event) {
        .message => |resp| {
            const resp_msg = try stun.Message.parse(resp.data);
            try testing.expectEqual(.success_response, resp_msg.header.message_type.class());
        },
        else => return error.UnexpectedEvent,
    }
    try testing.expectEqual(null, core.pollEvent());
    try testing.expectEqual(1, core.pairs.items.len);
}

test "handleInput: role conflict switches role and reports no event" {
    var core = try testNewCore(.controlled);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    const msg = try testBuildRequest(.{
        .ice_controlled = 0,
        .priority = 0x9090,
        .username = core.credentials.username,
    }, core.credentials.password, &buffer);

    try testing.expectError(error.SwitchRole, core.handleInput(.init(&from, &base_addr, msg.bytes), &resp_buffer));
    try testing.expectEqual(null, core.pollEvent());
}

test "handleInput: success response completes the pending request and marks the pair succeeded" {
    var core = try testNewCore(.controlling);
    defer core.deinit();

    core.remote_credentials = try (ice.Credentials{
        .username = "ruser",
        .password = "peer-password-0123456789",
    }).dupe(testing.allocator);

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    try core.candidates.append(testing.allocator, .initHost(base_addr));
    try core.remote_candidates.append(testing.allocator, .initHost(from));
    try core.pairs.append(testing.allocator, .{ .local = 0, .remote = 0, .status = .in_progress, .priority = 0 });
    try core.pending_requests.append(testing.allocator, .{
        .transaction_id = 0x2,
        .source = base_addr,
        .target = from,
    });

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [64]u8 = undefined;
    const msg = try testBuildResponse(0x2, base_addr, core.remote_credentials.?.password, &buffer);

    try core.handleInput(.init(&from, &base_addr, msg.bytes), &resp_buffer);

    try testing.expectEqual(null, core.pollEvent());

    try testing.expectEqual(.succeeded, core.pairs.items[0].status);
    try testing.expectEqual(0, core.pending_requests.items.len);
}

test "handleInput: success response nominates the pair and transitions to connected" {
    var core = try testNewCore(.controlled);
    defer core.deinit();

    core.remote_credentials = try (ice.Credentials{
        .username = "ruser",
        .password = "peer-password-0123456789",
    }).dupe(testing.allocator);

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    try core.candidates.append(testing.allocator, .initHost(base_addr));
    try core.remote_candidates.append(testing.allocator, .initHost(from));
    try core.pairs.append(testing.allocator, .{
        .local = 0,
        .remote = 0,
        .status = .in_progress,
        .priority = 0,
        .nominate_on_binding = true,
    });
    try core.pending_requests.append(testing.allocator, .{
        .transaction_id = 0x2,
        .source = base_addr,
        .target = from,
    });

    var buffer: [1024]u8 = undefined;
    var resp_buffer: [64]u8 = undefined;
    const msg = try testBuildResponse(0x2, base_addr, core.remote_credentials.?.password, &buffer);

    try core.handleInput(.init(&from, &base_addr, msg.bytes), &resp_buffer);

    try expectEvent(&core, .nominated);
    try expectConnectionStateEvent(&core, .connected);
    try testing.expectEqual(null, core.pollEvent());

    try testing.expectEqual(.connected, core.connection_state);
    try testing.expect(core.pairs.items[0].nominated);
    try testing.expect(core.nominated_pair != null);

    try testing.expectEqual(@as(i64, keep_alive_interval), core.keep_alive_deadline);
    try testing.expectEqual(@as(i64, core.disconnected_timeout), core.disconnected_connection_deadline);
}

test "handleTimeout: new connection starts checking and schedules a connectivity check" {
    var core = try testNewCore(.controlled);
    defer core.deinit();

    const failed_timeout: i64 = core.failed_timeout;
    const deadline = try core.handleTimeout(0);

    try testing.expectEqual(.checking, core.connection_state);
    try testing.expectEqual(connectivity_check_interval, deadline);
    try testing.expectEqual(connectivity_check_interval, core.connectivity_check_deadline);
    try testing.expectEqual(failed_timeout, core.failed_connection_deadline);

    try expectEvent(&core, .connectivity_check);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleTimeout: checking sends a connectivity_check every interval" {
    var core = try testNewCore(.controlled);
    defer core.deinit();

    _ = try core.handleTimeout(0);
    _ = core.pollEvent();

    const deadline1 = try core.handleTimeout(100);
    try testing.expectEqual(connectivity_check_interval, deadline1);
    try testing.expectEqual(null, core.pollEvent());

    const deadline2 = try core.handleTimeout(connectivity_check_interval);
    try testing.expectEqual(connectivity_check_interval * 2, deadline2);
    try expectEvent(&core, .connectivity_check);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleTimeout: checking fails after failed_timeout without connecting" {
    var core = try testNewCore(.controlled);
    defer core.deinit();

    _ = try core.handleTimeout(0);
    _ = core.pollEvent();

    const failed_timeout: i64 = core.failed_timeout;
    const deadline = try core.handleTimeout(failed_timeout);

    try testing.expectEqual(.failed, core.connection_state);
    try testing.expectEqual(failed_timeout + connectivity_check_interval, deadline);

    try expectEvent(&core, .connectivity_check);
    try expectConnectionStateEvent(&core, .failed);
    try testing.expectEqual(null, core.pollEvent());

    const next = try core.handleTimeout(failed_timeout + 1000);
    try testing.expectEqual(std.math.maxInt(i64), next);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleTimeout: connected transitions to completed once keep_alive_deadline elapses and clears the checklist" {
    var core = try testNewCore(.controlling);
    defer core.deinit();

    core.connection_state = .connected;
    core.connectivity_check_deadline = 100_000;
    core.disconnected_connection_deadline = 100_000;
    core.keep_alive_deadline = 1000;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);
    try core.remote_candidates.append(testing.allocator, .initHost(from));
    try core.pairs.append(testing.allocator, .{ .local = 0, .remote = 0, .status = .succeeded, .priority = 0 });
    try core.pending_requests.append(testing.allocator, .{ .transaction_id = 0x1, .source = base_addr, .target = from });

    const deadline = try core.handleTimeout(1000);

    try testing.expectEqual(.completed, core.connection_state);
    try testing.expectEqual(0, core.remote_candidates.items.len);
    try testing.expectEqual(0, core.pairs.items.len);
    try testing.expectEqual(0, core.pending_requests.items.len);
    try testing.expectEqual(1000 + keep_alive_interval, core.keep_alive_deadline);
    try testing.expectEqual(1000 + keep_alive_interval, deadline);

    try expectConnectionStateEvent(&core, .completed);
    try expectEvent(&core, .consent_freshness);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleTimeout: completed sends periodic consent_freshness without changing state" {
    var core = try testNewCore(.controlling);
    defer core.deinit();

    core.connection_state = .completed;
    core.disconnected_connection_deadline = 100_000;
    core.keep_alive_deadline = 1000;

    const deadline = try core.handleTimeout(1000);

    try testing.expectEqual(.completed, core.connection_state);
    try testing.expectEqual(1000 + keep_alive_interval, core.keep_alive_deadline);
    try testing.expectEqual(1000 + keep_alive_interval, deadline);

    try expectEvent(&core, .consent_freshness);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleTimeout: disconnected sends periodic consent_freshness without changing state" {
    var core = try testNewCore(.controlling);
    defer core.deinit();

    core.connection_state = .disconnected;
    core.failed_connection_deadline = 100_000;
    core.keep_alive_deadline = 1000;

    const deadline = try core.handleTimeout(1000);

    try testing.expectEqual(.disconnected, core.connection_state);
    try testing.expectEqual(1000 + keep_alive_interval, core.keep_alive_deadline);
    try testing.expectEqual(1000 + keep_alive_interval, deadline);

    try expectEvent(&core, .consent_freshness);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleTimeout: connected becomes disconnected after disconnected_timeout of silence and refreshes the failed deadline" {
    var core = try testNewCore(.controlling);
    defer core.deinit();

    core.connection_state = .connected;
    core.connectivity_check_deadline = 100_000;
    core.keep_alive_deadline = 100_000;
    core.disconnected_connection_deadline = 1000;

    const failed_timeout: i64 = core.failed_timeout;
    const deadline = try core.handleTimeout(1000);

    try testing.expectEqual(.disconnected, core.connection_state);
    try testing.expectEqual(1000 + failed_timeout, core.failed_connection_deadline);
    try testing.expectEqual(1000 + failed_timeout, deadline);

    try expectConnectionStateEvent(&core, .disconnected);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleTimeout: disconnected becomes failed after failed_timeout elapses" {
    var core = try testNewCore(.controlling);
    defer core.deinit();

    core.connection_state = .disconnected;
    core.keep_alive_deadline = 999_999;
    core.failed_connection_deadline = 1000;

    const deadline = try core.handleTimeout(1000);

    try testing.expectEqual(.failed, core.connection_state);
    try testing.expectEqual(999_999, deadline);

    try expectConnectionStateEvent(&core, .failed);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleTimeout: returns the earliest of the three schedules without firing anything" {
    var core = try testNewCore(.controlling);
    defer core.deinit();

    core.connection_state = .connected;
    core.connectivity_check_deadline = 5000;
    core.keep_alive_deadline = 3000;
    core.disconnected_connection_deadline = 8000;

    const deadline = try core.handleTimeout(1000);

    try testing.expectEqual(.connected, core.connection_state);
    try testing.expectEqual(3000, deadline);
    try testing.expectEqual(null, core.pollEvent());

    try testing.expectEqual(5000, core.connectivity_check_deadline);
    try testing.expectEqual(3000, core.keep_alive_deadline);
    try testing.expectEqual(8000, core.disconnected_connection_deadline);
}

test "setRemoteCredentials: replaces and frees the previous value" {
    var core = try testNewCore(.controlled);
    defer core.deinit();

    try core.setRemoteCredentials(.{ .username = "first", .password = "first-password-0123456789" });
    try testing.expectEqualStrings("first", core.remote_credentials.?.username);

    try core.setRemoteCredentials(.{ .username = "second", .password = "second-password-0123456789" });
    try testing.expectEqualStrings("second", core.remote_credentials.?.username);
    try testing.expectEqualStrings("second-password-0123456789", core.remote_credentials.?.password);
}
