const std = @import("std");
const stun = @import("stun");
const ice = @import("ice.zig");
const IfIterator = @import("if_iterator.zig");

const Io = std.Io;
const Allocator = std.mem.Allocator;
const Socket = Io.net.Socket;
const IpAddress = Io.net.IpAddress;
const Candidate = ice.Candidate;
const CandidatePair = ice.CandidatePair;
const Agent = @This();
const Logger = std.log.scoped(.ice);

const max_message_size = 1500;
const max_binding_requests: usize = 7;
const connectivity_check_interval: std.Io.Duration = .fromMilliseconds(200);
const keep_alive_interval: std.Io.Duration = .fromSeconds(4);
const disconnect_timeout: Io.Clock.Duration = .{ .clock = .awake, .raw = .fromSeconds(5) };
const failing_timeout: Io.Clock.Duration = .{ .clock = .awake, .raw = .fromSeconds(25) };

io: Io,
allocator: Allocator,
buffer_pool: std.heap.MemoryPool([max_message_size]u8),
connection_state: ice.ConnectionState = .new,
gathering_state: ice.GatheringState = .new,

// callbacks
on_connection_state_change: *const fn (*Agent, ice.ConnectionState) void,
on_data: *const fn (*Agent, []const u8) void,
on_candidate: *const fn (*Agent, candidate: ?Candidate) void,

// Stun related fields
role: ice.Role,
credentials: ice.Credentials,
remote_credentials: ?ice.Credentials = null,
tie_breaker: u64,

// Candidates and sockets
sockets: []Io.net.Socket = &.{},
candidates: std.ArrayList(Candidate) = .empty,
remote_candidates: std.ArrayList(Candidate) = .empty,
pairs: std.ArrayList(CandidatePair) = .empty,
pending_requests: std.ArrayList(PendingRequest) = .empty,
// This is a peer for which a use-candidate request is sent, but we didn't
// receive response yet.
selected_pair: ?SelectedPair = null,
// This the final pair selected by this agent or the remote one.
nominated_pair: ?SelectedPair = null,

mutex: Io.Mutex = .init,

pub const AgentConfig = struct {
    on_connection_state_change: *const fn (*Agent, ice.ConnectionState) void,
    on_data: *const fn (*Agent, []const u8) void,
    on_candidate: *const fn (*Agent, candidate: ?Candidate) void,
    /// Local credentials of the agent (ufrag and password)
    ///
    /// Generated automatically if not provided
    credentials: ?ice.Credentials = null,
    role: ice.Role = .controlling,
};

const SelectedPair = struct {
    pair: CandidatePair,
    socket: Socket,

    fn keep_alive(self: *const SelectedPair, io: Io) !void {
        var buffer: [20]u8 = undefined;
        try self.socket.send(io, &self.pair.remote.address, try buildIndicationRequest(&buffer));
    }

    inline fn sendData(self: *const SelectedPair, io: Io, data: []const u8) Socket.SendError!void {
        try self.socket.send(io, &self.pair.remote.address, data);
    }
};

const StunRequest = struct {
    username: []const u8 = &.{},
    ice_controlled: ?u64 = null,
    ice_controlling: ?u64 = null,
    use_candidate: bool = false,
    priority: u32 = 0,
};

const PendingRequest = struct {
    transaction_id: u96,
    source: IpAddress,
    target: IpAddress,
};

pub fn init(io: Io, allocator: Allocator, config: AgentConfig) !Agent {
    const credens =
        try if (config.credentials) |credens|
            credens.dupe(allocator)
        else
            ice.Credentials.generate(io, allocator);

    return .{
        .io = io,
        .allocator = allocator,
        .buffer_pool = .empty,
        .role = config.role,
        .tie_breaker = randomNumber(u64, io),
        .credentials = credens,
        .on_connection_state_change = config.on_connection_state_change,
        .on_data = config.on_data,
        .on_candidate = config.on_candidate,
    };
}

pub fn deinit(agent: *Agent) void {
    const io = agent.io;
    const allocator = agent.allocator;

    for (agent.sockets) |socket| socket.close(io);
    allocator.free(agent.sockets);

    agent.candidates.deinit(allocator);
    agent.remote_candidates.deinit(allocator);
    agent.pairs.deinit(allocator);
    agent.pending_requests.deinit(allocator);
    agent.credentials.deinit(allocator);
    if (agent.remote_credentials) |*credens| credens.deinit(allocator);

    agent.buffer_pool.deinit(allocator);
}

/// Start the event loop that'll handle internal events.
///
/// This function should be run concurrently (e.g. in a `Io.Group`).
pub fn startEventLoop(agent: *Agent) !void {
    return agent.innerEventHandler() catch |err| switch (err) {
        error.Canceled => error.Canceled,
        else => |e| Logger.err("error in event loop: {}", .{e}),
    };
}

/// Set remote credentials
///
/// Calling this function will trigger connectivity checks. `gatherCandidates` should be called first.
pub fn setRemoteCredentials(agent: *Agent, credentials: ice.Credentials) !void {
    switch (agent.connection_state) {
        .new => {
            agent.remote_credentials = try credentials.dupe(agent.allocator);
            agent.setConnectionState(.checking);
        },
        else => return error.CredentialsAlreadySet,
    }
}

pub fn addRemoteCandidate(agent: *Agent, remote_candidate: Candidate) !void {
    switch (agent.connection_state) {
        .new, .checking, .connected => try agent.doAddRemoteCandidate(remote_candidate),
        else => {},
    }
}

/// Start gathering candidates.
///
/// This function should be called first before starting the event loop so local sockets are
/// available to listen on.
pub fn gatherCandidates(agent: *Agent) !void {
    agent.gathering_state = .gathering;
    try agent.gatherLocalHostsAndInitSockets();
    for (agent.candidates.items) |candidate| agent.on_candidate(agent, candidate);
    agent.gathering_state = .complete;
    agent.on_candidate(agent, null);
}

pub fn sendData(agent: *const Agent, data: []const u8) Socket.SendError!void {
    switch (agent.connection_state) {
        .connected, .completed => try agent.nominated_pair.?.sendData(agent.io, data),
        else => Logger.warn("Agent not connected: ignore send request", .{}),
    }
}

/// Free the buffer and return it to the pool.
pub fn destroyPacket(agent: *Agent, data: []const u8) void {
    agent.buffer_pool.destroy(@ptrCast(@alignCast(@constCast(data))));
}

fn gatherLocalHostsAndInitSockets(agent: *Agent) !void {
    const allocator = agent.allocator;

    var it: IfIterator = undefined;
    try it.init();
    defer it.deinit();

    var sockets: std.ArrayList(Io.net.Socket) = .empty;
    errdefer {
        for (sockets.items) |*socket| socket.close(agent.io);
        sockets.deinit(allocator);
    }

    while (it.next()) |addr| {
        var candidate: Candidate = .initHost(addr);
        const socket = candidate.address.bind(agent.io, .{ .mode = .dgram }) catch |err| {
            Logger.warn("Could not bind address {f}: {}", .{ addr, err });
            continue;
        };
        candidate.base = socket.address;
        candidate.address = socket.address;

        try sockets.append(allocator, socket);
        try agent.doAddLocalCandidate(candidate);
    }

    agent.sockets = try sockets.toOwnedSlice(allocator);
}

fn calculatePairPriority(l: u32, r: u32, role: ice.Role) u64 {
    var g = l;
    var d = r;
    if (role == .controlled) g, d = .{ d, g };

    const last_part: u8 = if (g > d) 1 else 0;
    return (@as(u64, 1) << 32) * @min(g, d) + 2 * @max(g, d) + last_part;
}

fn randomNumber(T: type, io: Io) T {
    var bytes: [@typeInfo(T).int.bits / 8]u8 = undefined;
    io.random(&bytes);
    return @bitCast(bytes);
}

fn gatherHostCandidates(agent: *Agent) !void {
    var it: IfIterator = undefined;
    try it.init();
    defer it.deinit();

    while (it.next()) |addr| try agent.doAddLocalCandidate(.initHost(addr));
}

fn doAddRemoteCandidate(agent: *Agent, remote_candidate: Candidate) Allocator.Error!void {
    {
        agent.mutex.lockUncancelable(agent.io);
        defer agent.mutex.unlock(agent.io);
        try agent.remote_candidates.append(agent.allocator, remote_candidate);
    }

    outer_loop: for (agent.candidates.items) |candidate| {
        for (agent.pairs.items) |*pair|
            if (pair.local.base.eql(&candidate.base) and pair.remote.address.eql(&remote_candidate.address))
                continue :outer_loop;

        try agent.appendCandidatePair(.{
            .local = candidate,
            .remote = remote_candidate,
            .priority = calculatePairPriority(candidate.priority, remote_candidate.priority, agent.role),
        });
    }
}

fn doAddLocalCandidate(agent: *Agent, local_candidate: Candidate) Allocator.Error!void {
    {
        agent.mutex.lockUncancelable(agent.io);
        defer agent.mutex.unlock(agent.io);
        try agent.candidates.append(agent.allocator, local_candidate);
    }

    outer_loop: for (agent.remote_candidates.items) |remote_candidate| {
        for (agent.pairs.items) |*pair|
            if (pair.local.base.eql(&local_candidate.base) and pair.remote.address.eql(&remote_candidate.address))
                continue :outer_loop;

        try agent.appendCandidatePair(.{
            .local = local_candidate,
            .remote = remote_candidate,
            .priority = calculatePairPriority(local_candidate.priority, remote_candidate.priority, agent.role),
        });
    }
}

fn handleRequest(agent: *Agent, msg: *const stun.Message, base_addr: IpAddress, from: IpAddress) ![]const u8 {
    Logger.debug("Handle request on {f} from {f}", .{ base_addr, from });
    const buffer = try agent.buffer_pool.create(agent.allocator);
    errdefer agent.buffer_pool.destroy(buffer);

    const stun_req = agent.parseAndValidateStunRequest(msg) catch |err| switch (err) {
        error.RoleConflict => return try agent.buildRoleConflictErrorMessage(msg.header.transaction_id, buffer),
        else => |e| return e,
    };

    if (agent.findCandidatePair(&base_addr, &from)) |candidate_pair| {
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

        try agent.appendCandidatePair(.{
            .local = local,
            .remote = remote,
            .priority = calculatePairPriority(local.priority, remote.priority, agent.role),
            .status = .in_progress,
            .nominate_on_binding = stun_req.use_candidate,
        });
    }

    return try agent.buildSuccessResponse(msg, from, buffer);
}

fn handleSuccessResponse(agent: *Agent, msg: *const stun.Message, base_addr: IpAddress, from: IpAddress) !void {
    Logger.debug("Handle success response on {f} from {f}", .{ base_addr, from });

    const pending_request = blk: {
        const tx_id = msg.header.transaction_id;
        for (agent.pending_requests.items, 0..) |pr, i| {
            if (pr.transaction_id == tx_id) {
                const pending_request = agent.pending_requests.swapRemove(i);
                break :blk pending_request;
            }
        }

        return;
    };

    if (!pending_request.source.eql(&base_addr) or !pending_request.target.eql(&from)) return;

    if (agent.findCandidatePair(&base_addr, &from)) |candidate_pair| {
        const mapped_address = try agent.parseAndValidateStunResponse(msg);

        if (mapped_address.eql(&base_addr)) {
            candidate_pair.status = .succeeded;
            agent.maybeSetNominatedField(candidate_pair);
            return;
        }
        candidate_pair.status = .failed;

        const local_candidate = agent.findLocalCandidate(&base_addr, &mapped_address) orelse blk: {
            const prflx_candidate: Candidate = .initPeerReflexive(base_addr, mapped_address);
            try agent.mutex.lock(agent.io);
            defer agent.mutex.unlock(agent.io);
            try agent.candidates.append(agent.allocator, prflx_candidate);
            break :blk prflx_candidate;
        };

        if (agent.findCandidatePairByLocalAndRemote(&local_candidate, &from)) |existing_candidate_pair| {
            existing_candidate_pair.status = .succeeded;
            agent.maybeSetNominatedField(existing_candidate_pair);
            return;
        }

        try agent.appendCandidatePair(.{
            .local = local_candidate,
            .remote = candidate_pair.remote,
            .priority = calculatePairPriority(local_candidate.priority, candidate_pair.remote.priority, agent.role),
            .status = .succeeded,
        });
    }
}

fn maybeSetNominatedField(agent: *Agent, candidate_pair: *CandidatePair) void {
    if (candidate_pair.nominate_on_binding) {
        candidate_pair.nominate_on_binding = false;
        candidate_pair.nominated = true;
    } else if (agent.selected_pair != null and agent.selected_pair.?.pair.eql(candidate_pair)) {
        agent.nominated_pair = agent.selected_pair;
        agent.nominated_pair.?.pair.nominated = true;
        agent.selected_pair = null;
    }
}

fn parseAndValidateStunRequest(agent: *Agent, msg: *const stun.Message) !StunRequest {
    var it = msg.iterateAttributes(agent.credentials.password);
    var has_fingerprint: bool = false;
    var has_message_integrity = false;
    var stun_request: StunRequest = .{};

    while (try it.next()) |attribute| switch (attribute) {
        .username => |u| stun_request.username = u,
        .ice_controlled => |v| stun_request.ice_controlled = v,
        .ice_controlling => |v| stun_request.ice_controlling = v,
        .use_candidate => stun_request.use_candidate = true,
        .priority => |p| stun_request.priority = p,
        .fingerprint => has_fingerprint = true,
        .message_integrity => has_message_integrity = true,
        else => {},
    };

    if (!has_fingerprint or !has_message_integrity)
        return error.InvalidStunMessage;
    if (stun_request.ice_controlling == null and stun_request.ice_controlled == null or
        stun_request.ice_controlling != null and stun_request.ice_controlled != null)
        return error.InvalidStunMessage;

    if (stun_request.ice_controlled != null and agent.role == .controlled) {
        if (agent.tie_breaker >= stun_request.ice_controlled.?)
            return error.SwitchRole
        else
            return error.RoleConflict;
    }

    if (stun_request.ice_controlling != null and agent.role == .controlling) {
        if (agent.tie_breaker >= stun_request.ice_controlling.?)
            return error.RoleConflict
        else
            return error.SwitchRole;
    }

    if (stun_request.use_candidate and agent.role == .controlling)
        return error.InvalidStunMessage;

    //TODO: check username

    return stun_request;
}

fn parseAndValidateStunResponse(agent: *Agent, msg: *const stun.Message) !IpAddress {
    var it = msg.iterateAttributes(agent.remote_credentials.?.password);
    var has_fingerprint: bool = false;
    var has_message_integrity = false;
    var maybe_addr: ?IpAddress = null;

    while (try it.next()) |attribute| switch (attribute) {
        .xor_mapped_address => |value| maybe_addr = value,
        .fingerprint => has_fingerprint = true,
        .message_integrity => has_message_integrity = true,
        else => {},
    };

    if (!has_fingerprint or !has_message_integrity) return error.InvalidStunMessage;
    return if (maybe_addr) |addr| addr else error.MissingMappedAddress;
}

fn buildBindingRequest(agent: *Agent, tx_id: u96, use_candidate: bool, buffer: *[max_message_size]u8) ![]const u8 {
    var w = stun.Writer.init(&(buffer.*), .{ .password = agent.remote_credentials.?.password });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.request, .binding),
        .transaction_id = tx_id,
        .message_length = 0,
    });

    var username = [_][]const u8{ agent.remote_credentials.?.username, ":", agent.credentials.username };
    try w.writeRaw(.username, &username);
    try w.writeAttribute(.{ .priority = ice.CandidateType.prflx.priority() });
    const role_attribute: stun.Attribute = switch (agent.role) {
        .controlled => .{ .ice_controlled = agent.tie_breaker },
        .controlling => .{ .ice_controlling = agent.tie_breaker },
    };
    if (use_candidate) try w.writeAttribute(.use_candidate);
    try w.writeAttribute(role_attribute);
    try w.writeAttribute(.{ .message_integrity = &.{} });
    try w.writeAttribute(.fingerprint);

    return w.final();
}

// Used for keep alive
fn buildIndicationRequest(buffer: []u8) ![]const u8 {
    var w = stun.Writer.init(buffer, .{});
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.indication, .binding),
        .message_length = 0,
        .transaction_id = 0x1010101010,
    });

    return w.final();
}

fn buildSuccessResponse(
    agent: *const Agent,
    msg: *const stun.Message,
    from: IpAddress,
    buffer: *[max_message_size]u8,
) ![]const u8 {
    var w = stun.Writer.init(&(buffer.*), .{ .password = agent.credentials.password });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.success_response, .binding),
        .transaction_id = msg.header.transaction_id,
        .message_length = 0,
    });
    try w.writeAttribute(.{ .xor_mapped_address = from });
    try w.writeAttribute(.{ .message_integrity = &.{} });
    try w.writeAttribute(.fingerprint);
    return w.final();
}

fn buildRoleConflictErrorMessage(agent: *const Agent, transaction_id: u96, buffer: *[max_message_size]u8) ![]const u8 {
    var w = stun.Writer.init(&(buffer.*), .{ .password = agent.credentials.password });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.error_response, .binding),
        .transaction_id = transaction_id,
        .message_length = 0,
    });
    try w.writeAttribute(.{ .error_code = .{
        .code = 487,
        .reason = "Role conflict",
    } });
    try w.writeAttribute(.{ .message_integrity = &.{} });
    try w.writeAttribute(.fingerprint);
    return w.final();
}

fn findSocket(sockets: []Io.net.Socket, addr: *const IpAddress) *Io.net.Socket {
    for (sockets) |*socket| if (socket.address.eql(addr)) return socket;
    unreachable;
}

fn findLocalCandidate(agent: *Agent, base: *const IpAddress, addr: *const IpAddress) ?Candidate {
    for (agent.candidates.items) |candidate| if (candidate.base.eql(base) and candidate.address.eql(addr)) return candidate;
    return null;
}

fn findCandidatePair(agent: *Agent, local: *const IpAddress, remote: *const IpAddress) ?*CandidatePair {
    var pair: ?*CandidatePair = null;

    for (agent.pairs.items) |*candidate| if (candidate.local.base.eql(local) and candidate.remote.address.eql(remote)) {
        if (pair == null or candidate.status != .failed and pair.?.status == .failed) pair = candidate;
    };

    return pair;
}

fn findCandidatePairByLocalAndRemote(agent: *Agent, local: *const Candidate, remote: *const IpAddress) ?*CandidatePair {
    for (agent.pairs.items) |*candidate| if (candidate.local.eql(local) and candidate.remote.address.eql(remote))
        return candidate;
    return null;
}

fn setConnectionState(agent: *Agent, new_state: ice.ConnectionState) void {
    agent.connection_state = new_state;
    agent.on_connection_state_change(agent, new_state);
}

fn appendCandidatePair(agent: *Agent, candidate_pair: CandidatePair) !void {
    agent.mutex.lockUncancelable(agent.io);
    defer agent.mutex.unlock(agent.io);
    try agent.pairs.append(agent.allocator, candidate_pair);
}

// ============== Io related functions ======================
const MessageError = (Allocator.Error || Socket.ReceiveTimeoutError);

const Message = struct {
    socket: *const Socket,
    incoming_message: Io.net.IncomingMessage,
    err: ?MessageError = null,
};

const InnerEvent = union(enum) {
    message: Message,
    connectivity_check: Io.Cancelable!void,
    complete: Io.Cancelable!void,
    app_data: Message,
    keep_alive: Io.Cancelable!void,
};

fn innerEventHandler(agent: *Agent) !void {
    const io = agent.io;
    const Select = Io.Select(InnerEvent);

    var queue: [10]InnerEvent = undefined;
    var select = Select.init(agent.io, &queue);
    defer {
        while (select.cancel()) |event| switch (event) {
            .message, .app_data => |message| {
                if (message.err) |_| continue;
                agent.destroyPacket(message.incoming_message.data);
            },
            else => {},
        };
    }

    select.async(.connectivity_check, Io.sleep, .{ io, connectivity_check_interval, .awake });
    for (agent.sockets) |*socket| select.async(.message, receiveTimeout, .{ agent, socket, .none });

    while (select.await()) |event| switch (event) {
        .connectivity_check => |timeout| {
            try timeout;
            switch (agent.connection_state) {
                .completed, .failed, .closed => {},
                else => {
                    select.async(.connectivity_check, Io.sleep, .{ io, connectivity_check_interval, .awake });
                    agent.batchSendConnectivityCheck() catch |err| Logger.err("connectivity check failed due to {}", .{err});
                },
            }
        },
        .message => |message| {
            if (message.err) |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => continue,
            };

            agent.handleConnectivityCheckMessage(&select, message) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => {},
            };
        },
        .app_data => |message| {
            if (message.err) |err| switch (err) {
                error.Timeout => switch (agent.connection_state) {
                    .connected, .completed => {
                        select.async(.app_data, receiveTimeout, .{ agent, message.socket, .{ .duration = failing_timeout } });
                        agent.setConnectionState(.disconnected);
                        continue;
                    },
                    .disconnected => {
                        agent.setConnectionState(.failed);
                        return;
                    },
                    else => unreachable,
                },
                else => |e| return e,
            };
            defer agent.destroyPacket(message.incoming_message.data);
            select.async(.app_data, receiveTimeout, .{ agent, message.socket, .{ .duration = disconnect_timeout } });

            if (stun.isMessage(message.incoming_message.data))
                agent.handleConsentFreshness(message) catch continue
            else
                agent.on_data(agent, message.incoming_message.data);
        },
        .keep_alive => |timeout| {
            try timeout;
            select.async(.keep_alive, Io.sleep, .{ io, keep_alive_interval, .awake });

            const buffer = try agent.buffer_pool.create(agent.allocator);
            defer agent.destroyPacket(buffer);

            const req = try agent.buildBindingRequest(randomNumber(u96, io), false, buffer);
            const selected_pair = &agent.nominated_pair.?;
            try selected_pair.socket.send(agent.io, &selected_pair.pair.remote.address, req);
        },
        .complete => |result| {
            try result;
            agent.markConnectionCompleted();
        },
    } else |err| return err;
}

fn receiveTimeout(agent: *Agent, socket: *const Socket, timeout: Io.Timeout) Message {
    var result: Message = .{
        .socket = socket,
        .incoming_message = undefined,
    };

    const buffer = agent.buffer_pool.create(agent.allocator) catch |err| {
        result.err = err;
        return result;
    };

    result.incoming_message = socket.receiveTimeout(agent.io, &(buffer.*), timeout) catch |err| {
        agent.destroyPacket(buffer);
        result.err = err;
        return result;
    };

    return result;
}

fn send(agent: *Agent, socket: *const Socket, address: *const IpAddress, buffer: []const u8) (Allocator.Error || Socket.SendError)!void {
    defer agent.destroyPacket(buffer);
    try socket.send(agent.io, address, buffer);
}

fn selectBestPair(agent: *Agent) ?SelectedPair {
    var selected_pair: ?CandidatePair = null;
    for (agent.pairs.items) |candidate_pair| if (candidate_pair.status == .succeeded) {
        if (selected_pair == null or candidate_pair.priority > selected_pair.?.priority) {
            selected_pair = candidate_pair;
        }
    };

    return if (selected_pair) |pair|
        .{ .pair = pair, .socket = findSocket(agent.sockets, &pair.local.base).* }
    else
        null;
}

fn batchSendConnectivityCheck(agent: *Agent) !void {
    const buffer = try agent.buffer_pool.create(agent.allocator);
    defer agent.destroyPacket(buffer);

    if (agent.nominated_pair != null) return;

    if (agent.selected_pair == null) agent.selected_pair = agent.selectBestPair();

    if (agent.selected_pair) |selected_pair| {
        Logger.debug("Send binding request with use candidate on pair: {f}", .{selected_pair.pair});

        const transaction_id = randomNumber(u96, agent.io);
        const msg = try agent.buildBindingRequest(transaction_id, true, buffer);

        try agent.pending_requests.append(agent.allocator, .{
            .transaction_id = transaction_id,
            .source = selected_pair.pair.local.base,
            .target = selected_pair.pair.remote.address,
        });

        try selected_pair.sendData(agent.io, msg);
    }

    for (agent.pairs.items) |*candidate_pair| switch (candidate_pair.status) {
        .waiting, .in_progress => {
            candidate_pair.conn_check_count += 1;
            if (candidate_pair.conn_check_count > max_binding_requests) {
                candidate_pair.status = .failed;
                continue;
            }

            const transaction_id = randomNumber(u96, agent.io);
            const msg = try agent.buildBindingRequest(transaction_id, false, buffer);

            try agent.pending_requests.append(agent.allocator, .{
                .transaction_id = transaction_id,
                .source = candidate_pair.local.base,
                .target = candidate_pair.remote.address,
            });

            const socket = findSocket(agent.sockets, &candidate_pair.local.base);
            socket.send(agent.io, &candidate_pair.remote.address, msg) catch |err| {
                Logger.warn("Failed to send binding request on pair {f}: {}", .{ candidate_pair, err });
            };
        },
        else => {},
    };
}

fn handleConnectivityCheckMessage(agent: *Agent, select: *Io.Select(InnerEvent), message: Message) !void {
    const data = message.incoming_message.data;
    const sender = message.incoming_message.from;

    switch (agent.connection_state) {
        .completed => {
            agent.destroyPacket(data);
            return;
        },
        else => {},
    }

    defer agent.destroyPacket(data);
    if (stun.isMessage(data)) {
        const msg = try stun.Message.parse(data);

        switch (msg.header.message_type.class()) {
            .request => {
                const resp = try agent.handleRequest(&msg, message.socket.address, sender);
                defer agent.destroyPacket(resp);
                try message.socket.send(agent.io, &sender, resp);

                const nominated_pair: ?CandidatePair = blk: {
                    if (agent.role == .controlling or agent.nominated_pair != null) break :blk null;
                    for (agent.pairs.items) |candidate_pair| if (candidate_pair.nominated) break :blk candidate_pair;
                    break :blk null;
                };

                if (nominated_pair != null) {
                    agent.nominated_pair = .{
                        .pair = nominated_pair.?,
                        .socket = message.socket.*,
                    };
                }
            },
            .success_response => try agent.handleSuccessResponse(&msg, message.socket.address, sender),
            else => {},
        }

        if (agent.nominated_pair != null and agent.connection_state != .connected) {
            agent.setConnectionState(.connected);

            select.async(.complete, Io.sleep, .{ agent.io, .fromSeconds(3), .awake });
            select.async(.keep_alive, Io.sleep, .{ agent.io, keep_alive_interval, .awake });
            select.async(.app_data, receiveTimeout, .{ agent, &agent.nominated_pair.?.socket, .{ .duration = disconnect_timeout } });
            return;
        }
    } else {
        for (agent.pairs.items) |*candidate_pair| {
            if (candidate_pair.remote.address.eql(&sender)) {
                agent.on_data(agent, data);
                break;
            }
        } else Logger.warn("Drop non stun message from unknown remote candidate: {f}", .{sender});
    }

    select.async(.message, receiveTimeout, .{ agent, message.socket, .none });
}

fn handleConsentFreshness(agent: *Agent, message: Message) !void {
    const msg = try stun.Message.parse(message.incoming_message.data);
    switch (msg.header.message_type.class()) {
        .request => {
            Logger.debug("Received consent freshness request", .{});
            _ = try agent.parseAndValidateStunRequest(&msg);
            const buffer = try agent.buffer_pool.create(agent.allocator);
            defer agent.destroyPacket(buffer);

            const resp = try agent.buildSuccessResponse(&msg, message.incoming_message.from, buffer);
            try message.socket.send(agent.io, &message.incoming_message.from, resp);
        },
        else => {},
    }
}

fn markConnectionCompleted(agent: *Agent) void {
    const addr = agent.nominated_pair.?.socket.address;
    for (agent.sockets) |*socket| if (!socket.address.eql(&addr)) socket.close(agent.io);

    agent.allocator.free(agent.sockets);
    agent.sockets = &.{};

    agent.remote_candidates.clearAndFree(agent.allocator);
    agent.pairs.clearAndFree(agent.allocator);
    agent.pending_requests.clearAndFree(agent.allocator);
    agent.setConnectionState(.completed);
}

const testing = std.testing;

fn testNewAgent() !Agent {
    return try .init(testing.io, testing.allocator, .{
        .on_connection_state_change = undefined,
        .on_data = undefined,
        .on_candidate = undefined,
        .role = .controlled,
    });
}

fn testBuildRequest(req: StunRequest, peer_password: []const u8, buffer: []u8) !stun.Message {
    var w = stun.Writer.init(buffer, .{ .password = peer_password });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.request, .binding),
        .transaction_id = randomNumber(u96, testing.io),
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

test "init agent" {
    var agent: Agent = try .init(testing.io, testing.allocator, .{
        .on_connection_state_change = undefined,
        .on_data = undefined,
        .on_candidate = undefined,
    });
    defer agent.deinit();
}

test "handle request: generate success response" {
    var agent: Agent = try testNewAgent();
    defer agent.deinit();

    var buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = agent.credentials.username,
    }, agent.credentials.password, &buffer);

    const resp = try agent.handleRequest(&msg, base_addr, from);
    const resp_msg = try stun.Message.parse(resp);

    try testing.expectEqual(.success_response, resp_msg.header.message_type.class());
    try testing.expectEqual(.binding, resp_msg.header.message_type.method());
    try testing.expectEqual(msg.header.transaction_id, resp_msg.header.transaction_id);

    var it = resp_msg.iterateAttributes(agent.credentials.password);
    var attr = try it.next() orelse return error.ExpectedAttribute;
    try testing.expect(attr.xor_mapped_address.eql(&from));

    attr = try it.next() orelse return error.ExpectedAttribute;
    try testing.expectEqual(.message_integrity, @as(stun.AttributeType, attr));

    attr = try it.next() orelse return error.ExpectedAttribute;
    try testing.expectEqual(.fingerprint, @as(stun.AttributeType, attr));
    try testing.expectEqual(null, try it.next());
}

test "handle request: create peer reflexive candidate" {
    var agent: Agent = try testNewAgent();
    defer agent.deinit();

    var buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = agent.credentials.username,
    }, agent.credentials.password, &buffer);

    _ = try agent.handleRequest(&msg, base_addr, from);

    try testing.expectEqual(1, agent.pairs.items.len);

    const candidate_pair = agent.pairs.items[0];
    try testing.expect(candidate_pair.remote.address.eql(&from));
    try testing.expectEqual(candidate_pair.remote.priority, 0x9090);

    // Send request again
    _ = try agent.handleRequest(&msg, base_addr, from);
    try testing.expectEqual(1, agent.pairs.items.len); // no new peer is created
}

test "handle request: nominate peer" {
    var agent: Agent = try testNewAgent();
    defer agent.deinit();

    var buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    try agent.pairs.append(testing.allocator, .{
        .local = .initHost(base_addr),
        .remote = .initHost(from),
        .status = .in_progress,
        .priority = 0,
    });

    const msg = try testBuildRequest(.{
        .ice_controlling = 0x10000,
        .priority = 0x9090,
        .username = agent.credentials.username,
        .use_candidate = true,
    }, agent.credentials.password, &buffer);

    _ = try agent.handleRequest(&msg, base_addr, from);

    const candidate_pair = &agent.pairs.items[0];
    try testing.expect(candidate_pair.nominate_on_binding);
    try testing.expect(!candidate_pair.nominated);

    candidate_pair.status = .succeeded;
    _ = try agent.handleRequest(&msg, base_addr, from);
    try testing.expect(candidate_pair.nominated);
}

test "handle request: role conflict" {
    var agent: Agent = try testNewAgent();
    defer agent.deinit();

    var buffer: [1024]u8 = undefined;

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    {
        const msg = try testBuildRequest(.{
            .ice_controlled = std.math.maxInt(u64),
            .priority = 0x9090,
            .username = agent.credentials.username,
        }, agent.credentials.password, &buffer);

        const resp = try agent.handleRequest(&msg, base_addr, from);
        const resp_msg = try stun.Message.parse(resp);

        try testing.expectEqual(.error_response, resp_msg.header.message_type.class());
        try testing.expectEqual(.binding, resp_msg.header.message_type.method());
        try testing.expectEqual(msg.header.transaction_id, resp_msg.header.transaction_id);

        var it = resp_msg.iterateAttributes(agent.credentials.password);
        const attr = (try it.next()).?;
        try testing.expectEqual(.error_code, @as(stun.AttributeType, attr));
        try testing.expectEqual(487, attr.error_code.code);
        try testing.expectEqualStrings("Role conflict", attr.error_code.reason);
    }

    {
        const msg = try testBuildRequest(.{
            .ice_controlled = 0,
            .priority = 0x9090,
            .username = agent.credentials.username,
        }, agent.credentials.password, &buffer);

        try testing.expectError(error.SwitchRole, agent.handleRequest(&msg, base_addr, from));
    }
}

test "randomNumber" {
    const a = randomNumber(u64, testing.io);
    const b = randomNumber(u64, testing.io);
    const c = randomNumber(u64, testing.io);

    try testing.expect(a != b);
    try testing.expect(b != c);
    try testing.expect(a != c);
}
