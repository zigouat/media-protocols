const std = @import("std");
const c = @import("c");
const stun = @import("stun");
const ice = @import("ice.zig");

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
const keep_alive_interval: std.Io.Duration = .fromMilliseconds(200);
const disconnect_timeout: Io.Clock.Duration = .{ .clock = .awake, .raw = .fromSeconds(5) };
const failing_timeout: Io.Clock.Duration = .{ .clock = .awake, .raw = .fromSeconds(25) };

pub const AgentConfig = struct {
    onConnectionState: *const fn (*Agent, ice.ConnectionState) void,
    onData: *const fn (*Agent, []const u8) void,
};

io: Io,
allocator: Allocator,
buffer_pool: std.heap.MemoryPool([max_message_size]u8),
config: AgentConfig,
connection_state: ice.ConnectionState = .new,

// Stun related fields
role: Role,
credentials: ice.Credentials,
remote_credentials: ?ice.Credentials = null,
tie_breaker: u64,

// Candidates and sockets
sockets: []Io.net.Socket = &.{},
candidates: std.ArrayList(Candidate) = .empty,
pairs: std.ArrayList(CandidatePair) = .empty,
pending_requests: std.ArrayList(PendingRequest) = .empty,
nominated_pair: ?CandidatePair = null,

// Io handling
group: Io.Group = .init,

pub const Event = union(enum) {
    data: []const u8,
    connection_state: ice.ConnectionState,
};

const Role = enum { controlling, controlled };

const StunRequest = struct {
    username: []const u8 = &.{},
    ice_controlled: ?u64 = null,
    ice_controlling: ?u64 = null,
    use_candidate: bool = false,
    priority: u32 = 0,
};

const PendingRequest = struct {
    transaction_id: u96,
    source: Io.net.IpAddress,
    target: Io.net.IpAddress,
};

pub fn init(io: Io, allocator: Allocator, config: AgentConfig) !Agent {
    return .{
        .io = io,
        .allocator = allocator,
        .buffer_pool = .empty,
        .role = .controlled,
        .credentials = try (ice.Credentials{ .username = "test", .password = "test" }).dupe(allocator),
        .tie_breaker = generateTieBeaker(io),
        .config = config,
    };
}

pub fn deinit(agent: *Agent) void {
    const io = agent.io;
    const allocator = agent.allocator;
    agent.group.cancel(io);

    for (agent.sockets) |socket| socket.close(io);
    allocator.free(agent.sockets);

    agent.candidates.deinit(allocator);
    agent.pairs.deinit(allocator);
    agent.pending_requests.deinit(allocator);
    agent.credentials.deinit(allocator);
    if (agent.remote_credentials) |*credens| credens.deinit(allocator);

    agent.buffer_pool.deinit(allocator);
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
    // TODO: Add mutex
    switch (agent.connection_state) {
        .new, .checking, .connected => try agent.doAddRemoteCandidate(remote_candidate),
        else => {},
    }
}

/// Start gathering candidates and start inner event handler.
///
/// This function should be called first after initializing the agent.
pub fn gatherCandidates(agent: *Agent) !void {
    try agent.gatherHostCandidates();
    try agent.initSockets();
    try agent.group.concurrent(agent.io, innerEventHandlerWrapper, .{agent});
}

/// Free the buffer and return to the pool.
pub fn destroyPacket(agent: *Agent, data: []const u8) void {
    agent.buffer_pool.destroy(@ptrCast(@alignCast(@constCast(data))));
}

fn initSockets(agent: *Agent) !void {
    var sockets: std.ArrayList(Io.net.Socket) = try .initCapacity(agent.allocator, agent.candidates.items.len);
    errdefer sockets.deinit(agent.allocator);

    const candidates = agent.candidates.items;
    var index: usize = 0;

    while (true) {
        if (index >= candidates.len) break;
        const socket = candidates[index].address.bind(agent.io, .{ .mode = .dgram, .protocol = .udp }) catch {
            _ = agent.candidates.swapRemove(index);
            continue;
        };

        sockets.appendAssumeCapacity(socket);
        candidates[index].base = socket.address;
        candidates[index].address = socket.address;
        index += 1;
    }

    agent.sockets = try sockets.toOwnedSlice(agent.allocator);
}

fn calculatePairPriority(l: u32, r: u32, role: Role) u64 {
    var g = l;
    var d = r;
    if (role == .controlled) g, d = .{ d, g };

    const last_part: u8 = if (g > d) 1 else 0;
    return (@as(u64, 1) << 32) * @min(g, d) + 2 * @max(g, d) + last_part;
}

fn generateTieBeaker(io: Io) u64 {
    var bytes: [8]u8 = undefined;
    io.random(&bytes);
    return @bitCast(bytes);
}

fn generateTrasactionId(io: Io) u96 {
    var bytes: [12]u8 = undefined;
    io.random(&bytes);
    return std.mem.readInt(u96, &bytes, .big);
}

fn gatherHostCandidates(agent: *Agent) !void {
    var interfaces: [*c]c.ifaddrs = undefined;
    if (c.getifaddrs(&interfaces) != 0) {
        return error.GetIfAddrsFailed;
    }
    defer c.ifaddrs.freeifaddrs(interfaces);

    var it = interfaces;
    while (it) |p_ifa| : (it = p_ifa.*.ifa_next) if (p_ifa.*.ifa_addr) |addr| {
        switch (addr.*.sa_family) {
            c.AF_INET => {
                const sin: *const c.sockaddr_in = @ptrCast(@alignCast(addr));
                // Ignore loopback addresses.
                if (sin.sin_addr.s_addr == std.mem.nativeToBig(u32, 0x7f000001)) {
                    continue;
                }

                const ip_addr: Io.net.IpAddress = .{
                    .ip4 = .{ .bytes = std.mem.toBytes(sin.sin_addr.s_addr), .port = 0 },
                };
                try agent.candidates.append(agent.allocator, .initHost(ip_addr));
            },
            else => {},
        }
    };
}

fn doAddRemoteCandidate(agent: *Agent, remote_candidate: Candidate) Allocator.Error!void {
    for (agent.candidates.items) |candidate| {
        for (agent.pairs.items) |*pair|
            if (pair.local.base.eql(&candidate.base) and pair.remote.address.eql(&remote_candidate.address))
                continue;

        try agent.pairs.append(agent.allocator, .{
            .local = candidate,
            .remote = remote_candidate,
            .priority = calculatePairPriority(candidate.priority, remote_candidate.priority, agent.role),
        });
    }
}

fn handleReceivedMessage(agent: *Agent, base_addr: Io.net.IpAddress, incoming_message: Io.net.IncomingMessage) !?[]const u8 {
    const msg = try stun.Message.parse(incoming_message.data);
    switch (msg.header.message_type.class()) {
        .request => return try agent.handleRequest(&msg, base_addr, incoming_message.from),
        .success_response => {
            Logger.debug("Handle success response on {f} from {f}", .{ base_addr, incoming_message.from });

            const pending_request = blk: {
                const tx_id = msg.header.transaction_id;
                for (agent.pending_requests.items, 0..) |pr, i| {
                    if (pr.transaction_id == tx_id) {
                        const pending_request = agent.pending_requests.swapRemove(i);
                        break :blk pending_request;
                    }
                }

                return null;
            };

            if (!pending_request.source.eql(&base_addr) or !pending_request.target.eql(&incoming_message.from)) return null;

            if (agent.findCandidatePair(&base_addr, &incoming_message.from)) |candidate_pair| {
                const mapped_address = blk: {
                    var it = msg.iterateAttributes(&.{});
                    while (try it.next()) |attribute| switch (attribute) {
                        .xor_mapped_address => |addr| break :blk addr,
                        else => {},
                    };

                    return null;
                };

                if (mapped_address.eql(&base_addr)) {
                    candidate_pair.state.status = .succeeded;
                    if (agent.role == .controlled and candidate_pair.state.nominateOnBinding) {
                        candidate_pair.state.nominateOnBinding = false;
                        candidate_pair.state.nominated = true;
                    }
                    return null;
                }
                candidate_pair.state.status = .failed;

                if (agent.findCandidatePair(&mapped_address, &incoming_message.from)) |existing_candidate_pair| {
                    existing_candidate_pair.state.status = .succeeded;
                    return null;
                }

                const reflexive_candidate: Candidate = .initPeerReflexive(base_addr, mapped_address);
                try agent.pairs.append(agent.allocator, .{
                    .local = reflexive_candidate,
                    .remote = candidate_pair.remote,
                    .priority = calculatePairPriority(reflexive_candidate.priority, candidate_pair.remote.priority, agent.role),
                    .state = .{ .status = .succeeded },
                });

                return null;
            }
        },
        else => {},
    }

    return null;
}

fn handleRequest(agent: *Agent, msg: *const stun.Message, base_addr: IpAddress, from: IpAddress) ![]const u8 {
    Logger.debug("Handle request on {f} from {f}", .{ base_addr, from });
    const stun_req = try agent.parseAndValidateStunRequest(msg);

    if (agent.findCandidatePair(&base_addr, &from)) |candidate_pair| {
        switch (candidate_pair.state.status) {
            .succeeded => candidate_pair.state.nominated = stun_req.use_candidate,
            else => candidate_pair.state.nominateOnBinding = stun_req.use_candidate,
        }
    } else {
        const local: Candidate = .initHost(base_addr);
        const remote: Candidate = .{
            .base = from,
            .address = from,
            .candidate_type = .peer_reflexive,
            .priority = stun_req.priority,
        };

        try agent.pairs.append(agent.allocator, .{
            .local = local,
            .remote = remote,
            .priority = calculatePairPriority(local.priority, remote.priority, agent.role),
            .state = .{
                .status = .in_progress,
                .nominateOnBinding = stun_req.use_candidate,
            },
        });
    }

    const buffer = try agent.buffer_pool.create(agent.allocator);
    return try agent.buildSuccessResponse(msg, from, buffer);
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

fn buildBindingRequest(agent: *Agent, tx_id: u96, buffer: *[max_message_size]u8) ![]const u8 {
    var w = stun.Writer.init(&(buffer.*), .{ .password = agent.remote_credentials.?.password });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.request, .binding),
        .transaction_id = tx_id,
        .message_length = 0,
    });

    var username = [_][]const u8{ agent.remote_credentials.?.username, ":", agent.credentials.username };
    try w.writeRaw(.username, &username);
    try w.writeAttribute(.{ .priority = ice.CandidateType.peer_reflexive.priority() });
    const role_attribute: stun.Attribute = switch (agent.role) {
        .controlled => .{ .ice_controlled = agent.tie_breaker },
        .controlling => .{ .ice_controlling = agent.tie_breaker },
    };
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
        .transaction_id = 0x0010,
    });

    return w.final();
}

fn buildSuccessResponse(
    agent: *const Agent,
    msg: *const stun.Message,
    from: Io.net.IpAddress,
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

fn findSocket(sockets: []Io.net.Socket, addr: *const IpAddress) *Io.net.Socket {
    for (sockets) |*socket| if (socket.address.eql(addr)) return socket;
    unreachable;
}

fn findCandidatePair(agent: *Agent, local: *const IpAddress, remote: *const IpAddress) ?*CandidatePair {
    for (agent.pairs.items) |*candidate| {
        if (candidate.local.address.eql(local) and candidate.remote.address.eql(remote))
            return candidate;
    }

    return null;
}

fn maybeSetNominatedCandidate(agent: *Agent) !bool {
    if (agent.role == .controlling or agent.nominated_pair != null) return false;

    for (agent.pairs.items) |candidate_pair| if (candidate_pair.state.nominated) {
        agent.nominated_pair = candidate_pair;
        return true;
    };

    return false;
}

fn setConnectionState(agent: *Agent, new_state: ice.ConnectionState) void {
    agent.connection_state = new_state;
    agent.config.onConnectionState(agent, new_state);
}

// ============== Io related function ======================
const MessageError = (Allocator.Error || Socket.ReceiveTimeoutError);

const Message = struct {
    socket: *const Socket,
    incoming_message: Io.net.IncomingMessage,
};

const InnerEvent = union(enum) {
    message: MessageError!Message,
    connectivity_check: Io.Cancelable!void,
    send_message: (Allocator.Error || Socket.SendError)!void,
    complete: Io.Cancelable!void,
    // message received from the nominated peer
    data_message: MessageError!Message,
    keep_alive: Io.Cancelable!void,
};

fn innerEventHandlerWrapper(agent: *Agent) !void {
    agent.innerEventHandler() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => |e| std.log.err("Error occurred in event handler: {}", .{e}),
    };
}

fn innerEventHandler(agent: *Agent) !void {
    const io = agent.io;
    const Select = Io.Select(InnerEvent);

    var queue: [1]InnerEvent = undefined;
    var select = Select.init(agent.io, &queue);
    defer select.cancelDiscard();

    for (agent.sockets) |*socket| {
        select.async(.message, receiveTimeout, .{ agent, socket, .none });
    }
    select.async(.connectivity_check, Io.sleep, .{ io, connectivity_check_interval, .awake });

    var nominated_socket: Socket = undefined;

    while (true) switch (try select.await()) {
        .connectivity_check => |timeout| {
            try timeout;
            switch (agent.connection_state) {
                .completed, .failed => {},
                else => {
                    try agent.batchSendConnectivityCheck();
                    select.async(.connectivity_check, Io.sleep, .{ io, connectivity_check_interval, .awake });
                },
            }
        },
        .message => |result| {
            const message = try result;

            const data = message.incoming_message.data;
            const sender = message.incoming_message.from;

            if (stun.isMessage(data)) {
                defer agent.destroyPacket(data);
                if (try agent.handleReceivedMessage(message.socket.address, message.incoming_message)) |response|
                    select.async(.send_message, send, .{ agent, message.socket, &sender, response });

                if (try agent.maybeSetNominatedCandidate()) {
                    agent.setConnectionState(.connected);
                    nominated_socket = message.socket.*;

                    select.async(.data_message, receiveTimeout, .{ agent, &nominated_socket, .{ .duration = disconnect_timeout } });
                    select.async(.keep_alive, Io.sleep, .{ io, keep_alive_interval, .awake });
                    select.async(.complete, Io.sleep, .{ io, .fromSeconds(3), .awake });
                    continue;
                }
            } else {
                for (agent.pairs.items) |*candidate_pair| if (candidate_pair.remote.address.eql(&sender)) {
                    agent.config.onData(agent, data);
                } else {
                    std.log.warn("Drop non stun message from unknown remote candidate: {f}", .{sender});
                    agent.destroyPacket(data);
                };
            }

            select.async(.message, receiveTimeout, .{ agent, message.socket, .none });
        },
        .send_message => |result| result catch |err| std.log.err("failed to send response: {}", .{err}),
        .data_message => |result| {
            const message = result catch |err| switch (err) {
                error.Timeout => switch (agent.connection_state) {
                    .connected, .completed => {
                        agent.setConnectionState(.disconnected);
                        select.async(.data_message, receiveTimeout, .{ agent, &nominated_socket, .{ .duration = failing_timeout } });
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

            if (stun.isMessage(message.incoming_message.data))
                agent.buffer_pool.destroy(@ptrCast(@alignCast(message.incoming_message.data.ptr)))
            else
                agent.config.onData(agent, message.incoming_message.data);

            select.async(.data_message, receiveTimeout, .{ agent, message.socket, .{ .duration = disconnect_timeout } });
        },
        .keep_alive => |timeout| {
            try timeout;
            select.async(.keep_alive, Io.sleep, .{ io, keep_alive_interval, .awake });

            var buffer: [20]u8 = undefined;
            try nominated_socket.send(agent.io, &agent.nominated_pair.?.remote.address, try buildIndicationRequest(&buffer));
        },
        .complete => |result| {
            try result;
            try agent.markConnectionCompleted(nominated_socket);
        },
    };
}

fn receiveTimeout(agent: *Agent, socket: *const Socket, timeout: Io.Timeout) !Message {
    const buffer = try agent.buffer_pool.create(agent.allocator);
    errdefer agent.buffer_pool.destroy(buffer);

    const incoming_message = try socket.receiveTimeout(agent.io, &(buffer.*), timeout);
    return .{ .incoming_message = incoming_message, .socket = socket };
}

fn send(agent: *Agent, socket: *const Socket, address: *const IpAddress, buffer: []const u8) (Allocator.Error || Socket.SendError)!void {
    defer agent.buffer_pool.destroy(@ptrCast(@alignCast(@constCast(buffer))));
    try socket.send(agent.io, address, buffer);
}

fn batchSendConnectivityCheck(agent: *Agent) !void {
    const buffer = try agent.buffer_pool.create(agent.allocator);
    defer agent.buffer_pool.destroy(buffer);

    for (agent.pairs.items) |*candidate_pair| switch (candidate_pair.state.status) {
        .waiting, .in_progress => {
            candidate_pair.conn_check_count += 1;
            if (candidate_pair.conn_check_count > max_binding_requests) {
                candidate_pair.state.status = .failed;
                continue;
            }

            const transaction_id = generateTrasactionId(agent.io);
            const msg = try agent.buildBindingRequest(transaction_id, buffer);

            try agent.pending_requests.append(agent.allocator, .{
                .transaction_id = transaction_id,
                .source = candidate_pair.local.base,
                .target = candidate_pair.remote.address,
            });

            const socket = findSocket(agent.sockets, &candidate_pair.local.base);
            try socket.send(agent.io, &candidate_pair.remote.address, msg);
        },
        else => {},
    };
}

fn markConnectionCompleted(agent: *Agent, nominated_socket: Socket) !void {
    for (agent.sockets) |*socket| if (!socket.address.eql(&nominated_socket.address)) socket.close(agent.io);
    agent.sockets = try agent.allocator.realloc(agent.sockets, 1);
    agent.sockets[0] = nominated_socket;

    agent.pairs.clearAndFree(agent.allocator);
    agent.pending_requests.clearAndFree(agent.allocator);
    agent.setConnectionState(.completed);
}
