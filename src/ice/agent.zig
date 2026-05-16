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
const linux = std.os.linux;

const max_message_size = 1500;
const max_binding_requests: usize = 7;
const connectivity_check_interval: std.Io.Duration = .fromMilliseconds(200);
const keep_alive_interval: std.Io.Duration = .fromSeconds(2);
const disconnect_timeout: Io.Clock.Duration = .{ .clock = .awake, .raw = .fromSeconds(5) };
const failing_timeout: Io.Clock.Duration = .{ .clock = .awake, .raw = .fromSeconds(25) };

pub const AgentConfig = struct {
    on_connection_state_change: *const fn (*Agent, ice.ConnectionState) void,
    on_data: *const fn (*Agent, []const u8) void,
    /// Local credentials of the agent (ufrag and password)
    ///
    /// Generated automatically if not provided
    credentials: ?ice.Credentials = null,
};

io: Io,
allocator: Allocator,
buffer_pool: std.heap.MemoryPool([max_message_size]u8),
connection_state: ice.ConnectionState = .new,

// callbacks
on_connection_state_change: *const fn (*Agent, ice.ConnectionState) void,
on_data: *const fn (*Agent, []const u8) void,

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
nominated_pair: ?SelectedPair = null,

// Io handling
group: Io.Group = .init,

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
        .role = .controlled,
        .tie_breaker = generateTieBeaker(io),
        .credentials = credens,
        .on_connection_state_change = config.on_connection_state_change,
        .on_data = config.on_data,
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

pub fn sendData(agent: *const Agent, data: []const u8) Socket.SendError!void {
    switch (agent.connection_state) {
        .connected, .completed => try agent.nominated_pair.?.sendData(agent.io, data),
        else => std.log.debug("Agent not connected: ignore send request", .{}),
    }
}

/// Free the buffer and return to the pool.
pub fn destroyPacket(agent: *Agent, data: []const u8) void {
    agent.buffer_pool.destroy(@ptrCast(@alignCast(@constCast(data))));
}

fn initSockets(agent: *Agent) !void {
    const candidates = agent.candidates.items;
    var index: usize = 0;

    var sockets: std.ArrayList(Io.net.Socket) = try .initCapacity(agent.allocator, agent.candidates.items.len);
    errdefer {
        for (0..index) |idx| sockets.items[idx].close(agent.io);
        sockets.deinit(agent.allocator);
    }

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
    switch (@import("builtin").os.tag) {
        .linux => try agent.linuxGatherHostCandidates(),
        else => {},
    }
}

fn linuxGatherHostCandidates(agent: *Agent) !void {
    var interfaces: [*c]c.ifaddrs = undefined;
    if (c.getifaddrs(&interfaces) != 0) {
        return error.GetIfAddrsFailed;
    }
    defer c.ifaddrs.freeifaddrs(interfaces);

    var it = interfaces;
    while (it) |p_ifa| : (it = p_ifa.*.ifa_next) if (p_ifa.*.ifa_addr) |addr| {
        const sockaddr: linux.sockaddr = @bitCast(addr.*);

        switch (sockaddr.family) {
            linux.AF.INET => {
                const c_flags: u16 = @truncate(p_ifa.*.ifa_flags);
                const flags: linux.IFF = @bitCast(c_flags);
                if (flags.LOOPBACK) continue;

                const in: linux.sockaddr.in = @bitCast(sockaddr);
                const ip_addr: IpAddress = .{ .ip4 = .{ .bytes = std.mem.toBytes(in.addr), .port = 0 } };
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

fn handleReceivedMessage(agent: *Agent, base_addr: IpAddress, incoming_message: Io.net.IncomingMessage) !?[]const u8 {
    const msg = try stun.Message.parse(incoming_message.data);
    return switch (msg.header.message_type.class()) {
        .request => try agent.handleRequest(&msg, base_addr, incoming_message.from),
        .success_response => try agent.handleSuccessResponse(&msg, base_addr, incoming_message.from),
        else => null,
    };
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

    return try agent.buildSuccessResponse(msg, from, buffer);
}

fn handleSuccessResponse(agent: *Agent, msg: *const stun.Message, base_addr: IpAddress, from: IpAddress) !?[]const u8 {
    Logger.debug("Handle success response on {f} from {f}", .{ base_addr, from });

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

    if (!pending_request.source.eql(&base_addr) or !pending_request.target.eql(&from)) return null;

    if (agent.findCandidatePair(&base_addr, &from)) |candidate_pair| {
        const mapped_address = try agent.parseAndValidateStunResponse(msg);

        if (mapped_address.eql(&base_addr)) {
            candidate_pair.state.status = .succeeded;
            if (candidate_pair.state.nominateOnBinding) {
                candidate_pair.state.nominateOnBinding = false;
                candidate_pair.state.nominated = true;
            }
            return null;
        }
        candidate_pair.state.status = .failed;

        if (agent.findCandidatePair(&mapped_address, &from)) |existing_candidate_pair| {
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
    }
    return null;
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

fn findCandidatePair(agent: *Agent, local: *const IpAddress, remote: *const IpAddress) ?*CandidatePair {
    for (agent.pairs.items) |*candidate| {
        if (candidate.local.address.eql(local) and candidate.remote.address.eql(remote))
            return candidate;
    }

    return null;
}

fn setConnectionState(agent: *Agent, new_state: ice.ConnectionState) void {
    agent.connection_state = new_state;
    agent.on_connection_state_change(agent, new_state);
}

// ============== Io related functions ======================
const MessageError = (Allocator.Error || Socket.ReceiveTimeoutError);

const Message = struct {
    socket: *const Socket,
    incoming_message: Io.net.IncomingMessage,
};

const InnerEvent = union(enum) {
    message: MessageError!Message,
    connectivity_check: Io.Cancelable!void,
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

    select.async(.connectivity_check, Io.sleep, .{ io, connectivity_check_interval, .awake });
    for (agent.sockets) |*socket|
        select.async(.message, receiveTimeout, .{ agent, socket, .none });

    var nominated_socket: Socket = undefined;

    while (true) switch (try select.await()) {
        .connectivity_check => |timeout| {
            try timeout;
            switch (agent.connection_state) {
                .completed, .failed => {},
                else => {
                    select.async(.connectivity_check, Io.sleep, .{ io, connectivity_check_interval, .awake });
                    agent.batchSendConnectivityCheck() catch |err| std.log.err("connectivity check failed due to {}", .{err});
                },
            }
        },
        .message => |result| {
            const message = try result;

            const data = message.incoming_message.data;
            const sender = message.incoming_message.from;

            if (stun.isMessage(data)) {
                defer agent.destroyPacket(data);
                if (try agent.handleReceivedMessage(message.socket.address, message.incoming_message)) |response| {
                    defer agent.destroyPacket(response);
                    try message.socket.send(io, &sender, response);
                }

                const candidate_pair: ?CandidatePair = blk: {
                    if (agent.role == .controlling or agent.nominated_pair != null) break :blk null;
                    for (agent.pairs.items) |candidate_pair| if (candidate_pair.state.nominated) break :blk candidate_pair;
                    break :blk null;
                };

                if (candidate_pair != null) {
                    agent.nominated_pair = .{
                        .pair = candidate_pair.?,
                        .socket = message.socket.*,
                    };
                    nominated_socket = agent.nominated_pair.?.socket;
                    agent.setConnectionState(.connected);

                    select.async(.complete, Io.sleep, .{ io, .fromSeconds(3), .awake });
                    select.async(.keep_alive, Io.sleep, .{ io, keep_alive_interval, .awake });
                    select.async(.data_message, receiveTimeout, .{ agent, &nominated_socket, .{ .duration = disconnect_timeout } });
                    continue;
                }
            } else {
                for (agent.pairs.items) |*candidate_pair| if (candidate_pair.remote.address.eql(&sender)) {
                    agent.on_data(agent, data);
                } else {
                    std.log.warn("Drop non stun message from unknown remote candidate: {f}", .{sender});
                    agent.destroyPacket(data);
                };
            }

            select.async(.message, receiveTimeout, .{ agent, message.socket, .none });
        },
        .data_message => |result| {
            const message = result catch |err| switch (err) {
                error.Timeout => switch (agent.connection_state) {
                    .connected, .completed => {
                        select.async(.data_message, receiveTimeout, .{ agent, &nominated_socket, .{ .duration = failing_timeout } });
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

            select.async(.data_message, receiveTimeout, .{ agent, message.socket, .{ .duration = disconnect_timeout } });

            if (stun.isMessage(message.incoming_message.data))
                agent.destroyPacket(message.incoming_message.data)
            else
                agent.on_data(agent, message.incoming_message.data);
        },
        .keep_alive => |timeout| {
            try timeout;
            select.async(.keep_alive, Io.sleep, .{ io, keep_alive_interval, .awake });

            var buffer: [20]u8 = undefined;
            try nominated_socket.send(agent.io, &agent.nominated_pair.?.pair.remote.address, try buildIndicationRequest(&buffer));
        },
        .complete => |result| {
            try result;
            agent.markConnectionCompleted();
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

fn markConnectionCompleted(agent: *Agent) void {
    const addr = agent.nominated_pair.?.socket.address;
    for (agent.sockets) |*socket| if (!socket.address.eql(&addr)) socket.close(agent.io);

    agent.allocator.free(agent.sockets);
    agent.sockets = &.{};

    agent.pairs.clearAndFree(agent.allocator);
    agent.pending_requests.clearAndFree(agent.allocator);
    agent.setConnectionState(.completed);
}

const testing = std.testing;

fn testNewAgent() !Agent {
    return try .init(testing.io, testing.allocator, .{
        .on_connection_state_change = undefined,
        .on_data = undefined,
    });
}

fn testBuildRequest(req: StunRequest, peer_password: []const u8, buffer: []u8) !stun.Message {
    var w = stun.Writer.init(buffer, .{ .password = peer_password });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.request, .binding),
        .transaction_id = generateTrasactionId(testing.io),
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
        .state = .{ .status = .in_progress },
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
    try testing.expectEqual(true, candidate_pair.state.nominateOnBinding);
    try testing.expectEqual(false, candidate_pair.state.nominated);

    candidate_pair.state.status = .succeeded;
    _ = try agent.handleRequest(&msg, base_addr, from);
    try testing.expectEqual(true, candidate_pair.state.nominated);
}
