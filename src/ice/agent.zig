const std = @import("std");
const c = @import("c");
const stun = @import("stun");
const ice = @import("ice.zig");

const Io = std.Io;
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

io: Io,
allocator: std.mem.Allocator,
buffer_pool: std.heap.MemoryPool([max_message_size]u8),
state: State = .new,

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
queue_buffer: [1]InternalEvent = undefined,
queue: Io.Queue(InternalEvent) = undefined,

pub const State = enum { new, checking, connected, disconnected, failed };

const Role = enum { controlling, controlled };

const InternalEvent = union(enum) {
    add_candidate: Candidate,
    message: struct { IpAddress, Io.net.IncomingMessage },
    check_connectivity: void,
    data: []u8,
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
    source: Io.net.IpAddress,
    target: Io.net.IpAddress,
};

pub fn init(agent: *Agent, io: Io, allocator: std.mem.Allocator) !void {
    agent.* = .{
        .io = io,
        .allocator = allocator,
        .buffer_pool = .empty,
        .role = .controlled,
        .credentials = try (ice.Credentials{ .username = "test", .password = "test" }).dupe(allocator),
        .tie_breaker = generateTieBeaker(io),
    };

    agent.queue = .init(&agent.queue_buffer);
}

pub fn deinit(agent: *Agent) void {
    const io = agent.io;
    const allocator = agent.allocator;

    agent.buffer_pool.deinit(allocator);
    agent.candidates.deinit(allocator);
    agent.pairs.deinit(allocator);
    for (agent.sockets) |socket| socket.close(io);
    allocator.free(agent.sockets);

    agent.credentials.deinit(allocator);
    if (agent.remote_credentials) |*credens| credens.deinit(allocator);

    agent.queue.close(io);
    agent.group.cancel(io);
}

pub fn setRemoteCredentials(agent: *Agent, credentials: ice.Credentials) !void {
    switch (agent.state) {
        .new => {
            agent.remote_credentials = try credentials.dupe(agent.allocator);
            agent.state = .checking;
            try agent.group.concurrent(agent.io, startConnectivityChecks, .{agent});
        },
        else => return error.CredentialsAlreadySet,
    }
}

pub fn addRemoteCandidate(agent: *Agent, remote_candidate: Candidate) !void {
    switch (agent.state) {
        .new => try agent.doAddRemoteCandidate(remote_candidate),
        .checking => try agent.queue.putOne(agent.io, .{ .add_candidate = remote_candidate }),
        else => {},
    }
}

pub fn gatherCandidates(agent: *Agent) !void {
    try agent.gatherHostCandidates();
    try agent.initSockets();
    try agent.group.concurrent(agent.io, listenForMessages, .{agent});
}

/// Poll for events
pub fn poll(agent: *Agent) !?[]u8 {
    const io = agent.io;

    while (agent.queue.getOne(io)) |event| switch (event) {
        .add_candidate => |remote_candidate| try agent.addRemoteCandidate(remote_candidate),
        .message => |s| {
            defer agent.buffer_pool.destroy(@ptrCast(@alignCast(s.@"1".data.ptr)));
            if (stun.isMessage(s.@"1".data)) {
                if (try agent.handleReceivedMessage(s.@"0", s.@"1")) |response| {
                    defer agent.buffer_pool.destroy(@ptrCast(@alignCast(@constCast(response.ptr))));
                    try findSocket(agent.sockets, &s.@"0").send(io, &s.@"1".from, response);
                }
            } else {
                for (agent.pairs.items) |*candidate_pair| if (candidate_pair.remote.address.eql(&s.@"1".from)) {
                    return s.@"1".data;
                };
                continue;
            }

            try agent.maybeSetNominatedCandidate();
        },
        .check_connectivity => try agent.batchSendConnectivityCheck(),
        .data => |data| return data,
    } else |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => {},
    }

    return null;
}

fn initSockets(agent: *Agent) !void {
    agent.sockets = try agent.allocator.alloc(Io.net.Socket, agent.candidates.items.len);
    var initialized: usize = 0;
    errdefer {
        for (0..initialized) |idx| agent.sockets[idx].close(agent.io);
        agent.allocator.free(agent.sockets);
    }

    for (agent.candidates.items) |*candidate| {
        agent.sockets[initialized] = try candidate.address.bind(
            agent.io,
            .{ .mode = .dgram, .protocol = .udp },
        );
        candidate.base = agent.sockets[initialized].address;
        candidate.address = agent.sockets[initialized].address;
        initialized += 1;
    }
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

fn doAddRemoteCandidate(agent: *Agent, remote_candidate: Candidate) !void {
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
    try w.writeAttribute(.{ .priority = 10 });
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

fn findSocket(sockets: []Io.net.Socket, addr: *const Io.net.IpAddress) *Io.net.Socket {
    for (sockets) |*socket| if (socket.address.eql(addr)) return socket;
    unreachable;
}

fn findCandidatePair(agent: *Agent, local: *const Io.net.IpAddress, remote: *const Io.net.IpAddress) ?*CandidatePair {
    for (agent.pairs.items) |*candidate| {
        if (candidate.local.address.eql(local) and candidate.remote.address.eql(remote))
            return candidate;
    }

    return null;
}

fn maybeSetNominatedCandidate(agent: *Agent) !void {
    if (agent.role == .controlling or agent.nominated_pair != null) return;

    for (agent.pairs.items) |candidate_pair| if (candidate_pair.state.nominated) {
        agent.nominated_pair = candidate_pair;
        agent.state = .connected;
        agent.group.cancel(agent.io);

        // Clean up and listen on socket
        agent.candidates.deinit(agent.allocator);
        for (agent.sockets) |*socket| if (!socket.address.eql(&candidate_pair.local.base)) socket.close(agent.io);
        try agent.pairs.shrinkAndFreePrecise(agent.allocator, 1);
        agent.pairs.items[0] = candidate_pair;

        try agent.group.concurrent(agent.io, listen, .{agent});
        break;
    };
}

// ============== Io related function ======================
const Receive = union(enum) {
    message: anyerror!struct { usize, Io.net.IncomingMessage },
};

const ListenEvent = union(enum) {
    message: Io.net.Socket.ReceiveTimeoutError!Io.net.IncomingMessage,
    keep_alive: Io.Cancelable!void,
};

fn listen(agent: *Agent) !void {
    agent.doListen() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => {},
    };
}

fn doListen(agent: *Agent) !void {
    const ListenSelect = Io.Select(ListenEvent);
    var listen_event_buffer: [1]ListenEvent = undefined;
    var select = ListenSelect.init(agent.io, &listen_event_buffer);
    defer select.cancelDiscard();

    const socket = findSocket(agent.sockets, &agent.nominated_pair.?.local.base);
    const receive_timeout: Io.Timeout = .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(5) } };

    const buffer = try agent.buffer_pool.create(agent.allocator);
    defer agent.buffer_pool.destroy(buffer);

    var stun_indication: [20]u8 = undefined;
    const dest = &agent.nominated_pair.?.remote.address;

    select.async(.message, Io.net.Socket.receiveTimeout, .{ socket, agent.io, &(buffer.*), receive_timeout });
    select.async(.keep_alive, Io.sleep, .{ agent.io, Io.Duration.fromSeconds(2), Io.Clock.awake });

    while (true) switch (try select.await()) {
        .message => |maybe_msg| {
            const msg = maybe_msg catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.Timeout => {
                    if (agent.state != .disconnected) {
                        Logger.warn("Agent state transitioned to disconnected", .{});
                        agent.state = .disconnected;
                    }
                    continue;
                },
                else => return,
            };

            select.async(.message, Io.net.Socket.receiveTimeout, .{ socket, agent.io, &(buffer.*), receive_timeout });
            if (stun.isMessage(msg.data)) continue;
            try agent.queue.putOne(agent.io, .{ .data = msg.data });
        },
        .keep_alive => |timeout| {
            try timeout;
            select.async(.keep_alive, Io.sleep, .{ agent.io, keep_alive_interval, Io.Clock.awake });
            try socket.send(agent.io, dest, try buildIndicationRequest(&stun_indication));
        },
    };
}

fn listenForMessages(agent: *Agent) !void {
    agent.doListenForMessages() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => {},
    };
}

fn startConnectivityChecks(agent: *Agent) !void {
    while (true) {
        agent.queue.putOne(agent.io, .check_connectivity) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };
        try agent.io.sleep(connectivity_check_interval, .awake);
    }
}

fn doListenForMessages(agent: *Agent) !void {
    const IncomingMessageSelect = Io.Select(Receive);

    var queue: [4]Receive = undefined;
    var select = IncomingMessageSelect.init(agent.io, &queue);
    defer select.cancelDiscard();

    for (agent.sockets, 0..) |*socket, idx| {
        select.async(.message, receive, .{ agent, socket, idx });
    }

    while (true) {
        const result = try select.await();

        const index, const incoming_message = result.message catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => |e| {
                std.log.err("An error occurred when listening on socket: {}", .{e});
                continue;
            },
        };

        const socket = &agent.sockets[index];
        try agent.queue.putOne(agent.io, .{ .message = .{ socket.address, incoming_message } });
        select.async(.message, receive, .{ agent, socket, index });
    }
}

fn doStartChecks(agent: *Agent) !void {
    while (true) {
        const buffer = try agent.buffer_pool.create(agent.allocator);
        defer agent.buffer_pool.destroy(buffer);

        try agent.mutex.lock(agent.io);
        for (agent.pairs.items) |*pair| switch (pair.state.status) {
            .waiting, .in_progress => {
                pair.conn_check_count += 1;
                if (pair.conn_check_count > max_binding_requests) {
                    pair.state.status = .failed;
                    continue;
                }

                const transaction_id = generateTrasactionId(agent.io);
                const msg = try agent.buildBindingRequest(transaction_id, buffer);

                try agent.pending_requests.append(agent.allocator, .{
                    .transaction_id = transaction_id,
                    .source = pair.local.base,
                    .target = pair.remote.address,
                });

                const socket = findSocket(agent.sockets, &pair.local.base);
                try socket.send(agent.io, &pair.remote.address, msg);
            },
            else => {},
        };
        agent.mutex.unlock(agent.io);

        try agent.io.sleep(.fromMilliseconds(200), .awake);
    }
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

fn receive(agent: *Agent, socket: *Socket, index: usize) !struct { usize, Io.net.IncomingMessage } {
    const buffer = try agent.buffer_pool.create(agent.allocator);
    errdefer agent.buffer_pool.destroy(buffer);

    const incoming_message = try socket.receive(agent.io, &(buffer.*));
    return .{ index, incoming_message };
}
