const std = @import("std");
const stun = @import("stun");
const ice = @import("ice.zig");
const Messages = @import("messages.zig");

const IpAddress = std.Io.net.IpAddress;
const RemoteCandidate = ice.agent.RemoteCandidate;
const Server = ice.agent.Server;
const Candidate = ice.Candidate;
const Event = ice.agent.Event;

const testing = std.testing;
var rand = std.Random.DefaultPrng.init(0xDEADBEEF);

const TestAgent = ice.agent.Agent(.{});

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

fn testBuildErrorResponse(tx_id: [12]u8, code: stun.StunErrorCode, reason: []const u8, password: []const u8, buffer: []u8) ![]const u8 {
    var w = stun.Writer.init(buffer, .{ .password = password });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.error_response, .binding),
        .transaction_id = tx_id,
    });
    try w.writeAttribute(.{ .error_code = .{ .code = code, .reason = reason } });
    try w.writeAttribute(.{ .message_integrity = &.{} });
    try w.writeAttribute(.fingerprint);
    return w.final();
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

const test_local_password = "VOkJxbRl1RmTxUk/WvJxBt";
const test_peer_password = "peer-password-0123456789";
const test_new_credentials: ice.Credentials = .{ .username = "user2", .password = "user2-password-0123456789" };
const test_new_peer: ice.Credentials = .{ .username = "peer2", .password = "peer2-password-0123456789" };

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

fn testCompletedAgent(role: ice.Role, relay: bool, addrs: *const TestAddrs) !TestAgent {
    var core = try testNewAgent(role);
    errdefer core.deinit();
    if (relay) {
        try core.addServer(addrs.local, testTurnServer(addrs.server), 0);
        try core.addLocalAddrs(&.{addrs.local}, 0);
        while (core.pollEvent()) |_| {}
    }
    core.connection_state = .completed;
    core.remote_credentials = try .init("peer", test_peer_password);
    core.candidates[0] = if (relay) .initRelay(addrs.local, addrs.relayed) else .initHost(addrs.local);
    core.candidates_len = 1;
    core.remote_candidates[0] = testRemoteCandidate(addrs.remote);
    core.remote_candidates_len = 1;
    core.nominated_pair = .{ .local = 0, .remote = 0 };
    return core;
}

/// Fails unless the message carries a MESSAGE-INTEGRITY that verifies with `password`.
fn expectSignedWith(data: []const u8, password: []const u8) !void {
    const msg = try stun.Message.parse(data);
    var it = msg.iterateAttributes(password);
    var signed = false;
    while (try it.next()) |attr| if (attr == .message_integrity) {
        signed = true;
    };
    try testing.expect(signed);
}

fn testUsername(data: []const u8) ![]const u8 {
    const msg = try stun.Message.parse(data);
    var it = msg.iterateAttributes(&.{});
    while (try it.next()) |attr| if (attr == .username) return attr.username;
    return error.ExpectedAttribute;
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

test "addServer: rejects a turn username longer than the RFC limit" {
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    const local = try IpAddress.parse("10.0.0.10", 4000);
    const address = try IpAddress.parse("203.0.113.1", 3478);
    const username: [stun.turn.max_username_len + 1]u8 = @splat('u');

    const server: Server = .{ .turn = .{ .address = address, .username = &username, .password = "turnpass" } };
    try testing.expectError(error.UsernameTooLong, core.addServer(local, server, 0));
    try testing.expectEqual(0, core.turn_clients.items.len);

    try core.addServer(local, .{ .turn = .{ .address = address, .username = username[1..], .password = "turnpass" } }, 0);
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
            .username = "user:peer",
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

test "close: drops pending events and reports the closed state once" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    try core.setRemoteCredentials(.{ .username = "peer", .password = "peer-password-0123456789" }, 0);
    core.close();
    try expectConnectionStateEvent(&core, .closed);
    try testing.expectEqual(null, core.pollEvent());

    core.close();
    try testing.expectEqual(null, core.pollEvent());
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
    try testing.expectEqual(1000 + ice.agent.keep_alive_interval, core.keep_alive_deadline);

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
        try testing.expectEqual(1000 + ice.agent.keep_alive_interval, core.keep_alive_deadline);
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

test "handleRead: drops non-stun data from an unknown remote before connected" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    const base_addr = try IpAddress.parse("192.168.1.100", 1000);
    const from = try IpAddress.parse("192.168.1.120", 2000);

    const result = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = "hello" }, 0);

    try testing.expectEqual(.consumed, std.meta.activeTag(result));
    try testing.expectEqual(null, core.pollEvent());
}

test "handleRead: forwards non-stun data from a known remote candidate pair" {
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

test "handleRead: forwards non-stun data once connected regardless of sender" {
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

test "handleRead: completed state answers stun requests via consent freshness" {
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
        .username = "user:peer",
    }, core.credentials.getPassword(), &buffer);

    const result = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = msg.bytes }, 0);

    try testing.expectEqual(.consumed, std.meta.activeTag(result));
    try testing.expectEqual(.completed, core.connection_state);

    const resp = (try core.pollTransmit(&resp_buffer)) orelse return error.ExpectedTransmit;
    const resp_msg = try stun.Message.parse(resp.data);
    try testing.expectEqual(.success_response, resp_msg.header.message_type.class());

    try testing.expectEqual(null, core.pollEvent());
}

test "handleRead: stun request produces a response event" {
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
        .username = "user:peer",
    }, core.credentials.getPassword(), &buffer);

    _ = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = msg.bytes }, 0);

    const resp = (try core.pollTransmit(&resp_buffer)) orelse return error.ExpectedTransmit;
    const resp_msg = try stun.Message.parse(resp.data);
    try testing.expectEqual(.success_response, resp_msg.header.message_type.class());

    try testing.expectEqual(null, (try core.pollTransmit(&resp_buffer)));
    try expectEvent(&core, .candidate);
    try testing.expectEqual(1, core.pairs.items.len);
}

test "handleRead: role conflict switches role and produces a response" {
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
        .username = "user:peer",
    }, core.credentials.getPassword(), &buffer);

    _ = try core.handleRead(.{ .from = &from, .to = &base_addr, .data = msg.bytes }, 0);

    try testing.expectEqual(.controlling, core.role);

    const resp = (try core.pollTransmit(&resp_buffer)) orelse return error.ExpectedTransmit;
    const resp_msg = try stun.Message.parse(resp.data);
    try testing.expectEqual(.success_response, resp_msg.header.message_type.class());

    try expectEvent(&core, .candidate);
    try testing.expectEqual(null, core.pollEvent());
}

test "handleRead: success response completes the pending request and marks the pair succeeded" {
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

test "handleRead: success response nominates the pair and transitions to connected" {
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

    try testing.expectEqual(@as(i64, ice.agent.keep_alive_interval), core.keep_alive_deadline);
    try testing.expectEqual(@as(i64, core.timers.disconnected_timeout), core.disconnected_connection_deadline);
}

test "handleRead: handle role conflict error response" {
    var agent = try testNewAgent(.controlling);
    defer agent.deinit();

    _ = try agent.addLocalCandidate(.initHost(.{ .ip4 = .loopback(10000) }));
    _ = try agent.addRemoteCandidate(.initHost(.{ .ip4 = .loopback(20000) }), 0);
    _ = try agent.addRemoteCandidate(.initHost(.{ .ip4 = .loopback(20001) }), 0);
    try agent.setRemoteCredentials(test_new_credentials, 0);

    var buffer: [1024]u8 = undefined;
    var resp = try testBuildErrorResponse(
        @splat(0xee),
        .role_conflict,
        "",
        agent.remote_credentials.?.getPassword(),
        &buffer,
    );

    var result = try agent.handleRead(.{ .from = &.{ .ip4 = .loopback(20000) }, .to = &agent.candidates[0].base, .data = resp }, 0);
    try testing.expectEqual(.consumed, result);
    try testing.expectEqual(.controlling, agent.role);

    const req = try agent.pollTransmit(&buffer) orelse return error.TestFailed; // connectivity check request
    const req2 = try agent.pollTransmit(&buffer) orelse return error.TestFailed; // connectivity check request

    for (&[_]stun.TransportMessage{ req, req2 }) |r| {
        resp = try testBuildErrorResponse(
            r.data[8..20].*,
            .role_conflict,
            "",
            agent.remote_credentials.?.getPassword(),
            &buffer,
        );
        result = try agent.handleRead(.{ .from = r.to, .to = r.from, .data = resp }, 0);
        try testing.expectEqual(.controlled, agent.role);
        try testing.expectEqual(0, agent.pending_requests.items.len);
    }
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

test "setRemoteCredentials: same is a no-op, changed requires restart" {
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    try core.setRemoteCredentials(.{ .username = "first", .password = "first-password-0123456789" }, 0);
    try core.setRemoteCredentials(.{ .username = "first", .password = "first-password-0123456789" }, 0);
    try testing.expectError(
        error.RestartRequired,
        core.setRemoteCredentials(.{ .username = "second", .password = "second-password-0123456789" }, 0),
    );
    try testing.expectError(
        error.InvalidCredentials,
        core.setRemoteCredentials(.{ .username = "first", .password = "second-password-0123456789" }, 0),
    );
    try testing.expectEqualStrings("first", core.remote_credentials.?.getUsername());
    try testing.expectEqualStrings("first-password-0123456789", core.remote_credentials.?.getPassword());
}

test "pollTransmit: sends the nomination request once per connectivity check" {
    var tx_buf: [1024]u8 = undefined;
    var core = try testNewAgent(.controlling);
    defer core.deinit();

    try core.addLocalAddrs(&.{try IpAddress.parse("192.168.1.100", 1000)}, 0);
    try core.addRemoteCandidate(.initHost(try IpAddress.parse("192.168.1.120", 2000)), 0);
    try core.setRemoteCredentials(.{ .username = "peer", .password = "peer-password-0123456789" }, 0);

    core.selected_pair = 0;
    core.connectivity_check = .init;

    const nomination = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    try testing.expectEqual(.request, (try stun.Message.parse(nomination.data)).header.message_type.class());
    try testing.expect(core.connectivity_check.nomination_done);

    var count: usize = 0;
    while (try core.pollTransmit(&tx_buf)) |_| : (count += 1) {
        if (count > core.pairs.items.len) return error.TestUnexpectedResult;
    }
    try testing.expect(core.connectivity_check.done);
}

test "pollTransmit: pair fails after max_binding_requests connectivity checks" {
    var tx_buf: [1024]u8 = undefined;
    var core = try testNewAgent(.controlled);
    defer core.deinit();

    try core.addLocalAddrs(&.{try IpAddress.parse("192.168.1.100", 1000)}, 0);
    try core.addRemoteCandidate(.initHost(try IpAddress.parse("192.168.1.120", 2000)), 0);
    try core.setRemoteCredentials(.{ .username = "peer", .password = "peer-password-0123456789" }, 0);

    for (0..ice.agent.max_binding_requests) |_| {
        core.connectivity_check = .init;
        _ = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
        try testing.expectEqual(null, try core.pollTransmit(&tx_buf));
    }

    core.connectivity_check = .init;
    try testing.expectEqual(null, try core.pollTransmit(&tx_buf));
    try testing.expectEqual(.failed, core.pairs.items[0].status);
    try testing.expect(core.connectivity_check.done);
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

test "handleWrite: adds turn header in place and passes host data through" {
    var agent = try testNewAgent(.controlling);
    defer agent.deinit();

    const local = try IpAddress.parse("10.0.0.10", 4000);
    const host = try IpAddress.parse("10.0.0.11", 4000);
    const server = try IpAddress.parse("203.0.113.1", 3478);
    const relayed = try IpAddress.parse("203.0.113.1", 10900);
    const remote = try IpAddress.parse("192.168.1.10", 1000);
    try agent.addLocalAddrs(&.{host}, 0);
    try agent.addServer(local, testTurnServer(server), 0);
    try agent.addRemoteCandidate(.initHost(remote), 0);

    // simulate a successful allocation so that the relay candidate is present
    const relay_index = try agent.addLocalCandidate(.initRelay(local, relayed)) orelse return error.ExpectedCandidate;

    const payload = "hello";
    var buffer: [128]u8 = undefined;

    {
        agent.nominated_pair = .{ .local = 0, .remote = 0 };

        const offset, const size = agent.getDataFrameSize(payload.len);
        try testing.expectEqual(0, offset);
        try testing.expectEqual(payload.len, size);

        @memcpy(buffer[0..payload.len], payload);
        const msg = try agent.handleWrite(&buffer, payload.len);
        try testing.expectEqualSlices(u8, payload, msg.data);
    }

    agent.nominated_pair = .{ .local = relay_index, .remote = 0 };
    const offset, const size = agent.getDataFrameSize(payload.len);
    try testing.expectEqual(36, offset);

    @memcpy(buffer[offset..][0..payload.len], payload);
    const msg = try agent.handleWrite(&buffer, payload.len);
    try testing.expectEqual(size, msg.data.len);
    try testing.expectEqualSlices(u8, payload, msg.data[offset..][0..payload.len]);
    try testing.expect(std.mem.allEqual(u8, msg.data[offset + payload.len ..], 0));
    try testing.expect(msg.from.eql(&local));
    try testing.expect(msg.to.eql(&server));

    const indication = try stun.Message.parse(msg.data);
    try testing.expectEqual(.send, indication.header.message_type.method());
    try testing.expectEqual(.indication, indication.header.message_type.class());
    var it = indication.iterateAttributes(&.{});
    const attr = try it.next() orelse return error.ExpectedAttribute;
    try testing.expect(attr.xor_peer_address.eql(&remote));

    try testing.expectError(error.WriteFailed, agent.handleWrite(buffer[0 .. size - 1], payload.len));
}

test "stageRestart/discardRestart/applyRestart: staged credentials are advertised without touching the live session" {
    const addrs = try TestAddrs.init();
    var core = try testCompletedAgent(.controlling, false, &addrs);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var tx_buf: [1024]u8 = undefined;

    try core.applyRestart(0); // nothing staged
    try testing.expectEqual(null, core.ice_restart);

    const too_long: [65]u8 = @splat('a');
    try testing.expectError(error.CredentialsTooLong, core.stageRestart(.{ .username = &too_long, .password = "x" }));
    try core.stageRestart(.{ .username = "first", .password = "first-password-0123456789" });
    try core.stageRestart(test_new_credentials);
    try testing.expectEqualStrings("user2", core.getLocalCredentials().username);
    try testing.expectEqualStrings("user", core.credentials.getUsername());

    // The live session still authenticates with the current credentials.
    const req = try testBuildRequest(.{ .ice_controlled = 1, .username = "user:peer" }, test_local_password, &buffer);
    _ = try core.handleRead(.{ .from = &addrs.remote, .to = &addrs.local, .data = req.bytes }, 0);
    const resp = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    try expectSignedWith(resp.data, test_local_password);

    core.discardRestart();
    try testing.expectEqualStrings("user", core.getLocalCredentials().username);
    try core.applyRestart(0);
    try testing.expectEqual(null, core.ice_restart);

    try core.stageRestart(test_new_credentials);
    core.close();
    try testing.expectEqual(null, core.pending_credentials);
    try testing.expectError(error.Closed, core.stageRestart(test_new_credentials));
}

test "applyRestart: the new generation's nomination ends the restart" {
    const addrs = try TestAddrs.init();
    var core = try testCompletedAgent(.controlled, false, &addrs);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var tx_buf: [1024]u8 = undefined;

    try core.restart(test_new_credentials, 0);
    try core.setRemoteCredentials(test_new_peer, 0);
    _ = try core.addLocalCandidate(.initHost(addrs.new_local));
    try core.addRemoteCandidate(.initHost(addrs.new_remote), 0);

    // New-generation requests are answered with the new password.
    const req = try testBuildRequest(.{ .ice_controlling = 1, .username = "user2:peer2" }, test_new_credentials.password, &buffer);
    _ = try core.handleRead(.{ .from = &addrs.new_remote, .to = &addrs.new_local, .data = req.bytes }, 0);
    const resp = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    try expectSignedWith(resp.data, test_new_credentials.password);

    core.pairs.items[0].nominate_on_binding = true;
    try core.pending_requests.append(testing.allocator, .{ .transaction_id = @splat(2), .pair = 0 });
    const success = try testBuildResponse(@splat(2), addrs.new_local, test_new_peer.password, &buffer);
    _ = try core.handleRead(.{ .from = &addrs.new_remote, .to = &addrs.new_local, .data = success.bytes }, 0);

    try expectEvent(&core, .nominated);
    try expectConnectionStateEvent(&core, .connected);
    try testing.expectEqual(null, core.ice_restart);

    const data = try core.handleWrite(&buffer, 4);
    try testing.expect(data.from.eql(&addrs.new_local) and data.to.eql(&addrs.new_remote));
}

test "applyRestart: a checking or failed agent keeps no pair and checks once the new remote credentials arrive" {
    const addrs = try TestAddrs.init();
    var tx_buf: [1024]u8 = undefined;

    for ([_]ice.ConnectionState{ .checking, .failed }) |state| {
        var core = try testNewAgent(.controlling);
        defer core.deinit();
        core.connection_state = state;
        core.remote_credentials = try .init("peer", test_peer_password);

        try core.restart(test_new_credentials, 0);
        try testing.expectEqual(null, core.ice_restart);
        try testing.expectEqual(null, core.remote_credentials);

        // Checks wait for the peer's new credentials.
        _ = try core.addLocalCandidate(.initHost(addrs.local));
        try core.addRemoteCandidate(.initHost(addrs.remote), 0);
        core.connectivity_check = .init;
        try testing.expectEqual(null, try core.pollTransmit(&tx_buf));

        try core.setRemoteCredentials(test_new_peer, 0);
        try testing.expectEqual(.checking, core.connection_state);
        const check = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
        try testing.expect(check.to.eql(&addrs.remote));
        try testing.expectEqualStrings("peer2:user2", try testUsername(check.data));
        try expectSignedWith(check.data, test_new_peer.password);
    }
}

test "handleTimeout: losing the pre-restart pair hands over to the new generation" {
    const addrs = try TestAddrs.init();
    var tx_buf: [1024]u8 = undefined;

    for ([_]bool{ true, false }) |has_remote_credentials| {
        var core = try testCompletedAgent(.controlling, false, &addrs);
        defer core.deinit();
        core.connection_state = .disconnected;

        try core.restart(test_new_credentials, 0);
        if (has_remote_credentials) try core.setRemoteCredentials(test_new_peer, 0);
        core.consent_freshness = true;
        core.disconnected_connection_deadline = 1000;

        try core.handleTimeout(1000);

        const expected: ice.ConnectionState = if (has_remote_credentials) .checking else .failed;
        try expectConnectionStateEvent(&core, expected);
        try testing.expectEqual(null, core.ice_restart);
        try testing.expectEqual(null, try core.pollTransmit(&tx_buf)); // no consent without a pair
    }
}

test "handleRead: only an authenticated response to the last consent request refreshes consent" {
    const addrs = try TestAddrs.init();
    var core = try testCompletedAgent(.controlling, false, &addrs);
    defer core.deinit();

    var buffer: [1024]u8 = undefined;
    var tx_buf: [1024]u8 = undefined;

    core.connection_state = .disconnected;
    core.disconnected_connection_deadline = 500;
    core.consent_freshness = true;
    const consent = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    const tx_id = (try stun.Message.parse(consent.data)).header.transaction_id;

    const wrong_tx = try testBuildResponse(@splat(9), addrs.local, test_peer_password, &buffer);
    _ = try core.handleRead(.{ .from = &addrs.remote, .to = &addrs.local, .data = wrong_tx.bytes }, 100);
    const wrong_password = try testBuildResponse(tx_id, addrs.local, "wrong-password-012345678", &buffer);
    _ = try core.handleRead(.{ .from = &addrs.remote, .to = &addrs.local, .data = wrong_password.bytes }, 100);
    try testing.expectEqual(.disconnected, core.connection_state);
    try testing.expectEqual(500, core.disconnected_connection_deadline);

    const valid = try testBuildResponse(tx_id, addrs.local, test_peer_password, &buffer);
    _ = try core.handleRead(.{ .from = &addrs.remote, .to = &addrs.local, .data = valid.bytes }, 100);
    try expectConnectionStateEvent(&core, .completed);
    try testing.expectEqual(@as(i64, 100 + core.timers.disconnected_timeout), core.disconnected_connection_deadline);
    try testing.expectEqual(null, core.consent_tx_id);

    // Consent lost for good: a late response doesn't revive a failed agent.
    core.connection_state = .failed;
    core.disconnected_connection_deadline = std.math.maxInt(i64);
    core.consent_tx_id = tx_id;
    _ = try core.handleRead(.{ .from = &addrs.remote, .to = &addrs.local, .data = valid.bytes }, 200);
    try testing.expectEqual(.failed, core.connection_state);
    try testing.expectEqual(std.math.maxInt(i64), core.disconnected_connection_deadline);
}

test "handleRead: unauthenticated requests get a 401 from known senders only" {
    const addrs = try TestAddrs.init();
    var buffer: [1024]u8 = undefined;
    var tx_buf: [1024]u8 = undefined;

    // Wrong ufrag, then wrong password, in completed (consent) and checking (connectivity checks).
    const requests = [_]struct { username: []const u8, password: []const u8 }{
        .{ .username = "other:peer", .password = test_local_password },
        .{ .username = "user:peer", .password = "wrong-password-0123456789" },
    };

    for ([_]ice.ConnectionState{ .completed, .checking }) |state| for (requests) |r| {
        var core = try testCompletedAgent(.controlling, false, &addrs);
        defer core.deinit();
        if (state == .checking) {
            core.nominated_pair = null;
            core.connection_state = .checking;
        }

        const req = try testBuildRequest(.{ .ice_controlled = 1, .username = r.username }, r.password, &buffer);
        _ = try core.handleRead(.{ .from = &addrs.other, .to = &addrs.local, .data = req.bytes }, 0);
        try testing.expectEqual(null, try core.pollTransmit(&tx_buf));

        _ = try core.handleRead(.{ .from = &addrs.remote, .to = &addrs.local, .data = req.bytes }, 0);
        const resp = (try core.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
        try testing.expect(resp.from.eql(&addrs.local) and resp.to.eql(&addrs.remote));

        const msg = try stun.Message.parse(resp.data);
        try testing.expectEqual(.error_response, msg.header.message_type.class());
        var it = msg.iterateAttributes(&.{});
        try testing.expectEqual(.unauthorized, (try it.next()).?.error_code.code);
        try testing.expectEqual(0, core.pairs.items.len);
    };
}

test "applyRestart: a completed agent keeps the pre-restart pair for data and consent" {
    const addrs = try TestAddrs.init();
    var agent = try testCompletedAgent(.controlling, false, &addrs);
    defer agent.deinit();

    var buffer: [1024]u8 = undefined;
    var tx_buf: [1024]u8 = undefined;

    // Queue a response to the previous generation.
    const req = try testBuildRequest(.{ .ice_controlled = 1, .username = "user:peer" }, test_local_password, &buffer);
    _ = try agent.handleRead(.{ .from = &addrs.remote, .to = &addrs.local, .data = req.bytes }, 0);
    try agent.restart(test_new_credentials, 0);

    try testing.expect(agent.ice_restart != null);
    try testing.expectEqual(.completed, agent.connection_state);
    try testing.expectEqual(null, agent.pollEvent());
    try testing.expectEqual(null, agent.remote_credentials);
    try testing.expectEqual(null, agent.nominated_pair);
    try testing.expectEqual(0, agent.candidates_len);
    try testing.expectEqual(0, agent.remote_candidates_len);
    try testing.expectEqual(.new, agent.gathering_state);
    try testing.expectEqual(null, try agent.pollTransmit(&tx_buf)); // previous generation's response dropped

    // Data and consent still use the pre-restart pair and credentials.
    const data = try agent.handleWrite(&buffer, 4);
    try testing.expect(data.from.eql(&addrs.local) and data.to.eql(&addrs.remote));

    agent.consent_freshness = true;
    const consent = (try agent.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    try testing.expect(consent.to.eql(&addrs.remote));
    try testing.expectEqualStrings("peer:user", try testUsername(consent.data));
    try expectSignedWith(consent.data, test_peer_password);

    // Old-credentials requests are answered on the pre-restart pair only.
    _ = try agent.handleRead(.{ .from = &addrs.other, .to = &addrs.local, .data = req.bytes }, 0);
    try testing.expectEqual(null, try agent.pollTransmit(&tx_buf));

    _ = try agent.handleRead(.{ .from = &addrs.remote, .to = &addrs.local, .data = req.bytes }, 0);
    const resp = (try agent.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    try testing.expect(resp.from.eql(&addrs.local) and resp.to.eql(&addrs.remote));
    try expectSignedWith(resp.data, test_local_password);

    // The new generation's checks start without changing the reported state.
    try agent.setRemoteCredentials(test_new_peer, 100);
    try testing.expectEqual(.completed, agent.connection_state);
    try testing.expectEqual(null, agent.pollEvent());
    try testing.expect(!agent.connectivity_check.done);
    try testing.expectEqual(@as(i64, 100 + agent.timers.connectivity_check_interval), agent.connectivity_check_deadline);
}

test "applyRestart: a relayed pre-restart pair keeps its TURN client running" {
    const addrs = try TestAddrs.init();
    var agent = try testCompletedAgent(.controlling, true, &addrs);
    defer agent.deinit();

    var buffer: [1024]u8 = undefined;
    var tx_buf: [1024]u8 = undefined;

    try agent.restart(test_new_credentials, 0);
    try testing.expectEqual(0, agent.turn_clients.items.len);
    const turn_client = &agent.ice_restart.?.nominated_pair.relay;

    // Its requests, timers and responses are still served.
    const allocate = (try agent.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    try testing.expect(allocate.from.eql(&addrs.local) and allocate.to.eql(&addrs.server));
    try testing.expectEqual(turn_client.pollTimeout(), agent.pollTimeout());

    const tx_id = (try stun.Message.parse(allocate.data)).header.transaction_id;
    const allocated = try testTurnAllocateSuccessResponse(&buffer, tx_id, addrs.relayed, addrs.local, 600);
    const result = try agent.handleRead(.{ .from = &addrs.server, .to = &addrs.local, .data = allocated }, 0);
    try testing.expectEqual(.consumed, std.meta.activeTag(result));
    try testing.expect(turn_client.hasAllocation());

    // Consent and data are relayed to the pre-restart peer.
    agent.consent_freshness = true;
    const consent = (try agent.pollTransmit(&tx_buf)) orelse return error.ExpectedTransmit;
    try testing.expect(consent.from.eql(&addrs.local) and consent.to.eql(&addrs.server));
    const indication = try stun.Message.parse(consent.data);
    try testing.expectEqual(.send, indication.header.message_type.method());
    var it = indication.iterateAttributes(&.{});
    const attr = try it.next() orelse return error.ExpectedAttribute;
    try testing.expect(attr.xor_peer_address.eql(&addrs.remote));

    const data = try agent.handleWrite(&buffer, 4);
    try testing.expect(data.to.eql(&addrs.server));
}
