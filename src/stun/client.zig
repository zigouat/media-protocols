const std = @import("std");
const stun = @import("stun.zig");

const IpAddress = std.Io.net.IpAddress;

const Transaction = struct {
    id: u96,
    attempt: u8,
    payload_len: u16,
    deadline: i64,
};

fn Transactions(comptime max_transactions: u32, comptime max_payload_size: u32) type {
    return struct {
        const Self = @This();

        items: [max_transactions]Transaction,
        req_payload: [max_payload_size * max_transactions]u8,
        current_index: u32,

        const init = Self{ .items = undefined, .req_payload = undefined, .current_index = 0 };

        fn add(self: *Self) error{Overflow}!struct { usize, []u8 } {
            if (self.current_index >= max_transactions) return error.Overflow;
            const idx = self.current_index;
            self.current_index += 1;
            return .{ idx, self.getBuffer(idx, max_payload_size) };
        }

        fn remove(self: *Self, idx: usize) void {
            self.current_index -= 1;
            const last = self.current_index;
            if (idx == last) return;

            self.items[idx] = self.items[last];
            @memcpy(self.getBuffer(idx, max_payload_size), self.getBuffer(last, max_payload_size));
        }

        fn find(self: *Self, tx_id: u96) ?usize {
            for (self.items[0..self.current_index], 0..) |tr, idx| if (tr.id == tx_id) return idx;
            return null;
        }

        fn getBuffer(self: *Self, index: usize, payload_len: u32) []u8 {
            const start = index * max_payload_size;
            return self.req_payload[start .. start + payload_len];
        }

        fn slice(self: *Self) []Transaction {
            return self.items[0..self.current_index];
        }
    };
}

pub const Event = union(enum) {
    mapped_address: IpAddress,
    err: anyerror,
};

pub const Config = struct {
    local_addr: IpAddress,
    remote_addr: IpAddress,
    random: std.Random,
};

pub const ClientConfig = struct {
    max_payload_size: u32 = 64,
    max_transactions: u32 = 8,
};

pub fn Client(comptime config: ClientConfig) type {
    return struct {
        const Self = @This();

        pub const base_rto = 200; // milliseconds
        const max_attempts = 7;

        local_addr: IpAddress,
        remote_addr: IpAddress,
        random: std.Random,
        transactions: Transactions(config.max_transactions, config.max_payload_size),
        transmits: stun.BoundedDeque(stun.TransportMessage, config.max_transactions),
        events_out: stun.BoundedDeque(Event, config.max_transactions),

        pub fn init(cfg: Config) Self {
            return .{
                .local_addr = cfg.local_addr,
                .remote_addr = cfg.remote_addr,
                .random = cfg.random,
                .transactions = .init,
                .events_out = .empty,
                .transmits = .empty,
            };
        }

        pub fn bindingRequest(c: *Self, now: i64) !void {
            const id, const buffer = try c.transactions.add();
            const tr = &c.transactions.items[id];
            tr.id = c.random.int(u96);
            tr.attempt = 0;

            var out = stun.Writer.init(buffer, .{});
            try out.writeHeader(.{
                .message_type = .fromClassAndMethod(.request, .binding),
                .transaction_id = tr.id,
                .message_length = 0,
            });
            tr.payload_len = @intCast(out.final().len);
            tr.deadline = now + base_rto;

            try c.transmits.pushBack(.{
                .from = &c.local_addr,
                .to = &c.remote_addr,
                .data = buffer[0..tr.payload_len],
            });
        }

        pub fn handleRead(c: *Self, data: []const u8) !void {
            const msg = try stun.Message.parse(data);
            if (c.transactions.find(msg.header.transaction_id)) |idx| {
                c.transactions.remove(idx);
                const mapped_addr = try getMappedAddress(&msg) orelse return;
                try c.events_out.pushBack(.{ .mapped_address = mapped_addr });
            }
        }

        pub fn handleTimeout(c: *Self, now: i64) !void {
            var idx: usize = c.transactions.current_index;
            while (idx > 0) {
                idx -= 1;
                const tr = &c.transactions.items[idx];
                if (tr.deadline > now) continue;

                tr.attempt += 1;
                if (tr.attempt >= max_attempts) {
                    try c.events_out.pushBack(.{ .err = error.TransactionTimeout });
                    c.transactions.remove(idx);
                } else {
                    tr.deadline = now + @as(i64, tr.attempt + 1) * base_rto;
                    try c.transmits.pushBack(.{
                        .from = &c.local_addr,
                        .to = &c.remote_addr,
                        .data = c.transactions.getBuffer(idx, tr.payload_len),
                    });
                }
            }
        }

        pub fn pollEvent(c: *Self) ?Event {
            return c.events_out.popFront();
        }

        pub fn pollTransmit(c: *Self) ?stun.TransportMessage {
            return c.transmits.popFront();
        }

        pub fn pollTimeout(c: *Self) ?i64 {
            var next_deadline: i64 = std.math.maxInt(i64);
            for (c.transactions.slice()) |tr| next_deadline = @min(next_deadline, tr.deadline);
            if (next_deadline == std.math.maxInt(i64)) return null;
            return next_deadline;
        }
    };
}

fn getMappedAddress(msg: *const stun.Message) !?IpAddress {
    var it = msg.iterateAttributes(&.{});
    while (try it.next()) |attr| switch (attr) {
        .xor_mapped_address, .mapped_address => |addr| return addr,
        else => {},
    };
    return null;
}

const testing = std.testing;

const test_local_addr: IpAddress = .{ .ip4 = .loopback(1000) };
const test_remote_addr: IpAddress = .{ .ip4 = .loopback(2000) };

const TestClient = Client(.{});

fn testClient(random: std.Random) TestClient {
    return TestClient.init(.{ .local_addr = test_local_addr, .remote_addr = test_remote_addr, .random = random });
}

fn testBindingRequest(buffer: []u8, tx_id: u96) ![]const u8 {
    var out = stun.Writer.init(buffer, .{});
    try out.writeHeader(.{
        .message_type = .fromClassAndMethod(.request, .binding),
        .transaction_id = tx_id,
        .message_length = 0,
    });
    return out.final();
}

fn testBindingSuccessResponse(buffer: []u8, tx_id: u96, addr: IpAddress) ![]const u8 {
    var out = stun.Writer.init(buffer, .{});
    try out.writeHeader(.{
        .message_type = .fromClassAndMethod(.success_response, .binding),
        .transaction_id = tx_id,
        .message_length = 0,
    });
    try out.writeAttribute(.{ .xor_mapped_address = addr });
    return out.final();
}

test "bindingRequest: queues transmit and stores transaction" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var client = testClient(prng.random());

    try client.bindingRequest(100);

    try testing.expectEqual(1, client.transactions.current_index);
    const tr = client.transactions.items[0];
    try testing.expectEqual(0, tr.attempt);
    try testing.expectEqual(100 + TestClient.base_rto, tr.deadline);

    const tm = client.pollTransmit() orelse return error.ExpectedTransmit;
    try testing.expect(tm.from == &client.local_addr);
    try testing.expect(tm.to == &client.remote_addr);

    const msg = try stun.Message.parse(tm.data);
    try testing.expectEqual(.request, msg.header.message_type.class());
    try testing.expectEqual(.binding, msg.header.message_type.method());
    try testing.expectEqual(tr.id, msg.header.transaction_id);

    try testing.expectEqual(null, client.pollTransmit());
}

test "handleRead: matches pending transaction and emits mapped_address event" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var client = testClient(prng.random());

    try client.bindingRequest(0);
    const tx_id = client.transactions.items[0].id;
    _ = client.pollTransmit();

    const expected_addr: IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 32853 } };
    var buf: [64]u8 = undefined;
    try client.handleRead(try testBindingSuccessResponse(&buf, tx_id, expected_addr));

    try testing.expectEqual(0, client.transactions.current_index);
    const event = client.pollEvent() orelse return error.ExpectedEvent;
    try testing.expect(event.mapped_address.eql(&expected_addr));
    try testing.expectEqual(null, client.pollEvent());
}

test "handleRead: unknown transaction produces no event" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var client = testClient(prng.random());

    var buf: [stun.header_size]u8 = undefined;
    try client.handleRead(try testBindingRequest(&buf, 0xABC));

    try testing.expectEqual(null, client.pollEvent());
}

test "handleRead: invalid stun message returns error" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var client = testClient(prng.random());

    try testing.expectError(error.WrongMagicCookie, client.handleRead(&([_]u8{0} ** stun.header_size)));
}

test "handleTimeout: does nothing before the deadline" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var client = testClient(prng.random());

    try client.bindingRequest(0);
    _ = client.pollTransmit();

    try client.handleTimeout(TestClient.base_rto - 1);
    try testing.expectEqual(null, client.pollEvent());
    try testing.expectEqual(null, client.pollTransmit());

    const tr = client.transactions.items[0];
    try testing.expectEqual(0, tr.attempt);
    try testing.expectEqual(TestClient.base_rto, tr.deadline);
}

test "handleTimeout: retransmits and backs off before max attempts" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var client = testClient(prng.random());

    try client.bindingRequest(0);
    const original = client.pollTransmit() orelse return error.ExpectedTransmit;
    var original_buf: [64]u8 = undefined;
    @memcpy(original_buf[0..original.data.len], original.data);

    try client.handleTimeout(TestClient.base_rto);

    const tr = client.transactions.items[0];
    try testing.expectEqual(1, tr.attempt);
    try testing.expectEqual(TestClient.base_rto + 2 * TestClient.base_rto, tr.deadline);
    try testing.expectEqual(TestClient.base_rto + 2 * TestClient.base_rto, client.pollTimeout());

    const retransmit = client.pollEvent();
    try testing.expectEqual(null, retransmit);

    const tm = client.pollTransmit() orelse return error.ExpectedTransmit;
    try testing.expectEqualSlices(u8, original_buf[0..original.data.len], tm.data);
    try testing.expectEqual(null, client.pollTransmit());
}

test "handleTimeout: emits err event and drops transaction after max attempts" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var client = testClient(prng.random());

    try client.bindingRequest(0);
    _ = client.pollTransmit();

    var now: i64 = TestClient.base_rto;
    for (0..TestClient.max_attempts - 1) |_| {
        try client.handleTimeout(now);
        _ = client.pollTransmit();
        now = client.transactions.items[0].deadline;
    }

    try client.handleTimeout(now);

    try testing.expectEqual(0, client.transactions.current_index);
    const event = client.pollEvent() orelse return error.ExpectedEvent;
    try testing.expectEqual(error.TransactionTimeout, event.err);
    try testing.expectEqual(null, client.pollEvent());
}

test "poll*: return null when empty" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var client = testClient(prng.random());

    try testing.expectEqual(null, client.pollEvent());
    try testing.expectEqual(null, client.pollTransmit());
    try testing.expectEqual(null, client.pollTimeout());
}
