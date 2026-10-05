const std = @import("std");
const stun = @import("stun.zig");

const IpAddress = std.Io.net.IpAddress;
const AllocError = std.mem.Allocator.Error;

const Transaction = struct {
    id: [12]u8,
    attempt: u8,
    deadline: i64,

    const empty = Transaction{
        .id = @splat(0),
        .attempt = 0,
        .deadline = 0,
    };
};

fn Transactions(comptime max_transactions: u32) type {
    return struct {
        const Self = @This();

        items: [max_transactions]Transaction,
        current_index: u32,

        const init = Self{ .items = @splat(.empty), .current_index = 0 };

        fn add(self: *Self) AllocError!u32 {
            if (self.current_index >= max_transactions) return error.OutOfMemory;
            const idx = self.current_index;
            self.current_index += 1;
            return @intCast(idx);
        }

        fn remove(self: *Self, idx: usize) void {
            self.current_index -= 1;
            const last = self.current_index;
            if (idx == last) return;
            self.items[idx] = self.items[last];
        }

        fn find(self: *Self, tx_id: u96) ?usize {
            const tx: [12]u8 = @bitCast(tx_id);
            for (self.items[0..self.current_index], 0..) |tr, idx| if (std.mem.eql(u8, &tx, &tr.id)) return idx;
            return null;
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
        transactions: Transactions(config.max_transactions),
        transmits: stun.BoundedDeque(u32, config.max_transactions),
        events: stun.BoundedDeque(Event, config.max_transactions),

        pub fn init(cfg: Config) Self {
            return .{
                .local_addr = cfg.local_addr,
                .remote_addr = cfg.remote_addr,
                .random = cfg.random,
                .transactions = .init,
                .events = .empty,
                .transmits = .empty,
            };
        }

        pub fn bindingRequest(c: *Self, now: i64) AllocError!void {
            const id = try c.transactions.add();
            const tr = &c.transactions.items[id];
            tr.id = @bitCast(c.random.int(u96));
            tr.attempt = 0;
            tr.deadline = now + base_rto;
            try c.transmits.pushBack(@intCast(id));
        }

        pub fn handleRead(c: *Self, data: []const u8) AllocError!bool {
            const msg = stun.Message.parse(data) catch return false;
            if (c.transactions.find(msg.header.transaction_id)) |idx| {
                c.transactions.remove(idx);
                const mapped_addr = (getMappedAddress(&msg) catch return false) orelse return false;
                try c.events.pushBack(.{ .mapped_address = mapped_addr });
                return true;
            }

            return false;
        }

        pub fn handleTimeout(c: *Self, now: i64) AllocError!void {
            var idx: usize = c.transactions.current_index;
            while (idx > 0) {
                idx -= 1;
                const tr = &c.transactions.items[idx];
                if (tr.deadline > now) continue;

                tr.attempt += 1;
                if (tr.attempt >= max_attempts) {
                    try c.events.pushBack(.{ .err = error.TransactionTimeout });
                    c.transactions.remove(idx);
                } else {
                    tr.deadline = now + @as(i64, tr.attempt + 1) * base_rto;
                    try c.transmits.pushBack(@intCast(idx));
                }
            }
        }

        pub fn pollEvent(c: *Self) ?Event {
            return c.events.popFront();
        }

        pub fn pollTransmit(c: *Self, buffer: []u8) error{WriteFailed}!?stun.TransportMessage {
            const transaction_id = c.transmits.popFront() orelse return null;
            const tr = &c.transactions.items[transaction_id];
            var out = stun.Writer.init(buffer, .{});
            try out.writeHeader(.{
                .message_type = .fromClassAndMethod(.request, .binding),
                .transaction_id = @bitCast(tr.id),
                .message_length = 0,
            });

            return .{
                .from = &c.local_addr,
                .to = &c.remote_addr,
                .data = out.final(),
            };
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

test "StunClient.bindingRequest: queues transmit and stores transaction" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var client = testClient(prng.random());

    try client.bindingRequest(100);

    try testing.expectEqual(1, client.transactions.current_index);
    const tr = client.transactions.items[0];
    try testing.expectEqual(0, tr.attempt);
    try testing.expectEqual(100 + TestClient.base_rto, tr.deadline);

    var buffer: [64]u8 = undefined;
    const tm = try client.pollTransmit(&buffer) orelse return error.ExpectedTransmit;
    try testing.expect(tm.from == &client.local_addr);
    try testing.expect(tm.to == &client.remote_addr);

    const msg = try stun.Message.parse(tm.data);
    try testing.expectEqual(.request, msg.header.message_type.class());
    try testing.expectEqual(.binding, msg.header.message_type.method());
    try testing.expectEqualSlices(u8, &tr.id, &@as([12]u8, @bitCast(msg.header.transaction_id)));

    try testing.expectEqual(null, try client.pollTransmit(&buffer));
}

test "StunClient.handleRead: matches pending transaction and emits mapped_address event" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var client = testClient(prng.random());

    try client.bindingRequest(0);
    const tx_id = client.transactions.items[0].id;

    var buffer: [64]u8 = undefined;
    _ = try client.pollTransmit(&buffer);

    const expected_addr: IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 32853 } };
    var buf: [64]u8 = undefined;
    _ = try client.handleRead(try testBindingSuccessResponse(&buf, @bitCast(tx_id), expected_addr));

    try testing.expectEqual(0, client.transactions.current_index);
    const event = client.pollEvent() orelse return error.ExpectedEvent;
    try testing.expect(event.mapped_address.eql(&expected_addr));
    try testing.expectEqual(null, client.pollEvent());
}

test "StunClient.handleRead: unknown transaction produces no event" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var client = testClient(prng.random());

    var buf: [stun.header_size]u8 = undefined;
    const processed = try client.handleRead(try testBindingRequest(&buf, 0xABC));
    try testing.expect(!processed);
    try testing.expectEqual(null, client.pollEvent());
}

test "StunClient.handleRead: invalid stun message not processed" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var client = testClient(prng.random());

    try testing.expect(!try client.handleRead(&([_]u8{0} ** stun.header_size)));
}

test "StunClient.handleTimeout: does nothing before the deadline" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var client = testClient(prng.random());

    var buffer: [64]u8 = undefined;

    try client.bindingRequest(0);
    _ = try client.pollTransmit(&buffer);

    try client.handleTimeout(TestClient.base_rto - 1);
    try testing.expectEqual(null, client.pollEvent());
    try testing.expectEqual(null, try client.pollTransmit(&buffer));

    const tr = client.transactions.items[0];
    try testing.expectEqual(0, tr.attempt);
    try testing.expectEqual(TestClient.base_rto, tr.deadline);
}

test "StunClient.handleTimeout: retransmits and backs off before max attempts" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var client = testClient(prng.random());

    var buffer: [64]u8 = undefined;

    try client.bindingRequest(0);
    const original = try client.pollTransmit(&buffer) orelse return error.ExpectedTransmit;
    var original_buf: [64]u8 = undefined;
    @memcpy(original_buf[0..original.data.len], original.data);

    try client.handleTimeout(TestClient.base_rto);

    const tr = client.transactions.items[0];
    try testing.expectEqual(1, tr.attempt);
    try testing.expectEqual(TestClient.base_rto + 2 * TestClient.base_rto, tr.deadline);
    try testing.expectEqual(TestClient.base_rto + 2 * TestClient.base_rto, client.pollTimeout());

    const retransmit = client.pollEvent();
    try testing.expectEqual(null, retransmit);

    const tm = try client.pollTransmit(&buffer) orelse return error.ExpectedTransmit;
    try testing.expectEqualSlices(u8, original_buf[0..original.data.len], tm.data);
    try testing.expectEqual(null, try client.pollTransmit(&buffer));
}

test "StunClient.handleTimeout: emits err event and drops transaction after max attempts" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var client = testClient(prng.random());

    var buffer: [64]u8 = undefined;

    try client.bindingRequest(0);
    _ = try client.pollTransmit(&buffer);

    var now: i64 = TestClient.base_rto;
    for (0..TestClient.max_attempts - 1) |_| {
        try client.handleTimeout(now);
        _ = try client.pollTransmit(&buffer);
        now = client.transactions.items[0].deadline;
    }

    try client.handleTimeout(now);

    try testing.expectEqual(0, client.transactions.current_index);
    const event = client.pollEvent() orelse return error.ExpectedEvent;
    try testing.expectEqual(error.TransactionTimeout, event.err);
    try testing.expectEqual(null, client.pollEvent());
}

test "StunClient.poll*: return null when empty" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var client = testClient(prng.random());

    try testing.expectEqual(null, client.pollEvent());
    try testing.expectEqual(null, try client.pollTransmit(&.{}));
    try testing.expectEqual(null, client.pollTimeout());
}
