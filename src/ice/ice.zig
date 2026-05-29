pub const Agent = @import("agent.zig");

const std = @import("std");
const Io = std.Io;

pub const ConnectionState = enum { new, checking, connected, completed, disconnected, failed, closed };

pub const GatheringState = enum { new, gathering, complete };

pub const Role = enum { controlling, controlled };

pub const CandidateType = enum {
    host,
    srflx,
    prflx,
    relay,

    pub fn typePreference(self: CandidateType) u8 {
        return switch (self) {
            .host => 126,
            .prflx => 110,
            .srflx => 100,
            .relay => 0,
        };
    }

    pub fn priority(self: CandidateType) u32 {
        return (@as(u32, 1) << 24) * self.typePreference() + (1 << 8) * 65535 + 255;
    }

    test "type preference" {
        const types = [_]CandidateType{ .host, .prflx, .srflx, .relay };
        const preferences = [_]u8{ 126, 110, 100, 0 };

        for (&types, &preferences) |t, preference| {
            try std.testing.expectEqual(preference, t.typePreference());
        }
    }

    test "priority" {
        const types = [_]CandidateType{ .host, .prflx, .srflx, .relay };
        const priorities = [_]u32{ 2130706431, 1862270975, 1694498815, 16777215 };

        for (&types, &priorities) |t, type_priority| {
            try std.testing.expectEqual(type_priority, t.priority());
        }
    }
};

pub const Candidate = struct {
    foundation: u32 = 0,
    component: u8 = 1,
    transport: Transport = .udp,
    base: Io.net.IpAddress,
    address: Io.net.IpAddress,
    candidate_type: CandidateType,
    priority: u32 = 0,

    pub const Transport = enum { udp, tcp };

    pub fn initHost(address: Io.net.IpAddress) Candidate {
        var candidate: Candidate = .{
            .candidate_type = .host,
            .base = address,
            .address = address,
            .priority = CandidateType.host.priority(),
        };
        candidate.calculateFoundation();
        return candidate;
    }

    pub fn initPeerReflexive(base: Io.net.IpAddress, address: Io.net.IpAddress) Candidate {
        var candidate: Candidate = .{
            .candidate_type = .prflx,
            .base = base,
            .address = address,
            .priority = CandidateType.prflx.priority(),
        };
        candidate.calculateFoundation();
        return candidate;
    }

    pub fn parse(value: []const u8) !Candidate {
        var it = std.mem.tokenizeScalar(u8, value, ' ');

        const foundation = try std.fmt.parseUnsigned(u32, try nextToken(it.next()), 10);
        const component = try std.fmt.parseUnsigned(u8, try nextToken(it.next()), 10);

        const transport_str = try nextToken(it.next());
        const transport = if (std.ascii.eqlIgnoreCase(transport_str, "udp"))
            Transport.udp
        else if (std.ascii.eqlIgnoreCase(transport_str, "tcp"))
            Transport.tcp
        else
            return error.InvalidTransport;

        const priority = try std.fmt.parseUnsigned(u32, try nextToken(it.next()), 10);

        const address = try nextToken(it.next());
        const port = try std.fmt.parseUnsigned(u16, try nextToken(it.next()), 10);
        const addr = try Io.net.IpAddress.parse(address, port);

        if (!std.mem.eql(u8, try nextToken(it.next()), "typ")) return error.ParseError;

        const candidate_type = std.meta.stringToEnum(CandidateType, try nextToken(it.next())) orelse return error.ParseError;

        return .{
            .foundation = foundation,
            .component = component,
            .transport = transport,
            .priority = priority,
            .base = addr,
            .address = addr,
            .candidate_type = candidate_type,
        };
    }

    pub fn format(self: @This(), writer: *std.Io.Writer) !void {
        try writer.print("{d} {} {s} {} ", .{ self.foundation, self.component, @tagName(self.transport), self.priority });
        switch (self.address) {
            .ip4 => |ip| try writer.print("{d}.{d}.{d}.{d} {d} ", .{
                ip.bytes[0],
                ip.bytes[1],
                ip.bytes[2],
                ip.bytes[3],
                ip.port,
            }),
            .ip6 => |addr| {
                const u: Io.net.Ip6Address.Unresolved = .{ .bytes = addr.bytes, .interface_name = null };
                try writer.print("{f} {d} ", .{ u, addr.port });
            },
        }
        try writer.print("typ {s}", .{@tagName(self.candidate_type)});
        switch (self.candidate_type) {
            .host => {},
            else => try writer.writeAll(" raddr 0.0.0.0 rport 0"),
        }
    }

    pub fn eql(a: *const Candidate, b: *const Candidate) bool {
        return a.base.eql(&b.base) and a.address.eql(&b.address);
    }

    fn calculateFoundation(self: *Candidate) void {
        var hasher = std.hash.Crc32.init();
        hasher.update(@tagName(self.candidate_type));
        hasher.update(switch (self.address) {
            .ip4 => |addr| &addr.bytes,
            .ip6 => |addr| &addr.bytes,
        });
        hasher.update("udp");
        self.foundation = hasher.final();
    }

    fn nextToken(maybe_token: ?[]const u8) ![]const u8 {
        return if (maybe_token) |token| token else error.ParseError;
    }

    test "initHost" {
        const ip_addr: Io.net.IpAddress = try .parse("192.168.8.10", 1000);
        const candidate = initHost(ip_addr);

        try std.testing.expect(candidate.base.eql(&ip_addr));
        try std.testing.expect(candidate.address.eql(&ip_addr));
        try std.testing.expectEqual(.host, candidate.candidate_type);
        try std.testing.expectEqual(CandidateType.host.priority(), candidate.priority);
        try std.testing.expect(candidate.foundation != 0);
    }

    test "initPeerReflexive" {
        const ip_addr: Io.net.IpAddress = try .parse("192.168.8.10", 1000);
        const reflexive_addr: Io.net.IpAddress = try .parse("192.168.6.20", 1000);
        const candidate = initPeerReflexive(ip_addr, reflexive_addr);

        try std.testing.expect(candidate.base.eql(&ip_addr));
        try std.testing.expect(candidate.address.eql(&reflexive_addr));
        try std.testing.expectEqual(.prflx, candidate.candidate_type);
        try std.testing.expectEqual(CandidateType.prflx.priority(), candidate.priority);
        try std.testing.expect(candidate.foundation != 0);
    }

    test "parse" {
        const values = [_][]const u8{
            "1890 1 udp 998000 10.77.0.1 45909 typ prflx ufrag username",
            "1890 2 tcp 998000 ::1 45908 typ host ufrag username",
            "1890 1 unknown 998000 10.77.0.1 45909 typ prflx ufrag username",
        };

        {
            const candidate = try parse(values[0]);
            try std.testing.expectEqual(1890, candidate.foundation);
            try std.testing.expectEqual(998000, candidate.priority);
            try std.testing.expectEqual(.prflx, candidate.candidate_type);
            try std.testing.expectEqual(.udp, candidate.transport);

            const expected_addr = Io.net.IpAddress{ .ip4 = .{ .bytes = [_]u8{ 10, 77, 0, 1 }, .port = 45909 } };
            try std.testing.expect(expected_addr.eql(&candidate.address));
            try std.testing.expect(expected_addr.eql(&candidate.base));
        }

        {
            const candidate = try parse(values[1]);
            try std.testing.expectEqual(1890, candidate.foundation);
            try std.testing.expectEqual(998000, candidate.priority);
            try std.testing.expectEqual(.host, candidate.candidate_type);
            try std.testing.expectEqual(.tcp, candidate.transport);

            const expected_addr = Io.net.IpAddress{ .ip6 = .loopback(45908) };
            try std.testing.expect(expected_addr.eql(&candidate.address));
            try std.testing.expect(expected_addr.eql(&candidate.base));
        }

        {
            try std.testing.expectError(error.InvalidTransport, parse(values[2]));
        }
    }

    test "format" {
        const addr = Io.net.IpAddress{ .ip4 = .{ .bytes = [_]u8{ 10, 77, 0, 1 }, .port = 45909 } };
        var candidate: Candidate = .{
            .base = addr,
            .address = addr,
            .candidate_type = .prflx,
            .priority = 998000,
            .foundation = 1890,
        };

        var buffer: [128]u8 = undefined;
        var w = Io.Writer.fixed(&buffer);

        try candidate.format(&w);
        try std.testing.expectEqualStrings("1890 1 udp 998000 10.77.0.1 45909 typ prflx raddr 0.0.0.0 rport 0", w.buffered());
        _ = w.consumeAll();

        candidate.transport = .tcp;
        candidate.component = 2;
        candidate.candidate_type = .host;
        candidate.address = .{ .ip6 = .loopback(56000) };

        try candidate.format(&w);
        try std.testing.expectEqualStrings("1890 2 tcp 998000 ::1 56000 typ host", w.buffered());
    }
};

pub const Credentials = struct {
    username: []const u8,
    password: []const u8,

    pub fn dupe(credentials: *const Credentials, allocator: std.mem.Allocator) !Credentials {
        const u = try allocator.dupe(u8, credentials.username);
        errdefer allocator.free(u);
        const p = try allocator.dupe(u8, credentials.password);
        return .{ .username = u, .password = p };
    }

    pub fn deinit(credens: *Credentials, allocator: std.mem.Allocator) void {
        allocator.free(credens.username);
        allocator.free(credens.password);
    }

    pub fn generate(io: std.Io, allocator: std.mem.Allocator) !Credentials {
        var encoder = std.base64.standard.Encoder;

        var user_bytes: [6]u8 = undefined;
        io.random(&user_bytes);
        const username = try allocator.alloc(u8, encoder.calcSize(user_bytes.len));
        errdefer allocator.free(username);
        _ = encoder.encode(username, &user_bytes);

        var password_bytes: [12]u8 = undefined;
        try io.randomSecure(&password_bytes);
        const password = try allocator.alloc(u8, encoder.calcSize(password_bytes.len));
        _ = encoder.encode(password, &password_bytes);

        return .{
            .username = username,
            .password = password,
        };
    }

    test "credentials: generate" {
        var creds = try Credentials.generate(std.testing.io, std.testing.allocator);
        defer creds.deinit(std.testing.allocator);

        try std.testing.expect(creds.username.len >= 8);
        try std.testing.expect(creds.password.len >= 16);
    }

    test "credentials: clean up on failure" {
        var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
        try std.testing.expectError(error.OutOfMemory, Credentials.generate(std.testing.io, failing_allocator.allocator()));
    }
};

pub const CandidatePair = struct {
    pub const Status = enum(u2) { waiting, in_progress, failed, succeeded };

    local: Candidate,
    remote: Candidate,
    priority: u64,
    status: Status = .waiting,
    nominated: bool = false,
    nominate_on_binding: bool = false,

    /// private field: The number of connectivity checks sent so far.
    conn_check_count: u8 = 0,

    pub fn compare(_: void, lhs: CandidatePair, rhs: CandidatePair) bool {
        return lhs.priority > rhs.priority;
    }

    pub fn eql(a: *const CandidatePair, b: *const CandidatePair) bool {
        return a.local.base.eql(&b.local.base) and a.local.address.eql(&b.local.address) and a.remote.address.eql(&b.remote.address);
    }

    pub fn format(self: CandidatePair, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{f}({}) <=> {f}({})[{}]", .{
            self.local.address,
            self.local.candidate_type,
            self.remote.address,
            self.remote.candidate_type,
            self.priority,
        });
    }
};

test {
    std.testing.refAllDecls(@This());
    _ = @import("agent.zig");
}
