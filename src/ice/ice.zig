pub const Agent = @import("agent.zig");

const std = @import("std");

const Io = std.Io;

pub const CandidateType = enum {
    host,
    server_reflexive,
    peer_reflexive,
    relayed,

    pub fn typePreference(self: CandidateType) u8 {
        return switch (self) {
            .host => 126,
            .peer_reflexive => 110,
            .server_reflexive => 100,
            .relayed => 0,
        };
    }

    pub fn name(self: CandidateType) []const u8 {
        return switch (self) {
            .host => "host",
            .peer_reflexive => "prflx",
            .server_reflexive => "srflx",
            .relayed => "relay",
        };
    }

    pub fn fromSlice(slice: []const u8) !CandidateType {
        return if (std.mem.eql(u8, slice, "host"))
            .host
        else if (std.mem.eql(u8, slice, "prflx"))
            .peer_reflexive
        else if (std.mem.eql(u8, slice, "srflx"))
            .server_reflexive
        else if (std.mem.eql(u8, slice, "relay"))
            .relayed
        else
            error.InvalidCandidateType;
    }
};

pub const Candidate = struct {
    candidate_type: CandidateType,
    base: Io.net.IpAddress,
    address: Io.net.IpAddress,
    foundation: u32 = 0,
    priority: u32 = 0,

    pub fn initHost(address: Io.net.IpAddress) Candidate {
        var candidate: Candidate = .{
            .candidate_type = .host,
            .base = address,
            .address = address,
            .priority = calculatePriority(.host),
        };
        candidate.calculateFoundation();
        return candidate;
    }

    pub fn initPeerReflexive(base: Io.net.IpAddress, address: Io.net.IpAddress) Candidate {
        var candidate: Candidate = .{
            .candidate_type = .peer_reflexive,
            .base = base,
            .address = address,
            .priority = calculatePriority(.peer_reflexive),
        };
        candidate.calculateFoundation();
        return candidate;
    }

    pub fn parse(value: []const u8) !Candidate {
        var it = std.mem.tokenizeScalar(u8, value, ' ');

        const foundation = try std.fmt.parseUnsigned(u32, try nextToken(it.next()), 10);
        _ = try nextToken(it.next()); // component
        _ = try nextToken(it.next()); // assume udp
        const priority = try std.fmt.parseUnsigned(u32, try nextToken(it.next()), 10);

        const address = try nextToken(it.next());
        const port = try std.fmt.parseUnsigned(u16, try nextToken(it.next()), 10);
        const addr = try Io.net.IpAddress.parse(address, port);

        _ = try nextToken(it.next()); // typ
        const candidate_type = try CandidateType.fromSlice(try nextToken(it.next()));

        return .{
            .foundation = foundation,
            .priority = priority,
            .base = addr,
            .address = addr,
            .candidate_type = candidate_type,
        };
    }

    pub fn format(self: @This(), writer: *std.Io.Writer) !void {
        try writer.print("{d:0>8} {} {s} {} ", .{ self.foundation, 1, "udp", self.priority });
        switch (self.address) {
            .ip4 => |ip| try writer.print("{d}.{d}.{d}.{d} {d} ", .{
                ip.bytes[0],
                ip.bytes[1],
                ip.bytes[2],
                ip.bytes[3],
                ip.port,
            }),
            else => {},
        }
        try writer.print("typ {s}", .{self.candidate_type.name()});
    }

    fn calculateFoundation(self: *Candidate) void {
        var hasher = std.hash.Crc32.init();
        hasher.update(self.candidate_type.name());
        hasher.update(switch (self.address) {
            .ip4 => |addr| &addr.bytes,
            .ip6 => |addr| &addr.bytes,
        });
        hasher.update("udp");
        self.foundation = hasher.final();
    }

    fn calculatePriority(t: CandidateType) u32 {
        return (@as(u32, 1) << 24) * t.typePreference() + (1 << 8) * 65535 + 255;
    }

    inline fn nextToken(maybe_token: ?[]const u8) ![]const u8 {
        return if (maybe_token) |token| token else error.ParseError;
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
};

pub const CandidatePair = struct {
    local: Candidate,
    remote: Candidate,
    priority: u64,
    state: PairState = .{},

    /// The number of connectivity checks sent so far.
    conn_check_count: u8 = 0,

    pub const Status = enum(u2) { waiting, in_progress, failed, succeeded };

    pub const PairState = packed struct(u8) {
        status: Status = .waiting,
        nominated: bool = false,
        nominateOnBinding: bool = false,
        _pad: u4 = 0,
    };

    pub fn compare(_: void, lhs: CandidatePair, rhs: CandidatePair) bool {
        return lhs.priority > rhs.priority;
    }

    pub fn format(
        self: CandidatePair,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
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
    _ = @import("agent.zig");
}
