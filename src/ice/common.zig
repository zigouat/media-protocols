//! Types shared by the full and lite ICE agents.

const std = @import("std");
const ice = @import("ice.zig");
const IpAddress = std.Io.net.IpAddress;
const AllocError = std.mem.Allocator.Error;

pub const CandidateIndex = u7;

pub const RestartError = error{
    Closed,
    /// The previous restart's new generation hasn't nominated a pair yet.
    RestartInProgress,
    CredentialsTooLong,
};

pub const SetRemoteCredentialsError = AllocError || error{
    CredentialsTooLong,
    /// Credentials differ from the current ones; call `restart` first.
    RestartRequired,
    /// Only one of ufrag/pwd changed; a restart changes both (RFC 8839).
    InvalidCredentials,
};

pub const NominatedPair = struct {
    local: CandidateIndex,
    remote: CandidateIndex,
};

pub const RemoteCandidate = struct {
    address: IpAddress,
    candidate_type: ice.CandidateType,
    priority: u32,
};

pub fn LocalCredentials(comptime size: u8) type {
    return struct {
        buffer: [size]u8,
        user_len: u8,
        pass_len: u8,

        pub fn init(username: []const u8, password: []const u8) error{CredentialsTooLong}!@This() {
            if (username.len + password.len > size) return error.CredentialsTooLong;
            var credentials: @This() = undefined;
            @memcpy(credentials.buffer[0..username.len], username);
            @memcpy(credentials.buffer[username.len .. username.len + password.len], password);
            credentials.user_len = @intCast(username.len);
            credentials.pass_len = @intCast(password.len);
            return credentials;
        }

        pub fn getUsername(self: *const @This()) []const u8 {
            return self.buffer[0..self.user_len];
        }

        pub fn getPassword(self: *const @This()) []const u8 {
            return self.buffer[self.user_len .. self.user_len + self.pass_len];
        }

        pub fn toIceCredentials(self: *const @This()) ice.Credentials {
            return .{
                .username = self.getUsername(),
                .password = self.getPassword(),
            };
        }

        pub fn clear(self: *@This()) void {
            self.user_len = 0;
            self.pass_len = 0;
            std.crypto.secureZero(u8, &self.buffer);
        }
    };
}

pub const Event = union(enum) {
    connection_state: ice.ConnectionState,
    gathering_state: ice.GatheringState,
    nominated: NominatedPair,
    candidate: struct { CandidateIndex, CandidateIndex }, // range inclusive
};

pub const ReadResult = union(enum) {
    app_data: []const u8,
    consumed: void,
};

pub const Response = struct {
    tx_id: [12]u8,
    /// Null to answer on the pre-restart path.
    pair: ?NominatedPair,
    kind: Kind = .success,

    pub const Kind = enum(u2) { success, role_conflict, bad_request, unauthorized };

    pub fn authErrorKind(err: anyerror) ?Kind {
        return switch (err) {
            error.BadRequest => .bad_request,
            error.Unauthorized => .unauthorized,
            else => null,
        };
    }
};

pub const Config = struct {
    /// The role of the agent.
    role: ice.Role,
    credentials: ice.Credentials,
    /// A random number generator implementation used for generating transaction IDs and tie breakers.
    random: std.Random,
    /// The time in milliseconds after which a connection is considered failed if no data is received or no connection is established.
    failed_timeout: u32 = 25 * std.time.ms_per_s,
    /// The time in milliseconds after which a connection is considered disconnected if no data is received.
    disconnected_timeout: u32 = 5 * std.time.ms_per_s,
    /// The interval between connectivity checks in milliseconds. This is the time between sending binding requests on all pairs.
    /// Ignored by the lite agent, which sends no checks.
    connectivity_check_interval: u16 = 200,
};

pub const keep_alive_interval: i64 = 4 * std.time.ms_per_s;

pub const RestartMode = enum {
    /// The old nominated pair is kept so media and data can still flow until the new session nominates a pair.
    graceful,
    /// The whole session is dropped and restarted, which may cause a temporary disruption of media and data.
    hard,
};
