const std = @import("std");
const stun = @import("stun");
const ice = @import("ice.zig");

const IpAddress = std.Io.net.IpAddress;

pub const StunRequest = struct {
    tx_id: [12]u8 = @splat(0),
    username: []const u8 = &.{},
    ice_controlled: ?u64 = null,
    ice_controlling: ?u64 = null,
    use_candidate: bool = false,
    priority: u32 = 0,
};

pub fn builUnauthenticatedBindingRequest(buffer: []u8, tx_id: [12]u8) ![]const u8 {
    var w = stun.Writer.init(buffer, .{ .password = &.{} });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.request, .binding),
        .transaction_id = tx_id,
    });
    return w.final();
}

pub const BindingRequestConfig = struct {
    tx_id: [12]u8,
    username: []const u8,
    remote_username: []const u8,
    remote_password: []const u8,
    use_candidate: bool,
    role: ice.Role,
    tie_breaker: u64,
};

pub fn buildAuthenticatedBindingRequest(buffer: []u8, config: BindingRequestConfig) error{WriteFailed}![]const u8 {
    var w = stun.Writer.init(buffer, .{ .password = config.remote_password });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.request, .binding),
        .transaction_id = config.tx_id,
    });

    var username = [_][]const u8{ config.remote_username, ":", config.username };
    try w.writeRaw(.username, &username);
    try w.writeAttribute(.{ .priority = ice.CandidateType.prflx.priority() });
    const role_attribute: stun.Attribute = switch (config.role) {
        .controlled => .{ .ice_controlled = config.tie_breaker },
        .controlling => .{ .ice_controlling = config.tie_breaker },
    };
    if (config.use_candidate) try w.writeAttribute(.use_candidate);
    try w.writeAttribute(role_attribute);
    try w.writeAttribute(.{ .message_integrity = &.{} });
    try w.writeAttribute(.fingerprint);

    return w.final();
}

pub const AuthError = error{ BadRequest, Unauthorized };

pub fn validateConsentFreshnessRequest(msg: *const stun.Message, credentials: ice.Credentials) !void {
    var it = msg.iterateAttributes(credentials.password);
    var auth: Auth = .{};
    var has_fingerprint = false;

    while (try auth.next(&it)) |attribute| switch (attribute) {
        .fingerprint => has_fingerprint = true,
        else => {},
    };

    try auth.check(credentials.username);
    if (!has_fingerprint) return error.InvalidStunMessage;
}

pub fn parseAndValidateStunRequest(
    msg: *const stun.Message,
    credentials: ice.Credentials,
    role: ice.Role,
    tie_breaker: u64,
) !StunRequest {
    var it = msg.iterateAttributes(credentials.password);
    var auth: Auth = .{};
    var has_fingerprint = false;
    var stun_request: StunRequest = .{};

    while (try auth.next(&it)) |attribute| switch (attribute) {
        .username => |u| stun_request.username = u,
        .ice_controlled => |v| stun_request.ice_controlled = v,
        .ice_controlling => |v| stun_request.ice_controlling = v,
        .use_candidate => stun_request.use_candidate = true,
        .priority => |p| stun_request.priority = p,
        .fingerprint => has_fingerprint = true,
        else => {},
    };

    try auth.check(credentials.username);
    if (!has_fingerprint)
        return error.InvalidStunMessage;
    if (stun_request.ice_controlling == null and stun_request.ice_controlled == null or
        stun_request.ice_controlling != null and stun_request.ice_controlled != null)
        return error.InvalidStunMessage;

    if (stun_request.ice_controlled != null and role == .controlled) {
        if (tie_breaker >= stun_request.ice_controlled.?)
            return error.SwitchRole
        else
            return error.RoleConflict;
    }

    if (stun_request.ice_controlling != null and role == .controlling) {
        if (tie_breaker >= stun_request.ice_controlling.?)
            return error.RoleConflict
        else
            return error.SwitchRole;
    }

    if (stun_request.use_candidate and role == .controlling)
        return error.InvalidStunMessage;

    return stun_request;
}

pub fn parseAndValidateStunResponse(msg: *const stun.Message, pass: []const u8) !IpAddress {
    var it = msg.iterateAttributes(pass);
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

pub fn buildSuccessResponse(tx_id: [12]u8, password: []const u8, from: *const IpAddress, buffer: []u8) stun.Writer.Error![]const u8 {
    var w = stun.Writer.init(buffer, .{ .password = password });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.success_response, .binding),
        .transaction_id = tx_id,
    });
    try w.writeAttribute(.{ .xor_mapped_address = from.* });
    try w.writeAttribute(.{ .message_integrity = &.{} });
    try w.writeAttribute(.fingerprint);
    return w.final();
}

pub fn buildRoleConflictErrorMessage(transaction_id: [12]u8, pwd: []const u8, buffer: []u8) stun.Writer.Error![]const u8 {
    var w = stun.Writer.init(buffer, .{ .password = pwd });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.error_response, .binding),
        .transaction_id = transaction_id,
    });
    try w.writeAttribute(.{ .error_code = .{ .code = .role_conflict, .reason = "Role conflict" } });
    try w.writeAttribute(.{ .message_integrity = &.{} });
    try w.writeAttribute(.fingerprint);
    return w.final();
}

pub fn buildAuthErrorResponse(tx_id: [12]u8, err: AuthError, buffer: []u8) stun.Writer.Error![]const u8 {
    var w = stun.Writer.init(buffer, .{});
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.error_response, .binding),
        .transaction_id = tx_id,
    });
    try w.writeAttribute(.{ .error_code = switch (err) {
        error.BadRequest => .{ .code = .bad_request, .reason = "Bad Request" },
        error.Unauthorized => .{ .code = .unauthorized, .reason = "Unauthorized" },
    } });
    try w.writeAttribute(.fingerprint);
    return w.final();
}

pub fn getMappedAddress(resp: []const u8, tx_id: [12]u8) !IpAddress {
    const msg = try stun.Message.parse(resp);
    if (!std.mem.eql(u8, &msg.header.transaction_id, &tx_id)) return error.TransactionIdMismatch;

    switch (msg.header.message_type.class()) {
        .success_response => {
            var it = msg.iterateAttributes(&.{});
            while (try it.next()) |attr| switch (attr) {
                .mapped_address, .xor_mapped_address => |addr| return addr,
                else => {},
            };

            return error.MissingMappedAddress;
        },
        else => return error.InvalidStunMessage,
    }
}

const Auth = struct {
    username: ?[]const u8 = null,
    has_message_integrity: bool = false,
    integrity_failed: bool = false,

    fn next(auth: *Auth, it: *stun.AttributeIterator) !?stun.Attribute {
        const attribute = it.next() catch |err| switch (err) {
            error.MessageIntegrityCheckFailed => {
                auth.has_message_integrity = true;
                auth.integrity_failed = true;
                return null;
            },
            else => |e| return e,
        } orelse return null;

        switch (attribute) {
            .username => |u| auth.username = u,
            .message_integrity => auth.has_message_integrity = true,
            else => {},
        }
        return attribute;
    }

    /// RFC 5389 §10.1.2 checks in order. The username is valid if it is `<local ufrag>:<remote ufrag>` (RFC 8445 §7.3).
    fn check(auth: *const Auth, local_ufrag: []const u8) AuthError!void {
        const username = auth.username orelse return error.BadRequest;
        if (!auth.has_message_integrity) return error.BadRequest;

        const separator = std.mem.findScalar(u8, username, ':') orelse return error.Unauthorized;
        if (!std.mem.eql(u8, username[0..separator], local_ufrag)) return error.Unauthorized;
        if (auth.integrity_failed) return error.Unauthorized;
    }
};

const testing = std.testing;
const test_password = "VOkJxbRl1RmTxUk/WvJxBt";
const test_credentials: ice.Credentials = .{ .username = "user", .password = test_password };

const RequestOptions = struct {
    username: ?[]const u8 = "user:peer",
    priority: ?u32 = null,
    ice_controlling: ?u64 = null,
    ice_controlled: ?u64 = null,
    use_candidate: bool = false,
    message_integrity: bool = true,
    fingerprint: bool = true,
};

fn buildRequest(buffer: []u8, opts: RequestOptions) !stun.Message {
    var out = stun.Writer.init(buffer, .{ .password = test_password });
    try out.writeHeader(.{
        .message_type = .fromClassAndMethod(.request, .binding),
        .transaction_id = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 },
    });

    if (opts.username) |u| try out.writeAttribute(.{ .username = u });
    if (opts.priority) |p| try out.writeAttribute(.{ .priority = p });
    if (opts.ice_controlling) |v| try out.writeAttribute(.{ .ice_controlling = v });
    if (opts.ice_controlled) |v| try out.writeAttribute(.{ .ice_controlled = v });
    if (opts.use_candidate) try out.writeAttribute(.use_candidate);
    if (opts.message_integrity) try out.writeAttribute(.{ .message_integrity = &.{} });
    if (opts.fingerprint) try out.writeAttribute(.fingerprint);

    return stun.Message.parse(out.final());
}

fn buildResponse(buffer: []u8, addr: ?IpAddress, message_integrity: bool, fingerprint: bool) !stun.Message {
    var out = stun.Writer.init(buffer, .{ .password = test_password });
    try out.writeHeader(.{
        .message_type = .fromClassAndMethod(.success_response, .binding),
        .transaction_id = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 },
    });

    if (addr) |a| try out.writeAttribute(.{ .xor_mapped_address = a });
    if (message_integrity) try out.writeAttribute(.{ .message_integrity = &.{} });
    if (fingerprint) try out.writeAttribute(.fingerprint);

    return stun.Message.parse(out.final());
}

test "parseAndValidateStunRequest: valid controlling request" {
    var buffer: [256]u8 = undefined;
    const msg = try buildRequest(&buffer, .{
        .username = "user:h6vY",
        .priority = 0x6E0001FF,
        .ice_controlling = 100,
        .use_candidate = true,
    });

    const request = try parseAndValidateStunRequest(&msg, test_credentials, .controlled, 50);
    try testing.expectEqualStrings("user:h6vY", request.username);
    try testing.expectEqual(@as(u32, 0x6E0001FF), request.priority);
    try testing.expectEqual(@as(?u64, 100), request.ice_controlling);
    try testing.expectEqual(@as(?u64, null), request.ice_controlled);
    try testing.expect(request.use_candidate);
}

test "parseAndValidateStunRequest: missing fingerprint" {
    var buffer: [256]u8 = undefined;
    const msg = try buildRequest(&buffer, .{ .ice_controlling = 100, .fingerprint = false });
    try testing.expectError(error.InvalidStunMessage, parseAndValidateStunRequest(&msg, test_credentials, .controlled, 50));
}

test "parseAndValidateStunRequest/validateConsentFreshnessRequest: short-term credential checks" {
    var buffer: [256]u8 = undefined;
    const cases = [_]struct { opts: RequestOptions, credentials: ice.Credentials, err: AuthError }{
        .{ .opts = .{ .ice_controlling = 100, .message_integrity = false }, .credentials = test_credentials, .err = error.BadRequest },
        .{ .opts = .{ .ice_controlling = 100, .username = null }, .credentials = test_credentials, .err = error.BadRequest },
        .{ .opts = .{ .ice_controlling = 100, .username = "other:peer" }, .credentials = test_credentials, .err = error.Unauthorized },
        .{ .opts = .{ .ice_controlling = 100, .username = "user" }, .credentials = test_credentials, .err = error.Unauthorized },
        .{ .opts = .{ .ice_controlling = 100 }, .credentials = .{ .username = "user", .password = "wrong-password" }, .err = error.Unauthorized },
    };

    for (cases) |case| {
        const msg = try buildRequest(&buffer, case.opts);
        try testing.expectError(case.err, parseAndValidateStunRequest(&msg, case.credentials, .controlled, 50));
        try testing.expectError(case.err, validateConsentFreshnessRequest(&msg, case.credentials));
    }

    const msg = try buildRequest(&buffer, .{ .ice_controlling = 100 });
    try validateConsentFreshnessRequest(&msg, test_credentials);
}

test "buildAuthErrorResponse: error code and fingerprint, no integrity or username" {
    var buffer: [256]u8 = undefined;
    const data = try buildAuthErrorResponse(@splat(7), error.Unauthorized, &buffer);
    const msg = try stun.Message.parse(data);
    try testing.expectEqual(.error_response, msg.header.message_type.class());
    try testing.expectEqual(@as([12]u8, @splat(7)), msg.header.transaction_id);

    var it = msg.iterateAttributes(&.{});
    try testing.expectEqual(.unauthorized, (try it.next()).?.error_code.code);
    try testing.expectEqual(.fingerprint, @as(stun.AttributeType, (try it.next()).?));
    try testing.expectEqual(null, try it.next());
}

test "parseAndValidateStunRequest: missing ice role attribute" {
    var buffer: [256]u8 = undefined;
    const msg = try buildRequest(&buffer, .{});
    try testing.expectError(error.InvalidStunMessage, parseAndValidateStunRequest(&msg, test_credentials, .controlled, 50));
}

test "parseAndValidateStunRequest: both ice role attributes" {
    var buffer: [256]u8 = undefined;
    const msg = try buildRequest(&buffer, .{ .ice_controlling = 100, .ice_controlled = 200 });
    try testing.expectError(error.InvalidStunMessage, parseAndValidateStunRequest(&msg, test_credentials, .controlled, 50));
}

test "parseAndValidateStunRequest: controlled conflict switches role" {
    var buffer: [256]u8 = undefined;
    const msg = try buildRequest(&buffer, .{ .ice_controlled = 100 });
    try testing.expectError(error.SwitchRole, parseAndValidateStunRequest(&msg, test_credentials, .controlled, 200));
}

test "parseAndValidateStunRequest: controlled conflict keeps role" {
    var buffer: [256]u8 = undefined;
    const msg = try buildRequest(&buffer, .{ .ice_controlled = 200 });
    try testing.expectError(error.RoleConflict, parseAndValidateStunRequest(&msg, test_credentials, .controlled, 100));
}

test "parseAndValidateStunRequest: controlling conflict keeps role" {
    var buffer: [256]u8 = undefined;
    const msg = try buildRequest(&buffer, .{ .ice_controlling = 100 });
    try testing.expectError(error.RoleConflict, parseAndValidateStunRequest(&msg, test_credentials, .controlling, 200));
}

test "parseAndValidateStunRequest: controlling conflict switches role" {
    var buffer: [256]u8 = undefined;
    const msg = try buildRequest(&buffer, .{ .ice_controlling = 200 });
    try testing.expectError(error.SwitchRole, parseAndValidateStunRequest(&msg, test_credentials, .controlling, 100));
}

test "parseAndValidateStunRequest: use candidate rejected when controlling" {
    var buffer: [256]u8 = undefined;
    const msg = try buildRequest(&buffer, .{ .ice_controlled = 100, .use_candidate = true });
    try testing.expectError(error.InvalidStunMessage, parseAndValidateStunRequest(&msg, test_credentials, .controlling, 50));
}

test "parseAndValidateStunResponse: valid response" {
    const addr = IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 32853 } };
    var buffer: [256]u8 = undefined;
    const msg = try buildResponse(&buffer, addr, true, true);

    const parsed = try parseAndValidateStunResponse(&msg, test_credentials.password);
    try testing.expect(parsed.eql(&addr));
}

test "parseAndValidateStunResponse: missing fingerprint" {
    const addr = IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 32853 } };
    var buffer: [256]u8 = undefined;
    const msg = try buildResponse(&buffer, addr, true, false);
    try testing.expectError(error.InvalidStunMessage, parseAndValidateStunResponse(&msg, test_credentials.password));
}

test "parseAndValidateStunResponse: missing message integrity" {
    const addr = IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 32853 } };
    var buffer: [256]u8 = undefined;
    const msg = try buildResponse(&buffer, addr, false, true);
    try testing.expectError(error.InvalidStunMessage, parseAndValidateStunResponse(&msg, test_credentials.password));
}

test "parseAndValidateStunResponse: missing mapped address" {
    var buffer: [256]u8 = undefined;
    const msg = try buildResponse(&buffer, null, true, true);
    try testing.expectError(error.MissingMappedAddress, parseAndValidateStunResponse(&msg, test_credentials.password));
}
