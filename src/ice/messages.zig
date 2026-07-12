const std = @import("std");
const stun = @import("stun");
const ice = @import("ice.zig");

const IpAddress = std.Io.net.IpAddress;

pub const StunRequest = struct {
    tx_id: u96 = 0,
    username: []const u8 = &.{},
    ice_controlled: ?u64 = null,
    ice_controlling: ?u64 = null,
    use_candidate: bool = false,
    priority: u32 = 0,
};

pub fn parseAndValidateStunRequest(
    msg: *const stun.Message,
    credentials: ice.Credentials,
    role: ice.Role,
    tie_breaker: u64,
) !StunRequest {
    var it = msg.iterateAttributes(credentials.password);
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

    //TODO: check username

    return stun_request;
}

pub fn parseAndValidateStunResponse(msg: *const stun.Message, credentials: ice.Credentials) !IpAddress {
    var it = msg.iterateAttributes(credentials.password);
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

pub fn buildSuccessResponse(
    msg: *const stun.Message,
    password: []const u8,
    from: IpAddress,
    buffer: []u8,
) ![]const u8 {
    var w = stun.Writer.init(buffer, .{ .password = password });
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

pub fn buildRoleConflictErrorMessage(transaction_id: u96, pwd: []const u8, buffer: []u8) ![]const u8 {
    var w = stun.Writer.init(buffer, .{ .password = pwd });
    try w.writeHeader(.{
        .message_type = .fromClassAndMethod(.error_response, .binding),
        .transaction_id = transaction_id,
        .message_length = 0,
    });
    try w.writeAttribute(.{ .error_code = .{ .code = 487, .reason = "Role conflict" } });
    try w.writeAttribute(.{ .message_integrity = &.{} });
    try w.writeAttribute(.fingerprint);
    return w.final();
}

const testing = std.testing;
const test_password = "VOkJxbRl1RmTxUk/WvJxBt";
const test_credentials: ice.Credentials = .{ .username = "user", .password = test_password };

const RequestOptions = struct {
    username: ?[]const u8 = null,
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
        .transaction_id = 0x000102030405060708090A0B,
        .message_length = 0,
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
        .transaction_id = 0x000102030405060708090A0B,
        .message_length = 0,
    });

    if (addr) |a| try out.writeAttribute(.{ .xor_mapped_address = a });
    if (message_integrity) try out.writeAttribute(.{ .message_integrity = &.{} });
    if (fingerprint) try out.writeAttribute(.fingerprint);

    return stun.Message.parse(out.final());
}

test "parseAndValidateStunRequest: valid controlling request" {
    var buffer: [256]u8 = undefined;
    const msg = try buildRequest(&buffer, .{
        .username = "evtj:h6vY",
        .priority = 0x6E0001FF,
        .ice_controlling = 100,
        .use_candidate = true,
    });

    const request = try parseAndValidateStunRequest(&msg, test_credentials, .controlled, 50);
    try testing.expectEqualStrings("evtj:h6vY", request.username);
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

test "parseAndValidateStunRequest: missing message integrity" {
    var buffer: [256]u8 = undefined;
    const msg = try buildRequest(&buffer, .{ .ice_controlling = 100, .message_integrity = false });
    try testing.expectError(error.InvalidStunMessage, parseAndValidateStunRequest(&msg, test_credentials, .controlled, 50));
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

    const parsed = try parseAndValidateStunResponse(&msg, test_credentials);
    try testing.expect(parsed.eql(&addr));
}

test "parseAndValidateStunResponse: missing fingerprint" {
    const addr = IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 32853 } };
    var buffer: [256]u8 = undefined;
    const msg = try buildResponse(&buffer, addr, true, false);
    try testing.expectError(error.InvalidStunMessage, parseAndValidateStunResponse(&msg, test_credentials));
}

test "parseAndValidateStunResponse: missing message integrity" {
    const addr = IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 32853 } };
    var buffer: [256]u8 = undefined;
    const msg = try buildResponse(&buffer, addr, false, true);
    try testing.expectError(error.InvalidStunMessage, parseAndValidateStunResponse(&msg, test_credentials));
}

test "parseAndValidateStunResponse: missing mapped address" {
    var buffer: [256]u8 = undefined;
    const msg = try buildResponse(&buffer, null, true, true);
    try testing.expectError(error.MissingMappedAddress, parseAndValidateStunResponse(&msg, test_credentials));
}
