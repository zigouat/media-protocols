const std = @import("std");
const Reader = std.Io.Reader;

const Attribute = @This();

const attribute_types_map: std.StaticStringMap(AttributeType) = .initComptime(&.{
    .{ "fingerprint", .fingerprint },
    .{ "rtpmap", .rtpmap },
    .{ "fmtp", .fmtp },
    .{ "group", .group },
    .{ "ice-ufrag", .ice_ufrag },
    .{ "ice-pwd", .ice_pwd },
    .{ "candidate", .candidate },
    .{ "end-of-candidates", .end_of_candidates },
    .{ "sendrecv", .direction },
    .{ "sendonly", .direction },
    .{ "recvonly", .direction },
    .{ "inactive", .direction },
    .{ "mid", .mid },
    .{ "setup", .setup },
    .{ "rtcp-mux", .rtcp_mux },
    .{ "rtcp-mux-only", .rtcp_mux_only },
    .{ "rtcp-rsize", .rtcp_rsize },
    .{ "msid", .msid },
});

pub const AttributeType = enum {
    rtpmap,
    fmtp,
    fingerprint,
    group,
    ice_ufrag,
    ice_pwd,
    candidate,
    end_of_candidates,
    direction,
    mid,
    msid,
    setup,
    rtcp_mux,
    rtcp_mux_only,
    rtcp_rsize,
    control,
    unknown,
};

pub const Setup = enum { actpass, active, passive, holdconn };

pub const ParsedAttribute = union(AttributeType) {
    rtpmap: RtpMap,
    fmtp: []const u8,
    fingerprint: Fingerprint,
    group: []const u8,
    ice_ufrag: []const u8,
    ice_pwd: []const u8,
    candidate: []const u8,
    end_of_candidates: void,
    direction: []const u8,
    mid: []const u8,
    msid: Msid,
    setup: Setup,
    rtcp_mux: void,
    rtcp_mux_only: void,
    rtcp_rsize: void,
    control: []const u8,
    unknown,
};

key: []const u8,
value: ?[]const u8,

pub inline fn getType(attr: *const Attribute) AttributeType {
    return attribute_types_map.get(attr.key) orelse .unknown;
}

pub fn parse(attr: *const Attribute) !ParsedAttribute {
    const value = attr.value orelse "";

    return switch (attr.getType()) {
        .fingerprint => .{ .fingerprint = try Fingerprint.parse(attr.*) },
        .rtpmap => .{ .rtpmap = try RtpMap.parse(value) },
        .group => .{ .group = value },
        .ice_ufrag => .{ .ice_ufrag = value },
        .ice_pwd => .{ .ice_pwd = value },
        .candidate => .{ .candidate = value },
        .direction => .{ .direction = attr.key },
        .end_of_candidates => .end_of_candidates,
        .mid => .{ .mid = value },
        .msid => .{ .msid = Msid.fromSlice(value) },
        .fmtp => .{ .fmtp = value },
        .setup => if (std.meta.stringToEnum(Setup, value)) |setup| .{ .setup = setup } else error.InvalidAttribute,
        .rtcp_mux => .rtcp_mux,
        .rtcp_mux_only => .rtcp_mux_only,
        .rtcp_rsize => .rtcp_rsize,
        .control => |v| .{ .control = v },
        else => .unknown,
    };
}

/// An iterator over the attributes in an SDP message or media description.
/// Each attribute is represented as a key-value pair, where the key is the attribute name and
/// the value is the attribute value (if present).
pub const AttributeIterator = struct {
    reader: Reader,

    pub fn next(self: *AttributeIterator) !?Attribute {
        const line = self.reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.EndOfStream => return null,
            else => return error.InvalidAttribute,
        };

        const trimmed_line = std.mem.trimEnd(u8, line, "\r\n")[2..]; // skip "a="
        if (std.mem.indexOfScalar(u8, trimmed_line, ':')) |idx| {
            return .{ .key = trimmed_line[0..idx], .value = trimmed_line[idx + 1 ..] };
        } else {
            return .{ .key = trimmed_line, .value = null };
        }
    }
};

/// RTP mapping information, as specified in RFC 4566 section 6.
pub const RtpMap = struct {
    payload_type: u8,
    encoding: []const u8,
    clock_rate: u32,
    params: ?[]const u8,

    pub fn parse(value: []const u8) !RtpMap {
        const space = std.mem.indexOfScalar(u8, value, ' ') orelse return error.InvalidRtpMap;
        const payload_type = std.fmt.parseInt(u8, value[0..space], 10) catch return error.InvalidRtpMap;

        const rest = std.mem.trim(u8, value[space + 1 ..], " \t");
        var it = std.mem.splitScalar(u8, rest, '/');

        const encoding = it.next() orelse return error.InvalidRtpMap;
        const clock_rate = std.fmt.parseInt(u32, it.next() orelse return error.InvalidRtpMap, 10) catch return error.InvalidRtpMap;

        return .{
            .payload_type = payload_type,
            .encoding = encoding,
            .clock_rate = clock_rate,
            .params = it.next(),
        };
    }
};

/// Format parameters.
pub const Fmtp = struct {
    payload_type: u8,
    params: Params,

    pub const Params = union(enum) {
        h264: struct {
            packetization_mode: u8 = 0,
            level_asymmetry_allowed: bool = false,
            profile_level_id: u24 = 0x42000A,
            sprop_parameter_sets: ?struct { sps: []const u8, pps: []const u8 } = null,
        },
        rtx: struct {
            apt: u8,
            rtx_time: ?u32 = null,
        },
        unknown: []const u8,

        fn parse(params: []const u8, mime: []const u8) !Params {
            return if (std.ascii.eqlIgnoreCase(mime, "h264"))
                try parseH264Params(params)
            else if (std.ascii.eqlIgnoreCase(mime, "rtx"))
                try parseRtxParams(params)
            else
                .{ .unknown = params };
        }

        fn parseH264Params(params: []const u8) !Params {
            var iterator = std.mem.splitScalar(u8, params, ';');
            var result: Params = .{ .h264 = .{} };
            while (iterator.next()) |param| if (std.mem.cutScalar(u8, param, '=')) |key_value| {
                var key, const value = key_value;
                key = std.mem.trim(u8, key, " ");

                if (std.mem.eql(u8, key, "profile-level-id")) {
                    result.h264.profile_level_id = std.fmt.parseInt(u24, value, 16) catch return error.InvalidFmtp;
                } else if (std.mem.eql(u8, key, "sprop-parameter-sets")) {
                    if (std.mem.indexOfScalar(u8, value, ',')) |idx2| {
                        result.h264.sprop_parameter_sets = .{
                            .sps = value[0..idx2],
                            .pps = value[idx2 + 1 ..],
                        };
                    } else {
                        return error.InvalidSpropParameterSets;
                    }
                } else if (std.mem.eql(u8, key, "packetization-mode")) {
                    result.h264.packetization_mode = std.fmt.parseInt(u8, value, 10) catch return error.InvalidFmtp;
                } else if (std.mem.eql(u8, key, "level-asymmetry-allowed")) {
                    result.h264.level_asymmetry_allowed = (std.fmt.parseInt(u1, value, 10) catch return error.InvalidFmtp) == 1;
                }
            };

            return result;
        }

        fn parseRtxParams(params: []const u8) !Params {
            var iterator = std.mem.splitScalar(u8, params, ';');
            var apt: ?u8 = null;
            var rtx_time: ?u32 = null;

            while (iterator.next()) |param| if (std.mem.cutScalar(u8, param, '=')) |key_value| {
                var key, const value = key_value;
                key = std.mem.trim(u8, key, " ");

                if (std.mem.eql(u8, key, "apt")) {
                    apt = std.fmt.parseInt(u8, value, 10) catch return error.InvalidFmtp;
                } else if (std.mem.eql(u8, key, "rtx-time")) {
                    rtx_time = std.fmt.parseInt(u32, value, 10) catch return error.InvalidFmtp;
                }
            };

            if (apt == null) return error.InvalidFmtp;

            return .{ .rtx = .{ .apt = apt.?, .rtx_time = rtx_time } };
        }
    };

    /// Parse the fmtp data.
    ///
    /// mime represents the codec type in rtpmap
    pub fn parse(data: []const u8, mime: []const u8) !Fmtp {
        if (std.mem.indexOfScalar(u8, data, ' ')) |idx| {
            const payload_type = std.fmt.parseInt(u8, data[0..idx], 10) catch return error.InvalidFmtp;
            const params = data[idx + 1 ..];

            return .{
                .payload_type = payload_type,
                .params = try Params.parse(params, mime),
            };
        }

        return error.InvalidFmtp;
    }
};

pub const Fingerprint = union(enum) {
    sha_256: [32]u8,
    unknown,

    pub fn parse(attr: Attribute) !Fingerprint {
        if (attr.value == null) return error.InvalidAttribute;
        if (std.mem.cutScalar(u8, attr.value.?, ' ')) |fingerprint| {
            const hash_fn, const hash = fingerprint;
            if (!std.mem.eql(u8, hash_fn, "sha-256")) return .unknown;

            var res: [32]u8 = @splat(0);
            var it = std.mem.splitScalar(u8, hash, ':');
            for (&res) |*b| {
                b.* = try std.fmt.parseInt(u8, it.next() orelse return error.InvalidAttribute, 16);
            }

            if (it.next() != null) return error.InvalidAttribute;
            return .{ .sha_256 = res };
        }

        return error.InvalidAttribute;
    }
};

pub const Msid = struct {
    id: []const u8,
    app_data: ?[]const u8 = null,

    fn fromSlice(value: []const u8) Msid {
        return if (std.mem.indexOfScalar(u8, value, ' ')) |space_idx|
            .{ .id = value[0..space_idx], .app_data = value[space_idx + 1 ..] }
        else
            .{ .id = value };
    }
};

test "attribute parsing" {
    const input =
        \\a=rtpmap:96 opus/48000/2
        \\a=sendrecv
        \\a=fmtp:96 minptime=10;useinbandfec=1
        \\
    ;
    var iter = AttributeIterator{ .reader = Reader.fixed(input) };

    var part = try iter.next();
    try std.testing.expect(part != null);
    try std.testing.expectEqualStrings("rtpmap", part.?.key);
    try std.testing.expectEqualStrings("96 opus/48000/2", part.?.value.?);

    part = try iter.next();
    try std.testing.expect(part != null);
    try std.testing.expectEqualStrings("sendrecv", part.?.key);
    try std.testing.expect(part.?.value == null);

    part = try iter.next();
    try std.testing.expect(part != null);
    try std.testing.expectEqualStrings("fmtp", part.?.key);
    try std.testing.expectEqualStrings("96 minptime=10;useinbandfec=1", part.?.value.?);

    part = try iter.next();
    try std.testing.expect(part == null);
}

test "parse RtmMap" {
    const attribute = Attribute{
        .key = "rtpmap",
        .value = "96 opus/48000/2",
    };

    const rtpmap = try RtpMap.parse(attribute.value.?);
    try std.testing.expect(rtpmap.payload_type == 96);
    try std.testing.expectEqualStrings("opus", rtpmap.encoding);
    try std.testing.expect(rtpmap.clock_rate == 48000);
    try std.testing.expect(rtpmap.params != null);
    try std.testing.expectEqualStrings("2", rtpmap.params.?);
}

test "parse invalid RtmMap" {
    const attribute = Attribute{
        .key = "rtpmap",
        .value = "97 opus/4800q/2",
    };

    try std.testing.expectError(error.InvalidRtpMap, RtpMap.parse(attribute.value.?));
}

test "parse Fmtp" {
    {
        const fmtp = try Fmtp.parse(
            "96 packetization-mode=1; profile-level-id=458723; level-asymmetry-allowed=1",
            "H264",
        );
        try std.testing.expectEqual(96, fmtp.payload_type);
        try std.testing.expectEqual(0x458723, fmtp.params.h264.profile_level_id);
        try std.testing.expectEqual(1, fmtp.params.h264.packetization_mode);
        try std.testing.expectEqual(true, fmtp.params.h264.level_asymmetry_allowed);
        try std.testing.expect(fmtp.params.h264.sprop_parameter_sets == null);
    }

    {
        const fmtp = try Fmtp.parse(
            "97 profile-level-id=42E01F;sprop-parameter-sets=Z0LAH9oBQBboQAAAAwBAAAAMHixWoA==,aM48gA==",
            "h264",
        );
        try std.testing.expectEqual(97, fmtp.payload_type);
        try std.testing.expectEqual(0x42E01F, fmtp.params.h264.profile_level_id);
        try std.testing.expectEqual(0, fmtp.params.h264.packetization_mode);
        try std.testing.expectEqual(false, fmtp.params.h264.level_asymmetry_allowed);
        try std.testing.expect(fmtp.params.h264.sprop_parameter_sets != null);
        try std.testing.expectEqualStrings(
            "Z0LAH9oBQBboQAAAAwBAAAAMHixWoA==",
            fmtp.params.h264.sprop_parameter_sets.?.sps,
        );
        try std.testing.expectEqualStrings("aM48gA==", fmtp.params.h264.sprop_parameter_sets.?.pps);
    }

    try std.testing.expectError(error.InvalidFmtp, Fmtp.parse("96", "H264"));

    {
        const fmtp = try Fmtp.parse("98 apt=96;rtx-time=3000", "rtx");
        try std.testing.expectEqual(98, fmtp.payload_type);
        try std.testing.expectEqual(96, fmtp.params.rtx.apt);
        try std.testing.expectEqual(3000, fmtp.params.rtx.rtx_time.?);
    }

    {
        const fmtp = try Fmtp.parse("99 apt=100", "RTX");
        try std.testing.expectEqual(99, fmtp.payload_type);
        try std.testing.expectEqual(100, fmtp.params.rtx.apt);
        try std.testing.expect(fmtp.params.rtx.rtx_time == null);
    }

    try std.testing.expectError(error.InvalidFmtp, Fmtp.parse("101 rtx-time=3000", "rtx"));

    {
        const fmtp = try Fmtp.parse("111 minptime=10;useinbandfec=1", "opus");
        try std.testing.expectEqual(111, fmtp.payload_type);
        try std.testing.expectEqualStrings("minptime=10;useinbandfec=1", fmtp.params.unknown);
    }

    try std.testing.expectError(error.InvalidFmtp, Fmtp.parse("notanumber foo=bar", "opus"));
    try std.testing.expectError(error.InvalidFmtp, Fmtp.parse("96", "opus"));
}

test "parse attribute" {
    {
        const rtpmap = try (Attribute{ .key = "rtpmap", .value = "96 opus/48000/2" }).parse();
        try std.testing.expect(rtpmap == .rtpmap);
        try std.testing.expect(rtpmap.rtpmap.payload_type == 96);
        try std.testing.expectEqualStrings("opus", rtpmap.rtpmap.encoding);
        try std.testing.expect(rtpmap.rtpmap.clock_rate == 48000);
        try std.testing.expectEqualStrings("2", rtpmap.rtpmap.params.?);
    }

    {
        const attr = try (Attribute{
            .key = "fmtp",
            .value = "96 packetization-mode=1; profile-level-id=458723",
        }).parse();
        try std.testing.expect(attr == .fmtp);
        const fmtp = try Fmtp.parse(attr.fmtp, "H264");
        try std.testing.expectEqual(96, fmtp.payload_type);
        try std.testing.expectEqual(1, fmtp.params.h264.packetization_mode);
        try std.testing.expectEqual(0x458723, fmtp.params.h264.profile_level_id);
    }

    {
        const fingerprint = try (Attribute{
            .key = "fingerprint",
            .value = "sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF",
        }).parse();
        try std.testing.expect(fingerprint == .fingerprint);
        try std.testing.expect(fingerprint.fingerprint == .sha_256);
        const expected_fingerprint: [32]u8 = .{
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        };
        try std.testing.expectEqualSlices(u8, &expected_fingerprint, &fingerprint.fingerprint.sha_256);
    }

    {
        const group = try (Attribute{ .key = "group", .value = "BUNDLE 0 1" }).parse();
        try std.testing.expect(group == .group);
        try std.testing.expectEqualStrings("BUNDLE 0 1", group.group);
    }

    {
        const ice_ufrag = try (Attribute{ .key = "ice-ufrag", .value = "F7gI" }).parse();
        try std.testing.expect(ice_ufrag == .ice_ufrag);
        try std.testing.expectEqualStrings("F7gI", ice_ufrag.ice_ufrag);
    }

    {
        const ice_pwd = try (Attribute{ .key = "ice-pwd", .value = "x9cml/YzichV2+XlhiMu8g" }).parse();
        try std.testing.expect(ice_pwd == .ice_pwd);
        try std.testing.expectEqualStrings("x9cml/YzichV2+XlhiMu8g", ice_pwd.ice_pwd);
    }

    {
        inline for (.{ "sendrecv", "sendonly", "recvonly", "inactive" }) |dir| {
            const direction = try (Attribute{ .key = dir, .value = null }).parse();
            try std.testing.expect(direction == .direction);
            try std.testing.expectEqualStrings(dir, direction.direction);
        }
    }

    {
        const mid = try (Attribute{ .key = "mid", .value = "audio" }).parse();
        try std.testing.expect(mid == .mid);
        try std.testing.expectEqualStrings("audio", mid.mid);
    }

    {
        const attr = try (Attribute{ .key = "setup", .value = "actpass" }).parse();
        try std.testing.expectEqual(.setup, @as(AttributeType, attr));
        try std.testing.expectEqual(attr.setup, Setup.actpass);
    }

    {
        const unknown = try (Attribute{ .key = "some-unknown-key", .value = "some-value" }).parse();
        try std.testing.expect(unknown == .unknown);
    }
}
