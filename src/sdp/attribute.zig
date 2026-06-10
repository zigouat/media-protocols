const std = @import("std");
const Reader = std.Io.Reader;

const Attribute = @This();

const attribute_types_map: std.StaticStringMap(AttributeType) = .initComptime(&.{
    .{ "candidate", .candidate },
    .{ "control", .control },
    .{ "end-of-candidates", .end_of_candidates },
    .{ "extmap", .extmap },
    .{ "extmap-allow-mixed", .extmap_allow_mixed },
    .{ "fingerprint", .fingerprint },
    .{ "fmtp", .fmtp },
    .{ "group", .group },
    .{ "ice-lite", .ice_lite },
    .{ "ice-options", .ice_options },
    .{ "ice-pwd", .ice_pwd },
    .{ "ice-ufrag", .ice_ufrag },
    .{ "mid", .mid },
    .{ "msid", .msid },
    .{ "sendrecv", .direction },
    .{ "sendonly", .direction },
    .{ "recvonly", .direction },
    .{ "inactive", .direction },
    .{ "rtcp-mux", .rtcp_mux },
    .{ "rtcp-mux-only", .rtcp_mux_only },
    .{ "rtcp-rsize", .rtcp_rsize },
    .{ "rtpmap", .rtpmap },
    .{ "setup", .setup },
});

key: []const u8,
value: ?[]const u8,

pub const AttributeType = enum {
    candidate,
    control,
    direction,
    end_of_candidates,
    extmap,
    extmap_allow_mixed,
    fingerprint,
    fmtp,
    group,
    ice_lite,
    ice_options,
    ice_pwd,
    ice_ufrag,
    mid,
    msid,
    rtcp_mux,
    rtcp_mux_only,
    rtcp_rsize,
    rtpmap,
    setup,
    unknown,
};

pub const Setup = enum { actpass, active, passive, holdconn };

pub const ParsedAttribute = union(AttributeType) {
    candidate: []const u8,
    control: []const u8,
    direction: []const u8,
    end_of_candidates: void,
    extmap: ExtMap,
    extmap_allow_mixed: void,
    fingerprint: Fingerprint,
    fmtp: struct { u8, []const u8 },
    group: Group,
    ice_lite: void,
    ice_options: IceOptions,
    ice_pwd: []const u8,
    ice_ufrag: []const u8,
    mid: []const u8,
    msid: Msid,
    rtcp_mux: void,
    rtcp_mux_only: void,
    rtcp_rsize: void,
    rtpmap: RtpMap,
    setup: Setup,
    unknown,

    pub fn write(attr: ParsedAttribute, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (attr) {
            .control => |url| try w.print("a=control:{s}\r\n", .{url}),
            .direction => |v| try w.print("a={s}\r\n", .{v}),
            .end_of_candidates => try w.writeAll("a=end-of-candidates\r\n"),
            .extmap => |extmap| {
                try w.writeAll("a=extmap:");
                try extmap.write(w);
                try w.writeAll("\r\n");
            },
            .extmap_allow_mixed => try w.writeAll("a=extmap-allow-mixed\r\n"),
            .ice_lite => try w.writeAll("a=ice-lite\r\n"),
            .ice_options => |options| {
                try w.writeAll("a=ice-options:");
                if (options.ice2) try w.writeAll(" ice2");
                if (options.trickle) try w.writeAll(" trickle");
                try w.writeAll("\r\n");
            },
            .ice_ufrag => |v| try w.print("a=ice-ufrag:{s}\r\n", .{v}),
            .ice_pwd => |v| try w.print("a=ice-pwd:{s}\r\n", .{v}),
            .mid => |v| try w.print("a=mid:{s}\r\n", .{v}),
            .setup => |v| try w.print("a=setup:{s}\r\n", .{@tagName(v)}),
            .rtpmap => |rtpmap| try w.print("a={f}\r\n", .{rtpmap}),
            .rtcp_mux => try w.writeAll("a=rtcp-mux\r\n"),
            .rtcp_mux_only => try w.writeAll("a=rtcp-mux-only\r\n"),
            .rtcp_rsize => try w.writeAll("a=rtcp-rsize\r\n"),
            .fingerprint => |fingerprint| {
                try w.writeAll("a=fingerprint:");
                try fingerprint.write(w);
                try w.writeAll("\r\n");
            },
            else => {},
        }
    }
};

pub inline fn getType(attr: *const Attribute) AttributeType {
    return attribute_types_map.get(attr.key) orelse .unknown;
}

pub fn parse(attr: *const Attribute) !ParsedAttribute {
    const value = attr.value orelse "";

    return switch (attr.getType()) {
        .candidate => .{ .candidate = value },
        .control => .{ .control = value },
        .direction => .{ .direction = attr.key },
        .end_of_candidates => .end_of_candidates,
        .extmap_allow_mixed => .extmap_allow_mixed,
        .extmap => .{ .extmap = try ExtMap.parse(value) },
        .fingerprint => .{ .fingerprint = try Fingerprint.parse(attr.*) },
        .fmtp => blk: {
            if (std.mem.cutScalar(u8, value, ' ')) |cut| {
                const pt, const params = cut;
                const payload_type = std.fmt.parseInt(u8, pt, 10) catch break :blk error.InvalidAttribute;
                break :blk .{ .fmtp = .{ payload_type, params } };
            }
            break :blk error.InvalidAttribute;
        },
        .group => .{ .group = try Group.parse(value) },
        .ice_lite => .ice_lite,
        .ice_options => .{ .ice_options = try IceOptions.parse(value) },
        .ice_ufrag => .{ .ice_ufrag = value },
        .ice_pwd => .{ .ice_pwd = value },
        .mid => .{ .mid = value },
        .msid => .{ .msid = Msid.fromSlice(value) },
        .rtcp_mux => .rtcp_mux,
        .rtcp_mux_only => .rtcp_mux_only,
        .rtcp_rsize => .rtcp_rsize,
        .rtpmap => .{ .rtpmap = try RtpMap.parse(value) },
        .setup => if (std.meta.stringToEnum(Setup, value)) |setup| .{ .setup = setup } else error.InvalidAttribute,
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
    channels: ?u8 = null,

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
            .channels = std.fmt.parseInt(u8, it.rest(), 10) catch null,
        };
    }

    pub fn format(self: @This(), writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("rtpmap:{} {s}/{}", .{ self.payload_type, self.encoding, self.clock_rate });
        if (self.channels) |channels| try writer.print("/{}", .{channels});
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

        pub fn parse(params: []const u8, mime: []const u8) !Params {
            return if (std.ascii.eqlIgnoreCase(mime, "h264"))
                try parseH264Params(params)
            else if (std.ascii.eqlIgnoreCase(mime, "rtx"))
                try parseRtxParams(params)
            else
                .{ .unknown = params };
        }

        pub fn format(self: @This(), writer: *std.Io.Writer) std.Io.Writer.Error!void {
            switch (self) {
                .h264 => |params| {
                    try writer.print("packetization-mode={};level-asymmetry-allowed={};profile-level-id={x}", .{
                        params.packetization_mode,
                        @intFromBool(params.level_asymmetry_allowed),
                        params.profile_level_id,
                    });
                },
                .rtx => |params| {
                    try writer.print("apt={}", .{params.apt});
                    if (params.rtx_time) |rtx_time| try writer.print(";rtx-time={}", .{rtx_time});
                },
                .unknown => |params| try writer.writeAll(params),
            }
        }

        pub fn eql(a: *const Params, b: *const Params) bool {
            if (std.meta.activeTag(a.*) != std.meta.activeTag(b.*)) return false;
            return switch (a.*) {
                .h264 => |v| v.packetization_mode == b.h264.packetization_mode and
                    v.level_asymmetry_allowed == b.h264.level_asymmetry_allowed and
                    v.profile_level_id == b.h264.profile_level_id,
                .rtx => true,
                .unknown => |v| std.mem.eql(u8, v, b.unknown),
            };
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
        if (std.mem.cutScalar(u8, data, ' ')) |cut| {
            const pt, const params = cut;
            const payload_type = std.fmt.parseInt(u8, pt, 10) catch return error.InvalidFmtp;

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

    pub fn write(fingeprint: *const Fingerprint, w: *std.Io.Writer) !void {
        switch (fingeprint.*) {
            .sha_256 => |hash| {
                try w.print("sha-256 {X:>2}", .{hash[0]});
                for (hash[1..]) |b| try w.print(":{X:0>2}", .{b});
            },
            else => {},
        }
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

pub const GroupSemantics = enum { LS, FID, FEC, BUNDLE, UNKNOWN };

pub const Group = struct {
    semantics: GroupSemantics,
    mids: []const u8 = &.{},

    fn parse(attr_value: []const u8) !Group {
        if (attr_value.len == 0) return error.InvalidAttribute;
        const sp_idx = std.mem.indexOfScalar(u8, attr_value, ' ') orelse attr_value.len;
        return .{
            .semantics = std.meta.stringToEnum(GroupSemantics, attr_value[0..sp_idx]) orelse .UNKNOWN,
            .mids = if (sp_idx == attr_value.len) &.{} else attr_value[sp_idx + 1 ..],
        };
    }
};

pub const ExtMap = struct {
    id: u32,
    direction: ?[]const u8 = null,
    uri: []const u8,
    attributes: []const u8 = &.{},

    pub fn parse(attr: []const u8) !ExtMap {
        var it = std.mem.tokenizeScalar(u8, attr, ' ');
        var extmap: ExtMap = .{
            .id = 0,
            .uri = &.{},
        };

        const map_entry = it.next() orelse return error.InvalidAttribute;
        if (std.mem.findScalar(u8, map_entry, '/')) |pos| {
            extmap.id = try std.fmt.parseInt(u32, map_entry[0..pos], 10);
            const direction = attribute_types_map.get(map_entry[pos + 1 ..]) orelse return error.InvalidAttribute;
            if (direction != .direction) return error.InvalidAtttribute;
            extmap.direction = map_entry[pos + 1 ..];
        } else {
            extmap.id = try std.fmt.parseInt(u32, map_entry, 10);
        }

        extmap.uri = it.next() orelse return error.InvalidAttribute;
        extmap.attributes = it.rest();

        return extmap;
    }

    pub fn write(extmap: *const ExtMap, w: *std.Io.Writer) !void {
        try w.printInt(extmap.id, 10, .lower, .{});
        if (extmap.direction) |direction| {
            try w.writeByte('/');
            try w.writeAll(direction);
        }

        try w.writeByte(' ');
        try w.writeAll(extmap.uri);

        if (extmap.attributes.len != 0) {
            try w.writeByte(' ');
            try w.writeAll(extmap.attributes);
        }
    }
};

pub const IceOptions = packed struct(u8) {
    ice2: bool = false,
    trickle: bool = false,
    _pad: u6 = 0,

    fn parse(attr_value: []const u8) !IceOptions {
        var options: IceOptions = .{};
        var it = std.mem.tokenizeScalar(u8, attr_value, ' ');
        while (it.next()) |option| {
            if (std.ascii.eqlIgnoreCase(option, "ice2"))
                options.ice2 = true
            else if (std.ascii.eqlIgnoreCase(option, "trickle"))
                options.trickle = true
            else
                return error.InvalidAttribute;
        }

        return options;
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
    try std.testing.expect(rtpmap.channels != null);
    try std.testing.expectEqual(2, rtpmap.channels.?);
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
        try std.testing.expectEqual(2, rtpmap.rtpmap.channels.?);
    }

    {
        const attr = try (Attribute{
            .key = "fmtp",
            .value = "96 packetization-mode=1; profile-level-id=458723",
        }).parse();
        try std.testing.expect(attr == .fmtp);
        const payload_type, const params_text = attr.fmtp;
        try std.testing.expectEqual(96, payload_type);

        const fmtp_params = try Fmtp.Params.parse(params_text, "H264");
        try std.testing.expectEqual(1, fmtp_params.h264.packetization_mode);
        try std.testing.expectEqual(0x458723, fmtp_params.h264.profile_level_id);
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
        try std.testing.expectEqual(GroupSemantics.BUNDLE, group.group.semantics);
        try std.testing.expectEqualStrings("0 1", group.group.mids);
    }

    {
        const candidate = try (Attribute{
            .key = "candidate",
            .value = "1 1 UDP 2130706431 192.168.1.1 54321 typ host",
        }).parse();
        try std.testing.expect(candidate == .candidate);
        try std.testing.expectEqualStrings(
            "1 1 UDP 2130706431 192.168.1.1 54321 typ host",
            candidate.candidate,
        );
    }

    {
        const eoc = try (Attribute{ .key = "end-of-candidates", .value = null }).parse();
        try std.testing.expect(eoc == .end_of_candidates);
    }

    {
        const msid = try (Attribute{
            .key = "msid",
            .value = "stream-id track-id",
        }).parse();
        try std.testing.expect(msid == .msid);
        try std.testing.expectEqualStrings("stream-id", msid.msid.id);
        try std.testing.expectEqualStrings("track-id", msid.msid.app_data.?);
    }

    {
        const msid = try (Attribute{ .key = "msid", .value = "stream-id" }).parse();
        try std.testing.expect(msid == .msid);
        try std.testing.expectEqualStrings("stream-id", msid.msid.id);
        try std.testing.expect(msid.msid.app_data == null);
    }

    {
        const attr = try (Attribute{ .key = "rtcp-mux", .value = null }).parse();
        try std.testing.expect(attr == .rtcp_mux);
    }

    {
        const attr = try (Attribute{ .key = "rtcp-mux-only", .value = null }).parse();
        try std.testing.expect(attr == .rtcp_mux_only);
    }

    {
        const attr = try (Attribute{ .key = "rtcp-rsize", .value = null }).parse();
        try std.testing.expect(attr == .rtcp_rsize);
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
        const attr = try (Attribute{ .key = "extmap-allow-mixed", .value = null }).parse();
        try std.testing.expectEqual(.extmap_allow_mixed, @as(AttributeType, attr));
    }

    {
        const attr = try (Attribute{ .key = "extmap", .value = "10/sendrecv http://my-header-extension" }).parse();
        try std.testing.expectEqual(.extmap, @as(AttributeType, attr));

        const extmap = attr.extmap;
        try std.testing.expectEqual(10, extmap.id);
        try std.testing.expectEqualStrings("sendrecv", extmap.direction.?);
        try std.testing.expectEqualStrings("http://my-header-extension", extmap.uri);
        try std.testing.expectEqualStrings("", extmap.attributes);
    }

    {
        const attr = try (Attribute{ .key = "ice-options", .value = "ice2 trickle" }).parse();
        try std.testing.expectEqual(.ice_options, @as(AttributeType, attr));

        const ice_options = attr.ice_options;
        try std.testing.expect(ice_options.ice2);
        try std.testing.expect(ice_options.trickle);

        try std.testing.expectError(error.InvalidAttribute, (Attribute{ .key = "ice-options", .value = "trickl" }).parse());
    }

    {
        const unknown = try (Attribute{ .key = "some-unknown-key", .value = "some-value" }).parse();
        try std.testing.expect(unknown == .unknown);
    }
}

test "ParsedAttribute write" {
    var buffer: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buffer);

    const expectWrite = struct {
        fn f(writer: *std.Io.Writer, attr: ParsedAttribute, expected: []const u8) !void {
            try attr.write(writer);
            try std.testing.expectEqualStrings(expected, writer.buffered());
            _ = writer.consumeAll();
        }
    }.f;

    try expectWrite(&w, .{ .ice_ufrag = "F7gI" }, "a=ice-ufrag:F7gI\r\n");
    try expectWrite(&w, .{ .ice_pwd = "x9cml/YzichV2+XlhiMu8g" }, "a=ice-pwd:x9cml/YzichV2+XlhiMu8g\r\n");
    try expectWrite(&w, .{ .direction = "sendrecv" }, "a=sendrecv\r\n");
    try expectWrite(&w, .{ .mid = "audio" }, "a=mid:audio\r\n");
    try expectWrite(&w, .{ .setup = .actpass }, "a=setup:actpass\r\n");
    try expectWrite(&w, .rtcp_mux, "a=rtcp-mux\r\n");
    try expectWrite(&w, .rtcp_mux_only, "a=rtcp-mux-only\r\n");
    try expectWrite(&w, .rtcp_rsize, "a=rtcp-rsize\r\n");

    try expectWrite(
        &w,
        .{ .rtpmap = .{ .payload_type = 96, .encoding = "opus", .clock_rate = 48000, .channels = 2 } },
        "a=rtpmap:96 opus/48000/2\r\n",
    );
    try expectWrite(
        &w,
        .{ .rtpmap = .{ .payload_type = 0, .encoding = "PCMU", .clock_rate = 8000 } },
        "a=rtpmap:0 PCMU/8000\r\n",
    );

    const hash: [32]u8 = @splat(0xAB);
    try expectWrite(&w, .{ .fingerprint = .{ .sha_256 = hash } }, "a=fingerprint:sha-256 AB" ++ (":AB" ** 31) ++ "\r\n");
    try expectWrite(&w, .{ .fingerprint = .unknown }, "a=fingerprint:\r\n");

    try expectWrite(&w, .ice_lite, "a=ice-lite\r\n");
    try expectWrite(&w, .end_of_candidates, "a=end-of-candidates\r\n");
    try expectWrite(&w, .{ .candidate = "1 1 UDP 2130706431 192.168.1.1 54321 typ host" }, "");
    try expectWrite(&w, .{ .fmtp = .{ 96, "minptime=10" } }, "");
    try expectWrite(&w, .{ .group = .{ .semantics = .BUNDLE, .mids = "0 1" } }, "");
    try expectWrite(&w, .{ .msid = .{ .id = "stream-id" } }, "");
    try expectWrite(&w, .{ .control = "trackID=0" }, "a=control:trackID=0\r\n");
    try expectWrite(&w, .unknown, "");

    try expectWrite(&w, .extmap_allow_mixed, "a=extmap-allow-mixed\r\n");
    try expectWrite(
        &w,
        .{ .extmap = .{ .id = 1, .uri = "https://my-custom-ext" } },
        "a=extmap:1 https://my-custom-ext\r\n",
    );
    try expectWrite(
        &w,
        .{ .extmap = .{ .id = 1, .direction = "sendrecv", .uri = "https://my-custom-ext", .attributes = "att=1" } },
        "a=extmap:1/sendrecv https://my-custom-ext att=1\r\n",
    );

    try expectWrite(&w, .{ .ice_options = .{ .ice2 = true } }, "a=ice-options: ice2\r\n");
    try expectWrite(&w, .{ .ice_options = .{ .ice2 = true, .trickle = true } }, "a=ice-options: ice2 trickle\r\n");
}
