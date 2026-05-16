const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const media = b.dependency("media", .{ .target = target, .optimize = optimize });
    const zbench = b.dependency("zbench", .{ .target = target, .optimize = optimize });

    const rtp = b.addModule("rtp", .{
        .root_source_file = b.path("src/rtp/rtp.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "media", .module = media.module("media") },
        },
    });

    const rtcp = b.addModule("rtcp", .{
        .root_source_file = b.path("src/rtcp/rtcp.zig"),
        .target = target,
        .optimize = optimize,
    });

    const sdp = b.addModule("sdp", .{
        .root_source_file = b.path("src/sdp/sdp.zig"),
        .target = target,
        .optimize = optimize,
    });

    const rtsp = b.addModule("rtsp", .{
        .root_source_file = b.path("src/rtsp/rtsp.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "rtp", .module = rtp },
        },
    });

    const stun = b.addModule("stun", .{
        .root_source_file = b.path("src/stun/stun.zig"),
        .target = target,
        .optimize = optimize,
    });

    _ = b.addModule("protocols", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "rtp", .module = rtp },
            .{ .name = "rtcp", .module = rtp },
            .{ .name = "sdp", .module = sdp },
            .{ .name = "rtsp", .module = rtsp },
            .{ .name = "stun", .module = stun },
        },
    });

    {
        const test_filters = b.option([]const []const u8, "test-filter", "Skip tests that do not match any filter") orelse &[0][]const u8{};
        const modules = [_]*std.Build.Module{ rtp, rtcp, sdp, rtsp, stun };
        const test_step = b.step("test", "Run tests");

        inline for (modules) |sub_module| {
            const mod_tests = b.addTest(.{
                .root_module = sub_module,
                .filters = test_filters,
            });

            const run_mod_tests = b.addRunArtifact(mod_tests);
            test_step.dependOn(&run_mod_tests.step);
        }
    }

    {
        const bench_step = b.step("bench", "Run all benchmarks");

        const benches = .{
            .{ .name = "rtp_packet", .src = "bench/rtp/packet.zig" },
            .{ .name = "sdp_session", .src = "bench/sdp/session.zig" },
            .{ .name = "stun_message", .src = "bench/stun/message.zig" },
        };

        inline for (benches) |bench| {
            const bench_exe = b.addExecutable(.{
                .name = bench.name,
                .root_module = b.createModule(.{
                    .root_source_file = b.path(bench.src),
                    .target = target,
                    .optimize = .ReleaseFast,
                    .imports = &.{
                        .{ .name = "zbench", .module = zbench.module("zbench") },
                        .{ .name = "rtp", .module = rtp },
                        .{ .name = "sdp", .module = sdp },
                        .{ .name = "stun", .module = stun },
                    },
                }),
            });

            const run = b.addRunArtifact(bench_exe);
            const single_step = b.step("bench-" ++ bench.name, "Run " ++ bench.name ++ " benchmark");
            single_step.dependOn(&run.step);
            bench_step.dependOn(&run.step);
        }
    }
}
