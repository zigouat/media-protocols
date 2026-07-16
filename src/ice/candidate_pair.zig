const std = @import("std");

const Candidate = @import("ice.zig").Candidate;
const CandidatePair = @This();

/// Enum describing the status of a candidate pair in the ICE process.
pub const Status = enum(u2) {
    /// The candidate pair is waiting to be checked.
    waiting,
    /// Ice connectivity checks are in progress for this candidate pair.
    in_progress,
    /// The candidate didn't receive a response to the connectivity check.
    failed,
    /// The candidate pair check is successful (a binding response was received).
    succeeded,
};

local: Candidate,
remote: Candidate,
/// The priority of the candidate pair, calculated based on the priority of the local and remote candidates.
priority: u64,
status: Status = .waiting,
/// Whether the candidate pair has been nominated for use in the ICE process.
///
/// A nominated candidate pair is the one that will be used for media transmission.
nominated: bool = false,
/// True if the candidate pair received a Stun binding request with USE_CANDIDATE attribute, and it's not yet
/// in the success state. Once the candidate pair is in the success state, this field will be set to false and the
/// pair is nominated.
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
