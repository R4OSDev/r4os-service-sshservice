// Pure SFTP upload policy used by SSHD and the 0.60.20 host contract.
// Filesystem calls stay in main.zig; this module pins the externally visible
// state decisions without requiring an R4OS runtime.

pub const pflag_read: u32 = 0x0000_0001;
pub const pflag_write: u32 = 0x0000_0002;
pub const pflag_append: u32 = 0x0000_0004;
pub const pflag_creat: u32 = 0x0000_0008;
pub const pflag_trunc: u32 = 0x0000_0010;
pub const pflag_excl: u32 = 0x0000_0020;

pub fn supportsSequentialWriteOpen(flags: u32) bool {
    const supported = pflag_write | pflag_creat | pflag_trunc | pflag_excl;
    return (flags & pflag_write) != 0 and
        (flags & pflag_read) == 0 and
        (flags & pflag_append) == 0 and
        (flags & pflag_creat) != 0 and
        (flags & pflag_trunc) != 0 and
        (flags & ~supported) == 0;
}

pub fn supportsReadOpen(flags: u32) bool {
    return flags == pflag_read;
}

pub fn failedCloseNeedsCleanup(stream_active: bool, cleanup_pending: bool) bool {
    return stream_active or cleanup_pending;
}

pub fn validationFailureNeedsCleanup(stream_active: bool, cleanup_pending: bool) bool {
    return stream_active or cleanup_pending;
}

test "OpenSSH sequential create truncate is accepted" {
    const testing = @import("std").testing;
    try testing.expect(supportsSequentialWriteOpen(pflag_write | pflag_creat | pflag_trunc));
    try testing.expect(supportsSequentialWriteOpen(pflag_write | pflag_creat | pflag_trunc | pflag_excl));
}

test "read write and append modes are rejected" {
    const testing = @import("std").testing;
    try testing.expect(!supportsSequentialWriteOpen(pflag_read | pflag_write | pflag_creat | pflag_trunc));
    try testing.expect(!supportsSequentialWriteOpen(pflag_write | pflag_append | pflag_creat | pflag_trunc));
}

test "read accepts no mutating or unknown flags" {
    const testing = @import("std").testing;
    try testing.expect(supportsReadOpen(pflag_read));
    try testing.expect(!supportsReadOpen(pflag_read | pflag_trunc));
    try testing.expect(!supportsReadOpen(pflag_read | pflag_creat));
    try testing.expect(!supportsReadOpen(pflag_read | 0x8000_0000));
}

test "write without create and truncate is rejected" {
    const testing = @import("std").testing;
    try testing.expect(!supportsSequentialWriteOpen(pflag_write));
    try testing.expect(!supportsSequentialWriteOpen(pflag_write | pflag_creat));
}

test "failed close cleans an active or ambiguous stage" {
    const testing = @import("std").testing;
    try testing.expect(failedCloseNeedsCleanup(true, false));
    try testing.expect(failedCloseNeedsCleanup(false, true));
    try testing.expect(!failedCloseNeedsCleanup(false, false));
}

test "offset or size failure aborts a written prefix" {
    const testing = @import("std").testing;
    try testing.expect(validationFailureNeedsCleanup(true, true));
    try testing.expect(!validationFailureNeedsCleanup(false, false));
}
