const std = @import("std");

pub const output_capacity: usize = 64 * 1024;
pub const input_capacity: usize = 32 * 1024;

pub fn ByteQueue(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        data: [capacity]u8 = .{0} ** capacity,
        start: usize = 0,
        end: usize = 0,

        pub fn pending(self: *const Self) usize {
            return self.end - self.start;
        }

        pub fn available(self: *const Self) usize {
            return capacity - self.pending();
        }

        pub fn empty(self: *const Self) bool {
            return self.start == self.end;
        }

        pub fn append(self: *Self, bytes: []const u8) bool {
            if (bytes.len > self.available()) return false;
            if (bytes.len > capacity - self.end) self.compact();
            if (bytes.len != 0) @memcpy(self.data[self.end .. self.end + bytes.len], bytes);
            self.end += bytes.len;
            return true;
        }

        pub fn peek(self: *const Self) []const u8 {
            return self.data[self.start..self.end];
        }

        pub fn consume(self: *Self, count: usize) bool {
            if (count > self.pending()) return false;
            self.start += count;
            if (self.start == self.end) self.clear();
            return true;
        }

        pub fn clear(self: *Self) void {
            self.start = 0;
            self.end = 0;
        }

        fn compact(self: *Self) void {
            const count = self.pending();
            if (count != 0) std.mem.copyForwards(u8, self.data[0..count], self.data[self.start..self.end]);
            self.start = 0;
            self.end = count;
        }
    };
}

pub const OutputQueue = ByteQueue(output_capacity);
pub const InputQueue = ByteQueue(input_capacity);

pub const SendWindow = struct {
    remaining: u32 = 0,
    max_packet: u32 = 0,
    blocked: bool = false,
    blocked_since: u64 = 0,

    pub fn init(initial: u32, packet_max: u32) SendWindow {
        return .{ .remaining = initial, .max_packet = packet_max };
    }

    pub fn budget(self: *const SendWindow, requested: usize) usize {
        return @min(requested, @min(@as(usize, self.remaining), @as(usize, self.max_packet)));
    }

    pub fn consume(self: *SendWindow, count: usize) bool {
        if (count > self.remaining) return false;
        self.remaining -= @intCast(count);
        if (count != 0) self.clearBlocked();
        return true;
    }

    pub fn adjust(self: *SendWindow, increment: u32) bool {
        if (increment > std.math.maxInt(u32) - self.remaining) return false;
        self.remaining += increment;
        if (increment != 0) self.clearBlocked();
        return true;
    }

    pub fn noteBlocked(self: *SendWindow, now: u64) bool {
        if (self.blocked) return false;
        self.blocked = true;
        self.blocked_since = now;
        return true;
    }

    pub fn clearBlocked(self: *SendWindow) void {
        self.blocked = false;
        self.blocked_since = 0;
    }

    pub fn stalled(self: *const SendWindow, now: u64, timeout_ticks: u64) bool {
        return self.blocked and timeout_ticks != 0 and now -| self.blocked_since >= timeout_ticks;
    }
};

pub const NormalizeResult = struct {
    produced: usize = 0,
    consumed_without_output: usize = 0,
};

pub fn normalizeConsoleInput(out: []u8, input: []const u8, skip_next_lf: *bool) ?NormalizeResult {
    if (out.len < input.len) return null;
    var result = NormalizeResult{};
    for (input) |raw| {
        var ch = raw;
        if (skip_next_lf.*) {
            skip_next_lf.* = false;
            if (ch == '\n') {
                result.consumed_without_output += 1;
                continue;
            }
        }
        if (ch == '\r') {
            ch = '\n';
            skip_next_lf.* = true;
        }
        if (ch == 0x7f) ch = 0x08;
        out[result.produced] = ch;
        result.produced += 1;
    }
    return result;
}

test "bounded byte queue preserves order across compaction" {
    const TinyQueue = ByteQueue(8);
    var queue = TinyQueue{};
    try std.testing.expect(queue.append("abcdef"));
    try std.testing.expect(queue.consume(5));
    try std.testing.expect(queue.append("123456"));
    try std.testing.expectEqualStrings("f123456", queue.peek());
    try std.testing.expect(!queue.append("xx"));
    try std.testing.expect(queue.consume(7));
    try std.testing.expect(queue.empty());
}

test "send window obeys remote budget and has a monotone stall deadline" {
    var window = SendWindow.init(12, 5);
    try std.testing.expectEqual(@as(usize, 5), window.budget(20));
    try std.testing.expect(window.consume(5));
    try std.testing.expectEqual(@as(u32, 7), window.remaining);
    try std.testing.expect(window.noteBlocked(100));
    try std.testing.expect(!window.stalled(109, 10));
    try std.testing.expect(window.stalled(110, 10));
    try std.testing.expect(window.adjust(8));
    try std.testing.expect(!window.blocked);
    window.remaining = std.math.maxInt(u32);
    try std.testing.expect(!window.adjust(1));
}

test "console normalization batches CRLF and DEL across packet boundaries" {
    var out: [16]u8 = undefined;
    var skip = false;
    const first = normalizeConsoleInput(out[0..], "A\r", &skip).?;
    try std.testing.expectEqualStrings("A\n", out[0..first.produced]);
    try std.testing.expect(skip);
    const second = normalizeConsoleInput(out[0..], "\nB\x7f", &skip).?;
    try std.testing.expectEqualStrings("B\x08", out[0..second.produced]);
    try std.testing.expectEqual(@as(usize, 1), second.consumed_without_output);
    try std.testing.expect(!skip);
}

/// No decoding or key inference in the SSH transport. The byte queue retains
/// split scalars and receives credit only for the events accepted downstream.
pub fn consoleEvents(input: []const u8, out: []@import("r4os").abi.ConsoleInputEvent) []const @import("r4os").abi.ConsoleInputEvent {
    const count = @min(@min(input.len, out.len), 64);
    for (input[0..count], out[0..count]) |byte, *event| event.* = @import("r4os").input_events.utf8Byte(byte);
    return out[0..count];
}

test "SSH split UTF8 bytes80/81 survive full queue and acknowledged-prefix retry without key inference" {
    const r4os = @import("r4os");
    var queue: ByteQueue(16) = .{};
    const original = "\xc3\xbc\xe2\x82\xac\xd0\x81\xc4\x80\xf0\x9f\x98\x80";
    try std.testing.expect(queue.append(original[0..6]));
    var batch: [64]r4os.abi.ConsoleInputEvent = undefined;
    var first = consoleEvents(queue.peek(), &batch);
    for (first) |event| try std.testing.expectEqual(r4os.abi.console_input_event_utf8_byte, event.kind);
    // A full downstream queue acknowledges nothing, retaining the D0 prefix.
    try std.testing.expect(queue.consume(0));
    try std.testing.expectEqualStrings(original[0..6], queue.peek());
    try std.testing.expect(queue.consume(5));
    try std.testing.expect(queue.append(original[6..]));
    first = consoleEvents(queue.peek(), &batch);
    try std.testing.expectEqual(@as(u32, 0xd0), first[0].value);
    try std.testing.expectEqual(@as(u32, 0x81), first[1].value);
    var restored: [8]u8 = undefined;
    for (first, &restored) |event, *byte| byte.* = @intCast(event.value);
    try std.testing.expectEqualStrings(original[5..], &restored);
    try std.testing.expect(queue.consume(first.len));
    try std.testing.expect(queue.empty());
}
