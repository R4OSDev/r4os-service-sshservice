const std = @import("std");

const block_bytes: usize = 64;
const constants = [4]u32{
    0x6170_7865,
    0x3320_646e,
    0x7962_2d32,
    0x6b20_6574,
};

/// Scalar ChaCha20 with the original 64-bit counter/64-bit nonce layout used
/// by chacha20-poly1305@openssh.com.  Keeping this transport primitive in
/// explicit u32 operations also makes it an independent oracle for the
/// asynchronously interruptible SSH packet path.
pub fn xor(
    out: []u8,
    input: []const u8,
    initial_counter: u64,
    key: [32]u8,
    nonce: [8]u8,
) void {
    std.debug.assert(out.len == input.len);

    var counter = initial_counter;
    var offset: usize = 0;
    while (offset < input.len) {
        const key_stream = block(key, nonce, counter);
        const take = @min(block_bytes, input.len - offset);
        for (0..take) |index| {
            out[offset + index] = input[offset + index] ^ key_stream[index];
        }
        offset += take;
        counter +%= 1;
    }
}

pub fn stream(
    out: []u8,
    initial_counter: u64,
    key: [32]u8,
    nonce: [8]u8,
) void {
    var counter = initial_counter;
    var offset: usize = 0;
    while (offset < out.len) {
        const key_stream = block(key, nonce, counter);
        const take = @min(block_bytes, out.len - offset);
        @memcpy(out[offset .. offset + take], key_stream[0..take]);
        offset += take;
        counter +%= 1;
    }
}

fn block(key: [32]u8, nonce: [8]u8, counter: u64) [block_bytes]u8 {
    var initial: [16]u32 = undefined;
    initial[0..4].* = constants;
    for (0..8) |index| {
        initial[4 + index] = readLeU32(key[index * 4 ..][0..4]);
    }
    initial[12] = @truncate(counter);
    initial[13] = @truncate(counter >> 32);
    initial[14] = readLeU32(nonce[0..4]);
    initial[15] = readLeU32(nonce[4..8]);

    var working = initial;
    for (0..10) |_| {
        quarterRound(&working, 0, 4, 8, 12);
        quarterRound(&working, 1, 5, 9, 13);
        quarterRound(&working, 2, 6, 10, 14);
        quarterRound(&working, 3, 7, 11, 15);
        quarterRound(&working, 0, 5, 10, 15);
        quarterRound(&working, 1, 6, 11, 12);
        quarterRound(&working, 2, 7, 8, 13);
        quarterRound(&working, 3, 4, 9, 14);
    }

    var out: [block_bytes]u8 = undefined;
    for (0..16) |index| {
        writeLeU32(out[index * 4 ..][0..4], working[index] +% initial[index]);
    }
    return out;
}

fn quarterRound(state: *[16]u32, a: usize, b: usize, c: usize, d: usize) void {
    state[a] +%= state[b];
    state[d] = std.math.rotl(u32, state[d] ^ state[a], 16);
    state[c] +%= state[d];
    state[b] = std.math.rotl(u32, state[b] ^ state[c], 12);
    state[a] +%= state[b];
    state[d] = std.math.rotl(u32, state[d] ^ state[a], 8);
    state[c] +%= state[d];
    state[b] = std.math.rotl(u32, state[b] ^ state[c], 7);
}

fn readLeU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .little);
}

fn writeLeU32(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .little);
}

test "RFC 8439 all-zero key and nonce block zero" {
    const key = [_]u8{0} ** 32;
    const nonce = [_]u8{0} ** 8;
    const expected = [_]u8{
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
        0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
        0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
        0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
        0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
        0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
        0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
        0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
    };
    var actual: [block_bytes]u8 = undefined;
    stream(actual[0..], 0, key, nonce);
    try std.testing.expectEqualSlices(u8, expected[0..], actual[0..]);
}

test "RFC 8439 all-zero key and nonce block one" {
    const key = [_]u8{0} ** 32;
    const nonce = [_]u8{0} ** 8;
    const expected = [_]u8{
        0x9f, 0x07, 0xe7, 0xbe, 0x55, 0x51, 0x38, 0x7a,
        0x98, 0xba, 0x97, 0x7c, 0x73, 0x2d, 0x08, 0x0d,
        0xcb, 0x0f, 0x29, 0xa0, 0x48, 0xe3, 0x65, 0x69,
        0x12, 0xc6, 0x53, 0x3e, 0x32, 0xee, 0x7a, 0xed,
        0x29, 0xb7, 0x21, 0x76, 0x9c, 0xe6, 0x4e, 0x43,
        0xd5, 0x71, 0x33, 0xb0, 0x74, 0xd8, 0x39, 0xd5,
        0x31, 0xed, 0x1f, 0x28, 0x51, 0x0a, 0xfb, 0x45,
        0xac, 0xe1, 0x0a, 0x1f, 0x4b, 0x79, 0x4d, 0x6f,
    };
    var actual: [block_bytes]u8 = undefined;
    stream(actual[0..], 1, key, nonce);
    try std.testing.expectEqualSlices(u8, expected[0..], actual[0..]);
}

test "xor covers partial blocks and is reversible in place" {
    var key: [32]u8 = undefined;
    for (&key, 0..) |*byte, index| byte.* = @truncate(index * 17 + 3);
    const nonce = [8]u8{ 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78 };
    var plain: [193]u8 = undefined;
    for (&plain, 0..) |*byte, index| byte.* = @truncate(index * 29 + 11);

    var cipher: [plain.len]u8 = undefined;
    xor(cipher[0..], plain[0..], 7, key, nonce);
    xor(cipher[0..], cipher[0..], 7, key, nonce);
    try std.testing.expectEqualSlices(u8, plain[0..], cipher[0..]);
}
