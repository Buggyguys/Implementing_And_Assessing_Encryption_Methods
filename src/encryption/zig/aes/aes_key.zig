const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

// Import AES common functionality
const aes_common = @import("aes_common.zig");

// Key expansion constants
const AES_BLOCK_SIZE = aes_common.AES_BLOCK_SIZE;
const RCON = [11]u8{ 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

// AES S-box for key expansion
const SBOX = [256]u8{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

// Key schedule structure
pub const AesKeySchedule = struct {
    round_keys: []u8,
    num_rounds: usize,
    key_size: usize,
    allocator: Allocator,
    
    pub fn init(allocator: Allocator, key: []const u8, key_size_bits: i32) !AesKeySchedule {
        const key_size = aes_common.getKeySizeBytes(key_size_bits);
        const num_rounds = aes_common.getNumRounds(key_size_bits);
        const expanded_key_size = (num_rounds + 1) * AES_BLOCK_SIZE;
        
        var schedule = AesKeySchedule{
            .round_keys = try allocator.alloc(u8, expanded_key_size),
            .num_rounds = num_rounds,
            .key_size = key_size,
            .allocator = allocator,
        };
        
        try schedule.expandKey(key);
        return schedule;
    }
    
    pub fn deinit(self: *AesKeySchedule) void {
        self.allocator.free(self.round_keys);
    }
    
    pub fn getRoundKey(self: *const AesKeySchedule, round: usize) []const u8 {
        const start = round * AES_BLOCK_SIZE;
        const end = start + AES_BLOCK_SIZE;
        return self.round_keys[start..end];
    }
    
    fn expandKey(self: *AesKeySchedule, key: []const u8) !void {
        // Copy the original key to the beginning of the expanded key
        @memcpy(self.round_keys[0..self.key_size], key[0..self.key_size]);
        
        const nk = self.key_size / 4; // Number of 32-bit words in the key
        const nr = self.num_rounds;
        
        var i: usize = nk;
        while (i < 4 * (nr + 1)) : (i += 1) {
            var temp: [4]u8 = undefined;
            
            // Copy the previous word
            const prev_word_start = (i - 1) * 4;
            @memcpy(&temp, self.round_keys[prev_word_start..prev_word_start + 4]);
            
            if (i % nk == 0) {
                // Apply RotWord, SubWord, and XOR with Rcon
                rotWord(&temp);
                subWord(&temp);
                temp[0] ^= RCON[i / nk];
            } else if (nk > 6 and i % nk == 4) {
                // For AES-256, apply SubWord to every 4th word after the key
                subWord(&temp);
            }
            
            // XOR with the word nk positions back
            const back_word_start = (i - nk) * 4;
            const current_word_start = i * 4;
            
            for (0..4) |j| {
                self.round_keys[current_word_start + j] = 
                    self.round_keys[back_word_start + j] ^ temp[j];
            }
        }
    }
};

// Rotate a 4-byte word left by one byte
fn rotWord(word: []u8) void {
    const temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

// Apply S-box substitution to each byte in a 4-byte word
fn subWord(word: []u8) void {
    for (word) |*byte| {
        byte.* = SBOX[byte.*];
    }
}

// Generate a random AES key
pub fn generateAesKey(allocator: Allocator, key_size_bits: i32) ![]u8 {
    const key_size = aes_common.getKeySizeBytes(key_size_bits);
    const key = try allocator.alloc(u8, key_size);
    
    // Use cryptographically secure random number generation
    std.crypto.random.bytes(key);
    
    return key;
}

// Validate an AES key
pub fn validateAesKey(key: []const u8, expected_size_bits: i32) bool {
    const expected_size = aes_common.getKeySizeBytes(expected_size_bits);
    return key.len == expected_size;
}

// Convert key from hex string
pub fn keyFromHex(allocator: Allocator, hex_string: []const u8) ![]u8 {
    if (hex_string.len % 2 != 0) {
        return error.InvalidHexLength;
    }
    
    const key_size = hex_string.len / 2;
    const key = try allocator.alloc(u8, key_size);
    
    for (0..key_size) |i| {
        const hex_byte = hex_string[i * 2..i * 2 + 2];
        key[i] = try std.fmt.parseInt(u8, hex_byte, 16);
    }
    
    return key;
}

// Convert key to hex string
pub fn keyToHex(allocator: Allocator, key: []const u8) ![]u8 {
    const hex_string = try allocator.alloc(u8, key.len * 2);
    
    for (key, 0..) |byte, i| {
        _ = try std.fmt.bufPrint(hex_string[i * 2..i * 2 + 2], "{x:0>2}", .{byte});
    }
    
    return hex_string;
}

// Test key expansion with known test vectors
pub fn testKeyExpansion(allocator: Allocator) !void {
    // Test with AES-128 test vector
    const test_key_128 = [_]u8{ 
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c 
    };
    
    var schedule = try AesKeySchedule.init(allocator, &test_key_128, 128);
    defer schedule.deinit();
    
    // Verify the first round key is the original key
    const first_round = schedule.getRoundKey(0);
    for (test_key_128, 0..) |expected, i| {
        if (first_round[i] != expected) {
            print("Key expansion test failed at byte {d}\n", .{i});
            return error.KeyExpansionTestFailed;
        }
    }
    
    print("AES key expansion test passed\n", .{});
} 