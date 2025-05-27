const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

// Import AES modules
const aes_common = @import("aes_common.zig");
const aes_key = @import("aes_key.zig");
const AesContext = aes_common.AesContext;

// GCM constants
const GCM_IV_SIZE = 12; // 96 bits
const GCM_TAG_SIZE = 16; // 128 bits
const AES_BLOCK_SIZE = aes_common.AES_BLOCK_SIZE;

// GCM context for maintaining state
const GcmContext = struct {
    key_schedule: aes_key.AesKeySchedule,
    h: [AES_BLOCK_SIZE]u8, // Hash subkey
    allocator: Allocator,
    
    pub fn init(allocator: Allocator, key: []const u8, key_size_bits: i32) !GcmContext {
        var context = GcmContext{
            .key_schedule = try aes_key.AesKeySchedule.init(allocator, key, key_size_bits),
            .h = std.mem.zeroes([AES_BLOCK_SIZE]u8),
            .allocator = allocator,
        };
        
        // Generate hash subkey H = AES_K(0^128)
        var zero_block = std.mem.zeroes([AES_BLOCK_SIZE]u8);
        aesEncryptBlock(&context.key_schedule, &zero_block, &context.h);
        
        return context;
    }
    
    pub fn deinit(self: *GcmContext) void {
        self.key_schedule.deinit();
    }
};

// AES block encryption
fn aesEncryptBlock(key_schedule: *const aes_key.AesKeySchedule, input: []const u8, output: []u8) void {
    var state: [AES_BLOCK_SIZE]u8 = undefined;
    @memcpy(&state, input[0..AES_BLOCK_SIZE]);
    
    // Initial round
    aes_common.addRoundKey(&state, key_schedule.getRoundKey(0));
    
    // Main rounds
    for (1..key_schedule.num_rounds) |round| {
        aes_common.subBytes(&state);
        aes_common.shiftRows(&state);
        aes_common.mixColumns(&state);
        aes_common.addRoundKey(&state, key_schedule.getRoundKey(round));
    }
    
    // Final round (no MixColumns)
    aes_common.subBytes(&state);
    aes_common.shiftRows(&state);
    aes_common.addRoundKey(&state, key_schedule.getRoundKey(key_schedule.num_rounds));
    
    @memcpy(output[0..AES_BLOCK_SIZE], &state);
}

// AES block decryption
fn aesDecryptBlock(key_schedule: *const aes_key.AesKeySchedule, input: []const u8, output: []u8) void {
    var state: [AES_BLOCK_SIZE]u8 = undefined;
    @memcpy(&state, input[0..AES_BLOCK_SIZE]);
    
    // Initial round
    aes_common.addRoundKey(&state, key_schedule.getRoundKey(key_schedule.num_rounds));
    
    // Main rounds (in reverse)
    var round = key_schedule.num_rounds - 1;
    while (round > 0) : (round -= 1) {
        aes_common.invShiftRows(&state);
        aes_common.invSubBytes(&state);
        aes_common.addRoundKey(&state, key_schedule.getRoundKey(round));
        aes_common.invMixColumns(&state);
    }
    
    // Final round (no InvMixColumns)
    aes_common.invShiftRows(&state);
    aes_common.invSubBytes(&state);
    aes_common.addRoundKey(&state, key_schedule.getRoundKey(0));
    
    @memcpy(output[0..AES_BLOCK_SIZE], &state);
}

// Import crypto utilities
const crypto_utils = @import("../include/crypto_utils.zig");

// GHASH function for GCM authentication (wrapper for crypto_utils)
fn ghash(h: []const u8, data: []const u8, allocator: Allocator) ![]u8 {
    return crypto_utils.cryptoGhash(h, data, allocator);
}

// Generate GCM IV
fn generateGcmIv(allocator: Allocator) ![]u8 {
    const iv = try allocator.alloc(u8, GCM_IV_SIZE);
    std.crypto.random.bytes(iv);
    return iv;
}

// Increment counter for CTR mode (wrapper for crypto_utils)
fn incrementCounter(counter: []u8) void {
    crypto_utils.cryptoIncrementCounter(counter);
}

// AES-GCM encryption
pub fn encrypt(aes_context: *AesContext, data: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    if (aes_context.key == null) {
        return error.AesKeyNotSet;
    }
    
    const key = aes_context.key.?;
    
    // Initialize GCM context
    var gcm_context = try GcmContext.init(allocator, key, aes_context.key_size);
    defer gcm_context.deinit();
    
    // Generate IV if not set
    var iv: []u8 = undefined;
    var should_free_iv = false;
    
    if (aes_context.iv) |existing_iv| {
        iv = existing_iv;
    } else {
        iv = try generateGcmIv(allocator);
        should_free_iv = true;
    }
    defer if (should_free_iv) allocator.free(iv);
    
    // Prepare counter block
    var counter: [AES_BLOCK_SIZE]u8 = std.mem.zeroes([AES_BLOCK_SIZE]u8);
    @memcpy(counter[0..iv.len], iv);
    counter[AES_BLOCK_SIZE - 1] = 1; // Initial counter value
    
    // Allocate output buffer (IV + ciphertext + tag)
    const output_size = iv.len + data.len + GCM_TAG_SIZE;
    const output = try allocator.alloc(u8, output_size);
    
    // Copy IV to output
    @memcpy(output[0..iv.len], iv);
    
    // Encrypt data using CTR mode
    var offset: usize = 0;
    const ciphertext_offset = iv.len;
    
    while (offset < data.len) {
        var keystream: [AES_BLOCK_SIZE]u8 = undefined;
        aesEncryptBlock(&gcm_context.key_schedule, &counter, &keystream);
        
        const block_size = @min(AES_BLOCK_SIZE, data.len - offset);
        for (0..block_size) |i| {
            output[ciphertext_offset + offset + i] = data[offset + i] ^ keystream[i];
        }
        
        offset += block_size;
        incrementCounter(&counter);
    }
    
    // Calculate authentication tag using GHASH
    const ciphertext = output[iv.len..iv.len + data.len];
    const auth_data = try ghash(&gcm_context.h, ciphertext, allocator);
    defer allocator.free(auth_data);
    
    // Copy tag to output
    @memcpy(output[iv.len + data.len..], auth_data[0..GCM_TAG_SIZE]);
    
    output_length.* = @intCast(output_size);
    return output;
}

// AES-GCM decryption
pub fn decrypt(aes_context: *AesContext, data: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    if (aes_context.key == null) {
        return error.AesKeyNotSet;
    }
    
    if (data.len < GCM_IV_SIZE + GCM_TAG_SIZE) {
        return error.InvalidGcmData;
    }
    
    const key = aes_context.key.?;
    
    // Initialize GCM context
    var gcm_context = try GcmContext.init(allocator, key, aes_context.key_size);
    defer gcm_context.deinit();
    
    // Extract IV, ciphertext, and tag
    const iv = data[0..GCM_IV_SIZE];
    const ciphertext_len = data.len - GCM_IV_SIZE - GCM_TAG_SIZE;
    const ciphertext = data[GCM_IV_SIZE..GCM_IV_SIZE + ciphertext_len];
    const tag = data[GCM_IV_SIZE + ciphertext_len..];
    
    // Verify authentication tag
    const expected_tag = try ghash(&gcm_context.h, ciphertext, allocator);
    defer allocator.free(expected_tag);
    
    // Constant-time comparison
    var tag_valid = true;
    for (tag, 0..) |byte, i| {
        if (i < GCM_TAG_SIZE and byte != expected_tag[i]) {
            tag_valid = false;
        }
    }
    
    if (!tag_valid) {
        return error.GcmAuthenticationFailed;
    }
    
    // Prepare counter block
    var counter: [AES_BLOCK_SIZE]u8 = std.mem.zeroes([AES_BLOCK_SIZE]u8);
    @memcpy(counter[0..iv.len], iv);
    counter[AES_BLOCK_SIZE - 1] = 1; // Initial counter value
    
    // Allocate output buffer
    const output = try allocator.alloc(u8, ciphertext_len);
    
    // Decrypt data using CTR mode
    var offset: usize = 0;
    
    while (offset < ciphertext_len) {
        var keystream: [AES_BLOCK_SIZE]u8 = undefined;
        aesEncryptBlock(&gcm_context.key_schedule, &counter, &keystream);
        
        const block_size = @min(AES_BLOCK_SIZE, ciphertext_len - offset);
        for (0..block_size) |i| {
            output[offset + i] = ciphertext[offset + i] ^ keystream[i];
        }
        
        offset += block_size;
        incrementCounter(&counter);
    }
    
    output_length.* = @intCast(ciphertext_len);
    return output;
} 