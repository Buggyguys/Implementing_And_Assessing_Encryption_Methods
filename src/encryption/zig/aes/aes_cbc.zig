const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

// Import AES modules
const aes_common = @import("aes_common.zig");
const aes_key = @import("aes_key.zig");
const crypto_utils = @import("../include/crypto_utils.zig");
const AesContext = aes_common.AesContext;

// CBC constants
const AES_BLOCK_SIZE = aes_common.AES_BLOCK_SIZE;

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

// AES-CBC encryption
pub fn encrypt(aes_context: *AesContext, data: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    if (aes_context.key == null) {
        return error.AesKeyNotSet;
    }
    
    const key = aes_context.key.?;
    
    // Initialize key schedule
    var key_schedule = try aes_key.AesKeySchedule.init(allocator, key, aes_context.key_size);
    defer key_schedule.deinit();
    
    // Pad data using PKCS#7
    const padded_data = try crypto_utils.cryptoPadPKCS7(allocator, data, AES_BLOCK_SIZE);
    defer allocator.free(padded_data);
    
    // Generate IV if not set
    var iv: []u8 = undefined;
    var should_free_iv = false;
    
    if (aes_context.iv) |existing_iv| {
        iv = existing_iv;
    } else {
        iv = try crypto_utils.cryptoGenerateIv(allocator, AES_BLOCK_SIZE);
        should_free_iv = true;
    }
    defer if (should_free_iv) allocator.free(iv);
    
    // Calculate output size (IV + encrypted data)
    const output_size = AES_BLOCK_SIZE + padded_data.len;
    const output = try allocator.alloc(u8, output_size);
    
    // Copy IV to beginning of output
    @memcpy(output[0..AES_BLOCK_SIZE], iv);
    
    // Encrypt data using CBC mode
    var previous_block: [AES_BLOCK_SIZE]u8 = undefined;
    @memcpy(&previous_block, iv);
    
    var i: usize = 0;
    while (i < padded_data.len) : (i += AES_BLOCK_SIZE) {
        var current_block: [AES_BLOCK_SIZE]u8 = undefined;
        @memcpy(&current_block, padded_data[i..i + AES_BLOCK_SIZE]);
        
        // XOR with previous block (or IV for first block)
        aes_common.xorBlocks(&current_block, &current_block, &previous_block);
        
        // Encrypt block
        aesEncryptBlock(&key_schedule, &current_block, output[AES_BLOCK_SIZE + i..AES_BLOCK_SIZE + i + AES_BLOCK_SIZE]);
        
        // Update previous block for next iteration
        @memcpy(&previous_block, output[AES_BLOCK_SIZE + i..AES_BLOCK_SIZE + i + AES_BLOCK_SIZE]);
    }
    
    output_length.* = @intCast(output_size);
    return output;
}

// AES-CBC decryption
pub fn decrypt(aes_context: *AesContext, data: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    if (aes_context.key == null) {
        return error.AesKeyNotSet;
    }
    
    if (data.len < AES_BLOCK_SIZE * 2) { // At least IV + one block
        return error.InvalidCiphertext;
    }
    
    const key = aes_context.key.?;
    
    // Initialize key schedule
    var key_schedule = try aes_key.AesKeySchedule.init(allocator, key, aes_context.key_size);
    defer key_schedule.deinit();
    
    // Extract IV and ciphertext
    const iv = data[0..AES_BLOCK_SIZE];
    const ciphertext = data[AES_BLOCK_SIZE..];
    
    if (ciphertext.len % AES_BLOCK_SIZE != 0) {
        return error.InvalidCiphertext;
    }
    
    // Decrypt data using CBC mode
    const decrypted_padded = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(decrypted_padded);
    
    var previous_block: [AES_BLOCK_SIZE]u8 = undefined;
    @memcpy(&previous_block, iv);
    
    var i: usize = 0;
    while (i < ciphertext.len) : (i += AES_BLOCK_SIZE) {
        var current_block: [AES_BLOCK_SIZE]u8 = undefined;
        
        // Decrypt block
        aesDecryptBlock(&key_schedule, ciphertext[i..i + AES_BLOCK_SIZE], &current_block);
        
        // XOR with previous block (or IV for first block)
        aes_common.xorBlocks(decrypted_padded[i..i + AES_BLOCK_SIZE], &current_block, &previous_block);
        
        // Update previous block for next iteration
        @memcpy(&previous_block, ciphertext[i..i + AES_BLOCK_SIZE]);
    }
    
    // Remove PKCS#7 padding
    const unpadded_data = try crypto_utils.cryptoUnpadPKCS7(decrypted_padded, AES_BLOCK_SIZE);
    
    // Copy unpadded data to output
    const output = try allocator.alloc(u8, unpadded_data.len);
    @memcpy(output, unpadded_data);
    
    output_length.* = @intCast(output.len);
    return output;
} 