const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

// Import AES modules
const aes_common = @import("aes_common.zig");
const aes_key = @import("aes_key.zig");
const crypto_utils = @import("../include/crypto_utils.zig");
const AesContext = aes_common.AesContext;

// CTR constants
const AES_BLOCK_SIZE = aes_common.AES_BLOCK_SIZE;
const CTR_IV_SIZE = 12; // 96 bits for CTR mode

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

// Generate CTR IV/nonce
fn generateCtrIv(allocator: Allocator) ![]u8 {
    return crypto_utils.cryptoGenerateIv(allocator, CTR_IV_SIZE);
}

// AES-CTR encryption/decryption (same operation for both)
fn ctrCrypt(aes_context: *AesContext, data: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    if (aes_context.key == null) {
        return error.AesKeyNotSet;
    }
    
    const key = aes_context.key.?;
    
    // Initialize key schedule
    var key_schedule = try aes_key.AesKeySchedule.init(allocator, key, aes_context.key_size);
    defer key_schedule.deinit();
    
    // Generate IV if not set
    var iv: []u8 = undefined;
    var should_free_iv = false;
    
    if (aes_context.iv) |existing_iv| {
        iv = existing_iv;
    } else {
        iv = try generateCtrIv(allocator);
        should_free_iv = true;
    }
    defer if (should_free_iv) allocator.free(iv);
    
    // Calculate output size (IV + encrypted/decrypted data)
    const output_size = CTR_IV_SIZE + data.len;
    const output = try allocator.alloc(u8, output_size);
    
    // Copy IV to beginning of output
    @memcpy(output[0..CTR_IV_SIZE], iv);
    
    // Prepare counter block
    var counter: [AES_BLOCK_SIZE]u8 = std.mem.zeroes([AES_BLOCK_SIZE]u8);
    @memcpy(counter[0..CTR_IV_SIZE], iv);
    counter[AES_BLOCK_SIZE - 1] = 1; // Initial counter value
    
    // Process data in blocks
    var i: usize = 0;
    while (i < data.len) {
        // Encrypt counter to generate keystream
        var keystream: [AES_BLOCK_SIZE]u8 = undefined;
        aesEncryptBlock(&key_schedule, &counter, &keystream);
        
        // XOR data with keystream
        const block_size = @min(AES_BLOCK_SIZE, data.len - i);
        for (0..block_size) |j| {
            output[CTR_IV_SIZE + i + j] = data[i + j] ^ keystream[j];
        }
        
        // Increment counter
        crypto_utils.cryptoIncrementCounter(&counter);
        
        i += block_size;
    }
    
    output_length.* = @intCast(output_size);
    return output;
}

// AES-CTR encryption
pub fn encrypt(aes_context: *AesContext, data: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    return ctrCrypt(aes_context, data, allocator, output_length);
}

// AES-CTR decryption
pub fn decrypt(aes_context: *AesContext, data: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    if (data.len < CTR_IV_SIZE) {
        return error.InvalidCiphertext;
    }
    
    // Extract IV and ciphertext
    const iv = data[0..CTR_IV_SIZE];
    const ciphertext = data[CTR_IV_SIZE..];
    
    // Set IV in context for decryption
    if (aes_context.iv) |existing_iv| {
        allocator.free(existing_iv);
    }
    aes_context.iv = try allocator.dupe(u8, iv);
    
    // Decrypt (same as encrypt in CTR mode)
    const decrypted_with_iv = try ctrCrypt(aes_context, ciphertext, allocator, output_length);
    defer allocator.free(decrypted_with_iv);
    
    // Return only the decrypted data (without IV)
    const output = try allocator.alloc(u8, ciphertext.len);
    @memcpy(output, decrypted_with_iv[CTR_IV_SIZE..]);
    
    output_length.* = @intCast(output.len);
    return output;
} 