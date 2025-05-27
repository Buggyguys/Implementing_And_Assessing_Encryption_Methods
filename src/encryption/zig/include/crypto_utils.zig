const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

// Cryptographic random number generation
pub fn cryptoRandomBytes(buffer: []u8) !void {
    // Use Zig's cryptographically secure random number generator
    try std.posix.getrandom(buffer);
}

// Securely allocate memory for cryptographic operations
pub fn cryptoSecureAlloc(allocator: Allocator, size: usize) ![]u8 {
    const memory = try allocator.alloc(u8, size);
    // Zero the memory for security
    @memset(memory, 0);
    return memory;
}

// Securely free memory used for cryptographic operations
pub fn cryptoSecureFree(allocator: Allocator, memory: []u8) void {
    // Zero the memory before freeing
    @memset(memory, 0);
    allocator.free(memory);
}

// Generate a cryptographically secure key of specified size
pub fn cryptoGenerateKey(allocator: Allocator, key_size: usize) ![]u8 {
    const key_buffer = try allocator.alloc(u8, key_size);
    try cryptoRandomBytes(key_buffer);
    return key_buffer;
}

// Generate a cryptographically secure initialization vector (IV)
pub fn cryptoGenerateIv(allocator: Allocator, iv_size: usize) ![]u8 {
    const iv_buffer = try allocator.alloc(u8, iv_size);
    try cryptoRandomBytes(iv_buffer);
    return iv_buffer;
}

// Generate a cryptographically secure nonce
pub fn cryptoGenerateNonce(allocator: Allocator, nonce_size: usize) ![]u8 {
    const nonce_buffer = try allocator.alloc(u8, nonce_size);
    try cryptoRandomBytes(nonce_buffer);
    return nonce_buffer;
}

// Constant-time memory comparison to prevent timing attacks
pub fn cryptoConstantTimeEquals(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    
    var result: u8 = 0;
    for (a, b) |byte_a, byte_b| {
        result |= byte_a ^ byte_b;
    }
    return result == 0;
}

// Helper function to get standard IV size for a given algorithm and mode
pub fn cryptoGetStandardIvSize(algorithm: []const u8, mode: []const u8) usize {
    // Common modes
    if (std.mem.eql(u8, mode, "GCM")) {
        return 12; // 96 bits
    } else if (std.mem.eql(u8, mode, "CBC") or std.mem.eql(u8, mode, "CTR")) {
        return 16; // 128 bits
    } else if (std.mem.eql(u8, mode, "ECB")) {
        return 0; // ECB doesn't use IV
    }
    
    // ChaCha20 specific
    if (std.mem.eql(u8, algorithm, "ChaCha20")) {
        return 12; // 96 bits nonce
    }
    
    // Default fallback
    return 16; // Most common IV size
}

// Helper function to get standard authentication tag size
pub fn cryptoGetStandardTagSize(algorithm: []const u8, mode: []const u8) usize {
    _ = algorithm; // Unused for now
    
    if (std.mem.eql(u8, mode, "GCM")) {
        return 16; // 128 bits
    } else if (std.mem.eql(u8, mode, "CCM")) {
        return 16; // 128 bits
    } else if (std.mem.eql(u8, mode, "OCB")) {
        return 16; // 128 bits
    }
    
    // Default for authenticated modes
    return 16;
}

// Simple HMAC-like authentication tag generation (placeholder)
pub fn cryptoGenerateAuthenticationTag(
    allocator: Allocator,
    data: []const u8,
    key: []const u8,
    tag_size: usize,
) ![]u8 {
    // This is a simplified implementation
    // In a real implementation, you'd use proper HMAC or GMAC
    
    const tag = try allocator.alloc(u8, tag_size);
    
    // Simple XOR-based tag generation (NOT secure, just for structure)
    var hash = std.hash.Fnv1a_64.init();
    hash.update(data);
    hash.update(key);
    const hash_value = hash.final();
    
    const hash_bytes = std.mem.asBytes(&hash_value);
    for (tag, 0..) |*byte, i| {
        byte.* = hash_bytes[i % hash_bytes.len];
    }
    
    return tag;
}

// Verify authentication tag
pub fn cryptoVerifyAuthenticationTag(
    allocator: Allocator,
    tag: []const u8,
    data: []const u8,
    key: []const u8,
) !bool {
    const computed_tag = try cryptoGenerateAuthenticationTag(allocator, data, key, tag.len);
    defer allocator.free(computed_tag);
    
    return cryptoConstantTimeEquals(tag, computed_tag);
}

// Mix data with salt (simple key derivation)
pub fn cryptoMixWithSalt(
    allocator: Allocator,
    input: []const u8,
    salt: []const u8,
    output_size: usize,
    iterations: i32,
) ![]u8 {
    const output = try allocator.alloc(u8, output_size);
    
    // Simple iterative mixing (NOT secure, just for structure)
    var temp_buffer = try allocator.alloc(u8, input.len + salt.len);
    defer allocator.free(temp_buffer);
    
    @memcpy(temp_buffer[0..input.len], input);
    @memcpy(temp_buffer[input.len..], salt);
    
    var i: i32 = 0;
    while (i < iterations) : (i += 1) {
        var hash = std.hash.Fnv1a_64.init();
        hash.update(temp_buffer);
        const hash_value = hash.final();
        
        const hash_bytes = std.mem.asBytes(&hash_value);
        for (temp_buffer, 0..) |*byte, idx| {
            byte.* ^= hash_bytes[idx % hash_bytes.len];
        }
    }
    
    // Copy to output buffer
    for (output, 0..) |*byte, idx| {
        byte.* = temp_buffer[idx % temp_buffer.len];
    }
    
    return output;
}

// Derive key from password (simplified PBKDF2-like function)
pub fn cryptoDeriveKeyFromPassword(
    allocator: Allocator,
    password: []const u8,
    salt: []const u8,
    derived_key_len: usize,
    iterations: i32,
) ![]u8 {
    // This is a simplified implementation
    // In a real implementation, you'd use proper PBKDF2, scrypt, or Argon2
    
    return cryptoMixWithSalt(allocator, password, salt, derived_key_len, iterations);
}

// Secure memory comparison (wrapper for constant-time comparison)
pub fn secureMemcmp(a: []const u8, b: []const u8) bool {
    return cryptoConstantTimeEquals(a, b);
}

// Generate secure random number in range
pub fn cryptoRandomInRange(max: u64) !u64 {
    var random_bytes: [8]u8 = undefined;
    try cryptoRandomBytes(&random_bytes);
    const random_value = std.mem.readInt(u64, &random_bytes, .little);
    return random_value % max;
}

// Generate secure random string (hex encoded)
pub fn cryptoRandomHexString(allocator: Allocator, length: usize) ![]u8 {
    const byte_length = (length + 1) / 2; // Round up for odd lengths
    const random_bytes = try allocator.alloc(u8, byte_length);
    defer allocator.free(random_bytes);
    
    try cryptoRandomBytes(random_bytes);
    
    const hex_string = try allocator.alloc(u8, length);
    const hex_chars = "0123456789abcdef";
    
    for (random_bytes, 0..) |byte, i| {
        if (i * 2 < length) {
            hex_string[i * 2] = hex_chars[byte >> 4];
        }
        if (i * 2 + 1 < length) {
            hex_string[i * 2 + 1] = hex_chars[byte & 0x0F];
        }
    }
    
    return hex_string;
}

// Wipe memory securely
pub fn cryptoWipeMemory(memory: []u8) void {
    // Use volatile to prevent compiler optimization
    const volatile_ptr: [*]volatile u8 = @ptrCast(memory.ptr);
    for (memory, 0..) |_, i| {
        volatile_ptr[i] = 0;
    }
}

// Test if system has secure random number generation
pub fn cryptoHasSecureRandom() bool {
    // On most modern systems, getrandom should be available
    var test_buffer: [1]u8 = undefined;
    return (std.posix.getrandom(&test_buffer) catch null) != null;
}

// ============================================================================
// COMMON BLOCK CIPHER OPERATIONS
// ============================================================================

// XOR two blocks of equal size
pub fn cryptoXorBlocks(dest: []u8, src1: []const u8, src2: []const u8) void {
    std.debug.assert(dest.len == src1.len and src1.len == src2.len);
    for (dest, 0..) |*byte, i| {
        byte.* = src1[i] ^ src2[i];
    }
}

// Copy block data
pub fn cryptoCopyBlock(dest: []u8, src: []const u8) void {
    std.debug.assert(dest.len >= src.len);
    @memcpy(dest[0..src.len], src);
}

// Increment counter for CTR mode (big-endian)
pub fn cryptoIncrementCounter(counter: []u8) void {
    var i: usize = counter.len;
    while (i > 0) {
        i -= 1;
        counter[i] = counter[i] +% 1;
        if (counter[i] != 0) break;
    }
}

// Increment counter for CTR mode (little-endian)
pub fn cryptoIncrementCounterLE(counter: []u8) void {
    for (counter) |*byte| {
        byte.* = byte.* +% 1;
        if (byte.* != 0) break;
    }
}

// Pad data using PKCS#7 padding
pub fn cryptoPadPKCS7(allocator: Allocator, data: []const u8, block_size: usize) ![]u8 {
    const padding_len = block_size - (data.len % block_size);
    const padded_len = data.len + padding_len;
    
    const padded_data = try allocator.alloc(u8, padded_len);
    @memcpy(padded_data[0..data.len], data);
    
    // Fill padding bytes with padding length value
    @memset(padded_data[data.len..], @intCast(padding_len));
    
    return padded_data;
}

// Remove PKCS#7 padding
pub fn cryptoUnpadPKCS7(data: []const u8, block_size: usize) ![]const u8 {
    if (data.len == 0 or data.len % block_size != 0) {
        return error.InvalidPadding;
    }
    
    const padding_len = data[data.len - 1];
    if (padding_len == 0 or padding_len > block_size) {
        return error.InvalidPadding;
    }
    
    // Verify all padding bytes are correct
    const start_idx = data.len - padding_len;
    for (data[start_idx..]) |byte| {
        if (byte != padding_len) {
            return error.InvalidPadding;
        }
    }
    
    return data[0..start_idx];
}

// Generate initialization vector for block ciphers
pub fn cryptoGenerateBlockIv(allocator: Allocator, block_size: usize) ![]u8 {
    return cryptoGenerateIv(allocator, block_size);
}

// ============================================================================
// GALOIS FIELD OPERATIONS (for GCM mode)
// ============================================================================

// Galois field multiplication in GF(2^128) for GCM
pub fn cryptoGfMul128(a: u128, b: u128) u128 {
    var result: u128 = 0;
    var a_copy = a;
    var b_copy = b;
    
    while (b_copy != 0) {
        if (b_copy & 1 != 0) {
            result ^= a_copy;
        }
        
        const carry = a_copy & (1 << 127) != 0;
        a_copy <<= 1;
        if (carry) {
            a_copy ^= 0x87; // Reduction polynomial for GF(2^128)
        }
        
        b_copy >>= 1;
    }
    
    return result;
}

// Convert bytes to u128 (big-endian)
pub fn cryptoBytesToU128(bytes: []const u8) u128 {
    std.debug.assert(bytes.len >= 16);
    var result: u128 = 0;
    for (bytes[0..16]) |byte| {
        result = (result << 8) | byte;
    }
    return result;
}

// Convert u128 to bytes (big-endian)
pub fn cryptoU128ToBytes(value: u128, bytes: []u8) void {
    std.debug.assert(bytes.len >= 16);
    var val = value;
    var i: usize = 16;
    while (i > 0) {
        i -= 1;
        bytes[i] = @intCast(val & 0xFF);
        val >>= 8;
    }
}

// GHASH function for GCM authentication
pub fn cryptoGhash(h: []const u8, data: []const u8, allocator: Allocator) ![]u8 {
    std.debug.assert(h.len >= 16);
    
    const h_val = cryptoBytesToU128(h);
    var y: u128 = 0;
    
    // Process data in 16-byte blocks
    var i: usize = 0;
    while (i < data.len) {
        var block: [16]u8 = std.mem.zeroes([16]u8);
        const block_size = @min(16, data.len - i);
        @memcpy(block[0..block_size], data[i..i + block_size]);
        
        const block_val = cryptoBytesToU128(&block);
        y = cryptoGfMul128(y ^ block_val, h_val);
        
        i += 16;
    }
    
    const result = try allocator.alloc(u8, 16);
    cryptoU128ToBytes(y, result);
    return result;
}

// ============================================================================
// KEY DERIVATION AND MANAGEMENT
// ============================================================================

// Expand key using a simple key schedule (for custom implementations)
pub fn cryptoExpandKey(allocator: Allocator, key: []const u8, expanded_size: usize) ![]u8 {
    const expanded_key = try allocator.alloc(u8, expanded_size);
    
    // Simple key expansion using repeated hashing
    var current_pos: usize = 0;
    var round: u32 = 0;
    
    while (current_pos < expanded_size) {
        var hash = std.hash.Fnv1a_64.init();
        hash.update(key);
        hash.update(std.mem.asBytes(&round));
        
        const hash_value = hash.final();
        const hash_bytes = std.mem.asBytes(&hash_value);
        
        const copy_len = @min(hash_bytes.len, expanded_size - current_pos);
        @memcpy(expanded_key[current_pos..current_pos + copy_len], hash_bytes[0..copy_len]);
        
        current_pos += copy_len;
        round += 1;
    }
    
    return expanded_key;
}

// Rotate key bytes (for key schedule operations)
pub fn cryptoRotateKeyBytes(key: []u8, positions: usize) void {
    if (key.len == 0) return;
    
    const actual_positions = positions % key.len;
    if (actual_positions == 0) return;
    
    // Simple rotation using temporary buffer
    var temp: [256]u8 = undefined; // Support up to 256-byte keys
    std.debug.assert(key.len <= temp.len);
    
    @memcpy(temp[0..key.len], key);
    
    for (key, 0..) |*byte, i| {
        byte.* = temp[(i + actual_positions) % key.len];
    }
}

// ============================================================================
// TIMING ATTACK PROTECTION
// ============================================================================

// Constant-time conditional move
pub fn cryptoConstantTimeMove(dest: []u8, src: []const u8, condition: bool) void {
    std.debug.assert(dest.len == src.len);
    
    const mask: u8 = if (condition) 0xFF else 0x00;
    
    for (dest, 0..) |*dest_byte, i| {
        dest_byte.* = (dest_byte.* & ~mask) | (src[i] & mask);
    }
}

// Constant-time byte selection
pub fn cryptoConstantTimeSelect(a: u8, b: u8, condition: bool) u8 {
    const mask: u8 = if (condition) 0xFF else 0x00;
    return (a & ~mask) | (b & mask);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// Convert hex string to bytes
pub fn cryptoHexToBytes(allocator: Allocator, hex_string: []const u8) ![]u8 {
    if (hex_string.len % 2 != 0) {
        return error.InvalidHexString;
    }
    
    const bytes = try allocator.alloc(u8, hex_string.len / 2);
    
    for (0..bytes.len) |i| {
        const hex_pair = hex_string[i * 2..i * 2 + 2];
        bytes[i] = std.fmt.parseInt(u8, hex_pair, 16) catch return error.InvalidHexString;
    }
    
    return bytes;
}

// Convert bytes to hex string
pub fn cryptoBytesToHex(allocator: Allocator, bytes: []const u8) ![]u8 {
    const hex_string = try allocator.alloc(u8, bytes.len * 2);
    const hex_chars = "0123456789abcdef";
    
    for (bytes, 0..) |byte, i| {
        hex_string[i * 2] = hex_chars[byte >> 4];
        hex_string[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    
    return hex_string;
} 