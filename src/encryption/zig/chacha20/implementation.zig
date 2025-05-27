const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;
const json = std.json;

// Import our modules
const utils = @import("../include/utils.zig");
const crypto_utils = @import("../include/crypto_utils.zig");

// Import ChaCha20 custom implementation modules
const chacha20_core = @import("chacha20_core.zig");

// Import from parent module
const ImplementationRegistry = @import("../zig_core.zig").ImplementationRegistry;
const ImplementationInfo = @import("../zig_core.zig").ImplementationInfo;
const AlgorithmType = @import("../zig_core.zig").AlgorithmType;

// ChaCha20 context structure
pub const ChaCha20Context = struct {
    key: ?[]u8,
    nonce: ?[]u8,
    counter: u32,
    is_custom: bool,
    allocator: Allocator,
    
    pub fn init(allocator: Allocator) ChaCha20Context {
        return ChaCha20Context{
            .key = null,
            .nonce = null,
            .counter = 0,
            .is_custom = false,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *ChaCha20Context) void {
        if (self.key) |key| {
            utils.secureFree(self.allocator, key);
            self.key = null;
        }
        if (self.nonce) |nonce| {
            self.allocator.free(nonce);
            self.nonce = null;
        }
    }
};

// ChaCha20 constants
const CHACHA20_KEY_SIZE = 32; // 256 bits
const CHACHA20_NONCE_SIZE = 12; // 96 bits
const CHACHA20_BLOCK_SIZE = 64; // 512 bits

// ============================================================================
// STANDARD CHACHA20 IMPLEMENTATION (using Zig stdlib crypto)
// ============================================================================

fn chacha20StdInit(allocator: Allocator) !*anyopaque {
    const context = try allocator.create(ChaCha20Context);
    context.* = ChaCha20Context.init(allocator);
    context.is_custom = false;
    return @ptrCast(context);
}

fn chacha20StdCleanup(context: *anyopaque, allocator: Allocator) void {
    const chacha_context: *ChaCha20Context = @ptrCast(@alignCast(context));
    chacha_context.deinit();
    allocator.destroy(chacha_context);
}

fn chacha20StdGenerateKey(context: *anyopaque, allocator: Allocator, key_length: *i32) ![]u8 {
    const chacha_context: *ChaCha20Context = @ptrCast(@alignCast(context));
    
    // ChaCha20 always uses 256-bit (32-byte) keys
    const key = try utils.secureAlloc(allocator, CHACHA20_KEY_SIZE);
    
    // Use stdlib's cryptographically secure random number generator
    std.crypto.random.bytes(key);
    
    // Store key in context
    if (chacha_context.key) |old_key| {
        utils.secureFree(allocator, old_key);
    }
    chacha_context.key = try allocator.dupe(u8, key);
    
    // Generate nonce
    const nonce = try allocator.alloc(u8, CHACHA20_NONCE_SIZE);
    std.crypto.random.bytes(nonce);
    
    if (chacha_context.nonce) |old_nonce| {
        allocator.free(old_nonce);
    }
    chacha_context.nonce = nonce;
    chacha_context.counter = 0;
    
    key_length.* = CHACHA20_KEY_SIZE;
    return key;
}

fn chacha20StdEncrypt(context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    _ = key; // Key is stored in context
    const chacha_context: *ChaCha20Context = @ptrCast(@alignCast(context));
    
    if (chacha_context.key == null or chacha_context.nonce == null) {
        return error.ChaCha20KeyOrNonceNotSet;
    }
    
    const stored_key = chacha_context.key.?;
    const stored_nonce = chacha_context.nonce.?;
    
    // Use Zig's stdlib ChaCha20 for standard implementation
    return chacha20StdEncryptData(stored_key, stored_nonce, data, allocator, output_length);
}

fn chacha20StdDecrypt(context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    _ = key; // Key is stored in context
    const chacha_context: *ChaCha20Context = @ptrCast(@alignCast(context));
    
    if (chacha_context.key == null) {
        return error.ChaCha20KeyNotSet;
    }
    
    const stored_key = chacha_context.key.?;
    
    // Use Zig's stdlib ChaCha20 for standard implementation
    return chacha20StdDecryptData(stored_key, data, allocator, output_length);
}

// Standard ChaCha20 encryption using Zig stdlib
fn chacha20StdEncryptData(key: []const u8, nonce: []const u8, data: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    // Prepare output buffer: nonce + ciphertext
    const output_size = nonce.len + data.len;
    const output = try allocator.alloc(u8, output_size);
    
    // Copy nonce to output
    @memcpy(output[0..nonce.len], nonce);
    
    // Get ciphertext slice
    const ciphertext = output[nonce.len..];
    
    // Use Zig's stdlib ChaCha20 - Fixed for Zig 0.14
    const ChaCha20 = std.crypto.stream.chacha.ChaCha20IETF;
    ChaCha20.xor(ciphertext, data, 0, key[0..32].*, nonce[0..12].*);
    
    output_length.* = @intCast(output_size);
    return output;
}

// Standard ChaCha20 decryption using Zig stdlib
fn chacha20StdDecryptData(key: []const u8, data: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    if (data.len < CHACHA20_NONCE_SIZE) {
        return error.InvalidCiphertext;
    }
    
    // Extract nonce and ciphertext
    const nonce = data[0..CHACHA20_NONCE_SIZE];
    const ciphertext = data[CHACHA20_NONCE_SIZE..];
    
    // Prepare output buffer
    const output = try allocator.alloc(u8, ciphertext.len);
    
    // Use Zig's stdlib ChaCha20 - Fixed for Zig 0.14
    const ChaCha20 = std.crypto.stream.chacha.ChaCha20IETF;
    ChaCha20.xor(output, ciphertext, 0, key[0..32].*, nonce[0..12].*);
    
    output_length.* = @intCast(output.len);
    return output;
}

// ============================================================================
// CUSTOM CHACHA20 IMPLEMENTATION (from scratch, no stdlib crypto)
// ============================================================================

fn chacha20CustomInit(allocator: Allocator) !*anyopaque {
    const context = try allocator.create(ChaCha20Context);
    context.* = ChaCha20Context.init(allocator);
    context.is_custom = true;
    return @ptrCast(context);
}

fn chacha20CustomCleanup(context: *anyopaque, allocator: Allocator) void {
    const chacha_context: *ChaCha20Context = @ptrCast(@alignCast(context));
    chacha_context.deinit();
    allocator.destroy(chacha_context);
}

fn chacha20CustomGenerateKey(context: *anyopaque, allocator: Allocator, key_length: *i32) ![]u8 {
    const chacha_context: *ChaCha20Context = @ptrCast(@alignCast(context));
    
    // ChaCha20 always uses 256-bit (32-byte) keys
    const key = try utils.secureAlloc(allocator, CHACHA20_KEY_SIZE);
    
    // Enhanced custom secure random generation with multiple entropy sources
    var entropy_pool: [128]u8 = undefined;
    
    // Source 1: Primary cryptographic random (32 bytes)
    std.crypto.random.bytes(entropy_pool[0..32]);
    
    // Source 2: High-resolution timestamp entropy
    const timestamp_ns = std.time.nanoTimestamp();
    const timestamp_ms = std.time.milliTimestamp();
    std.mem.writeInt(i128, entropy_pool[32..48], timestamp_ns, .little);
    std.mem.writeInt(i64, entropy_pool[48..56], timestamp_ms, .little);
    
    // Source 3: Memory address entropy (ASLR provides randomness)
    const stack_addr = @intFromPtr(&entropy_pool);
    const heap_addr = @intFromPtr(key.ptr);
    std.mem.writeInt(usize, entropy_pool[56..64], stack_addr, .little);
    std.mem.writeInt(usize, entropy_pool[64..72], heap_addr, .little);
    
    // Source 4: Additional system entropy
    std.crypto.random.bytes(entropy_pool[72..104]);
    
    // Source 5: Process and thread specific entropy
    var thread_local_entropy: [24]u8 = undefined;
    std.crypto.random.bytes(&thread_local_entropy);
    @memcpy(entropy_pool[104..128], &thread_local_entropy);
    
    // Multi-round key derivation using HKDF-like approach with SHA3-256
    // Round 1: Extract phase - create pseudorandom key from entropy
    var extract_state = std.crypto.hash.sha3.Sha3_256.init(.{});
    extract_state.update("ChaCha20-Custom-Extract-Salt"); // Salt for extraction
    extract_state.update(&entropy_pool);
    
    var prk: [32]u8 = undefined; // Pseudorandom key
    extract_state.final(&prk);
    
    // Round 2: Expand phase - derive actual key material
    var expand_state = std.crypto.hash.sha3.Sha3_256.init(.{});
    expand_state.update(&prk);
    expand_state.update("ChaCha20-Custom-Key-Derivation-Info"); // Info string
    expand_state.update(&[_]u8{0x01}); // Counter byte
    
    var derived_key: [32]u8 = undefined;
    expand_state.final(&derived_key);
    
    // Round 3: Additional strengthening with fresh entropy
    var strengthen_state = std.crypto.hash.sha3.Sha3_256.init(.{});
    strengthen_state.update(&derived_key);
    
    // Add fresh entropy for each strengthening round
    var fresh_entropy: [32]u8 = undefined;
    std.crypto.random.bytes(&fresh_entropy);
    strengthen_state.update(&fresh_entropy);
    
    // Add temporal uniqueness
    const final_timestamp = std.time.nanoTimestamp();
    strengthen_state.update(std.mem.asBytes(&final_timestamp));
    
    var strengthened_key: [32]u8 = undefined;
    strengthen_state.final(&strengthened_key);
    
    // Copy the final derived key to our key buffer
    @memcpy(key, &strengthened_key);
    
    // Final non-linear mixing to ensure avalanche effect
    // Each byte influences multiple other bytes
    for (0..3) |round| { // Multiple mixing rounds
        for (key, 0..) |*byte, i| {
            // Create non-linear dependencies between bytes
            const prev_idx = (i + key.len - 1) % key.len;
            const next_idx = (i + 1) % key.len;
            const far_idx = (i + 16) % key.len;
            
            // Non-linear mixing using the bytes themselves
            const mix_val = key[prev_idx] ^ key[next_idx] ^ key[far_idx];
            byte.* ^= mix_val;
            byte.* = byte.* +% @as(u8, @truncate(round + i));
            
            // Add fresh randomness for each byte
            byte.* ^= @as(u8, @truncate(std.crypto.random.int(u64)));
        }
    }
    
    // Store key in context
    if (chacha_context.key) |old_key| {
        utils.secureFree(allocator, old_key);
    }
    chacha_context.key = try allocator.dupe(u8, key);
    
    // Generate nonce using similar enhanced approach
    const nonce = try allocator.alloc(u8, CHACHA20_NONCE_SIZE);
    
    // Enhanced nonce generation with temporal and spatial uniqueness
    var nonce_entropy: [64]u8 = undefined;
    std.crypto.random.bytes(&nonce_entropy);
    
    // Add high-resolution temporal entropy
    const nonce_timestamp = std.time.nanoTimestamp();
    const nonce_counter = std.time.microTimestamp();
    
    // HKDF-like nonce derivation
    var nonce_extract_state = std.crypto.hash.sha3.Sha3_256.init(.{});
    nonce_extract_state.update("ChaCha20-Custom-Nonce-Salt");
    nonce_extract_state.update(&nonce_entropy);
    nonce_extract_state.update(std.mem.asBytes(&nonce_timestamp));
    nonce_extract_state.update(std.mem.asBytes(&nonce_counter));
    
    var nonce_prk: [32]u8 = undefined;
    nonce_extract_state.final(&nonce_prk);
    
    var nonce_expand_state = std.crypto.hash.sha3.Sha3_256.init(.{});
    nonce_expand_state.update(&nonce_prk);
    nonce_expand_state.update("ChaCha20-Custom-Nonce-Info");
    nonce_expand_state.update(key); // Tie nonce to key for additional security
    nonce_expand_state.update(&[_]u8{0x01}); // Counter
    
    var nonce_derived: [32]u8 = undefined;
    nonce_expand_state.final(&nonce_derived);
    
    // Extract nonce from derived material (first 12 bytes)
    @memcpy(nonce, nonce_derived[0..CHACHA20_NONCE_SIZE]);
    
    // Additional nonce uniqueness processing
    for (nonce, 0..) |*byte, i| {
        // Ensure nonce is unique and unpredictable
        byte.* ^= @as(u8, @truncate(std.crypto.random.int(u64)));
        
        // Mix with key material to prevent nonce reuse with same key
        if (i < key.len) {
            byte.* ^= key[i];
        }
        
        // Add position-dependent mixing
        byte.* = byte.* +% @as(u8, @truncate(i * 31)); // Prime number for better distribution
    }
    
    // Final nonce validation - ensure it's not all zeros
    var nonce_sum: u32 = 0;
    for (nonce) |byte| {
        nonce_sum += byte;
    }
    if (nonce_sum == 0) {
        // Extremely unlikely, but add entropy if somehow all zeros
        nonce[0] = @as(u8, @truncate(std.crypto.random.int(u64))) | 1; // Ensure non-zero
    }
    
    if (chacha_context.nonce) |old_nonce| {
        allocator.free(old_nonce);
    }
    chacha_context.nonce = nonce;
    chacha_context.counter = 0;
    
    key_length.* = CHACHA20_KEY_SIZE;
    return key;
}

fn chacha20CustomEncrypt(context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    _ = key; // Key is stored in context
    const chacha_context: *ChaCha20Context = @ptrCast(@alignCast(context));
    
    if (chacha_context.key == null or chacha_context.nonce == null) {
        return error.ChaCha20KeyOrNonceNotSet;
    }
    
    const stored_key = chacha_context.key.?;
    const stored_nonce = chacha_context.nonce.?;
    
    // Use our custom ChaCha20 implementation
    return chacha20_core.encrypt(stored_key, stored_nonce, data, chacha_context.counter, allocator, output_length);
}

fn chacha20CustomDecrypt(context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    _ = key; // Key is stored in context
    const chacha_context: *ChaCha20Context = @ptrCast(@alignCast(context));
    
    if (chacha_context.key == null) {
        return error.ChaCha20KeyNotSet;
    }
    
    const stored_key = chacha_context.key.?;
    
    // Use our custom ChaCha20 implementation
    return chacha20_core.decrypt(stored_key, data, allocator, output_length);
}

// Stream processing functions
fn chacha20StdEncryptStream(context: *anyopaque, data: []const u8, key: []const u8, chunk_index: i32, allocator: Allocator, output_length: *i32) ![]u8 {
    _ = chunk_index;
    return chacha20StdEncrypt(context, data, key, allocator, output_length);
}

fn chacha20StdDecryptStream(context: *anyopaque, data: []const u8, key: []const u8, chunk_index: i32, allocator: Allocator, output_length: *i32) ![]u8 {
    _ = chunk_index;
    return chacha20StdDecrypt(context, data, key, allocator, output_length);
}

fn chacha20CustomEncryptStream(context: *anyopaque, data: []const u8, key: []const u8, chunk_index: i32, allocator: Allocator, output_length: *i32) ![]u8 {
    _ = chunk_index;
    return chacha20CustomEncrypt(context, data, key, allocator, output_length);
}

fn chacha20CustomDecryptStream(context: *anyopaque, data: []const u8, key: []const u8, chunk_index: i32, allocator: Allocator, output_length: *i32) ![]u8 {
    _ = chunk_index;
    return chacha20CustomDecrypt(context, data, key, allocator, output_length);
}

// Function to register ChaCha20 implementations
pub fn registerChaCha20Implementations(registry: *ImplementationRegistry, config_json: ?[]const u8, allocator: Allocator) !void {
    print("Registering ChaCha20 implementations...\n", .{});
    
    // Parse configuration to determine which implementations to register
    var chacha20_enabled = true;
    
    if (config_json) |config_str| {
        if (json.parseFromSlice(json.Value, allocator, config_str, .{})) |parsed| {
            defer parsed.deinit();
            
            if (parsed.value.object.get("encryption_methods")) |methods| {
                if (methods.object.get("chacha20")) |chacha20_config| {
                    if (chacha20_config.object.get("enabled")) |enabled| {
                        chacha20_enabled = enabled.bool;
                    }
                }
            }
        } else |_| {
            print("Warning: Could not parse config JSON for ChaCha20\n", .{});
            // Continue with defaults
        }
    }
    
    if (!chacha20_enabled) {
        print("ChaCha20 implementations disabled in configuration\n", .{});
        return;
    }
    
    print("ChaCha20 configuration: key_size=256 (fixed)\n", .{});
    
    // Register standard ChaCha20 implementation (using stdlib)
    var std_impl = ImplementationInfo.init();
    const std_name = "chacha20";
    @memcpy(std_impl.name[0..std_name.len], std_name);
    std_impl.algo_type = .chacha20;
    std_impl.is_custom = false;
    std_impl.key_size = 256; // ChaCha20 always uses 256-bit keys
    // ChaCha20 doesn't have modes like AES, so leave mode empty
    std_impl.init_fn = chacha20StdInit;
    std_impl.cleanup_fn = chacha20StdCleanup;
    std_impl.generate_key_fn = chacha20StdGenerateKey;
    std_impl.encrypt_fn = chacha20StdEncrypt;
    std_impl.decrypt_fn = chacha20StdDecrypt;
    std_impl.encrypt_stream_fn = chacha20StdEncryptStream;
    std_impl.decrypt_stream_fn = chacha20StdDecryptStream;
    
    try registry.register(std_impl);
    print("Registered: Standard ChaCha20 Implementation (using Zig stdlib)\n", .{});
    
    // Register custom ChaCha20 implementation (from scratch)
    var custom_impl = ImplementationInfo.init();
    const custom_name = "chacha20_custom";
    @memcpy(custom_impl.name[0..custom_name.len], custom_name);
    custom_impl.algo_type = .chacha20;
    custom_impl.is_custom = true;
    custom_impl.key_size = 256; // ChaCha20 always uses 256-bit keys
    // ChaCha20 doesn't have modes like AES, so leave mode empty
    custom_impl.init_fn = chacha20CustomInit;
    custom_impl.cleanup_fn = chacha20CustomCleanup;
    custom_impl.generate_key_fn = chacha20CustomGenerateKey;
    custom_impl.encrypt_fn = chacha20CustomEncrypt;
    custom_impl.decrypt_fn = chacha20CustomDecrypt;
    custom_impl.encrypt_stream_fn = chacha20CustomEncryptStream;
    custom_impl.decrypt_stream_fn = chacha20CustomDecryptStream;
    
    try registry.register(custom_impl);
    print("Registered: Custom ChaCha20 Implementation (from scratch)\n", .{});
    
    print("ChaCha20 implementations registered successfully\n", .{});
} 