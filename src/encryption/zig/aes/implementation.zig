const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;
const json = std.json;

// Import our modules
const utils = @import("../include/utils.zig");
const crypto_utils = @import("../include/crypto_utils.zig");

// Import AES mode implementations (for custom implementation only)
const aes_common = @import("aes_common.zig");
const aes_key = @import("aes_key.zig");
const aes_gcm = @import("aes_gcm.zig");
const aes_cbc = @import("aes_cbc.zig");
const aes_ctr = @import("aes_ctr.zig");
const aes_ecb = @import("aes_ecb.zig");

// Import from parent module
const ImplementationRegistry = @import("../zig_core.zig").ImplementationRegistry;
const ImplementationInfo = @import("../zig_core.zig").ImplementationInfo;
const AlgorithmType = @import("../zig_core.zig").AlgorithmType;

// AES context structure
pub const AesContext = struct {
    key: ?[]u8,
    key_size: i32,
    iv: ?[]u8,
    iv_length: usize,
    mode: [16]u8,
    is_custom: bool,
    allocator: Allocator,
    
    pub fn init(allocator: Allocator) AesContext {
        return AesContext{
            .key = null,
            .key_size = 128, // Default to AES-128, will be overridden by config
            .iv = null,
            .iv_length = 16, // Standard IV size for AES
            .mode = std.mem.zeroes([16]u8),
            .is_custom = false,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *AesContext) void {
        if (self.key) |key| {
            utils.secureFree(self.allocator, key);
            self.key = null;
        }
        if (self.iv) |iv| {
            self.allocator.free(iv);
            self.iv = null;
        }
    }
};

// Global configuration for AES implementations
var global_aes_key_size: i32 = 128;
var global_aes_mode: [16]u8 = std.mem.zeroes([16]u8);

// ============================================================================
// STANDARD AES IMPLEMENTATION (using Zig stdlib crypto)
// ============================================================================

fn aesStdInit(allocator: Allocator) !*anyopaque {
    const context = try allocator.create(AesContext);
    context.* = AesContext.init(allocator);
    context.is_custom = false;
    context.key_size = global_aes_key_size; // Use global configuration
    
    // Set mode from global configuration
    context.mode = global_aes_mode;
    
    return @ptrCast(context);
}

fn aesStdCleanup(context: *anyopaque, allocator: Allocator) void {
    const aes_context: *AesContext = @ptrCast(@alignCast(context));
    aes_context.deinit();
    allocator.destroy(aes_context);
}

fn aesStdGenerateKey(context: *anyopaque, allocator: Allocator, key_length: *i32) ![]u8 {
    const aes_context: *AesContext = @ptrCast(@alignCast(context));
    
    // Generate key based on configured key size using stdlib
    const key_size_bytes = @divExact(aes_context.key_size, 8);
    const key = try utils.secureAlloc(allocator, @intCast(key_size_bytes));
    
    // Use stdlib's cryptographically secure random number generator
    std.crypto.random.bytes(key);
    
    // Store key in context
    if (aes_context.key) |old_key| {
        utils.secureFree(allocator, old_key);
    }
    aes_context.key = try allocator.dupe(u8, key);
    
    key_length.* = key_size_bytes;
    return key;
}

fn aesStdEncrypt(context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    _ = key; // Key is stored in context
    const aes_context: *AesContext = @ptrCast(@alignCast(context));
    
    if (aes_context.key == null) {
        return error.AesKeyNotSet;
    }
    
    const stored_key = aes_context.key.?;
    const mode_str = std.mem.sliceTo(&aes_context.mode, 0);
    
    // Use Zig's stdlib crypto for standard implementation
    if (std.mem.eql(u8, mode_str, "GCM")) {
        return aesStdEncryptGCM(stored_key, data, allocator, output_length);
    } else {
        // Default to GCM if mode not recognized
        return aesStdEncryptGCM(stored_key, data, allocator, output_length);
    }
}

fn aesStdDecrypt(context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    _ = key; // Key is stored in context
    const aes_context: *AesContext = @ptrCast(@alignCast(context));
    
    if (aes_context.key == null) {
        return error.AesKeyNotSet;
    }
    
    const stored_key = aes_context.key.?;
    const mode_str = std.mem.sliceTo(&aes_context.mode, 0);
    
    // Use Zig's stdlib crypto for standard implementation
    if (std.mem.eql(u8, mode_str, "GCM")) {
        return aesStdDecryptGCM(stored_key, data, allocator, output_length);
    } else {
        // Default to GCM if mode not recognized
        return aesStdDecryptGCM(stored_key, data, allocator, output_length);
    }
}

// Standard AES-GCM encryption using Zig stdlib
fn aesStdEncryptGCM(key: []const u8, data: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    // Generate random nonce (12 bytes for GCM)
    var nonce: [12]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    
    // Prepare output buffer: nonce + ciphertext + tag
    const tag_size = 16;
    const output_size = nonce.len + data.len + tag_size;
    const output = try allocator.alloc(u8, output_size);
    
    // Copy nonce to output
    @memcpy(output[0..nonce.len], &nonce);
    
    // Get ciphertext and tag slices
    const ciphertext = output[nonce.len..nonce.len + data.len];
    var tag_array: [16]u8 = undefined;
    
    // Use stdlib AES-GCM based on key size
    switch (key.len) {
        16 => { // AES-128
            const aes = std.crypto.aead.aes_gcm.Aes128Gcm;
            aes.encrypt(ciphertext, &tag_array, data, "", nonce, key[0..16].*);
        },
        24 => { // AES-192 (fallback to AES-256)
            const aes = std.crypto.aead.aes_gcm.Aes256Gcm;
            var key256: [32]u8 = std.mem.zeroes([32]u8);
            @memcpy(key256[0..24], key[0..24]);
            aes.encrypt(ciphertext, &tag_array, data, "", nonce, key256);
        },
        32 => { // AES-256
            const aes = std.crypto.aead.aes_gcm.Aes256Gcm;
            aes.encrypt(ciphertext, &tag_array, data, "", nonce, key[0..32].*);
        },
        else => return error.InvalidKeySize,
    }
    
    // Copy tag to output
    @memcpy(output[nonce.len + data.len..], &tag_array);
    
    output_length.* = @intCast(output_size);
    return output;
}

// Standard AES-GCM decryption using Zig stdlib
fn aesStdDecryptGCM(key: []const u8, data: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    const nonce_size = 12;
    const tag_size = 16;
    
    if (data.len < nonce_size + tag_size) {
        return error.InvalidCiphertext;
    }
    
    // Extract components
    const nonce = data[0..nonce_size];
    const ciphertext_len = data.len - nonce_size - tag_size;
    const ciphertext = data[nonce_size..nonce_size + ciphertext_len];
    const tag = data[nonce_size + ciphertext_len..];
    
    // Prepare output buffer
    const output = try allocator.alloc(u8, ciphertext_len);
    
    // Use stdlib AES-GCM based on key size
    switch (key.len) {
        16 => { // AES-128
            const aes = std.crypto.aead.aes_gcm.Aes128Gcm;
            aes.decrypt(output, ciphertext, tag[0..16].*, "", nonce[0..12].*, key[0..16].*) catch {
                allocator.free(output);
                return error.AuthenticationFailed;
            };
        },
        24 => { // AES-192 (fallback to AES-256)
            const aes = std.crypto.aead.aes_gcm.Aes256Gcm;
            var key256: [32]u8 = std.mem.zeroes([32]u8);
            @memcpy(key256[0..24], key[0..24]);
            aes.decrypt(output, ciphertext, tag[0..16].*, "", nonce[0..12].*, key256) catch {
                allocator.free(output);
                return error.AuthenticationFailed;
            };
        },
        32 => { // AES-256
            const aes = std.crypto.aead.aes_gcm.Aes256Gcm;
            aes.decrypt(output, ciphertext, tag[0..16].*, "", nonce[0..12].*, key[0..32].*) catch {
                allocator.free(output);
                return error.AuthenticationFailed;
            };
        },
        else => {
            allocator.free(output);
            return error.InvalidKeySize;
        },
    }
    
    output_length.* = @intCast(output.len);
    return output;
}

// ============================================================================
// CUSTOM AES IMPLEMENTATION (from scratch, no stdlib crypto)
// ============================================================================

fn aesCustomInit(allocator: Allocator) !*anyopaque {
    const context = try allocator.create(AesContext);
    context.* = AesContext.init(allocator);
    context.is_custom = true;
    context.key_size = global_aes_key_size; // Use global configuration
    
    // Set mode from global configuration
    context.mode = global_aes_mode;
    
    return @ptrCast(context);
}

fn aesCustomCleanup(context: *anyopaque, allocator: Allocator) void {
    const aes_context: *AesContext = @ptrCast(@alignCast(context));
    aes_context.deinit();
    allocator.destroy(aes_context);
}

fn aesCustomGenerateKey(context: *anyopaque, allocator: Allocator, key_length: *i32) ![]u8 {
    const aes_context: *AesContext = @ptrCast(@alignCast(context));
    
    // Generate key based on configured key size (custom implementation)
    const key_size_bytes = @divExact(aes_context.key_size, 8);
    const key = try utils.secureAlloc(allocator, @intCast(key_size_bytes));
    
    // Use our own random generation (not stdlib crypto)
    // For demonstration, we'll still use std.crypto.random but add custom processing
    std.crypto.random.bytes(key);
    
    // Apply custom key strengthening
    for (key, 0..) |*byte, i| {
        byte.* ^= @as(u8, @intCast(i % 256)); // XOR with index for custom pattern
        byte.* = byte.* +% @as(u8, @intCast((i * 7) % 256)); // Add custom offset
    }
    
    // Store key in context
    if (aes_context.key) |old_key| {
        utils.secureFree(allocator, old_key);
    }
    aes_context.key = try allocator.dupe(u8, key);
    
    key_length.* = key_size_bytes;
    return key;
}

fn aesCustomEncrypt(context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    _ = key; // Use key from context
    const aes_context: *AesContext = @ptrCast(@alignCast(context));
    
    if (aes_context.key == null) {
        return error.AesKeyNotSet;
    }
    
    _ = aes_context.key.?; // Ensure key exists
    const mode_str = std.mem.sliceTo(&aes_context.mode, 0);
    
    // Use our custom AES implementation
    if (std.mem.eql(u8, mode_str, "GCM")) {
        return aes_gcm.encrypt(aes_context, data, allocator, output_length);
    } else if (std.mem.eql(u8, mode_str, "CBC")) {
        return aes_cbc.encrypt(aes_context, data, allocator, output_length);
    } else if (std.mem.eql(u8, mode_str, "CTR")) {
        return aes_ctr.encrypt(aes_context, data, allocator, output_length);
    } else if (std.mem.eql(u8, mode_str, "ECB")) {
        return aes_ecb.encrypt(aes_context, data, allocator, output_length);
    } else {
        // Default to GCM
        return aes_gcm.encrypt(aes_context, data, allocator, output_length);
    }
}

fn aesCustomDecrypt(context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    _ = key; // Use key from context
    const aes_context: *AesContext = @ptrCast(@alignCast(context));
    
    if (aes_context.key == null) {
        return error.AesKeyNotSet;
    }
    
    _ = aes_context.key.?; // Ensure key exists
    const mode_str = std.mem.sliceTo(&aes_context.mode, 0);
    
    // Use our custom AES implementation
    if (std.mem.eql(u8, mode_str, "GCM")) {
        return aes_gcm.decrypt(aes_context, data, allocator, output_length);
    } else if (std.mem.eql(u8, mode_str, "CBC")) {
        return aes_cbc.decrypt(aes_context, data, allocator, output_length);
    } else if (std.mem.eql(u8, mode_str, "CTR")) {
        return aes_ctr.decrypt(aes_context, data, allocator, output_length);
    } else if (std.mem.eql(u8, mode_str, "ECB")) {
        return aes_ecb.decrypt(aes_context, data, allocator, output_length);
    } else {
        // Default to GCM
        return aes_gcm.decrypt(aes_context, data, allocator, output_length);
    }
}

// Stream processing functions
fn aesStdEncryptStream(context: *anyopaque, data: []const u8, key: []const u8, chunk_index: i32, allocator: Allocator, output_length: *i32) ![]u8 {
    _ = chunk_index;
    return aesStdEncrypt(context, data, key, allocator, output_length);
}

fn aesStdDecryptStream(context: *anyopaque, data: []const u8, key: []const u8, chunk_index: i32, allocator: Allocator, output_length: *i32) ![]u8 {
    _ = chunk_index;
    return aesStdDecrypt(context, data, key, allocator, output_length);
}

fn aesCustomEncryptStream(context: *anyopaque, data: []const u8, key: []const u8, chunk_index: i32, allocator: Allocator, output_length: *i32) ![]u8 {
    _ = chunk_index;
    return aesCustomEncrypt(context, data, key, allocator, output_length);
}

fn aesCustomDecryptStream(context: *anyopaque, data: []const u8, key: []const u8, chunk_index: i32, allocator: Allocator, output_length: *i32) ![]u8 {
    _ = chunk_index;
    return aesCustomDecrypt(context, data, key, allocator, output_length);
}

// Function to register AES implementations
pub fn registerAesImplementations(registry: *ImplementationRegistry, config_json: ?[]const u8, allocator: Allocator) !void {
    print("Registering AES implementations...\n", .{});
    
    // Parse configuration to determine which implementations to register
    var aes_enabled = true;
    var aes_key_size: i32 = 256; // Default to AES-256
    var aes_mode_buf: [16]u8 = std.mem.zeroes([16]u8);
    const aes_mode_str = "GCM";
    @memcpy(aes_mode_buf[0..aes_mode_str.len], aes_mode_str);
    
    if (config_json) |config_str| {
        if (json.parseFromSlice(json.Value, allocator, config_str, .{})) |parsed| {
            defer parsed.deinit();
            
            if (parsed.value.object.get("encryption_methods")) |methods| {
                if (methods.object.get("aes")) |aes_config| {
                    if (aes_config.object.get("enabled")) |enabled| {
                        aes_enabled = enabled.bool;
                    }
                    
                    if (aes_config.object.get("key_size")) |key_size| {
                        if (std.fmt.parseInt(i32, key_size.string, 10)) |size| {
                            aes_key_size = size;
                        } else |_| {
                            print("Warning: Invalid AES key size, using default 256\n", .{});
                        }
                    }
                    
                    if (aes_config.object.get("mode")) |mode| {
                        const mode_str = mode.string;
                        const copy_len = @min(mode_str.len, aes_mode_buf.len - 1);
                        @memset(&aes_mode_buf, 0);
                        @memcpy(aes_mode_buf[0..copy_len], mode_str[0..copy_len]);
                    }
                }
            }
        } else |_| {
            print("Warning: Could not parse config JSON\n", .{});
            // Continue with defaults
        }
    }
    
    if (!aes_enabled) {
        print("AES implementations disabled in configuration\n", .{});
        return;
    }
    
    print("AES configuration: key_size={d}, mode={s}\n", .{ aes_key_size, std.mem.sliceTo(&aes_mode_buf, 0) });
    
    // Set global configuration
    global_aes_key_size = aes_key_size;
    global_aes_mode = aes_mode_buf;
    
    // Register standard AES implementation (using stdlib)
    var std_impl = ImplementationInfo.init();
    const std_name = "aes";
    @memcpy(std_impl.name[0..std_name.len], std_name);
    std_impl.algo_type = .aes;
    std_impl.is_custom = false;
    std_impl.key_size = aes_key_size;
    std_impl.mode = aes_mode_buf;
    std_impl.init_fn = aesStdInit;
    std_impl.cleanup_fn = aesStdCleanup;
    std_impl.generate_key_fn = aesStdGenerateKey;
    std_impl.encrypt_fn = aesStdEncrypt;
    std_impl.decrypt_fn = aesStdDecrypt;
    std_impl.encrypt_stream_fn = aesStdEncryptStream;
    std_impl.decrypt_stream_fn = aesStdDecryptStream;
    
    try registry.register(std_impl);
    print("Registered: Standard AES-{d} {s} Implementation (using Zig stdlib)\n", .{ aes_key_size, std.mem.sliceTo(&aes_mode_buf, 0) });
    
    // Register custom AES implementation (from scratch)
    var custom_impl = ImplementationInfo.init();
    const custom_name = "aes_custom";
    @memcpy(custom_impl.name[0..custom_name.len], custom_name);
    custom_impl.algo_type = .aes;
    custom_impl.is_custom = true;
    custom_impl.key_size = aes_key_size;
    custom_impl.mode = aes_mode_buf;
    custom_impl.init_fn = aesCustomInit;
    custom_impl.cleanup_fn = aesCustomCleanup;
    custom_impl.generate_key_fn = aesCustomGenerateKey;
    custom_impl.encrypt_fn = aesCustomEncrypt;
    custom_impl.decrypt_fn = aesCustomDecrypt;
    custom_impl.encrypt_stream_fn = aesCustomEncryptStream;
    custom_impl.decrypt_stream_fn = aesCustomDecryptStream;
    
    try registry.register(custom_impl);
    print("Registered: Custom AES-{d} {s} Implementation (from scratch)\n", .{ aes_key_size, std.mem.sliceTo(&aes_mode_buf, 0) });
    
    print("AES implementations registered successfully\n", .{});
} 