const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

// Import our modules
const utils = @import("../include/utils.zig");
const crypto_utils = @import("../include/crypto_utils.zig");

// Import AES mode implementations
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
    key_size: i32,          // Key size in bits (128, 192, or 256)
    mode: [16]u8,           // Mode of operation (CBC, CTR, GCM, ECB)
    is_custom: bool,        // Whether this is a custom implementation
    key: ?[]u8,             // Encryption key
    key_length: usize,      // Key length in bytes
    iv: ?[]u8,              // Initialization vector
    iv_length: usize,       // IV length in bytes
    allocator: Allocator,   // Memory allocator
    
    pub fn init(allocator: Allocator) AesContext {
        return AesContext{
            .key_size = 256,
            .mode = std.mem.zeroes([16]u8),
            .is_custom = false,
            .key = null,
            .key_length = 0,
            .iv = null,
            .iv_length = 0,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *AesContext) void {
        if (self.key) |key| {
            crypto_utils.cryptoSecureFree(self.allocator, key);
            self.key = null;
        }
        if (self.iv) |iv| {
            self.allocator.free(iv);
            self.iv = null;
        }
    }
    
    pub fn setMode(self: *AesContext, mode: []const u8) void {
        @memset(&self.mode, 0);
        @memcpy(self.mode[0..mode.len], mode);
    }
    
    pub fn getMode(self: *const AesContext) []const u8 {
        return std.mem.sliceTo(&self.mode, 0);
    }
};

// Function to register AES implementations
pub fn registerAesImplementations(registry: *ImplementationRegistry, config_json: ?[]const u8, allocator: Allocator) !void {
    const implementations_before = registry.count;
    
    // Parse configuration from JSON if provided
    var key_size: i32 = 256; // Default to 256
    var mode_buf: [16]u8 = std.mem.zeroes([16]u8); // Buffer for mode string
    @memcpy(mode_buf[0.."GCM".len], "GCM"); // Default to GCM
    var use_stdlib = true; // Default to true
    var use_custom = true; // Default to true
    var aes_enabled = true; // Default to enabled
    
    if (config_json) |json_str| {
        if (std.json.parseFromSlice(std.json.Value, allocator, json_str, .{})) |parsed| {
            defer parsed.deinit();
            
            // Check if AES is enabled
            if (parsed.value.object.get("encryption_methods")) |encryption_methods| {
                if (encryption_methods.object.get("aes")) |aes_config| {
                    if (aes_config.object.get("enabled")) |enabled| {
                        aes_enabled = enabled.bool;
                    }
                    
                    if (aes_config.object.get("key_size")) |key_size_str| {
                        const key_size_value = std.fmt.parseInt(i32, key_size_str.string, 10) catch 256;
                        key_size = key_size_value;
                    }
                    
                    if (aes_config.object.get("mode")) |mode_str| {
                        @memset(&mode_buf, 0);
                        const copy_len = @min(mode_str.string.len, mode_buf.len - 1);
                        @memcpy(mode_buf[0..copy_len], mode_str.string[0..copy_len]);
                    }
                }
            }
            
            // Check test parameters for stdlib/custom settings
            if (parsed.value.object.get("test_parameters")) |test_params| {
                if (test_params.object.get("use_stdlib")) |stdlib| {
                    use_stdlib = stdlib.bool;
                }
                
                if (test_params.object.get("use_custom")) |custom| {
                    use_custom = custom.bool;
                }
            }
        } else |err| {
            print("Warning: Could not parse config JSON for AES: {}\n", .{err});
            // Continue with defaults
        }
    }
    
    // Check if AES is enabled in the configuration
    if (!aes_enabled) {
        return;
    }
    
    // Register standard AES implementation if enabled
    if (use_stdlib) {
        var impl = ImplementationInfo.init();
        @memcpy(impl.name[0.."aes".len], "aes");
        impl.algo_type = .aes;
        impl.is_custom = false;
        impl.key_size = key_size;
        const mode_slice = std.mem.sliceTo(&mode_buf, 0);
        const mode_copy_len = @min(mode_slice.len, impl.mode.len - 1);
        @memcpy(impl.mode[0..mode_copy_len], mode_slice[0..mode_copy_len]);
        impl.mode[mode_copy_len] = 0;
        impl.init_fn = aesInit;
        impl.cleanup_fn = aesCleanup;
        impl.generate_key_fn = aesGenerateKey;
        impl.encrypt_fn = aesEncrypt;
        impl.decrypt_fn = aesDecrypt;
        impl.encrypt_stream_fn = aesEncryptStream;
        impl.decrypt_stream_fn = aesDecryptStream;
        
        try registry.register(impl);
    }
    
    // Register custom AES implementation if enabled
    if (use_custom) {
        var impl = ImplementationInfo.init();
        @memcpy(impl.name[0.."aes_custom".len], "aes_custom");
        impl.algo_type = .aes;
        impl.is_custom = true;
        impl.key_size = key_size;
        const mode_slice = std.mem.sliceTo(&mode_buf, 0);
        const mode_copy_len = @min(mode_slice.len, impl.mode.len - 1);
        @memcpy(impl.mode[0..mode_copy_len], mode_slice[0..mode_copy_len]);
        impl.mode[mode_copy_len] = 0;
        impl.init_fn = aesCustomInit;
        impl.cleanup_fn = aesCustomCleanup;
        impl.generate_key_fn = aesCustomGenerateKey;
        impl.encrypt_fn = aesCustomEncrypt;
        impl.decrypt_fn = aesCustomDecrypt;
        impl.encrypt_stream_fn = aesEncryptStream;
        impl.decrypt_stream_fn = aesDecryptStream;
        
        try registry.register(impl);
    }
    
    print("Registered {d} AES implementations\n", .{registry.count - implementations_before});
}

// Standard library implementation functions
fn aesInit(allocator: Allocator) anyerror!*anyopaque {
    const context = try allocator.create(AesContext);
    context.* = AesContext.init(allocator);
    context.key_size = 256;
    context.setMode("GCM");
    context.is_custom = false;
    
    return @ptrCast(context);
}

fn aesCleanup(context: *anyopaque, allocator: Allocator) void {
    const aes_context: *AesContext = @ptrCast(@alignCast(context));
    aes_context.deinit();
    allocator.destroy(aes_context);
}

fn aesGenerateKey(context: *anyopaque, allocator: Allocator, key_length: *i32) anyerror![]u8 {
    const aes_context: *AesContext = @ptrCast(@alignCast(context));
    const key_size_bytes = @as(usize, @intCast(@divExact(aes_context.key_size, 8)));
    
    const key = try crypto_utils.cryptoGenerateKey(allocator, key_size_bytes);
    key_length.* = @intCast(key_size_bytes);
    
    return key;
}

fn aesEncrypt(context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) anyerror![]u8 {
    const aes_context: *AesContext = @ptrCast(@alignCast(context));
    
    // Set the key if provided
    if (key.len > 0) {
        if (aes_context.key) |old_key| {
            crypto_utils.cryptoSecureFree(allocator, old_key);
        }
        
        aes_context.key_length = @as(usize, @intCast(@divExact(aes_context.key_size, 8)));
        aes_context.key = try allocator.dupe(u8, key[0..aes_context.key_length]);
    }
    
    // Check if key exists
    if (aes_context.key == null) {
        return error.AesKeyNotSet;
    }
    
    const mode = aes_context.getMode();
    
    // Encrypt based on mode
    if (std.mem.eql(u8, mode, "GCM")) {
        return aes_gcm.encrypt(aes_context, data, allocator, output_length);
    } else if (std.mem.eql(u8, mode, "CBC")) {
        return aes_cbc.encrypt(aes_context, data, allocator, output_length);
    } else if (std.mem.eql(u8, mode, "CTR")) {
        return aes_ctr.encrypt(aes_context, data, allocator, output_length);
    } else if (std.mem.eql(u8, mode, "ECB")) {
        return aes_ecb.encrypt(aes_context, data, allocator, output_length);
    } else {
        print("Error: Unsupported AES mode: {s}\n", .{mode});
        return error.UnsupportedAesMode;
    }
}

fn aesDecrypt(context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) anyerror![]u8 {
    const aes_context: *AesContext = @ptrCast(@alignCast(context));
    
    // Set the key if provided
    if (key.len > 0) {
        if (aes_context.key) |old_key| {
            crypto_utils.cryptoSecureFree(allocator, old_key);
        }
        
        aes_context.key_length = @as(usize, @intCast(@divExact(aes_context.key_size, 8)));
        aes_context.key = try allocator.dupe(u8, key[0..aes_context.key_length]);
    }
    
    // Check if key exists
    if (aes_context.key == null) {
        return error.AesKeyNotSet;
    }
    
    const mode = aes_context.getMode();
    
    // Decrypt based on mode
    if (std.mem.eql(u8, mode, "GCM")) {
        return aes_gcm.decrypt(aes_context, data, allocator, output_length);
    } else if (std.mem.eql(u8, mode, "CBC")) {
        return aes_cbc.decrypt(aes_context, data, allocator, output_length);
    } else if (std.mem.eql(u8, mode, "CTR")) {
        return aes_ctr.decrypt(aes_context, data, allocator, output_length);
    } else if (std.mem.eql(u8, mode, "ECB")) {
        return aes_ecb.decrypt(aes_context, data, allocator, output_length);
    } else {
        print("Error: Unsupported AES mode: {s}\n", .{mode});
        return error.UnsupportedAesMode;
    }
}

// Custom implementation functions (simplified - same as standard for now)
fn aesCustomInit(allocator: Allocator) anyerror!*anyopaque {
    const context = try allocator.create(AesContext);
    context.* = AesContext.init(allocator);
    context.key_size = 256;
    context.setMode("GCM");
    context.is_custom = true;
    
    return @ptrCast(context);
}

fn aesCustomCleanup(context: *anyopaque, allocator: Allocator) void {
    const aes_context: *AesContext = @ptrCast(@alignCast(context));
    aes_context.deinit();
    allocator.destroy(aes_context);
}

fn aesCustomGenerateKey(context: *anyopaque, allocator: Allocator, key_length: *i32) anyerror![]u8 {
    return aesGenerateKey(context, allocator, key_length);
}

fn aesCustomEncrypt(context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) anyerror![]u8 {
    // For now, custom implementation is the same as standard
    // In a real implementation, this would use a custom AES implementation
    return aesEncrypt(context, data, key, allocator, output_length);
}

fn aesCustomDecrypt(context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) anyerror![]u8 {
    // For now, custom implementation is the same as standard
    // In a real implementation, this would use a custom AES implementation
    return aesDecrypt(context, data, key, allocator, output_length);
}

// Stream processing functions
fn aesEncryptStream(context: *anyopaque, data: []const u8, key: []const u8, chunk_index: i32, allocator: Allocator, output_length: *i32) anyerror![]u8 {
    _ = chunk_index; // For now, we'll treat stream processing the same as regular processing
    return aesEncrypt(context, data, key, allocator, output_length);
}

fn aesDecryptStream(context: *anyopaque, data: []const u8, key: []const u8, chunk_index: i32, allocator: Allocator, output_length: *i32) anyerror![]u8 {
    _ = chunk_index; // For now, we'll treat stream processing the same as regular processing
    return aesDecrypt(context, data, key, allocator, output_length);
} 