const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;
const json = std.json;

// Import our modules
const utils = @import("../include/utils.zig");
const crypto_utils = @import("../include/crypto_utils.zig");
const json_writer = @import("../include/json_writer.zig");

// Import RSA modules
const types = @import("types.zig");
const standard = @import("standard.zig");
const custom = @import("custom.zig");

// Use types from json_writer to avoid duplication
const AlgorithmType = json_writer.AlgorithmType;
const ImplementationInfo = json_writer.ImplementationInfo;
const ImplementationRegistry = @import("../zig_core.zig").ImplementationRegistry;

// Re-export RSA types and constants
pub const RSAContext = types.RSAContext;
pub const RSA_1024_KEY_SIZE = types.RSA_1024_KEY_SIZE;
pub const RSA_2048_KEY_SIZE = types.RSA_2048_KEY_SIZE;
pub const RSA_3072_KEY_SIZE = types.RSA_3072_KEY_SIZE;
pub const RSA_4096_KEY_SIZE = types.RSA_4096_KEY_SIZE;

// Re-export standard implementation functions
pub const rsaStandardInit = standard.rsaStandardInit;
pub const rsaStandardCleanup = standard.rsaStandardCleanup;
pub const rsaStandardGenerateKey = standard.rsaStandardGenerateKey;
pub const rsaStandardEncrypt = standard.rsaStandardEncrypt;
pub const rsaStandardDecrypt = standard.rsaStandardDecrypt;
pub const rsaStandardEncryptStream = standard.rsaStandardEncryptStream;
pub const rsaStandardDecryptStream = standard.rsaStandardDecryptStream;

// Re-export custom implementation functions
pub const rsaCustomInit = custom.rsaCustomInit;
pub const rsaCustomCleanup = custom.rsaCustomCleanup;
pub const rsaCustomGenerateKey = custom.rsaCustomGenerateKey;
pub const rsaCustomEncrypt = custom.rsaCustomEncrypt;
pub const rsaCustomDecrypt = custom.rsaCustomDecrypt;
pub const rsaCustomEncryptStream = custom.rsaCustomEncryptStream;
pub const rsaCustomDecryptStream = custom.rsaCustomDecryptStream;

// Function to register RSA implementations
pub fn registerRsaImplementations(registry: *ImplementationRegistry, config_json: ?[]const u8, allocator: Allocator) !void {
    print("Registering RSA implementations...\n", .{});
    
    // Parse configuration for RSA settings
    var key_size: i32 = RSA_2048_KEY_SIZE;
    var use_stdlib = true;
    var use_custom = true;
    
    if (config_json) |json_str| {
        if (json.parseFromSlice(json.Value, allocator, json_str, .{})) |parsed| {
            defer parsed.deinit();
            
            if (parsed.value.object.get("encryption_methods")) |methods| {
                if (methods.object.get("rsa")) |rsa_config| {
                    if (rsa_config.object.get("enabled")) |enabled| {
                        if (!enabled.bool) {
                            print("RSA implementations disabled in configuration\n", .{});
                            return;
                        }
                    }
                    
                    if (rsa_config.object.get("key_size")) |size| {
                        switch (size) {
                            .integer => |int_val| key_size = @intCast(int_val),
                            .string => |str_val| {
                                key_size = std.fmt.parseInt(i32, str_val, 10) catch RSA_2048_KEY_SIZE;
                            },
                            else => {},
                        }
                    }
                }
            }
            
            if (parsed.value.object.get("test_parameters")) |test_params| {
                if (test_params.object.get("use_stdlib")) |stdlib| {
                    use_stdlib = stdlib.bool;
                }
                if (test_params.object.get("use_custom")) |custom_param| {
                    use_custom = custom_param.bool;
                }
            }
        } else |err| {
            print("Warning: Could not parse config for RSA: {}\n", .{err});
            // Continue with defaults
        }
    }
    
    print("RSA configuration: key_size={d}\n", .{key_size});
    
    // Register standard implementation
    if (use_stdlib) {
        var std_impl = ImplementationInfo.init();
        
        // Set name and basic info
        const std_name = "rsa";
        @memcpy(std_impl.name[0..std_name.len], std_name);
        std_impl.name[std_name.len] = 0;
        
        std_impl.algo_type = .rsa;
        std_impl.is_custom = false;
        std_impl.key_size = key_size;
        
        // Set mode (RSA doesn't have modes like AES, but we'll indicate the key size)
        const mode_str = std.fmt.allocPrint(allocator, "{d}-bit", .{key_size}) catch "2048-bit";
        defer allocator.free(mode_str);
        const mode_len = @min(mode_str.len, std_impl.mode.len - 1);
        @memcpy(std_impl.mode[0..mode_len], mode_str[0..mode_len]);
        std_impl.mode[mode_len] = 0;
        
        // Set function pointers
        std_impl.init_fn = rsaStandardInit;
        std_impl.cleanup_fn = rsaStandardCleanup;
        std_impl.generate_key_fn = rsaStandardGenerateKey;
        std_impl.encrypt_fn = rsaStandardEncrypt;
        std_impl.decrypt_fn = rsaStandardDecrypt;
        std_impl.encrypt_stream_fn = rsaStandardEncryptStream;
        std_impl.decrypt_stream_fn = rsaStandardDecryptStream;
        
        try registry.register(std_impl);
        print("Registered: Standard RSA-{d} Implementation (using simulated RSA)\n", .{key_size});
    }
    
    // Register custom implementation
    if (use_custom) {
        var custom_impl = ImplementationInfo.init();
        
        // Set name and basic info
        const custom_name = "rsa_custom";
        @memcpy(custom_impl.name[0..custom_name.len], custom_name);
        custom_impl.name[custom_name.len] = 0;
        
        custom_impl.algo_type = .rsa;
        custom_impl.is_custom = true;
        custom_impl.key_size = key_size;
        
        // Set mode
        const mode_str = std.fmt.allocPrint(allocator, "{d}-bit", .{key_size}) catch "2048-bit";
        defer allocator.free(mode_str);
        const mode_len = @min(mode_str.len, custom_impl.mode.len - 1);
        @memcpy(custom_impl.mode[0..mode_len], mode_str[0..mode_len]);
        custom_impl.mode[mode_len] = 0;
        
        // Set function pointers
        custom_impl.init_fn = rsaCustomInit;
        custom_impl.cleanup_fn = rsaCustomCleanup;
        custom_impl.generate_key_fn = rsaCustomGenerateKey;
        custom_impl.encrypt_fn = rsaCustomEncrypt;
        custom_impl.decrypt_fn = rsaCustomDecrypt;
        custom_impl.encrypt_stream_fn = rsaCustomEncryptStream;
        custom_impl.decrypt_stream_fn = rsaCustomDecryptStream;
        
        try registry.register(custom_impl);
        print("Registered: Custom RSA-{d} Implementation (from scratch)\n", .{key_size});
    }
    
    print("RSA implementations registered successfully\n", .{});
} 