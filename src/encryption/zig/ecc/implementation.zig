const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;
const json = std.json;

// Import our modules
const utils = @import("../include/utils.zig");
const crypto_utils = @import("../include/crypto_utils.zig");
const json_writer = @import("../include/json_writer.zig");

// Import ECC modules
const types = @import("types.zig");
const standard = @import("standard.zig");
const custom = @import("custom.zig");

// Use types from json_writer to avoid duplication
const AlgorithmType = json_writer.AlgorithmType;
const ImplementationInfo = json_writer.ImplementationInfo;
const ImplementationRegistry = @import("../zig_core.zig").ImplementationRegistry;

// Re-export ECC types and constants
pub const ECCContext = types.ECCContext;
pub const ECCCurve = types.ECCCurve;
pub const ECCPoint = types.ECCPoint;
pub const DEFAULT_CURVE = types.DEFAULT_CURVE;
pub const FAST_CURVE = types.FAST_CURVE;
pub const HIGH_SECURITY_CURVE = types.HIGH_SECURITY_CURVE;

// Re-export standard implementation functions
pub const eccStandardInit = standard.eccStandardInit;
pub const eccStandardCleanup = standard.eccStandardCleanup;
pub const eccStandardGenerateKey = standard.eccStandardGenerateKey;
pub const eccStandardEncrypt = standard.eccStandardEncrypt;
pub const eccStandardDecrypt = standard.eccStandardDecrypt;
pub const eccStandardEncryptStream = standard.eccStandardEncryptStream;
pub const eccStandardDecryptStream = standard.eccStandardDecryptStream;

// Re-export custom implementation functions
pub const eccCustomInit = custom.eccCustomInit;
pub const eccCustomCleanup = custom.eccCustomCleanup;
pub const eccCustomGenerateKey = custom.eccCustomGenerateKey;
pub const eccCustomEncrypt = custom.eccCustomEncrypt;
pub const eccCustomDecrypt = custom.eccCustomDecrypt;
pub const eccCustomEncryptStream = custom.eccCustomEncryptStream;
pub const eccCustomDecryptStream = custom.eccCustomDecryptStream;

// Global curve configuration
var global_ecc_curve: ECCCurve = DEFAULT_CURVE;

// Wrapper init functions that use the global curve configuration
pub fn eccStandardInitWithConfig(allocator: Allocator) !*anyopaque {
    const context = try allocator.create(ECCContext);
    context.* = ECCContext.init(allocator, global_ecc_curve);
    return @ptrCast(context);
}

pub fn eccCustomInitWithConfig(allocator: Allocator) !*anyopaque {
    const context = try allocator.create(ECCContext);
    context.* = ECCContext.init(allocator, global_ecc_curve);
    return @ptrCast(context);
}

// Configuration parsing for ECC
pub fn parseECCConfig(config_obj: std.json.Value, ecc_context: *ECCContext) !void {
    if (config_obj.object.get("encryption_methods")) |methods| {
        if (methods.object.get("ecc")) |ecc_config| {
            // Parse curve type
            if (ecc_config.object.get("curve")) |curve_value| {
                const curve_name = curve_value.string;
                if (std.mem.eql(u8, curve_name, "secp256r1") or std.mem.eql(u8, curve_name, "P-256")) {
                    ecc_context.curve = ECCCurve.secp256r1;
                } else if (std.mem.eql(u8, curve_name, "secp384r1") or std.mem.eql(u8, curve_name, "P-384")) {
                    ecc_context.curve = ECCCurve.secp384r1;
                } else if (std.mem.eql(u8, curve_name, "secp521r1") or std.mem.eql(u8, curve_name, "P-521")) {
                    ecc_context.curve = ECCCurve.secp521r1;
                } else {
                    print("Warning: Unknown ECC curve '{s}', using default secp256r1\n", .{curve_name});
                    ecc_context.curve = DEFAULT_CURVE;
                }
            }
        }
    }
}

// Register ECC implementations
pub fn registerEccImplementations(registry: *ImplementationRegistry, config_json: ?[]const u8, allocator: Allocator) !void {
    print("Registering ECC implementations...\n", .{});
    
    // Parse configuration for ECC settings
    var curve: ECCCurve = DEFAULT_CURVE;
    var use_stdlib = true;
    var use_custom = true;
    
    if (config_json) |json_str| {
        if (json.parseFromSlice(json.Value, allocator, json_str, .{})) |parsed| {
            defer parsed.deinit();
            
            if (parsed.value.object.get("encryption_methods")) |methods| {
                if (methods.object.get("ecc")) |ecc_config| {
                    if (ecc_config.object.get("enabled")) |enabled| {
                        if (!enabled.bool) {
                            print("ECC implementations disabled in configuration\n", .{});
                            return;
                        }
                    }
                    
                    if (ecc_config.object.get("curve")) |curve_value| {
                        const curve_name = curve_value.string;
                        if (std.mem.eql(u8, curve_name, "secp256r1") or std.mem.eql(u8, curve_name, "P-256")) {
                            curve = ECCCurve.secp256r1;
                        } else if (std.mem.eql(u8, curve_name, "secp384r1") or std.mem.eql(u8, curve_name, "P-384")) {
                            curve = ECCCurve.secp384r1;
                        } else if (std.mem.eql(u8, curve_name, "secp521r1") or std.mem.eql(u8, curve_name, "P-521")) {
                            curve = ECCCurve.secp521r1;
                        } else {
                            print("Warning: Unknown ECC curve '{s}', using default secp256r1\n", .{curve_name});
                            curve = DEFAULT_CURVE;
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
            print("Warning: Could not parse config for ECC: {}\n", .{err});
            // Continue with defaults
        }
    }
    
    const key_size = curve.getKeySize();
    print("ECC configuration: curve={s}, key_size={d}\n", .{ curve.getName(), key_size });
    
    // Set global curve configuration
    global_ecc_curve = curve;
    
    // Register standard implementation
    if (use_stdlib) {
        var std_impl = ImplementationInfo.init();
        
        // Set name and basic info
        const std_name = "ecc";
        @memcpy(std_impl.name[0..std_name.len], std_name);
        std_impl.name[std_name.len] = 0;
        
        std_impl.algo_type = .ecc;
        std_impl.is_custom = false;
        std_impl.key_size = key_size;
        
        // Set mode (curve name)
        const curve_name = curve.getName();
        const mode_len = @min(curve_name.len, std_impl.mode.len - 1);
        @memcpy(std_impl.mode[0..mode_len], curve_name[0..mode_len]);
        std_impl.mode[mode_len] = 0;
        
        // Set function pointers - use config-aware init function
        std_impl.init_fn = eccStandardInitWithConfig;
        std_impl.cleanup_fn = eccStandardCleanup;
        std_impl.generate_key_fn = eccStandardGenerateKey;
        std_impl.encrypt_fn = eccStandardEncrypt;
        std_impl.decrypt_fn = eccStandardDecrypt;
        std_impl.encrypt_stream_fn = eccStandardEncryptStream;
        std_impl.decrypt_stream_fn = eccStandardDecryptStream;
        
        try registry.register(std_impl);
        print("Registered: Standard ECC-{s} Implementation (using ECIES)\n", .{curve.getName()});
    }
    
    // Register custom implementation
    if (use_custom) {
        var custom_impl = ImplementationInfo.init();
        
        // Set name and basic info
        const custom_name = "ecc_custom";
        @memcpy(custom_impl.name[0..custom_name.len], custom_name);
        custom_impl.name[custom_name.len] = 0;
        
        custom_impl.algo_type = .ecc;
        custom_impl.is_custom = true;
        custom_impl.key_size = key_size;
        
        // Set mode (curve name)
        const curve_name = curve.getName();
        const mode_len = @min(curve_name.len, custom_impl.mode.len - 1);
        @memcpy(custom_impl.mode[0..mode_len], curve_name[0..mode_len]);
        custom_impl.mode[mode_len] = 0;
        
        // Set function pointers - use config-aware init function
        custom_impl.init_fn = eccCustomInitWithConfig;
        custom_impl.cleanup_fn = eccCustomCleanup;
        custom_impl.generate_key_fn = eccCustomGenerateKey;
        custom_impl.encrypt_fn = eccCustomEncrypt;
        custom_impl.decrypt_fn = eccCustomDecrypt;
        custom_impl.encrypt_stream_fn = eccCustomEncryptStream;
        custom_impl.decrypt_stream_fn = eccCustomDecryptStream;
        
        try registry.register(custom_impl);
        print("Registered: Custom ECC-{s} Implementation (enhanced from scratch)\n", .{curve.getName()});
    }
    
    print("ECC implementations registered successfully\n", .{});
} 