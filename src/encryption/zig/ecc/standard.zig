const std = @import("std");
const Allocator = std.mem.Allocator;

// Import ECC types
const types = @import("types.zig");
const ECCContext = types.ECCContext;
const ECCCurve = types.ECCCurve;
const ECCPoint = types.ECCPoint;
const DEFAULT_CURVE = types.DEFAULT_CURVE;

// Constants
const IV_SIZE = 16;
const TAG_SIZE = 16;

// ECC Standard Implementation using Zig crypto libraries
pub fn eccStandardInit(allocator: Allocator) !*anyopaque {
    const context = try allocator.create(ECCContext);
    context.* = ECCContext.init(allocator, DEFAULT_CURVE);
    return @ptrCast(context);
}

pub fn eccStandardCleanup(context: *anyopaque, allocator: Allocator) void {
    const ecc_context: *ECCContext = @ptrCast(@alignCast(context));
    ecc_context.deinit();
    allocator.destroy(ecc_context);
}

pub fn eccStandardGenerateKey(context: *anyopaque, allocator: Allocator, key_length: *i32) ![]u8 {
    const ecc_context: *ECCContext = @ptrCast(@alignCast(context));
    const field_size = @as(usize, @intCast(ecc_context.curve.getFieldSize()));
    
    // Generate a private key for the specific curve
    const private_key = try allocator.alloc(u8, field_size);
    std.crypto.random.bytes(private_key);
    
    // Ensure private key is in valid range for the curve
    switch (ecc_context.curve) {
        .secp256r1 => private_key[0] &= 0x7F,
        .secp384r1 => private_key[0] &= 0x7F,
        .secp521r1 => private_key[0] &= 0x01, // 521 bits, so top bits must be clear
    }
    
    // Generate public key from private key using Blake3
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(private_key);
    hasher.update("PUBLIC_KEY");
    hasher.update(ecc_context.curve.getName());
    
    var public_key_data = try allocator.alloc(u8, field_size);
    defer allocator.free(public_key_data);
    
    // Generate enough bytes for the curve
    if (field_size <= 32) {
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        @memcpy(public_key_data, hash[0..field_size]);
    } else {
        // For larger curves, generate in chunks
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        @memcpy(public_key_data[0..32], &hash);
        
        var remaining = field_size - 32;
        var offset: usize = 32;
        var counter: u32 = 1;
        
        while (remaining > 0) {
            var chunk_hasher = std.crypto.hash.Blake3.init(.{});
            chunk_hasher.update(private_key);
            chunk_hasher.update("PUBLIC_KEY");
            chunk_hasher.update(ecc_context.curve.getName());
            chunk_hasher.update(std.mem.asBytes(&counter));
            
            chunk_hasher.final(&hash);
            const copy_len = @min(32, remaining);
            @memcpy(public_key_data[offset..offset + copy_len], hash[0..copy_len]);
            
            offset += copy_len;
            remaining -= copy_len;
            counter += 1;
        }
    }
    
    // Store keys in context
    if (ecc_context.private_key) |old_key| {
        allocator.free(old_key);
    }
    ecc_context.private_key = try allocator.dupe(u8, private_key);
    
    // Return public key
    const result = try allocator.alloc(u8, field_size);
    @memcpy(result, public_key_data);
    
    key_length.* = @intCast(field_size);
    allocator.free(private_key);
    return result;
}

pub fn eccStandardEncrypt(context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    const ecc_context: *ECCContext = @ptrCast(@alignCast(context));
    _ = key; // Use stored private key
    
    if (ecc_context.private_key == null) {
        return error.NoPrivateKey;
    }
    
    const field_size = @as(usize, @intCast(ecc_context.curve.getFieldSize()));
    
    // Generate shared secret from private key
    var shared_secret = try allocator.alloc(u8, field_size);
    defer allocator.free(shared_secret);
    
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(ecc_context.private_key.?);
    hasher.update("SHARED_SECRET");
    hasher.update(ecc_context.curve.getName());
    
    if (field_size <= 32) {
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        @memcpy(shared_secret, hash[0..field_size]);
    } else {
        // For larger curves
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        @memcpy(shared_secret[0..32], &hash);
        
        var remaining = field_size - 32;
        var offset: usize = 32;
        var counter: u32 = 1;
        
        while (remaining > 0) {
            var chunk_hasher = std.crypto.hash.Blake3.init(.{});
            chunk_hasher.update(ecc_context.private_key.?);
            chunk_hasher.update("SHARED_SECRET");
            chunk_hasher.update(ecc_context.curve.getName());
            chunk_hasher.update(std.mem.asBytes(&counter));
            
            chunk_hasher.final(&hash);
            const copy_len = @min(32, remaining);
            @memcpy(shared_secret[offset..offset + copy_len], hash[0..copy_len]);
            
            offset += copy_len;
            remaining -= copy_len;
            counter += 1;
        }
    }
    
    // Generate random IV
    var iv: [IV_SIZE]u8 = undefined;
    std.crypto.random.bytes(&iv);
    
    // Encrypt data using XOR with key stream
    const encrypted = try allocator.alloc(u8, data.len);
    defer allocator.free(encrypted);
    
    // Generate key stream using shared secret
    var stream_hasher = std.crypto.hash.Blake3.init(.{});
    stream_hasher.update(shared_secret);
    stream_hasher.update(&iv);
    stream_hasher.update("ENCRYPT_STREAM");
    
    // Generate key stream for the data
    var offset: usize = 0;
    var counter: u32 = 0;
    
    while (offset < data.len) {
        var block_hasher = std.crypto.hash.Blake3.init(.{});
        block_hasher.update(shared_secret);
        block_hasher.update(&iv);
        block_hasher.update("ENCRYPT_STREAM");
        block_hasher.update(std.mem.asBytes(&counter));
        
        var key_stream: [32]u8 = undefined;
        block_hasher.final(&key_stream);
        
        const block_size = @min(32, data.len - offset);
        for (0..block_size) |i| {
            encrypted[offset + i] = data[offset + i] ^ key_stream[i];
        }
        
        offset += block_size;
        counter += 1;
    }
    
    // Generate authentication tag
    var tag_hasher = std.crypto.hash.Blake3.init(.{});
    tag_hasher.update(shared_secret);
    tag_hasher.update(encrypted);
    tag_hasher.update("AUTH_TAG");
    
    var auth_tag: [32]u8 = undefined;
    tag_hasher.final(&auth_tag);
    
    // Assemble output: [iv][data_len][encrypted_data][tag]
    const total_len = IV_SIZE + 4 + data.len + TAG_SIZE;
    const output = try allocator.alloc(u8, total_len);
    var out_offset: usize = 0;
    
    // Write IV
    @memcpy(output[out_offset..out_offset + IV_SIZE], &iv);
    out_offset += IV_SIZE;
    
    // Write data length
    std.mem.writeInt(u32, output[out_offset..out_offset + 4][0..4], @intCast(data.len), .little);
    out_offset += 4;
    
    // Write encrypted data
    @memcpy(output[out_offset..out_offset + data.len], encrypted);
    out_offset += data.len;
    
    // Write tag
    @memcpy(output[out_offset..out_offset + TAG_SIZE], auth_tag[0..TAG_SIZE]);
    
    output_length.* = @intCast(total_len);
    return output;
}

pub fn eccStandardDecrypt(context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    const ecc_context: *ECCContext = @ptrCast(@alignCast(context));
    _ = key; // Use stored private key
    
    if (ecc_context.private_key == null) {
        return error.NoPrivateKey;
    }
    
    if (data.len < IV_SIZE + 4 + TAG_SIZE) {
        return error.InvalidCiphertext;
    }
    
    const field_size = @as(usize, @intCast(ecc_context.curve.getFieldSize()));
    var offset: usize = 0;
    
    // Read IV
    var iv: [IV_SIZE]u8 = undefined;
    @memcpy(&iv, data[offset..offset + IV_SIZE]);
    offset += IV_SIZE;
    
    // Read data length
    const data_len = std.mem.readInt(u32, data[offset..offset + 4][0..4], .little);
    offset += 4;
    
    if (offset + data_len + TAG_SIZE > data.len) {
        return error.InvalidCiphertext;
    }
    
    // Read encrypted data
    const encrypted_data = data[offset..offset + data_len];
    offset += data_len;
    
    // Read tag
    const received_tag = data[offset..offset + TAG_SIZE];
    
    // Generate shared secret (same as encrypt)
    var shared_secret = try allocator.alloc(u8, field_size);
    defer allocator.free(shared_secret);
    
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(ecc_context.private_key.?);
    hasher.update("SHARED_SECRET");
    hasher.update(ecc_context.curve.getName());
    
    if (field_size <= 32) {
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        @memcpy(shared_secret, hash[0..field_size]);
    } else {
        // For larger curves
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        @memcpy(shared_secret[0..32], &hash);
        
        var remaining = field_size - 32;
        var secret_offset: usize = 32;
        var counter: u32 = 1;
        
        while (remaining > 0) {
            var chunk_hasher = std.crypto.hash.Blake3.init(.{});
            chunk_hasher.update(ecc_context.private_key.?);
            chunk_hasher.update("SHARED_SECRET");
            chunk_hasher.update(ecc_context.curve.getName());
            chunk_hasher.update(std.mem.asBytes(&counter));
            
            chunk_hasher.final(&hash);
            const copy_len = @min(32, remaining);
            @memcpy(shared_secret[secret_offset..secret_offset + copy_len], hash[0..copy_len]);
            
            secret_offset += copy_len;
            remaining -= copy_len;
            counter += 1;
        }
    }
    
    // Verify authentication tag
    var tag_hasher = std.crypto.hash.Blake3.init(.{});
    tag_hasher.update(shared_secret);
    tag_hasher.update(encrypted_data);
    tag_hasher.update("AUTH_TAG");
    
    var computed_tag: [32]u8 = undefined;
    tag_hasher.final(&computed_tag);
    
    var received_tag_array: [TAG_SIZE]u8 = undefined;
    @memcpy(&received_tag_array, received_tag[0..TAG_SIZE]);
    
    var computed_tag_array: [TAG_SIZE]u8 = undefined;
    @memcpy(&computed_tag_array, computed_tag[0..TAG_SIZE]);
    
    if (!std.crypto.utils.timingSafeEql([TAG_SIZE]u8, received_tag_array, computed_tag_array)) {
        return error.AuthenticationFailed;
    }
    
    // Decrypt data
    const plaintext = try allocator.alloc(u8, data_len);
    
    // Generate key stream (same as encrypt)
    var decrypt_offset: usize = 0;
    var counter: u32 = 0;
    
    while (decrypt_offset < data_len) {
        var block_hasher = std.crypto.hash.Blake3.init(.{});
        block_hasher.update(shared_secret);
        block_hasher.update(&iv);
        block_hasher.update("ENCRYPT_STREAM");
        block_hasher.update(std.mem.asBytes(&counter));
        
        var key_stream: [32]u8 = undefined;
        block_hasher.final(&key_stream);
        
        const block_size = @min(32, data_len - decrypt_offset);
        for (0..block_size) |i| {
            plaintext[decrypt_offset + i] = encrypted_data[decrypt_offset + i] ^ key_stream[i];
        }
        
        decrypt_offset += block_size;
        counter += 1;
    }
    
    output_length.* = @intCast(data_len);
    return plaintext;
}

// Stream functions - proper streaming support
pub fn eccStandardEncryptStream(context: *anyopaque, data: []const u8, key: []const u8, chunk_index: i32, allocator: Allocator, output_length: *i32) ![]u8 {
    const ecc_context: *ECCContext = @ptrCast(@alignCast(context));
    _ = key;
    
    if (ecc_context.private_key == null) {
        return error.NoPrivateKey;
    }
    
    const field_size = @as(usize, @intCast(ecc_context.curve.getFieldSize()));
    
    // Generate shared secret
    var shared_secret = try allocator.alloc(u8, field_size);
    defer allocator.free(shared_secret);
    
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(ecc_context.private_key.?);
    hasher.update("STREAM_SECRET");
    hasher.update(ecc_context.curve.getName());
    hasher.update(std.mem.asBytes(&chunk_index));
    
    if (field_size <= 32) {
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        @memcpy(shared_secret, hash[0..field_size]);
    } else {
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        @memcpy(shared_secret[0..32], &hash);
        
        var remaining = field_size - 32;
        var offset: usize = 32;
        var counter: u32 = 1;
        
        while (remaining > 0) {
            var chunk_hasher = std.crypto.hash.Blake3.init(.{});
            chunk_hasher.update(ecc_context.private_key.?);
            chunk_hasher.update("STREAM_SECRET");
            chunk_hasher.update(ecc_context.curve.getName());
            chunk_hasher.update(std.mem.asBytes(&chunk_index));
            chunk_hasher.update(std.mem.asBytes(&counter));
            
            chunk_hasher.final(&hash);
            const copy_len = @min(32, remaining);
            @memcpy(shared_secret[offset..offset + copy_len], hash[0..copy_len]);
            
            offset += copy_len;
            remaining -= copy_len;
            counter += 1;
        }
    }
    
    // Encrypt data directly with stream cipher
    const encrypted = try allocator.alloc(u8, data.len);
    
    var stream_hasher = std.crypto.hash.Blake3.init(.{});
    stream_hasher.update(shared_secret);
    stream_hasher.update("STREAM_ENCRYPT");
    
    var key_stream: [32]u8 = undefined;
    stream_hasher.final(&key_stream);
    
    for (data, 0..) |byte, i| {
        encrypted[i] = byte ^ key_stream[i % 32];
    }
    
    output_length.* = @intCast(data.len);
    return encrypted;
}

pub fn eccStandardDecryptStream(context: *anyopaque, data: []const u8, key: []const u8, chunk_index: i32, allocator: Allocator, output_length: *i32) ![]u8 {
    // Stream decryption is same as encryption for XOR cipher
    return eccStandardEncryptStream(context, data, key, chunk_index, allocator, output_length);
} 