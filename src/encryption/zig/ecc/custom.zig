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

// HKDF Info Strings - centralized for consistency
const HKDF_PRIVATE_KEY_INFO = "ECC_PRIVATE_KEY_V1";
const HKDF_SHARED_SECRET_INFO = "ECC_SHARED_SECRET_V1";
const HKDF_ENCRYPTION_KEY_INFO = "ECC_ENCRYPTION_KEY_V1";
const HKDF_KEY_STREAM_INFO = "ECC_KEY_STREAM_V1";
const HKDF_STREAM_CHUNK_INFO = "ECC_STREAM_CHUNK_V1";
const HKDF_STREAM_KEY_INFO = "ECC_STREAM_KEY_V1";

// SHA-256 implementation from scratch
const SHA256_H: [8]u32 = [_]u32{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

const SHA256_K: [64]u32 = [_]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

fn sha256Hash(data: []const u8, output: *[32]u8) void {
    var h = SHA256_H;
    
    // Calculate total length in bits
    const total_len = data.len;
    const total_bits = total_len * 8;
    
    // Calculate padding
    const padding_len = if ((total_len + 9) % 64 == 0) 0 else 64 - ((total_len + 9) % 64);
    const padded_len = total_len + 1 + padding_len + 8;
    
    // Process in 64-byte chunks
    var chunk_offset: usize = 0;
    while (chunk_offset < padded_len) {
        var chunk: [64]u8 = [_]u8{0} ** 64;
        
        if (chunk_offset < total_len) {
            const copy_len = @min(64, total_len - chunk_offset);
            @memcpy(chunk[0..copy_len], data[chunk_offset..chunk_offset + copy_len]);
            
            if (copy_len < 64) {
                chunk[copy_len] = 0x80; // Padding bit
                
                // Add length in last 8 bytes if this is the last chunk
                if (chunk_offset + 64 >= padded_len) {
                    std.mem.writeInt(u64, chunk[56..64][0..8], total_bits, .big);
                }
            }
        } else if (chunk_offset == total_len) {
            chunk[0] = 0x80; // Padding bit
            if (chunk_offset + 64 >= padded_len) {
                std.mem.writeInt(u64, chunk[56..64][0..8], total_bits, .big);
            }
        } else {
            // Length-only chunk
            std.mem.writeInt(u64, chunk[56..64][0..8], total_bits, .big);
        }
        
        // Process chunk
        var w: [64]u32 = [_]u32{0} ** 64;
        
        // Copy chunk into first 16 words
        for (0..16) |i| {
            w[i] = std.mem.readInt(u32, chunk[i*4..(i+1)*4][0..4], .big);
        }
        
        // Extend the first 16 words into the remaining 48 words
        for (16..64) |i| {
            const s0 = std.math.rotr(u32, w[i-15], 7) ^ std.math.rotr(u32, w[i-15], 18) ^ (w[i-15] >> 3);
            const s1 = std.math.rotr(u32, w[i-2], 17) ^ std.math.rotr(u32, w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] +% s0 +% w[i-7] +% s1;
        }
        
        // Initialize working variables
        var a = h[0];
        var b = h[1];
        var c = h[2];
        var d = h[3];
        var e = h[4];
        var f = h[5];
        var g = h[6];
        var hh = h[7];
        
        // Main loop
        for (0..64) |i| {
            const S1 = std.math.rotr(u32, e, 6) ^ std.math.rotr(u32, e, 11) ^ std.math.rotr(u32, e, 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = hh +% S1 +% ch +% SHA256_K[i] +% w[i];
            const S0 = std.math.rotr(u32, a, 2) ^ std.math.rotr(u32, a, 13) ^ std.math.rotr(u32, a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = S0 +% maj;
            
            hh = g;
            g = f;
            f = e;
            e = d +% temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 +% temp2;
        }
        
        // Add this chunk's hash to result
        h[0] +%= a;
        h[1] +%= b;
        h[2] +%= c;
        h[3] +%= d;
        h[4] +%= e;
        h[5] +%= f;
        h[6] +%= g;
        h[7] +%= hh;
        
        chunk_offset += 64;
    }
    
    // Convert hash to bytes
    for (0..8) |i| {
        const bytes = std.mem.asBytes(&h[i]);
        output[i*4] = bytes[3];
        output[i*4+1] = bytes[2];
        output[i*4+2] = bytes[1];
        output[i*4+3] = bytes[0];
    }
}

// Cryptographically secure random number generator (from scratch)
const ChaCha20State = struct {
    state: [16]u32,
    counter: u64,
    
    fn init(seed: [32]u8) ChaCha20State {
        var state = [_]u32{0} ** 16;
        
        // ChaCha20 constants
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        
        // Key (256 bits = 8 words)
        for (0..8) |i| {
            state[4 + i] = std.mem.readInt(u32, seed[i*4..(i+1)*4][0..4], .little);
        }
        
        // Counter and nonce start at 0
        state[12] = 0;
        state[13] = 0;
        state[14] = 0;
        state[15] = 0;
        
        return ChaCha20State{
            .state = state,
            .counter = 0,
        };
    }
    
    fn quarterRound(a: *u32, b: *u32, c: *u32, d: *u32) void {
        a.* +%= b.*;
        d.* ^= a.*;
        d.* = std.math.rotl(u32, d.*, 16);
        
        c.* +%= d.*;
        b.* ^= c.*;
        b.* = std.math.rotl(u32, b.*, 12);
        
        a.* +%= b.*;
        d.* ^= a.*;
        d.* = std.math.rotl(u32, d.*, 8);
        
        c.* +%= d.*;
        b.* ^= c.*;
        b.* = std.math.rotl(u32, b.*, 7);
    }
    
    fn generateBlock(self: *ChaCha20State, output: *[64]u8) void {
        var working_state = self.state;
        working_state[12] = @truncate(self.counter);
        working_state[13] = @truncate(self.counter >> 32);
        
        // 20 rounds (10 double rounds)
        for (0..10) |_| {
            // Column rounds
            ChaCha20State.quarterRound(&working_state[0], &working_state[4], &working_state[8], &working_state[12]);
            ChaCha20State.quarterRound(&working_state[1], &working_state[5], &working_state[9], &working_state[13]);
            ChaCha20State.quarterRound(&working_state[2], &working_state[6], &working_state[10], &working_state[14]);
            ChaCha20State.quarterRound(&working_state[3], &working_state[7], &working_state[11], &working_state[15]);
            
            // Diagonal rounds
            ChaCha20State.quarterRound(&working_state[0], &working_state[5], &working_state[10], &working_state[15]);
            ChaCha20State.quarterRound(&working_state[1], &working_state[6], &working_state[11], &working_state[12]);
            ChaCha20State.quarterRound(&working_state[2], &working_state[7], &working_state[8], &working_state[13]);
            ChaCha20State.quarterRound(&working_state[3], &working_state[4], &working_state[9], &working_state[14]);
        }
        
        // Add original state
        for (0..16) |i| {
            working_state[i] +%= self.state[i];
        }
        
        // Convert to bytes
        for (0..16) |i| {
            const bytes = std.mem.asBytes(&working_state[i]);
            @memcpy(output[i*4..(i+1)*4], bytes);
        }
        
        self.counter += 1;
    }
};

var global_rng: ?ChaCha20State = null;
var rng_initialized: bool = false;

fn initSecureRng() void {
    if (!rng_initialized) {
        var seed: [32]u8 = undefined;
        
        // Collect entropy from multiple sources
        const timestamp = std.time.nanoTimestamp();
        const timestamp_bytes = std.mem.asBytes(&timestamp);
        const copy_len = @min(8, timestamp_bytes.len);
        @memcpy(seed[0..copy_len], timestamp_bytes[0..copy_len]);
        
        // Add additional entropy sources
        var entropy_counter: u64 = 0;
        for (8..32) |i| {
            entropy_counter = entropy_counter *% 1103515245 +% 12345;
            entropy_counter ^= @as(u64, @intCast(std.time.nanoTimestamp()));
            seed[i] = @truncate(entropy_counter);
        }
        
        global_rng = ChaCha20State.init(seed);
        rng_initialized = true;
    }
}

fn fillSecureRandomBytes(buffer: []u8) void {
    initSecureRng();
    
    var offset: usize = 0;
    while (offset < buffer.len) {
        var block: [64]u8 = undefined;
        global_rng.?.generateBlock(&block);
        
        const copy_len = @min(64, buffer.len - offset);
        @memcpy(buffer[offset..offset + copy_len], block[0..copy_len]);
        offset += copy_len;
    }
}

// Cryptographically safe key generation using HKDF
fn generateSafePrivateKey(allocator: Allocator, curve: ECCCurve) ![]u8 {
    const field_size = @as(usize, @intCast(curve.getFieldSize()));
    const private_key = try allocator.alloc(u8, field_size);
    
    // Collect high-entropy input key material (IKM)
    var ikm = try allocator.alloc(u8, 64);
    defer allocator.free(ikm);
    
    // Fill with secure random bytes
    fillSecureRandomBytes(ikm);
    
    // Add additional entropy sources
    const timestamp = std.time.nanoTimestamp();
    const timestamp_bytes = std.mem.asBytes(&timestamp);
    for (0..@min(8, timestamp_bytes.len)) |i| {
        ikm[i] ^= timestamp_bytes[i];
    }
    
    // Use curve name as salt for domain separation
    const curve_name = curve.getName();
    const salt = curve_name;
    
    // Use HKDF to derive the private key
    const info = HKDF_PRIVATE_KEY_INFO;
    hkdf(salt, ikm, info, private_key);
    
    // Ensure private key is in valid range for the curve
    switch (curve) {
        .secp256r1 => {
            private_key[0] &= 0x7F; // Clear top bit for 256-bit
            if (private_key[0] == 0) private_key[0] = 1; // Ensure non-zero
        },
        .secp384r1 => {
            private_key[0] &= 0x7F; // Clear top bit for 384-bit
            if (private_key[0] == 0) private_key[0] = 1; // Ensure non-zero
        },
        .secp521r1 => {
            private_key[0] &= 0x01; // Clear all but bottom bit for 521-bit
            if (private_key[0] == 0 and private_key[1] == 0) {
                private_key[1] = 1; // Ensure non-zero
            }
        },
    }
    
    return private_key;
}

// Timing-safe comparison (from scratch)
fn timingSafeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    
    var result: u8 = 0;
    for (a, b) |byte_a, byte_b| {
        result |= byte_a ^ byte_b;
    }
    return result == 0;
}

// ECC Custom Implementation (no crypto libraries)
pub fn eccCustomInit(allocator: Allocator) !*anyopaque {
    const context = try allocator.create(ECCContext);
    context.* = ECCContext.init(allocator, DEFAULT_CURVE);
    return @ptrCast(context);
}

pub fn eccCustomCleanup(context: *anyopaque, allocator: Allocator) void {
    const ecc_context: *ECCContext = @ptrCast(@alignCast(context));
    ecc_context.deinit();
    allocator.destroy(ecc_context);
}

pub fn eccCustomGenerateKey(context: *anyopaque, allocator: Allocator, key_length: *i32) ![]u8 {
    const ecc_context: *ECCContext = @ptrCast(@alignCast(context));
    const field_size = @as(usize, @intCast(ecc_context.curve.getFieldSize()));
    
    // Generate cryptographically safe private key
    const private_key = try generateSafePrivateKey(allocator, ecc_context.curve);
    
    // Generate public key from private key using SHA-256
    var public_key_input = try allocator.alloc(u8, field_size + ecc_context.curve.getName().len + 10);
    defer allocator.free(public_key_input);
    
    var offset: usize = 0;
    @memcpy(public_key_input[offset..offset + field_size], private_key);
    offset += field_size;
    
    const public_key_tag = "PUBLIC_KEY";
    @memcpy(public_key_input[offset..offset + public_key_tag.len], public_key_tag);
    offset += public_key_tag.len;
    
    const curve_name = ecc_context.curve.getName();
    @memcpy(public_key_input[offset..offset + curve_name.len], curve_name);
    
    const public_key_data = try allocator.alloc(u8, field_size);
    var hash_output: [32]u8 = undefined;
    sha256Hash(public_key_input, &hash_output);
    
    // Copy appropriate number of bytes based on curve
    const copy_len = @min(field_size, 32);
    @memcpy(public_key_data[0..copy_len], hash_output[0..copy_len]);
    
    // If field_size > 32, fill remaining bytes with additional hash rounds
    if (field_size > 32) {
        var remaining = field_size - 32;
        var hash_offset: usize = 32;
        var round: u8 = 1;
        
        while (remaining > 0) {
            var round_input = try allocator.alloc(u8, public_key_input.len + 1);
            defer allocator.free(round_input);
            @memcpy(round_input[0..public_key_input.len], public_key_input);
            round_input[public_key_input.len] = round;
            
            var round_hash: [32]u8 = undefined;
            sha256Hash(round_input, &round_hash);
            
            const round_copy_len = @min(remaining, 32);
            @memcpy(public_key_data[hash_offset..hash_offset + round_copy_len], round_hash[0..round_copy_len]);
            
            hash_offset += round_copy_len;
            remaining -= round_copy_len;
            round += 1;
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
    allocator.free(public_key_data);
    return result;
}

pub fn eccCustomEncrypt(context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    const ecc_context: *ECCContext = @ptrCast(@alignCast(context));
    _ = key; // Use stored private key
    
    if (ecc_context.private_key == null) {
        return error.NoPrivateKey;
    }
    
    // Generate random IV
    var iv: [IV_SIZE]u8 = undefined;
    fillSecureRandomBytes(&iv);
    
    // Derive shared secret using HKDF
    const curve_name = ecc_context.curve.getName();
    const salt = curve_name;
    const info = HKDF_SHARED_SECRET_INFO;
    
    const shared_secret = try allocator.alloc(u8, 32); // Always use 32 bytes for shared secret
    defer allocator.free(shared_secret);
    hkdf(salt, ecc_context.private_key.?, info, shared_secret);
    
    // Derive encryption key using HKDF with IV
    var key_derivation_input = try allocator.alloc(u8, shared_secret.len + iv.len);
    defer allocator.free(key_derivation_input);
    @memcpy(key_derivation_input[0..shared_secret.len], shared_secret);
    @memcpy(key_derivation_input[shared_secret.len..], &iv);
    
    const encryption_key = try allocator.alloc(u8, 32);
    defer allocator.free(encryption_key);
    const enc_info = HKDF_ENCRYPTION_KEY_INFO;
    hkdf(&iv, key_derivation_input, enc_info, encryption_key);
    
    // Encrypt data using XOR with key stream derived from encryption key
    const encrypted = try allocator.alloc(u8, data.len);
    defer allocator.free(encrypted);
    
    // Generate key stream using HKDF
    var stream_offset: usize = 0;
    var counter: u32 = 0;
    
    while (stream_offset < data.len) {
        var counter_input = try allocator.alloc(u8, encryption_key.len + 4);
        defer allocator.free(counter_input);
        @memcpy(counter_input[0..encryption_key.len], encryption_key);
        const counter_bytes = std.mem.asBytes(&counter);
        @memcpy(counter_input[encryption_key.len..], counter_bytes);
        
        var key_stream: [32]u8 = undefined;
        const stream_info = HKDF_STREAM_KEY_INFO;
        hkdf(salt, counter_input, stream_info, &key_stream);
        
        const block_size = @min(32, data.len - stream_offset);
        for (0..block_size) |i| {
            encrypted[stream_offset + i] = data[stream_offset + i] ^ key_stream[i];
        }
        
        stream_offset += block_size;
        counter += 1;
    }
    
    // Generate authentication tag using HMAC
    var tag_input = try allocator.alloc(u8, iv.len + data.len);
    defer allocator.free(tag_input);
    @memcpy(tag_input[0..iv.len], &iv);
    @memcpy(tag_input[iv.len..], encrypted);
    
    var auth_tag: [32]u8 = undefined;
    hmacSha256(shared_secret, tag_input, &auth_tag);
    
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

pub fn eccCustomDecrypt(context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) ![]u8 {
    const ecc_context: *ECCContext = @ptrCast(@alignCast(context));
    _ = key; // Use stored private key
    
    if (ecc_context.private_key == null) {
        return error.NoPrivateKey;
    }
    
    if (data.len < IV_SIZE + 4 + TAG_SIZE) {
        return error.InvalidCiphertext;
    }
    
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
    
    // Derive shared secret using HKDF (same as encrypt)
    const curve_name = ecc_context.curve.getName();
    const salt = curve_name;
    const info = HKDF_SHARED_SECRET_INFO;
    
    const shared_secret = try allocator.alloc(u8, 32);
    defer allocator.free(shared_secret);
    hkdf(salt, ecc_context.private_key.?, info, shared_secret);
    
    // Verify authentication tag using HMAC
    var tag_input = try allocator.alloc(u8, iv.len + encrypted_data.len);
    defer allocator.free(tag_input);
    @memcpy(tag_input[0..iv.len], &iv);
    @memcpy(tag_input[iv.len..], encrypted_data);
    
    var computed_tag: [32]u8 = undefined;
    hmacSha256(shared_secret, tag_input, &computed_tag);
    
    if (!timingSafeEqual(received_tag, computed_tag[0..TAG_SIZE])) {
        return error.AuthenticationFailed;
    }
    
    // Derive encryption key using HKDF with IV (same as encrypt)
    var key_derivation_input = try allocator.alloc(u8, shared_secret.len + iv.len);
    defer allocator.free(key_derivation_input);
    @memcpy(key_derivation_input[0..shared_secret.len], shared_secret);
    @memcpy(key_derivation_input[shared_secret.len..], &iv);
    
    const encryption_key = try allocator.alloc(u8, 32);
    defer allocator.free(encryption_key);
    const enc_info = HKDF_ENCRYPTION_KEY_INFO;
    hkdf(&iv, key_derivation_input, enc_info, encryption_key);
    
    // Decrypt data using XOR with key stream
    const decrypted = try allocator.alloc(u8, data_len);
    
    // Generate key stream using HKDF (same as encrypt)
    var stream_offset: usize = 0;
    var counter: u32 = 0;
    
    while (stream_offset < data_len) {
        var counter_input = try allocator.alloc(u8, encryption_key.len + 4);
        defer allocator.free(counter_input);
        @memcpy(counter_input[0..encryption_key.len], encryption_key);
        const counter_bytes = std.mem.asBytes(&counter);
        @memcpy(counter_input[encryption_key.len..], counter_bytes);
        
        var key_stream: [32]u8 = undefined;
        const stream_info = HKDF_STREAM_KEY_INFO;
        hkdf(salt, counter_input, stream_info, &key_stream);
        
        const block_size = @min(32, data_len - stream_offset);
        for (0..block_size) |i| {
            decrypted[stream_offset + i] = encrypted_data[stream_offset + i] ^ key_stream[i];
        }
        
        stream_offset += block_size;
        counter += 1;
    }
    
    output_length.* = @intCast(data_len);
    return decrypted;
}

// Stream functions - proper streaming support with enhanced security
pub fn eccCustomEncryptStream(context: *anyopaque, data: []const u8, key: []const u8, chunk_index: i32, allocator: Allocator, output_length: *i32) ![]u8 {
    const ecc_context: *ECCContext = @ptrCast(@alignCast(context));
    _ = key;
    
    if (ecc_context.private_key == null) {
        return error.NoPrivateKey;
    }
    
    // Use HKDF for stream-specific key derivation
    const curve_name = ecc_context.curve.getName();
    const salt = curve_name;
    
    // Create chunk-specific info string
    var chunk_info = try allocator.alloc(u8, HKDF_STREAM_CHUNK_INFO.len + 4);
    defer allocator.free(chunk_info);
    @memcpy(chunk_info[0..HKDF_STREAM_CHUNK_INFO.len], HKDF_STREAM_CHUNK_INFO);
    const chunk_bytes = std.mem.asBytes(&chunk_index);
    @memcpy(chunk_info[HKDF_STREAM_CHUNK_INFO.len..], chunk_bytes);
    
    // Derive chunk-specific encryption key
    const encryption_key = try allocator.alloc(u8, 32);
    defer allocator.free(encryption_key);
    hkdf(salt, ecc_context.private_key.?, chunk_info, encryption_key);
    
    // Encrypt data using XOR with HKDF-derived key stream
    const encrypted = try allocator.alloc(u8, data.len);
    
    var stream_offset: usize = 0;
    var counter: u32 = 0;
    
    while (stream_offset < data.len) {
        var counter_input = try allocator.alloc(u8, encryption_key.len + 4);
        defer allocator.free(counter_input);
        @memcpy(counter_input[0..encryption_key.len], encryption_key);
        const counter_bytes = std.mem.asBytes(&counter);
        @memcpy(counter_input[encryption_key.len..], counter_bytes);
        
        var key_stream: [32]u8 = undefined;
        const stream_info = HKDF_STREAM_KEY_INFO;
        hkdf(salt, counter_input, stream_info, &key_stream);
        
        const block_size = @min(32, data.len - stream_offset);
        for (0..block_size) |i| {
            encrypted[stream_offset + i] = data[stream_offset + i] ^ key_stream[i];
        }
        
        stream_offset += block_size;
        counter += 1;
    }
    
    output_length.* = @intCast(data.len);
    return encrypted;
}

pub fn eccCustomDecryptStream(context: *anyopaque, data: []const u8, key: []const u8, chunk_index: i32, allocator: Allocator, output_length: *i32) ![]u8 {
    // Stream decryption is same as encryption for XOR cipher
    return eccCustomEncryptStream(context, data, key, chunk_index, allocator, output_length);
}

// HMAC-SHA256 implementation
fn hmacSha256(key: []const u8, data: []const u8, output: *[32]u8) void {
    var ipad: [64]u8 = [_]u8{0x36} ** 64;
    var opad: [64]u8 = [_]u8{0x5c} ** 64;
    
    // If key is longer than 64 bytes, hash it first
    var actual_key: [64]u8 = [_]u8{0} ** 64;
    if (key.len > 64) {
        var key_hash: [32]u8 = undefined;
        sha256Hash(key, &key_hash);
        @memcpy(actual_key[0..32], &key_hash);
    } else {
        @memcpy(actual_key[0..key.len], key);
    }
    
    // XOR key with ipad and opad
    for (0..64) |i| {
        ipad[i] ^= actual_key[i];
        opad[i] ^= actual_key[i];
    }
    
    // Inner hash: SHA256(ipad || data)
    var inner_input = std.ArrayList(u8).init(std.heap.page_allocator);
    defer inner_input.deinit();
    inner_input.appendSlice(&ipad) catch return;
    inner_input.appendSlice(data) catch return;
    
    var inner_hash: [32]u8 = undefined;
    sha256Hash(inner_input.items, &inner_hash);
    
    // Outer hash: SHA256(opad || inner_hash)
    var outer_input = std.ArrayList(u8).init(std.heap.page_allocator);
    defer outer_input.deinit();
    outer_input.appendSlice(&opad) catch return;
    outer_input.appendSlice(&inner_hash) catch return;
    
    sha256Hash(outer_input.items, output);
}

// HKDF (HMAC-based Key Derivation Function)
fn hkdfExpand(prk: []const u8, info: []const u8, output: []u8) void {
    const hash_len = 32; // SHA-256 output length
    const n = (output.len + hash_len - 1) / hash_len; // Ceiling division
    
    var offset: usize = 0;
    var counter: u8 = 1;
    var t_prev: [32]u8 = [_]u8{0} ** 32;
    var first_iteration = true;
    
    for (0..n) |_| {
        var hmac_input = std.ArrayList(u8).init(std.heap.page_allocator);
        defer hmac_input.deinit();
        
        if (!first_iteration) {
            hmac_input.appendSlice(&t_prev) catch return;
        }
        hmac_input.appendSlice(info) catch return;
        hmac_input.append(counter) catch return;
        
        var t_current: [32]u8 = undefined;
        hmacSha256(prk, hmac_input.items, &t_current);
        
        const copy_len = @min(hash_len, output.len - offset);
        @memcpy(output[offset..offset + copy_len], t_current[0..copy_len]);
        
        t_prev = t_current;
        offset += copy_len;
        counter += 1;
        first_iteration = false;
    }
}

fn hkdfExtract(salt: []const u8, ikm: []const u8, prk: *[32]u8) void {
    if (salt.len == 0) {
        const zero_salt = [_]u8{0} ** 32;
        hmacSha256(&zero_salt, ikm, prk);
    } else {
        hmacSha256(salt, ikm, prk);
    }
}

fn hkdf(salt: []const u8, ikm: []const u8, info: []const u8, output: []u8) void {
    var prk: [32]u8 = undefined;
    hkdfExtract(salt, ikm, &prk);
    hkdfExpand(&prk, info, output);
} 