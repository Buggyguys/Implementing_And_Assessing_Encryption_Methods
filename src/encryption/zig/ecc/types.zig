const std = @import("std");
const Allocator = std.mem.Allocator;

// ECC curve types
pub const ECCCurve = enum {
    secp256r1,  // NIST P-256 (most common)
    secp384r1,  // NIST P-384
    secp521r1,  // NIST P-521
    
    pub fn getKeySize(self: ECCCurve) i32 {
        return switch (self) {
            .secp256r1 => 256,
            .secp384r1 => 384,
            .secp521r1 => 521,
        };
    }
    
    pub fn getFieldSize(self: ECCCurve) i32 {
        return switch (self) {
            .secp256r1 => 32,   // 256 bits = 32 bytes
            .secp384r1 => 48,   // 384 bits = 48 bytes
            .secp521r1 => 66,   // 521 bits = 66 bytes (rounded up)
        };
    }
    
    pub fn getName(self: ECCCurve) []const u8 {
        return switch (self) {
            .secp256r1 => "secp256r1",
            .secp384r1 => "secp384r1",
            .secp521r1 => "secp521r1",
        };
    }
};

// ECC point structure (for public keys)
pub const ECCPoint = struct {
    x: []u8,
    y: []u8,
    allocator: Allocator,
    
    pub fn init(allocator: Allocator, field_size: usize) !ECCPoint {
        const x = try allocator.alloc(u8, field_size);
        const y = try allocator.alloc(u8, field_size);
        return ECCPoint{
            .x = x,
            .y = y,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *ECCPoint) void {
        self.allocator.free(self.x);
        self.allocator.free(self.y);
    }
};

// ECC context structure
pub const ECCContext = struct {
    curve: ECCCurve,
    private_key: ?[]u8,
    public_key: ?ECCPoint,
    shared_secret: ?[]u8,
    allocator: Allocator,
    
    pub fn init(allocator: Allocator, curve: ECCCurve) ECCContext {
        return ECCContext{
            .curve = curve,
            .private_key = null,
            .public_key = null,
            .shared_secret = null,
            .allocator = allocator,
        };
    }
    
    pub fn setCurve(self: *ECCContext, curve: ECCCurve) void {
        // Clean up existing keys when changing curves
        if (self.private_key) |key| {
            self.allocator.free(key);
            self.private_key = null;
        }
        if (self.public_key) |*point| {
            point.deinit();
            self.public_key = null;
        }
        if (self.shared_secret) |secret| {
            self.allocator.free(secret);
            self.shared_secret = null;
        }
        self.curve = curve;
    }
    
    pub fn deinit(self: *ECCContext) void {
        if (self.private_key) |key| {
            self.allocator.free(key);
        }
        if (self.public_key) |*point| {
            point.deinit();
        }
        if (self.shared_secret) |secret| {
            self.allocator.free(secret);
        }
    }
};

// ECC operation modes
pub const ECCMode = enum {
    ecdh,    // Elliptic Curve Diffie-Hellman (key exchange)
    ecdsa,   // Elliptic Curve Digital Signature Algorithm
    ecies,   // Elliptic Curve Integrated Encryption Scheme
};

// Default curve configurations
pub const DEFAULT_CURVE = ECCCurve.secp256r1;
pub const FAST_CURVE = ECCCurve.secp256r1;
pub const HIGH_SECURITY_CURVE = ECCCurve.secp521r1; 