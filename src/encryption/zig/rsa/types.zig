const std = @import("std");
const Allocator = std.mem.Allocator;

// RSA key sizes (in bits)
pub const RSA_1024_KEY_SIZE = 1024;
pub const RSA_2048_KEY_SIZE = 2048;
pub const RSA_3072_KEY_SIZE = 3072;
pub const RSA_4096_KEY_SIZE = 4096;

// RSA context structure
pub const RSAContext = struct {
    key_size_bits: i32,
    public_key: ?[]u8,
    private_key: ?[]u8,
    allocator: Allocator,
    
    pub fn init(allocator: Allocator, key_size_bits: i32) RSAContext {
        return RSAContext{
            .key_size_bits = key_size_bits,
            .public_key = null,
            .private_key = null,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *RSAContext) void {
        if (self.public_key) |key| {
            self.allocator.free(key);
        }
        if (self.private_key) |key| {
            self.allocator.free(key);
        }
    }
}; 