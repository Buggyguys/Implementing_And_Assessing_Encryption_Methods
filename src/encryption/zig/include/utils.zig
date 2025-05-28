const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

// Platform-specific imports for resource monitoring
const builtin = @import("builtin");

// Maximum input size for chunked processing
pub const MAX_CHUNK_SIZE = 16 * 1024 * 1024; // 16MB default chunk size

// Benchmark metrics structure to match C implementation
pub const BenchmarkMetrics = struct {
    // Time measurements (in nanoseconds for precision)
    keygen_time_ns: u64,
    encrypt_time_ns: u64,
    decrypt_time_ns: u64,
    
    // Memory usage
    keygen_peak_memory_bytes: usize,
    encrypt_peak_memory_bytes: usize,
    decrypt_peak_memory_bytes: usize,
    keygen_allocated_memory_bytes: usize,
    encrypt_allocated_memory_bytes: usize,
    decrypt_allocated_memory_bytes: usize,
    
    // CPU utilization
    keygen_cpu_time_ns: u64,
    encrypt_cpu_time_ns: u64,
    decrypt_cpu_time_ns: u64,
    keygen_cpu_percent: f64,
    encrypt_cpu_percent: f64,
    decrypt_cpu_percent: f64,
    
    // Data processing
    input_size_bytes: usize,
    ciphertext_size_bytes: usize,
    decrypted_size_bytes: usize,
    
    // Operation-specific
    iv_size_bytes: usize,
    key_size_bits: i32,
    key_size_bytes: usize,
    block_size_bytes: i32,
    num_rounds: i32,
    
    // System information
    thread_count: i32,
    process_priority: i32,
    
    // Context switches and cache
    ctx_switches_voluntary: u64,
    ctx_switches_involuntary: u64,
    page_faults: u64,
    
    // Implementation details
    is_custom_implementation: bool,
    library_version: [64]u8,
    
    // Correctness check
    correctness_passed: bool,
    
    pub fn init() BenchmarkMetrics {
        return BenchmarkMetrics{
            .keygen_time_ns = 0,
            .encrypt_time_ns = 0,
            .decrypt_time_ns = 0,
            .keygen_peak_memory_bytes = 0,
            .encrypt_peak_memory_bytes = 0,
            .decrypt_peak_memory_bytes = 0,
            .keygen_allocated_memory_bytes = 0,
            .encrypt_allocated_memory_bytes = 0,
            .decrypt_allocated_memory_bytes = 0,
            .keygen_cpu_time_ns = 0,
            .encrypt_cpu_time_ns = 0,
            .decrypt_cpu_time_ns = 0,
            .keygen_cpu_percent = 0.0,
            .encrypt_cpu_percent = 0.0,
            .decrypt_cpu_percent = 0.0,
            .input_size_bytes = 0,
            .ciphertext_size_bytes = 0,
            .decrypted_size_bytes = 0,
            .iv_size_bytes = 0,
            .key_size_bits = 0,
            .key_size_bytes = 0,
            .block_size_bytes = 0,
            .num_rounds = 0,
            .thread_count = 1,
            .process_priority = 0,
            .ctx_switches_voluntary = 0,
            .ctx_switches_involuntary = 0,
            .page_faults = 0,
            .is_custom_implementation = false,
            .library_version = std.mem.zeroes([64]u8),
            .correctness_passed = false,
        };
    }
};

// Resource usage tracking structure
pub const ResourceUsage = struct {
    cpu_time_ns: u64,
    cpu_percent: f64,
    peak_memory_bytes: usize,
    allocated_memory_bytes: usize,
    voluntary_ctx_switches: u64,
    involuntary_ctx_switches: u64,
    page_faults: u64,
    thread_count: i32,
    process_priority: i32,
    
    pub fn init() ResourceUsage {
        return ResourceUsage{
            .cpu_time_ns = 0,
            .cpu_percent = 0.0,
            .peak_memory_bytes = 0,
            .allocated_memory_bytes = 0,
            .voluntary_ctx_switches = 0,
            .involuntary_ctx_switches = 0,
            .page_faults = 0,
            .thread_count = 1,
            .process_priority = 0,
        };
    }
    
    pub fn diff(start: ResourceUsage, end: ResourceUsage) ResourceUsage {
        return ResourceUsage{
            .cpu_time_ns = end.cpu_time_ns - start.cpu_time_ns,
            .cpu_percent = end.cpu_percent,
            .peak_memory_bytes = @max(end.peak_memory_bytes, start.peak_memory_bytes),
            .allocated_memory_bytes = end.allocated_memory_bytes - start.allocated_memory_bytes,
            .voluntary_ctx_switches = end.voluntary_ctx_switches - start.voluntary_ctx_switches,
            .involuntary_ctx_switches = end.involuntary_ctx_switches - start.involuntary_ctx_switches,
            .page_faults = end.page_faults - start.page_faults,
            .thread_count = end.thread_count,
            .process_priority = end.process_priority,
        };
    }
};

// Processing strategy enumeration
pub const ProcessingStrategy = enum {
    memory,
    stream,
};

// Chunked file structure
pub const ChunkedFile = struct {
    file: std.fs.File,
    filename: []const u8,
    file_size: usize,
    chunk_size: usize,
    current_chunk: []u8,
    position: usize,
    eof: bool,
    allocator: Allocator,
    
    pub fn init(allocator: Allocator, filename: []const u8, chunk_size: usize) !*ChunkedFile {
        const file = std.fs.cwd().openFile(filename, .{}) catch |err| {
            print("Error opening file {s}: {}\n", .{ filename, err });
            return err;
        };
        
        const file_size = file.getEndPos() catch |err| {
            file.close();
            return err;
        };
        
        const chunk_buffer = allocator.alloc(u8, chunk_size) catch |err| {
            file.close();
            return err;
        };
        
        const filename_copy = allocator.dupe(u8, filename) catch |err| {
            allocator.free(chunk_buffer);
            file.close();
            return err;
        };
        
        const chunked_file = allocator.create(ChunkedFile) catch |err| {
            allocator.free(filename_copy);
            allocator.free(chunk_buffer);
            file.close();
            return err;
        };
        
        chunked_file.* = ChunkedFile{
            .file = file,
            .filename = filename_copy,
            .file_size = file_size,
            .chunk_size = chunk_size,
            .current_chunk = chunk_buffer,
            .position = 0,
            .eof = false,
            .allocator = allocator,
        };
        
        return chunked_file;
    }
    
    pub fn deinit(self: *ChunkedFile) void {
        self.file.close();
        self.allocator.free(self.filename);
        self.allocator.free(self.current_chunk);
        self.allocator.destroy(self);
    }
    
    pub fn readNextChunk(self: *ChunkedFile) !usize {
        if (self.eof) return 0;
        
        const bytes_read = self.file.read(self.current_chunk) catch |err| {
            print("Error reading chunk: {}\n", .{err});
            return err;
        };
        
        self.position += bytes_read;
        
        if (bytes_read < self.chunk_size or self.position >= self.file_size) {
            self.eof = true;
        }
        
        return bytes_read;
    }
};

// Get high-precision timestamp in nanoseconds
pub fn getTimeNs() u64 {
    return @intCast(std.time.nanoTimestamp());
}

// Get current resource usage
pub fn getResourceUsage() ResourceUsage {
    var usage = ResourceUsage.init();
    
    // Get current memory usage (simplified for cross-platform compatibility)
    if (builtin.os.tag == .linux) {
        // On Linux, we can read from /proc/self/status
        getLinuxResourceUsage(&usage);
    } else if (builtin.os.tag == .macos) {
        // On macOS, use mach APIs
        getMacOSResourceUsage(&usage);
    } else {
        // Fallback for other platforms
        getFallbackResourceUsage(&usage);
    }
    
    return usage;
}

// Linux-specific resource usage
fn getLinuxResourceUsage(usage: *ResourceUsage) void {
    // Read memory info from /proc/self/status
    const status_file = std.fs.openFileAbsolute("/proc/self/status", .{}) catch return;
    defer status_file.close();
    
    var buf: [4096]u8 = undefined;
    const bytes_read = status_file.readAll(&buf) catch return;
    const content = buf[0..bytes_read];
    
    // Parse VmRSS (resident set size)
    if (std.mem.indexOf(u8, content, "VmRSS:")) |start| {
        const line_start = start;
        if (std.mem.indexOf(u8, content[line_start..], "\n")) |line_end| {
            const line = content[line_start..line_start + line_end];
            // Extract number (in kB)
            var iter = std.mem.tokenize(u8, line, " \t");
            _ = iter.next(); // Skip "VmRSS:"
            if (iter.next()) |kb_str| {
                if (std.fmt.parseInt(usize, kb_str, 10)) |kb| {
                    usage.peak_memory_bytes = kb * 1024;
                } else |_| {}
            }
        }
    }
    
    // Get CPU time from /proc/self/stat
    const stat_file = std.fs.openFileAbsolute("/proc/self/stat", .{}) catch return;
    defer stat_file.close();
    
    const stat_content = stat_file.readToEndAlloc(std.heap.page_allocator, 1024) catch return;
    defer std.heap.page_allocator.free(stat_content);
    
    var stat_iter = std.mem.tokenize(u8, stat_content, " ");
    var field_count: usize = 0;
    while (stat_iter.next()) |field| {
        field_count += 1;
        if (field_count == 14) { // utime (user CPU time)
            if (std.fmt.parseInt(u64, field, 10)) |utime| {
                usage.cpu_time_ns = utime * 10_000_000; // Convert from clock ticks to ns (assuming 100 Hz)
            } else |_| {}
        }
    }
}

// macOS-specific resource usage
fn getMacOSResourceUsage(usage: *ResourceUsage) void {
    // For macOS, we'll use a simplified approach
    // In a real implementation, you'd use mach APIs
    usage.peak_memory_bytes = 50 * 1024 * 1024; // Placeholder: 50MB
    usage.cpu_time_ns = getTimeNs() / 1000; // Simplified CPU time estimation
}

// Fallback resource usage for other platforms
fn getFallbackResourceUsage(usage: *ResourceUsage) void {
    // Provide reasonable defaults
    usage.peak_memory_bytes = 32 * 1024 * 1024; // 32MB default
    usage.cpu_time_ns = getTimeNs() / 1000; // Simplified
    usage.cpu_percent = 95.0; // Assume high CPU usage during crypto operations
}

// Get current memory usage (simplified implementation)
fn getCurrentMemoryUsage() usize {
    // This is a simplified implementation
    // In a real implementation, you'd use platform-specific APIs
    return 1024 * 1024; // 1MB placeholder
}

// Calculate CPU percentage based on wall time and CPU time
pub fn calculateCpuPercent(wall_time_ns: u64, cpu_time_ns: u64) f64 {
    if (wall_time_ns == 0) return 0.0;
    return (@as(f64, @floatFromInt(cpu_time_ns)) / @as(f64, @floatFromInt(wall_time_ns))) * 100.0;
}

// Secure memory allocation (simplified)
pub fn secureAlloc(allocator: Allocator, size: usize) ![]u8 {
    const memory = try allocator.alloc(u8, size);
    @memset(memory, 0);
    return memory;
}

// Secure memory deallocation
pub fn secureFree(allocator: Allocator, memory: []u8) void {
    @memset(memory, 0); // Clear memory before freeing
    allocator.free(memory);
}

// Read file into memory
pub fn readFile(allocator: Allocator, path: []const u8) ![]u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    
    const file_size = try file.getEndPos();
    const contents = try allocator.alloc(u8, file_size);
    _ = try file.readAll(contents);
    
    return contents;
}

// Verify data integrity
pub fn verifyDataIntegrity(original: []const u8, decrypted: []const u8) bool {
    if (original.len != decrypted.len) return false;
    return std.mem.eql(u8, original, decrypted);
}

// Convert chunk size string to bytes
pub fn chunkSizeToBytes(chunk_size_str: []const u8) usize {
    if (std.mem.endsWith(u8, chunk_size_str, "K") or std.mem.endsWith(u8, chunk_size_str, "k")) {
        const num_str = chunk_size_str[0..chunk_size_str.len - 1];
        if (std.fmt.parseInt(usize, num_str, 10)) |num| {
            return num * 1024;
        } else |_| {}
    } else if (std.mem.endsWith(u8, chunk_size_str, "M") or std.mem.endsWith(u8, chunk_size_str, "m")) {
        const num_str = chunk_size_str[0..chunk_size_str.len - 1];
        if (std.fmt.parseInt(usize, num_str, 10)) |num| {
            return num * 1024 * 1024;
        } else |_| {}
    } else {
        if (std.fmt.parseInt(usize, chunk_size_str, 10)) |num| {
            return num;
        } else |_| {}
    }
    
    return 1024; // Default to 1KB
}

// Get algorithm-specific parameters
pub fn getAlgorithmParams(algo_name: []const u8, key_size: i32) struct { block_size: i32, rounds: i32 } {
    if (std.mem.eql(u8, algo_name, "AES")) {
        var rounds: i32 = 10;
        if (key_size == 128) {
            rounds = 10;
        } else if (key_size == 192) {
            rounds = 12;
        } else if (key_size == 256) {
            rounds = 14;
        }
        return .{ .block_size = 16, .rounds = rounds };
    } else if (std.mem.eql(u8, algo_name, "Camellia")) {
        var rounds: i32 = 18;
        if (key_size == 128) {
            rounds = 18;
        } else if (key_size == 192 or key_size == 256) {
            rounds = 24;
        }
        return .{ .block_size = 16, .rounds = rounds };
    } else if (std.mem.eql(u8, algo_name, "ChaCha20")) {
        return .{ .block_size = 64, .rounds = 20 };
    } else if (std.mem.eql(u8, algo_name, "RSA")) {
        // For RSA, block size is the key size in bytes
        // Rounds represent the key size in bits for RSA
        const block_size_bytes = @divExact(key_size, 8);
        return .{ .block_size = block_size_bytes, .rounds = key_size };
    } else if (std.mem.eql(u8, algo_name, "ECC")) {
        // For ECC, block size is the field size in bytes
        // Rounds represent the curve security level in bits
        var block_size_bytes: i32 = 32; // Default for secp256r1
        var security_bits: i32 = 256;   // Default security level
        
        if (key_size == 256) {
            // secp256r1 or curve25519
            block_size_bytes = 32;
            security_bits = 256;
        } else if (key_size == 384) {
            // secp384r1
            block_size_bytes = 48;
            security_bits = 384;
        } else if (key_size == 521) {
            // secp521r1
            block_size_bytes = 66;
            security_bits = 521;
        } else if (key_size == 255) {
            // curve25519 (255-bit curve)
            block_size_bytes = 32;
            security_bits = 255;
        }
        
        return .{ .block_size = block_size_bytes, .rounds = security_bits };
    }
    
    return .{ .block_size = 16, .rounds = 10 }; // Default
}

// Create directory
pub fn createDirectory(path: []const u8) !void {
    std.fs.cwd().makeDir(path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
}

// Get file size
pub fn getFileSize(filename: []const u8) !usize {
    const file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();
    return try file.getEndPos();
}

// Write file
pub fn writeFile(filename: []const u8, data: []const u8) !void {
    const file = try std.fs.cwd().createFile(filename, .{});
    defer file.close();
    try file.writeAll(data);
}

// Print hex data
pub fn printHex(data: []const u8) void {
    for (data, 0..) |byte, i| {
        if (i > 0 and i % 16 == 0) print("\n", .{});
        print("{:02x} ", .{byte});
    }
    print("\n", .{});
}

// Generate random bytes
pub fn generateRandomBytes(buffer: []u8) !void {
    var prng = std.rand.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&seed));
        break :blk seed;
    });
    const random = prng.random();
    
    for (buffer) |*byte| {
        byte.* = random.int(u8);
    }
}

// Compare byte arrays
pub fn byteArraysEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    return std.mem.eql(u8, a, b);
}

// Get time in milliseconds (for compatibility)
pub fn getTimeMs() f64 {
    return @as(f64, @floatFromInt(getTimeNs())) / 1_000_000.0;
}

// Get CPU time in milliseconds (placeholder)
pub fn getCpuTimeMs() f64 {
    // This would need platform-specific implementation
    return getTimeMs();
}

// Get memory usage in bytes (placeholder)
pub fn getMemoryUsage() usize {
    return getCurrentMemoryUsage();
} 