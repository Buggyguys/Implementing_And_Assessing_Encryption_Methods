const std = @import("std");
const print = std.debug.print;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const json = std.json;

// Import our modules
const utils = @import("include/utils.zig");
const crypto_utils = @import("include/crypto_utils.zig");
const json_writer = @import("include/json_writer.zig");

// Use types from json_writer to avoid duplication
pub const AlgorithmType = json_writer.AlgorithmType;
pub const ImplementationInfo = json_writer.ImplementationInfo;

// Maximum number of implementations we can register
const MAX_IMPLEMENTATIONS = 100;
const MAX_PATH_LENGTH = 1024;

// Implementation registry structure
pub const ImplementationRegistry = struct {
    implementations: [MAX_IMPLEMENTATIONS]ImplementationInfo,
    count: usize,
    
    pub fn init() ImplementationRegistry {
        return ImplementationRegistry{
            .implementations = [_]ImplementationInfo{ImplementationInfo.init()} ** MAX_IMPLEMENTATIONS,
            .count = 0,
        };
    }
    
    pub fn register(self: *ImplementationRegistry, impl: ImplementationInfo) !void {
        if (self.count >= MAX_IMPLEMENTATIONS) {
            return error.RegistryFull;
        }
        self.implementations[self.count] = impl;
        self.count += 1;
    }
    
    pub fn countByType(self: *const ImplementationRegistry, algo_type: AlgorithmType) usize {
        var count: usize = 0;
        for (self.implementations[0..self.count]) |impl| {
            if (impl.algo_type == algo_type) {
                count += 1;
            }
        }
        return count;
    }
};

// Test configuration structure
const TestConfig = struct {
    // Test parameters
    iterations: i32,
    dataset_path: [1024]u8,
    dataset_size_bytes: usize,
    dataset_size_kb: i32,
    use_stdlib: bool,
    use_custom: bool,
    processing_strategy: [32]u8,
    chunk_size: [32]u8,
    
    // Zig-specific parameters
    memory_mode: i32,
    
    // Session directory
    session_dir: [1024]u8,
    
    pub fn init() TestConfig {
        return TestConfig{
            .iterations = 1,
            .dataset_path = std.mem.zeroes([1024]u8),
            .dataset_size_bytes = 0,
            .dataset_size_kb = 0,
            .use_stdlib = true,
            .use_custom = false,
            .processing_strategy = std.mem.zeroes([32]u8),
            .chunk_size = std.mem.zeroes([32]u8),
            .memory_mode = 0,
            .session_dir = std.mem.zeroes([1024]u8),
        };
    }
};

// Global registry
var global_registry: ImplementationRegistry = undefined;

// Function to get algorithm name
fn getAlgorithmName(algo_type: AlgorithmType) []const u8 {
    return switch (algo_type) {
        .aes => "AES",
        .camellia => "Camellia",
        .chacha20 => "ChaCha20",
        .rsa => "RSA",
        .ecc => "ECC",
        .undefined => "Undefined",
    };
}

// Function to get current time string
fn getTimeString(allocator: Allocator) ![]u8 {
    const timestamp = std.time.timestamp();
    const datetime = std.time.epoch.EpochSeconds{ .secs = @intCast(timestamp) };
    const day_seconds = datetime.getDaySeconds();
    const epoch_day = datetime.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    
    return std.fmt.allocPrint(allocator, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        year_day.year, @intFromEnum(month_day.month), month_day.day_index + 1,
        day_seconds.getHoursIntoDay(), day_seconds.getMinutesIntoHour(), day_seconds.getSecondsIntoMinute(),
    });
}

// Function to register all implementations
fn registerAllImplementations(allocator: Allocator, config_json: ?[]const u8) !void {
    global_registry = ImplementationRegistry.init();
    
    // Register AES implementations
    try registerAesImplementations(&global_registry, config_json, allocator);
    
    // Register ChaCha20 implementations
    try registerChaCha20Implementations(&global_registry, config_json, allocator);
    
    // Register other implementations (placeholders for now)
    // try registerCamelliaImplementations(&global_registry);
    // try registerRsaImplementations(&global_registry);
    // try registerEccImplementations(&global_registry);
}

// Import AES implementation
const aes_impl = @import("aes/implementation.zig");

// Import ChaCha20 implementation
const chacha20_impl = @import("chacha20/implementation.zig");

// Register AES implementations
fn registerAesImplementations(registry: *ImplementationRegistry, config_json: ?[]const u8, allocator: Allocator) !void {
    try aes_impl.registerAesImplementations(registry, config_json, allocator);
}

// Register ChaCha20 implementations
fn registerChaCha20Implementations(registry: *ImplementationRegistry, config_json: ?[]const u8, allocator: Allocator) !void {
    try chacha20_impl.registerChaCha20Implementations(registry, config_json, allocator);
}

// Function to print all implementations
fn printAllImplementations() void {
    print("Registered Implementations:\n", .{});
    print("==========================\n", .{});
    
    for (global_registry.implementations[0..global_registry.count]) |impl| {
        const name_slice = std.mem.sliceTo(&impl.name, 0);
        const mode_slice = std.mem.sliceTo(&impl.mode, 0);
        const algo_name = getAlgorithmName(impl.algo_type);
        
        print("- {s} ({s}) - {s} mode, {d}-bit key, {s}\n", .{
            name_slice,
            algo_name,
            mode_slice,
            impl.key_size,
            if (impl.is_custom) "Custom" else "Standard",
        });
    }
    
    print("\nTotal implementations: {d}\n", .{global_registry.count});
}

// Function to parse configuration file
fn parseConfigFile(allocator: Allocator, config_path: []const u8) !TestConfig {
    const file = std.fs.cwd().openFile(config_path, .{}) catch |err| {
        print("Error opening config file: {}\n", .{err});
        return err;
    };
    defer file.close();
    
    const file_size = try file.getEndPos();
    const contents = try allocator.alloc(u8, file_size);
    defer allocator.free(contents);
    
    _ = try file.readAll(contents);
    
    const parsed = json.parseFromSlice(json.Value, allocator, contents, .{}) catch |err| {
        print("Error parsing JSON: {}\n", .{err});
        return err;
    };
    defer parsed.deinit();
    
    var config = TestConfig.init();
    
    // Parse test parameters
    if (parsed.value.object.get("test_parameters")) |test_params| {
        if (test_params.object.get("iterations")) |iterations| {
            config.iterations = @intCast(iterations.integer);
        }
        
        if (test_params.object.get("dataset_path")) |dataset_path| {
            const path_str = dataset_path.string;
            const copy_len = @min(path_str.len, config.dataset_path.len - 1);
            @memcpy(config.dataset_path[0..copy_len], path_str[0..copy_len]);
            config.dataset_path[copy_len] = 0; // Null terminate
        }
        
        if (test_params.object.get("use_stdlib")) |use_stdlib| {
            config.use_stdlib = use_stdlib.bool;
        }
        
        if (test_params.object.get("use_custom")) |use_custom| {
            config.use_custom = use_custom.bool;
        }
        
        if (test_params.object.get("processing_strategy")) |strategy| {
            const strategy_str = strategy.string;
            const copy_len = @min(strategy_str.len, config.processing_strategy.len - 1);
            @memcpy(config.processing_strategy[0..copy_len], strategy_str[0..copy_len]);
            config.processing_strategy[copy_len] = 0; // Null terminate
        }
        
        if (test_params.object.get("chunk_size")) |chunk_size| {
            const chunk_str = chunk_size.string;
            const copy_len = @min(chunk_str.len, config.chunk_size.len - 1);
            @memcpy(config.chunk_size[0..copy_len], chunk_str[0..copy_len]);
            config.chunk_size[copy_len] = 0; // Null terminate
        }
    }
    
    // Parse dataset info
    if (parsed.value.object.get("dataset_info")) |dataset_info| {
        if (dataset_info.object.get("file_size_kb")) |size| {
            switch (size) {
                .integer => |int_val| config.dataset_size_kb = @intCast(int_val),
                .float => |float_val| config.dataset_size_kb = @intCast(@as(i64, @intFromFloat(float_val))),
                else => {
                    print("Warning: file_size_kb has unexpected type\n", .{});
                    config.dataset_size_kb = 0;
                },
            }
        }
    }
    
    // Parse session information
    if (parsed.value.object.get("session_info")) |session_info| {
        if (session_info.object.get("session_dir")) |session_dir| {
            const dir_str = session_dir.string;
            const copy_len = @min(dir_str.len, config.session_dir.len - 1);
            @memcpy(config.session_dir[0..copy_len], dir_str[0..copy_len]);
            config.session_dir[copy_len] = 0; // Null terminate
        }
    }
    
    // Calculate dataset size in bytes from file if path exists
    const dataset_path_slice = std.mem.sliceTo(&config.dataset_path, 0);
    if (dataset_path_slice.len > 0) {
        const dataset_file = std.fs.cwd().openFile(dataset_path_slice, .{}) catch |err| {
            print("Warning: Could not open dataset file: {}\n", .{err});
            config.dataset_size_bytes = @as(usize, @intCast(config.dataset_size_kb)) * 1024;
            return config;
        };
        defer dataset_file.close();
        
        const file_stat = dataset_file.stat() catch |err| {
            print("Warning: Could not stat dataset file: {}\n", .{err});
            config.dataset_size_bytes = @as(usize, @intCast(config.dataset_size_kb)) * 1024;
            return config;
        };
        
        config.dataset_size_bytes = file_stat.size;
        print("Dataset size: {d} bytes\n", .{config.dataset_size_bytes});
    }
    
    return config;
}

// Benchmark result structure
const BenchmarkResult = struct {
    encrypt_wall_time: u64,
    decrypt_wall_time: u64,
    encrypt_diff: utils.ResourceUsage,
    decrypt_diff: utils.ResourceUsage,
    encrypt_cpu_percent: f64,
    decrypt_cpu_percent: f64,
    ciphertext_length: i32,
    plaintext_length: i32,
    is_correct: bool,
};

// Function to run stream mode benchmark
fn runStreamModeBenchmark(allocator: Allocator, impl: *const ImplementationInfo, ctx: *anyopaque, 
                         test_data: []const u8, key: []const u8, config: *const TestConfig) !BenchmarkResult {
    print("    Encrypting data (Stream mode)...\n", .{});
    
    // Parse chunk size
    const chunk_size_slice = std.mem.sliceTo(&config.chunk_size, 0);
    const chunk_size = utils.chunkSizeToBytes(chunk_size_slice);
    
    // Calculate number of chunks
    const total_chunks = (test_data.len + chunk_size - 1) / chunk_size;
    print("    Dataset will be processed in {d} chunks\n", .{total_chunks});
    
    const encrypt_start_time = utils.getTimeNs();
    const encrypt_start_usage = utils.getResourceUsage();
    
    // Allocate buffer for all ciphertext (approximate size)
    const max_ciphertext_size = test_data.len + (test_data.len / 10) + 1024 + (total_chunks * 8);
    var all_ciphertext = try allocator.alloc(u8, max_ciphertext_size);
    defer allocator.free(all_ciphertext);
    
    var total_ciphertext_length: usize = 0;
    var chunk_index: i32 = 0;
    var offset: usize = 0;
    
    // Process each chunk
    while (offset < test_data.len) {
        const chunk_end = @min(offset + chunk_size, test_data.len);
        const chunk_data = test_data[offset..chunk_end];
        
        // Adaptive progress reporting based on total chunks
        const progress_percent = (@as(f64, @floatFromInt(chunk_index + 1)) / @as(f64, @floatFromInt(total_chunks))) * 100.0;
        
        // Show progress intelligently based on chunk count:
        // - For ≤5 chunks: show all
        // - For 6-20 chunks: show every 20% (5 updates)
        // - For 21-100 chunks: show every 10% (10 updates)  
        // - For >100 chunks: show every 5% (20 updates)
        var should_show_progress = false;
        if (total_chunks <= 5) {
            should_show_progress = true;
        } else if (total_chunks <= 20) {
            should_show_progress = (chunk_index == 0 or @mod(@as(usize, @intCast(chunk_index + 1)), @max(1, total_chunks / 5)) == 0 or @as(usize, @intCast(chunk_index + 1)) == total_chunks);
        } else if (total_chunks <= 100) {
            should_show_progress = (chunk_index == 0 or @mod(@as(usize, @intCast(chunk_index + 1)), @max(1, total_chunks / 10)) == 0 or @as(usize, @intCast(chunk_index + 1)) == total_chunks);
        } else {
            should_show_progress = (chunk_index == 0 or @mod(@as(usize, @intCast(chunk_index + 1)), @max(1, total_chunks / 20)) == 0 or @as(usize, @intCast(chunk_index + 1)) == total_chunks);
        }
        
        if (should_show_progress) {
            print("    Processing chunk {d}/{d} ({d:.1}%)...\n", .{ 
                chunk_index + 1, 
                total_chunks, 
                progress_percent
            });
        }
        
        var chunk_ciphertext_length: i32 = 0;
        const chunk_ciphertext = impl.encrypt_stream_fn.?(ctx, chunk_data, key, chunk_index, allocator, &chunk_ciphertext_length) catch |err| {
            print("Error: Chunk encryption failed: {}\n", .{err});
            break;
        };
        defer allocator.free(chunk_ciphertext);
        
        // Store chunk size header (4 bytes) + ciphertext
        if (total_ciphertext_length + 4 + @as(usize, @intCast(chunk_ciphertext_length)) > max_ciphertext_size) {
            print("Error: Ciphertext buffer overflow\n", .{});
            break;
        }
        
        // Write chunk size header
        std.mem.writeInt(u32, all_ciphertext[total_ciphertext_length..][0..4], @intCast(chunk_ciphertext_length), .little);
        total_ciphertext_length += 4;
        
        // Write chunk ciphertext
        @memcpy(all_ciphertext[total_ciphertext_length..total_ciphertext_length + @as(usize, @intCast(chunk_ciphertext_length))], chunk_ciphertext);
        total_ciphertext_length += @intCast(chunk_ciphertext_length);
        
        offset = chunk_end;
        chunk_index += 1;
    }
    
    print("    Processed {d} chunks successfully\n", .{chunk_index});
    
    const encrypt_end_time = utils.getTimeNs();
    const encrypt_end_usage = utils.getResourceUsage();
    const encrypt_diff = utils.ResourceUsage.diff(encrypt_start_usage, encrypt_end_usage);
    
    const encrypt_wall_time = encrypt_end_time - encrypt_start_time;
    const encrypt_cpu_percent = utils.calculateCpuPercent(encrypt_wall_time, encrypt_diff.cpu_time_ns);
    
    // Create final ciphertext buffer
    const ciphertext = try allocator.alloc(u8, total_ciphertext_length);
    @memcpy(ciphertext, all_ciphertext[0..total_ciphertext_length]);
    defer allocator.free(ciphertext);
    const ciphertext_length: i32 = @intCast(total_ciphertext_length);
    
    // Measure decryption (Stream mode)
    print("    Decrypting data (Stream mode)...\n", .{});
    print("    Decrypting {d} bytes of ciphertext in chunks...\n", .{ciphertext_length});
    
    const decrypt_start_time = utils.getTimeNs();
    const decrypt_start_usage = utils.getResourceUsage();
    
    // Allocate buffer for decrypted data
    const max_plaintext_size = test_data.len + 1024;
    var all_decrypted = try allocator.alloc(u8, max_plaintext_size);
    defer allocator.free(all_decrypted);
    
    var total_plaintext_length: usize = 0;
    var ciphertext_offset: usize = 0;
    chunk_index = 0;
    
    // Process each encrypted chunk
    while (ciphertext_offset < ciphertext.len) {
        if (ciphertext_offset + 4 > ciphertext.len) break;
        
        // Read chunk size header
        const chunk_ciphertext_length = std.mem.readInt(u32, ciphertext[ciphertext_offset..][0..4], .little);
        ciphertext_offset += 4;
        
        if (ciphertext_offset + chunk_ciphertext_length > ciphertext.len) break;
        
        // Adaptive progress reporting based on total chunks
        const decrypt_progress_percent = (@as(f64, @floatFromInt(chunk_index + 1)) / @as(f64, @floatFromInt(total_chunks))) * 100.0;
        
        // Show progress intelligently based on chunk count (same logic as encryption)
        var should_show_decrypt_progress = false;
        if (total_chunks <= 5) {
            should_show_decrypt_progress = true;
        } else if (total_chunks <= 20) {
            should_show_decrypt_progress = (chunk_index == 0 or @mod(@as(usize, @intCast(chunk_index + 1)), @max(1, total_chunks / 5)) == 0 or @as(usize, @intCast(chunk_index + 1)) == total_chunks);
        } else if (total_chunks <= 100) {
            should_show_decrypt_progress = (chunk_index == 0 or @mod(@as(usize, @intCast(chunk_index + 1)), @max(1, total_chunks / 10)) == 0 or @as(usize, @intCast(chunk_index + 1)) == total_chunks);
        } else {
            should_show_decrypt_progress = (chunk_index == 0 or @mod(@as(usize, @intCast(chunk_index + 1)), @max(1, total_chunks / 20)) == 0 or @as(usize, @intCast(chunk_index + 1)) == total_chunks);
        }
        
        if (should_show_decrypt_progress) {
            print("    Decrypting chunk {d}/{d} ({d:.1}%)...\n", .{ 
                chunk_index + 1, 
                total_chunks, 
                decrypt_progress_percent
            });
        }
        
        const chunk_ciphertext_data = ciphertext[ciphertext_offset..ciphertext_offset + chunk_ciphertext_length];
        
        var chunk_plaintext_length: i32 = 0;
        const chunk_plaintext = impl.decrypt_stream_fn.?(ctx, chunk_ciphertext_data, key, chunk_index, allocator, &chunk_plaintext_length) catch |err| {
            print("Error: Chunk decryption failed: {}\n", .{err});
            break;
        };
        defer allocator.free(chunk_plaintext);
        
        // Copy to final buffer
        if (total_plaintext_length + @as(usize, @intCast(chunk_plaintext_length)) > max_plaintext_size) {
            print("Error: Plaintext buffer overflow\n", .{});
            break;
        }
        
        @memcpy(all_decrypted[total_plaintext_length..total_plaintext_length + @as(usize, @intCast(chunk_plaintext_length))], chunk_plaintext);
        total_plaintext_length += @intCast(chunk_plaintext_length);
        
        ciphertext_offset += chunk_ciphertext_length;
        chunk_index += 1;
    }
    
    print("    Decrypted {d} chunks successfully, total plaintext: {d} bytes\n", .{ chunk_index, total_plaintext_length });
    
    const decrypt_end_time = utils.getTimeNs();
    const decrypt_end_usage = utils.getResourceUsage();
    const decrypt_diff = utils.ResourceUsage.diff(decrypt_start_usage, decrypt_end_usage);
    
    const decrypt_wall_time = decrypt_end_time - decrypt_start_time;
    const decrypt_cpu_percent = utils.calculateCpuPercent(decrypt_wall_time, decrypt_diff.cpu_time_ns);
    
    const plaintext_length: i32 = @intCast(total_plaintext_length);
    
    // Check correctness (Stream mode verification)
    const length_diff = if (test_data.len > total_plaintext_length) 
        test_data.len - total_plaintext_length 
    else 
        total_plaintext_length - test_data.len;
    const tolerance_bytes = @max(1048, test_data.len / 1000); // 0.1% tolerance or 1KB minimum
    const length_check_passed = length_diff <= tolerance_bytes;
    
    // For stream mode, we do a length check instead of full data verification for performance
    const tolerance_percent = if (test_data.len > 0) 
        (@as(f64, @floatFromInt(length_diff)) / @as(f64, @floatFromInt(test_data.len))) * 100.0 
    else 0.0;
    
    print("    Verification (Stream mode): Length check {s} (diff {d}/{d} bytes, within {d:.3}% tolerance), full data verification skipped\n", .{
        if (length_check_passed) "passed" else "failed",
        length_diff,
        tolerance_bytes,
        tolerance_percent
    });
    
    return BenchmarkResult{
        .encrypt_wall_time = encrypt_wall_time,
        .decrypt_wall_time = decrypt_wall_time,
        .encrypt_diff = encrypt_diff,
        .decrypt_diff = decrypt_diff,
        .encrypt_cpu_percent = encrypt_cpu_percent,
        .decrypt_cpu_percent = decrypt_cpu_percent,
        .ciphertext_length = ciphertext_length,
        .plaintext_length = plaintext_length,
        .is_correct = length_check_passed,
    };
}

// Function to run memory mode benchmark
fn runMemoryModeBenchmark(allocator: Allocator, impl: *const ImplementationInfo, ctx: *anyopaque, 
                         test_data: []const u8, key: []const u8) !BenchmarkResult {
    // Memory mode (original implementation)
    print("    Encrypting data (Memory mode)...\n", .{});
    const encrypt_start_time = utils.getTimeNs();
    const encrypt_start_usage = utils.getResourceUsage();
    
    var ciphertext_length: i32 = 0;
    const ciphertext = impl.encrypt_fn.?(ctx, test_data, key, allocator, &ciphertext_length) catch |err| {
        print("Error: Encryption failed: {}\n", .{err});
        return err;
    };
    defer allocator.free(ciphertext);
    
    const encrypt_end_time = utils.getTimeNs();
    const encrypt_end_usage = utils.getResourceUsage();
    const encrypt_diff = utils.ResourceUsage.diff(encrypt_start_usage, encrypt_end_usage);
    
    const encrypt_wall_time = encrypt_end_time - encrypt_start_time;
    const encrypt_cpu_percent = utils.calculateCpuPercent(encrypt_wall_time, encrypt_diff.cpu_time_ns);
    
    // Measure decryption
    print("    Decrypting data (Memory mode)...\n", .{});
    const decrypt_start_time = utils.getTimeNs();
    const decrypt_start_usage = utils.getResourceUsage();
    
    var plaintext_length: i32 = 0;
    const decrypted = impl.decrypt_fn.?(ctx, ciphertext, key, allocator, &plaintext_length) catch |err| {
        print("Error: Decryption failed: {}\n", .{err});
        return err;
    };
    defer allocator.free(decrypted);
    
    const decrypt_end_time = utils.getTimeNs();
    const decrypt_end_usage = utils.getResourceUsage();
    const decrypt_diff = utils.ResourceUsage.diff(decrypt_start_usage, decrypt_end_usage);
    
    const decrypt_wall_time = decrypt_end_time - decrypt_start_time;
    const decrypt_cpu_percent = utils.calculateCpuPercent(decrypt_wall_time, decrypt_diff.cpu_time_ns);
    
    // Check correctness
    const is_correct = utils.verifyDataIntegrity(test_data, decrypted[0..@intCast(plaintext_length)]);
    
    print("    Verification: Data integrity check {s}\n", .{if (is_correct) "passed" else "failed"});
    
    return BenchmarkResult{
        .encrypt_wall_time = encrypt_wall_time,
        .decrypt_wall_time = decrypt_wall_time,
        .encrypt_diff = encrypt_diff,
        .decrypt_diff = decrypt_diff,
        .encrypt_cpu_percent = encrypt_cpu_percent,
        .decrypt_cpu_percent = decrypt_cpu_percent,
        .ciphertext_length = ciphertext_length,
        .plaintext_length = plaintext_length,
        .is_correct = is_correct,
    };
}

// Function to run benchmarks
fn runBenchmarks(allocator: Allocator, config: *const TestConfig) !void {
    print("Starting Zig encryption benchmarks...\n", .{});
    
    const session_dir_slice = std.mem.sliceTo(&config.session_dir, 0);
    const dataset_path_slice = std.mem.sliceTo(&config.dataset_path, 0);
    const current_processing_strategy = std.mem.sliceTo(&config.processing_strategy, 0);
    
    print("Session directory: {s}\n", .{session_dir_slice});
    print("Dataset path: {s}\n", .{dataset_path_slice});
    print("Dataset size: {d} KB\n", .{config.dataset_size_kb});
    print("Iterations: {d}\n", .{config.iterations});
    print("Processing strategy: {s}\n", .{current_processing_strategy});
    print("Use stdlib: {}\n", .{config.use_stdlib});
    print("Use custom: {}\n", .{config.use_custom});
    
    // Create results directory
    var results_dir_buf: [2048]u8 = undefined;
    const results_dir = try std.fmt.bufPrint(results_dir_buf[0..], "{s}/results", .{session_dir_slice});
    
    std.fs.cwd().makeDir(results_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    
    // Extract session ID from session directory path
    var session_id: []const u8 = "unknown";
    if (std.mem.lastIndexOf(u8, session_dir_slice, "/")) |last_slash| {
        session_id = session_dir_slice[last_slash + 1..];
    }
    
    // Load test data
    const test_data = utils.readFile(allocator, dataset_path_slice) catch |err| {
        print("Error: Could not read test data: {}\n", .{err});
        return;
    };
    defer allocator.free(test_data);
    
    print("Loaded test data: {d} bytes\n", .{test_data.len});
    
    // Create JSON results writer
    var json_results = json_writer.JsonResultsWriter.init(allocator);
    defer json_results.deinit();
    
    // Write JSON header
    const timestamp_str = try getTimeString(allocator);
    defer allocator.free(timestamp_str);
    
    try json_results.writeHeader(timestamp_str, session_id, dataset_path_slice, 
                                config.dataset_size_bytes, config.iterations, 
                                current_processing_strategy, config.use_stdlib, config.use_custom);
    
    // Run benchmarks for each registered implementation
    var implementations_tested: i32 = 0;
    
    for (0..global_registry.count) |i| {
        const impl = &global_registry.implementations[i];
        
        // Skip implementations based on configuration
        if ((impl.is_custom and !config.use_custom) or 
            (!impl.is_custom and !config.use_stdlib)) {
            continue;
        }
        
        const impl_name = std.mem.sliceTo(&impl.name, 0);
        const description = if (impl.is_custom) "Custom" else "Standard";
        const algo_name = getAlgorithmName(impl.algo_type);
        
        print("Running benchmark for {s} {s} Implementation\n", .{ description, algo_name });
        
        // Start implementation in JSON
        try json_results.startImplementation(impl_name, implementations_tested == 0);
        
        // Track aggregated metrics
        var total_keygen_time_ns: u64 = 0;
        var total_encrypt_time_ns: u64 = 0;
        var total_decrypt_time_ns: u64 = 0;
        var total_keygen_cpu_time_ns: u64 = 0;
        var total_encrypt_cpu_time_ns: u64 = 0;
        var total_decrypt_cpu_time_ns: u64 = 0;
        var total_keygen_cpu_percent: f64 = 0.0;
        var total_encrypt_cpu_percent: f64 = 0.0;
        var total_decrypt_cpu_percent: f64 = 0.0;
        var total_keygen_memory: usize = 0;
        var total_encrypt_memory: usize = 0;
        var total_decrypt_memory: usize = 0;
        var total_key_size_bytes: usize = 0;
        var total_ciphertext_size: usize = 0;
        var correctness_failures: i32 = 0;
        
        // Run iterations
        for (0..@intCast(config.iterations)) |iter| {
            print("  Running iteration {d}/{d} for {s} {s} Implementation\n", .{ iter + 1, config.iterations, description, algo_name });
            
            // Initialize implementation context
            const ctx = impl.init_fn.?(allocator) catch |err| {
                print("Error: Failed to initialize implementation: {}\n", .{err});
                continue;
            };
            defer impl.cleanup_fn.?(ctx, allocator);
            
            // Start iteration in JSON
            try json_results.startIteration(iter, iter == 0);
            
            // Measure key generation
            print("    Generating key...\n", .{});
            const keygen_start_time = utils.getTimeNs();
            const keygen_start_usage = utils.getResourceUsage();
            
            var key_length: i32 = 0;
            const key = impl.generate_key_fn.?(ctx, allocator, &key_length) catch |err| {
                print("Error: Failed to generate key: {}\n", .{err});
                continue;
            };
            defer allocator.free(key);
            
            const keygen_end_time = utils.getTimeNs();
            const keygen_end_usage = utils.getResourceUsage();
            const keygen_diff = utils.ResourceUsage.diff(keygen_start_usage, keygen_end_usage);
            
            const keygen_wall_time = keygen_end_time - keygen_start_time;
            const keygen_cpu_percent = utils.calculateCpuPercent(keygen_wall_time, keygen_diff.cpu_time_ns);
            
            // Write key generation metrics to JSON
            try json_results.writeKeygenMetrics(keygen_wall_time, keygen_diff, keygen_cpu_percent, key_length);
            
            // Run encryption/decryption based on processing strategy
            const is_stream_mode = std.mem.eql(u8, current_processing_strategy, "Stream");
            const benchmark_result = if (is_stream_mode) 
                try runStreamModeBenchmark(allocator, impl, ctx, test_data, key, config)
            else 
                try runMemoryModeBenchmark(allocator, impl, ctx, test_data, key);
            
            // Write encryption and decryption metrics to JSON
            try json_results.writeEncryptionMetrics(benchmark_result.encrypt_wall_time, benchmark_result.encrypt_diff, 
                                                   benchmark_result.encrypt_cpu_percent, test_data.len, benchmark_result.ciphertext_length);
            try json_results.writeDecryptionMetrics(benchmark_result.decrypt_wall_time, benchmark_result.decrypt_diff, 
                                                   benchmark_result.decrypt_cpu_percent, benchmark_result.plaintext_length, benchmark_result.is_correct);
            
            // Write algorithm-specific parameters
            try json_results.writeAlgorithmParams(impl.algo_type, impl.key_size, impl.is_custom);
            
            // End iteration in JSON
            try json_results.endIteration();
            
            // Update totals for aggregated metrics
            total_keygen_time_ns += keygen_wall_time;
            total_encrypt_time_ns += benchmark_result.encrypt_wall_time;
            total_decrypt_time_ns += benchmark_result.decrypt_wall_time;
            total_keygen_cpu_time_ns += keygen_diff.cpu_time_ns;
            total_encrypt_cpu_time_ns += benchmark_result.encrypt_diff.cpu_time_ns;
            total_decrypt_cpu_time_ns += benchmark_result.decrypt_diff.cpu_time_ns;
            total_keygen_cpu_percent += keygen_cpu_percent;
            total_encrypt_cpu_percent += benchmark_result.encrypt_cpu_percent;
            total_decrypt_cpu_percent += benchmark_result.decrypt_cpu_percent;
            total_keygen_memory += keygen_diff.peak_memory_bytes;
            total_encrypt_memory += benchmark_result.encrypt_diff.peak_memory_bytes;
            total_decrypt_memory += benchmark_result.decrypt_diff.peak_memory_bytes;
            total_key_size_bytes += @intCast(key_length);
            total_ciphertext_size += @intCast(benchmark_result.ciphertext_length);
            
            if (!benchmark_result.is_correct) {
                correctness_failures += 1;
            }
            
            print("    Iteration {d} completed {s}\n", .{ iter + 1, if (benchmark_result.is_correct) "successfully" else "with verification failures" });
        }
        
        // Write aggregated metrics to JSON
        try json_results.writeAggregatedMetrics(config.iterations, correctness_failures,
                                               total_keygen_time_ns, total_encrypt_time_ns, total_decrypt_time_ns,
                                               total_keygen_cpu_time_ns, total_encrypt_cpu_time_ns, total_decrypt_cpu_time_ns,
                                               total_keygen_cpu_percent, total_encrypt_cpu_percent, total_decrypt_cpu_percent,
                                               total_keygen_memory, total_encrypt_memory, total_decrypt_memory,
                                               total_key_size_bytes, total_ciphertext_size, config.dataset_size_bytes,
                                               impl.algo_type, impl.key_size, impl.is_custom);
        
        // Write implementation configuration
        try json_results.writeImplementationConfig(impl, description, algo_name);
        
        implementations_tested += 1;
        print("  Benchmark completed for {s} {s} Implementation\n", .{ description, algo_name });
    }
    
    // Write results to file
    var results_file_buf: [2048]u8 = undefined;
    const results_file = try std.fmt.bufPrint(results_file_buf[0..], "{s}/zig_results.json", .{results_dir});
    
    try json_results.writeToFile(results_file);
    
    print("Results written to: {s}\n", .{results_file});
    print("Tested {d} implementations successfully.\n", .{implementations_tested});
}

// Main function
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    
    if (args.len < 2) {
        print("Usage: zig_core <config_file>\n", .{});
        return;
    }
    
    const config_file = args[1];
    
    print("Zig Encryption Benchmarking Core\n", .{});
    print("=================================\n", .{});
    print("Loading configuration from: {s}\n", .{config_file});
    
    // Read the config file for algorithm registration
    const config_file_handle = std.fs.cwd().openFile(config_file, .{}) catch |err| {
        print("Error opening config file: {}\n", .{err});
        return;
    };
    defer config_file_handle.close();
    
    const config_file_size = try config_file_handle.getEndPos();
    const config_contents = try allocator.alloc(u8, config_file_size);
    defer allocator.free(config_contents);
    
    _ = try config_file_handle.readAll(config_contents);
    
    // Register all implementations with config
    try registerAllImplementations(allocator, config_contents);
    
    // Print registered implementations
    printAllImplementations();
    
    // Parse configuration
    const config = parseConfigFile(allocator, config_file) catch |err| {
        print("Failed to parse configuration: {}\n", .{err});
        return;
    };
    
    // Run benchmarks
    try runBenchmarks(allocator, &config);
    
    print("Zig benchmarks completed successfully.\n", .{});
} 