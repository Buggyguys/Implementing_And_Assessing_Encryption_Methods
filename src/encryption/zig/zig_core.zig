const std = @import("std");
const print = std.debug.print;
const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;
const json = std.json;

// Import our modules
const utils = @import("include/utils.zig");
const crypto_utils = @import("include/crypto_utils.zig");

// Maximum number of implementations we can register
const MAX_IMPLEMENTATIONS = 100;
const MAX_PATH_LENGTH = 1024;

// Encryption algorithm types
pub const AlgorithmType = enum(u8) {
    undefined = 0,
    aes,
    camellia,
    chacha20,
    rsa,
    ecc,
};

// Implementation info structure
pub const ImplementationInfo = struct {
    name: [64]u8,
    algo_type: AlgorithmType,
    is_custom: bool,
    key_size: i32,
    mode: [16]u8,
    
    // Function pointers for algorithm operations
    init_fn: ?*const fn (allocator: Allocator) anyerror!*anyopaque,
    cleanup_fn: ?*const fn (context: *anyopaque, allocator: Allocator) void,
    generate_key_fn: ?*const fn (context: *anyopaque, allocator: Allocator, key_length: *i32) anyerror![]u8,
    encrypt_fn: ?*const fn (context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) anyerror![]u8,
    decrypt_fn: ?*const fn (context: *anyopaque, data: []const u8, key: []const u8, allocator: Allocator, output_length: *i32) anyerror![]u8,
    
    // Stream processing functions
    encrypt_stream_fn: ?*const fn (context: *anyopaque, data: []const u8, key: []const u8, chunk_index: i32, allocator: Allocator, output_length: *i32) anyerror![]u8,
    decrypt_stream_fn: ?*const fn (context: *anyopaque, data: []const u8, key: []const u8, chunk_index: i32, allocator: Allocator, output_length: *i32) anyerror![]u8,
    
    pub fn init() ImplementationInfo {
        return ImplementationInfo{
            .name = std.mem.zeroes([64]u8),
            .algo_type = .undefined,
            .is_custom = false,
            .key_size = 0,
            .mode = std.mem.zeroes([16]u8),
            .init_fn = null,
            .cleanup_fn = null,
            .generate_key_fn = null,
            .encrypt_fn = null,
            .decrypt_fn = null,
            .encrypt_stream_fn = null,
            .decrypt_stream_fn = null,
        };
    }
};

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
    
    // Register other implementations (placeholders for now)
    // try registerCamelliaImplementations(&global_registry);
    // try registerChachaImplementations(&global_registry);
    // try registerRsaImplementations(&global_registry);
    // try registerEccImplementations(&global_registry);
}

// Import AES implementation
const aes_impl = @import("aes/implementation.zig");

// Register AES implementations
fn registerAesImplementations(registry: *ImplementationRegistry, config_json: ?[]const u8, allocator: Allocator) !void {
    try aes_impl.registerAesImplementations(registry, config_json, allocator);
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
            config.dataset_size_kb = @intCast(@as(i64, @intFromFloat(size.float)));
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

// Function to run benchmarks
fn runBenchmarks(allocator: Allocator, config: *const TestConfig) !void {
    print("Starting Zig encryption benchmarks...\n", .{});
    
    const session_dir_slice = std.mem.sliceTo(&config.session_dir, 0);
    const dataset_path_slice = std.mem.sliceTo(&config.dataset_path, 0);
    const processing_strategy_slice = std.mem.sliceTo(&config.processing_strategy, 0);
    
    print("Session directory: {s}\n", .{session_dir_slice});
    print("Dataset path: {s}\n", .{dataset_path_slice});
    print("Dataset size: {d} KB\n", .{config.dataset_size_kb});
    print("Iterations: {d}\n", .{config.iterations});
    print("Processing strategy: {s}\n", .{processing_strategy_slice});
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
    
    // Create comprehensive results structure
    const timestamp_str = try getTimeString(allocator);
    defer allocator.free(timestamp_str);
    
    var results_file_buf: [2048]u8 = undefined;
    const results_file = try std.fmt.bufPrint(results_file_buf[0..], "{s}/zig_results.json", .{results_dir});
    
    // Start building results JSON
    var results_json = std.ArrayList(u8).init(allocator);
    defer results_json.deinit();
    
    const writer = results_json.writer();
    
    // Write JSON header
    try writer.print(
        \\{{
        \\    "timestamp": "{s}",
        \\    "session_id": "{s}",
        \\    "language": "zig",
        \\    "dataset": {{
        \\        "path": "{s}",
        \\        "size_bytes": {d}
        \\    }},
        \\    "test_configuration": {{
        \\        "iterations": {d},
        \\        "processing_strategy": "{s}",
        \\        "use_stdlib_implementations": {},
        \\        "use_custom_implementations": {}
        \\    }},
        \\    "encryption_results": {{
    , .{ 
        timestamp_str, 
        session_id,
        dataset_path_slice,
        config.dataset_size_bytes,
        config.iterations,
        processing_strategy_slice,
        config.use_stdlib,
        config.use_custom
    });
    
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
        
        print("Running benchmark for {s} {s} Implementation\n", .{ description, getAlgorithmName(impl.algo_type) });
        
        // Add implementation to JSON
        if (implementations_tested > 0) {
            try writer.writeAll(",\n");
        }
        try writer.print("        \"{s}\": {{\n", .{impl_name});
        try writer.writeAll("            \"iterations\": [\n");
        
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
            print("  Running iteration {d}/{d} for {s} {s} Implementation\n", .{ iter + 1, config.iterations, description, getAlgorithmName(impl.algo_type) });
            
            // Initialize implementation context
            const ctx = impl.init_fn.?(allocator) catch |err| {
                print("Error: Failed to initialize implementation: {}\n", .{err});
                continue;
            };
            defer impl.cleanup_fn.?(ctx, allocator);
            
            // Add iteration to JSON
            if (iter > 0) {
                try writer.writeAll(",\n");
            }
            try writer.print("                {{\n", .{});
            try writer.print("                    \"iteration\": {d},\n", .{iter + 1});
            
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
            
            // Add key generation metrics
            try writer.print("                    \"keygen_time_ns\": {d},\n", .{keygen_wall_time});
            try writer.print("                    \"keygen_cpu_time_ns\": {d},\n", .{keygen_diff.cpu_time_ns});
            try writer.print("                    \"keygen_cpu_percent\": {d:.6},\n", .{keygen_cpu_percent});
            try writer.print("                    \"keygen_peak_memory_bytes\": {d},\n", .{keygen_diff.peak_memory_bytes});
            try writer.print("                    \"keygen_allocated_memory_bytes\": {d},\n", .{keygen_diff.allocated_memory_bytes});
            try writer.print("                    \"keygen_page_faults\": {d},\n", .{keygen_diff.page_faults});
            try writer.print("                    \"keygen_ctx_switches_voluntary\": {d},\n", .{keygen_diff.voluntary_ctx_switches});
            try writer.print("                    \"keygen_ctx_switches_involuntary\": {d},\n", .{keygen_diff.involuntary_ctx_switches});
            try writer.print("                    \"key_size_bytes\": {d},\n", .{key_length});
            try writer.print("                    \"key_size_bits\": {d},\n", .{key_length * 8});
            try writer.print("                    \"thread_count\": {d},\n", .{keygen_diff.thread_count});
            try writer.print("                    \"process_priority\": {d},\n", .{keygen_diff.process_priority});
            
            // Measure encryption
            print("    Encrypting data (Memory mode)...\n", .{});
            const encrypt_start_time = utils.getTimeNs();
            const encrypt_start_usage = utils.getResourceUsage();
            
            var ciphertext_length: i32 = 0;
            const ciphertext = impl.encrypt_fn.?(ctx, test_data, key, allocator, &ciphertext_length) catch |err| {
                print("Error: Encryption failed: {}\n", .{err});
                continue;
            };
            defer allocator.free(ciphertext);
            
            const encrypt_end_time = utils.getTimeNs();
            const encrypt_end_usage = utils.getResourceUsage();
            const encrypt_diff = utils.ResourceUsage.diff(encrypt_start_usage, encrypt_end_usage);
            
            const encrypt_wall_time = encrypt_end_time - encrypt_start_time;
            const encrypt_cpu_percent = utils.calculateCpuPercent(encrypt_wall_time, encrypt_diff.cpu_time_ns);
            
            // Add encryption metrics
            try writer.print("                    \"encrypt_time_ns\": {d},\n", .{encrypt_wall_time});
            try writer.print("                    \"encrypt_cpu_time_ns\": {d},\n", .{encrypt_diff.cpu_time_ns});
            try writer.print("                    \"encrypt_cpu_percent\": {d:.6},\n", .{encrypt_cpu_percent});
            try writer.print("                    \"encrypt_peak_memory_bytes\": {d},\n", .{encrypt_diff.peak_memory_bytes});
            try writer.print("                    \"encrypt_allocated_memory_bytes\": {d},\n", .{encrypt_diff.allocated_memory_bytes});
            try writer.print("                    \"encrypt_page_faults\": {d},\n", .{encrypt_diff.page_faults});
            try writer.print("                    \"encrypt_ctx_switches_voluntary\": {d},\n", .{encrypt_diff.voluntary_ctx_switches});
            try writer.print("                    \"encrypt_ctx_switches_involuntary\": {d},\n", .{encrypt_diff.involuntary_ctx_switches});
            try writer.print("                    \"input_size_bytes\": {d},\n", .{test_data.len});
            try writer.print("                    \"ciphertext_size_bytes\": {d},\n", .{ciphertext_length});
            
            // Measure decryption
            print("    Decrypting data (Memory mode)...\n", .{});
            const decrypt_start_time = utils.getTimeNs();
            const decrypt_start_usage = utils.getResourceUsage();
            
            var plaintext_length: i32 = 0;
            const decrypted = impl.decrypt_fn.?(ctx, ciphertext, key, allocator, &plaintext_length) catch |err| {
                print("Error: Decryption failed: {}\n", .{err});
                continue;
            };
            defer allocator.free(decrypted);
            
            const decrypt_end_time = utils.getTimeNs();
            const decrypt_end_usage = utils.getResourceUsage();
            const decrypt_diff = utils.ResourceUsage.diff(decrypt_start_usage, decrypt_end_usage);
            
            const decrypt_wall_time = decrypt_end_time - decrypt_start_time;
            const decrypt_cpu_percent = utils.calculateCpuPercent(decrypt_wall_time, decrypt_diff.cpu_time_ns);
            
            // Check correctness
            const is_correct = utils.verifyDataIntegrity(test_data, decrypted[0..@intCast(plaintext_length)]);
            if (!is_correct) {
                correctness_failures += 1;
            }
            
            print("    Verification: Data integrity check {s}\n", .{if (is_correct) "passed" else "failed"});
            
            // Add decryption metrics
            try writer.print("                    \"decrypt_time_ns\": {d},\n", .{decrypt_wall_time});
            try writer.print("                    \"decrypt_cpu_time_ns\": {d},\n", .{decrypt_diff.cpu_time_ns});
            try writer.print("                    \"decrypt_cpu_percent\": {d:.6},\n", .{decrypt_cpu_percent});
            try writer.print("                    \"decrypt_peak_memory_bytes\": {d},\n", .{decrypt_diff.peak_memory_bytes});
            try writer.print("                    \"decrypt_allocated_memory_bytes\": {d},\n", .{decrypt_diff.allocated_memory_bytes});
            try writer.print("                    \"decrypt_page_faults\": {d},\n", .{decrypt_diff.page_faults});
            try writer.print("                    \"decrypt_ctx_switches_voluntary\": {d},\n", .{decrypt_diff.voluntary_ctx_switches});
            try writer.print("                    \"decrypt_ctx_switches_involuntary\": {d},\n", .{decrypt_diff.involuntary_ctx_switches});
            try writer.print("                    \"decrypted_size_bytes\": {d},\n", .{plaintext_length});
            try writer.print("                    \"correctness_passed\": {},\n", .{is_correct});
            
            // Add algorithm-specific parameters
            const algo_params = utils.getAlgorithmParams(getAlgorithmName(impl.algo_type), impl.key_size);
            try writer.print("                    \"block_size_bytes\": {d},\n", .{algo_params.block_size});
            try writer.print("                    \"iv_size_bytes\": 16,\n", .{}); // Standard for most algorithms
            try writer.print("                    \"num_rounds\": {d},\n", .{algo_params.rounds});
            try writer.print("                    \"is_custom_implementation\": {},\n", .{impl.is_custom});
            try writer.print("                    \"library_version\": \"{s}\"\n", .{if (impl.is_custom) "custom" else "zig_std"});
            
            try writer.writeAll("                }");
            
            // Update totals for aggregated metrics
            total_keygen_time_ns += keygen_wall_time;
            total_encrypt_time_ns += encrypt_wall_time;
            total_decrypt_time_ns += decrypt_wall_time;
            total_keygen_cpu_time_ns += keygen_diff.cpu_time_ns;
            total_encrypt_cpu_time_ns += encrypt_diff.cpu_time_ns;
            total_decrypt_cpu_time_ns += decrypt_diff.cpu_time_ns;
            total_keygen_cpu_percent += keygen_cpu_percent;
            total_encrypt_cpu_percent += encrypt_cpu_percent;
            total_decrypt_cpu_percent += decrypt_cpu_percent;
            total_keygen_memory += keygen_diff.peak_memory_bytes;
            total_encrypt_memory += encrypt_diff.peak_memory_bytes;
            total_decrypt_memory += decrypt_diff.peak_memory_bytes;
            total_key_size_bytes += @intCast(key_length);
            total_ciphertext_size += @intCast(ciphertext_length);
            
            print("    Iteration {d} completed {s}\n", .{ iter + 1, if (is_correct) "successfully" else "with verification failures" });
        }
        
        // Close iterations array and add aggregated metrics
        try writer.writeAll("\n            ],\n");
        try writer.writeAll("            \"aggregated_metrics\": {\n");
        
        const iterations_f = @as(f64, @floatFromInt(config.iterations));
        
        // Calculate averages
        const avg_keygen_time_ns = @as(f64, @floatFromInt(total_keygen_time_ns)) / iterations_f;
        const avg_encrypt_time_ns = @as(f64, @floatFromInt(total_encrypt_time_ns)) / iterations_f;
        const avg_decrypt_time_ns = @as(f64, @floatFromInt(total_decrypt_time_ns)) / iterations_f;
        
        try writer.print("                \"iterations_completed\": {d},\n", .{config.iterations});
        try writer.print("                \"all_correctness_checks_passed\": {},\n", .{correctness_failures == 0});
        try writer.print("                \"avg_keygen_time_ns\": {d:.6},\n", .{avg_keygen_time_ns});
        try writer.print("                \"avg_encrypt_time_ns\": {d:.6},\n", .{avg_encrypt_time_ns});
        try writer.print("                \"avg_decrypt_time_ns\": {d:.6},\n", .{avg_decrypt_time_ns});
        try writer.print("                \"avg_keygen_time_s\": {d:.9},\n", .{avg_keygen_time_ns / 1e9});
        try writer.print("                \"avg_encrypt_time_s\": {d:.9},\n", .{avg_encrypt_time_ns / 1e9});
        try writer.print("                \"avg_decrypt_time_s\": {d:.9},\n", .{avg_decrypt_time_ns / 1e9});
        
        // CPU metrics
        try writer.print("                \"avg_keygen_cpu_time_ns\": {d:.6},\n", .{@as(f64, @floatFromInt(total_keygen_cpu_time_ns)) / iterations_f});
        try writer.print("                \"avg_encrypt_cpu_time_ns\": {d:.6},\n", .{@as(f64, @floatFromInt(total_encrypt_cpu_time_ns)) / iterations_f});
        try writer.print("                \"avg_decrypt_cpu_time_ns\": {d:.6},\n", .{@as(f64, @floatFromInt(total_decrypt_cpu_time_ns)) / iterations_f});
        try writer.print("                \"avg_keygen_cpu_percent\": {d:.6},\n", .{total_keygen_cpu_percent / iterations_f});
        try writer.print("                \"avg_encrypt_cpu_percent\": {d:.6},\n", .{total_encrypt_cpu_percent / iterations_f});
        try writer.print("                \"avg_decrypt_cpu_percent\": {d:.6},\n", .{total_decrypt_cpu_percent / iterations_f});
        
        // Memory metrics
        const avg_keygen_memory = @as(f64, @floatFromInt(total_keygen_memory)) / iterations_f;
        const avg_encrypt_memory = @as(f64, @floatFromInt(total_encrypt_memory)) / iterations_f;
        const avg_decrypt_memory = @as(f64, @floatFromInt(total_decrypt_memory)) / iterations_f;
        
        try writer.print("                \"avg_keygen_peak_memory_bytes\": {d:.0},\n", .{avg_keygen_memory});
        try writer.print("                \"avg_encrypt_peak_memory_bytes\": {d:.0},\n", .{avg_encrypt_memory});
        try writer.print("                \"avg_decrypt_peak_memory_bytes\": {d:.0},\n", .{avg_decrypt_memory});
        try writer.print("                \"avg_keygen_peak_memory_mb\": {d:.6},\n", .{avg_keygen_memory / (1024.0 * 1024.0)});
        try writer.print("                \"avg_encrypt_peak_memory_mb\": {d:.6},\n", .{avg_encrypt_memory / (1024.0 * 1024.0)});
        try writer.print("                \"avg_decrypt_peak_memory_mb\": {d:.6},\n", .{avg_decrypt_memory / (1024.0 * 1024.0)});
        
        // Data metrics
        try writer.print("                \"avg_key_size_bytes\": {d:.0},\n", .{@as(f64, @floatFromInt(total_key_size_bytes)) / iterations_f});
        try writer.print("                \"avg_ciphertext_size_bytes\": {d:.0},\n", .{@as(f64, @floatFromInt(total_ciphertext_size)) / iterations_f});
        
        // Algorithm-specific parameters
        const algo_params = utils.getAlgorithmParams(getAlgorithmName(impl.algo_type), impl.key_size);
        try writer.print("                \"thread_count\": 1,\n", .{});
        try writer.print("                \"process_priority\": 0,\n", .{});
        try writer.print("                \"block_size_bytes\": {d},\n", .{algo_params.block_size});
        try writer.print("                \"iv_size_bytes\": 16,\n", .{});
        try writer.print("                \"num_rounds\": {d},\n", .{algo_params.rounds});
        try writer.print("                \"is_custom_implementation\": {},\n", .{impl.is_custom});
        try writer.print("                \"library_version\": \"{s}\",\n", .{if (impl.is_custom) "custom" else "zig_std"});
        
        // Throughput metrics
        const dataset_size_f = @as(f64, @floatFromInt(config.dataset_size_bytes));
        const encrypt_throughput_bps = (dataset_size_f * 8.0) / (avg_encrypt_time_ns / 1e9);
        const decrypt_throughput_bps = (dataset_size_f * 8.0) / (avg_decrypt_time_ns / 1e9);
        const encrypt_mbps = (dataset_size_f / (1024.0 * 1024.0)) / (avg_encrypt_time_ns / 1e9);
        const decrypt_mbps = (dataset_size_f / (1024.0 * 1024.0)) / (avg_decrypt_time_ns / 1e9);
        
        try writer.print("                \"avg_encrypt_throughput_bps\": {d:.6},\n", .{encrypt_throughput_bps});
        try writer.print("                \"avg_decrypt_throughput_bps\": {d:.6},\n", .{decrypt_throughput_bps});
        try writer.print("                \"avg_throughput_encrypt_mb_per_s\": {d:.6},\n", .{encrypt_mbps});
        try writer.print("                \"avg_throughput_decrypt_mb_per_s\": {d:.6},\n", .{decrypt_mbps});
        
        // Overhead metrics
        const avg_ciphertext_size = @as(f64, @floatFromInt(total_ciphertext_size)) / iterations_f;
        const overhead_percent = if (dataset_size_f > 0) 
            ((avg_ciphertext_size - dataset_size_f) / dataset_size_f) * 100.0 
        else 0.0;
        try writer.print("                \"avg_ciphertext_overhead_percent\": {d:.6},\n", .{overhead_percent});
        
        // Total metrics
        try writer.print("                \"total_keygen_time_ns\": {d},\n", .{total_keygen_time_ns});
        try writer.print("                \"total_encrypt_time_ns\": {d},\n", .{total_encrypt_time_ns});
        try writer.print("                \"total_decrypt_time_ns\": {d},\n", .{total_decrypt_time_ns});
        try writer.print("                \"total_num_keys\": {d},\n", .{config.iterations});
        try writer.print("                \"total_key_size_bytes\": {d},\n", .{total_key_size_bytes});
        try writer.print("                \"correctness_failures\": {d}\n", .{correctness_failures});
        
        try writer.writeAll("            },\n");
        
        // Add configuration
        try writer.writeAll("            \"configuration\": {\n");
        try writer.writeAll("                \"enabled\": true,\n");
        try writer.print("                \"key_size\": \"{d}\",\n", .{impl.key_size});
        const mode_slice = std.mem.sliceTo(&impl.mode, 0);
        try writer.print("                \"mode\": \"{s}\",\n", .{mode_slice});
        try writer.print("                \"is_custom\": {}\n", .{impl.is_custom});
        try writer.writeAll("            },\n");
        
        // Add implementation type and description
        try writer.print("            \"implementation_type\": \"{s}\",\n", .{if (impl.is_custom) "custom" else "stdlib"});
        try writer.print("            \"description\": \"{s} {s} Implementation\"\n", .{ description, getAlgorithmName(impl.algo_type) });
        
        try writer.writeAll("        }");
        
        implementations_tested += 1;
        print("  Benchmark completed for {s} {s} Implementation\n", .{ description, getAlgorithmName(impl.algo_type) });
    }
    
    // Close encryption_results and main JSON
    try writer.writeAll("\n    }\n}");
    
    // Write results to file
    const file = try std.fs.cwd().createFile(results_file, .{});
    defer file.close();
    
    try file.writeAll(results_json.items);
    
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