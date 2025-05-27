const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const utils = @import("utils.zig");

// Local definitions to avoid circular imports
pub const AlgorithmType = enum(u8) {
    undefined = 0,
    aes,
    camellia,
    chacha20,
    rsa,
    ecc,
};

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

// JSON Results Writer for Zig Encryption Benchmarks
pub const JsonResultsWriter = struct {
    allocator: Allocator,
    results_json: ArrayList(u8),
    
    pub fn init(allocator: Allocator) JsonResultsWriter {
        const results_json = ArrayList(u8).init(allocator);
        
        return JsonResultsWriter{
            .allocator = allocator,
            .results_json = results_json,
        };
    }
    
    pub fn deinit(self: *JsonResultsWriter) void {
        self.results_json.deinit();
    }
    
    // Get writer (call this when you need to write)
    fn getWriter(self: *JsonResultsWriter) ArrayList(u8).Writer {
        return self.results_json.writer();
    }
    
    // Write the JSON header with session information
    pub fn writeHeader(self: *JsonResultsWriter, timestamp_str: []const u8, session_id: []const u8, 
                      dataset_path: []const u8, dataset_size_bytes: usize, iterations: i32, 
                      processing_strategy: []const u8, use_stdlib: bool, use_custom: bool) !void {
        const writer = self.getWriter();
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
            dataset_path,
            dataset_size_bytes,
            iterations,
            processing_strategy,
            use_stdlib,
            use_custom
        });
    }
    
    // Start a new implementation section
    pub fn startImplementation(self: *JsonResultsWriter, impl_name: []const u8, is_first: bool) !void {
        const writer = self.getWriter();
        if (!is_first) {
            try writer.writeAll(",\n");
        }
        try writer.print("        \"{s}\": {{\n", .{impl_name});
        try writer.writeAll("            \"iterations\": [\n");
    }
    
    // Start a new iteration
    pub fn startIteration(self: *JsonResultsWriter, iteration: usize, is_first: bool) !void {
        const writer = self.getWriter();
        if (!is_first) {
            try writer.writeAll(",\n");
        }
        try writer.print("                {{\n", .{});
        try writer.print("                    \"iteration\": {d},\n", .{iteration + 1});
    }
    
    // Write key generation metrics
    pub fn writeKeygenMetrics(self: *JsonResultsWriter, keygen_wall_time: u64, keygen_diff: utils.ResourceUsage, 
                             keygen_cpu_percent: f64, key_length: i32) !void {
        const writer = self.getWriter();
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
    }
    
    // Write encryption metrics
    pub fn writeEncryptionMetrics(self: *JsonResultsWriter, encrypt_wall_time: u64, encrypt_diff: utils.ResourceUsage, 
                                 encrypt_cpu_percent: f64, input_size: usize, ciphertext_length: i32) !void {
        const writer = self.getWriter();
        try writer.print("                    \"encrypt_time_ns\": {d},\n", .{encrypt_wall_time});
        try writer.print("                    \"encrypt_cpu_time_ns\": {d},\n", .{encrypt_diff.cpu_time_ns});
        try writer.print("                    \"encrypt_cpu_percent\": {d:.6},\n", .{encrypt_cpu_percent});
        try writer.print("                    \"encrypt_peak_memory_bytes\": {d},\n", .{encrypt_diff.peak_memory_bytes});
        try writer.print("                    \"encrypt_allocated_memory_bytes\": {d},\n", .{encrypt_diff.allocated_memory_bytes});
        try writer.print("                    \"encrypt_page_faults\": {d},\n", .{encrypt_diff.page_faults});
        try writer.print("                    \"encrypt_ctx_switches_voluntary\": {d},\n", .{encrypt_diff.voluntary_ctx_switches});
        try writer.print("                    \"encrypt_ctx_switches_involuntary\": {d},\n", .{encrypt_diff.involuntary_ctx_switches});
        try writer.print("                    \"input_size_bytes\": {d},\n", .{input_size});
        try writer.print("                    \"ciphertext_size_bytes\": {d},\n", .{ciphertext_length});
    }
    
    // Write decryption metrics
    pub fn writeDecryptionMetrics(self: *JsonResultsWriter, decrypt_wall_time: u64, decrypt_diff: utils.ResourceUsage, 
                                 decrypt_cpu_percent: f64, plaintext_length: i32, is_correct: bool) !void {
        const writer = self.getWriter();
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
    }
    
    // Write algorithm-specific parameters
    pub fn writeAlgorithmParams(self: *JsonResultsWriter, algo_type: AlgorithmType, key_size: i32, is_custom: bool) !void {
        const writer = self.getWriter();
        const algo_params = utils.getAlgorithmParams(getAlgorithmName(algo_type), key_size);
        try writer.print("                    \"block_size_bytes\": {d},\n", .{algo_params.block_size});
        try writer.print("                    \"iv_size_bytes\": 16,\n", .{}); // Standard for most algorithms
        try writer.print("                    \"num_rounds\": {d},\n", .{algo_params.rounds});
        try writer.print("                    \"is_custom_implementation\": {},\n", .{is_custom});
        try writer.print("                    \"library_version\": \"{s}\"\n", .{if (is_custom) "custom" else "zig_std"});
    }
    
    // End an iteration
    pub fn endIteration(self: *JsonResultsWriter) !void {
        const writer = self.getWriter();
        try writer.writeAll("                }");
    }
    
    // Write aggregated metrics for an implementation
    pub fn writeAggregatedMetrics(self: *JsonResultsWriter, iterations: i32, correctness_failures: i32,
                                 total_keygen_time_ns: u64, total_encrypt_time_ns: u64, total_decrypt_time_ns: u64,
                                 total_keygen_cpu_time_ns: u64, total_encrypt_cpu_time_ns: u64, total_decrypt_cpu_time_ns: u64,
                                 total_keygen_cpu_percent: f64, total_encrypt_cpu_percent: f64, total_decrypt_cpu_percent: f64,
                                 total_keygen_memory: usize, total_encrypt_memory: usize, total_decrypt_memory: usize,
                                 total_key_size_bytes: usize, total_ciphertext_size: usize, dataset_size_bytes: usize,
                                 algo_type: AlgorithmType, key_size: i32, is_custom: bool) !void {
        
        const writer = self.getWriter();
        
        // Close iterations array and add aggregated metrics
        try writer.writeAll("\n            ],\n");
        try writer.writeAll("            \"aggregated_metrics\": {\n");
        
        const iterations_f = @as(f64, @floatFromInt(iterations));
        
        // Calculate averages
        const avg_keygen_time_ns = @as(f64, @floatFromInt(total_keygen_time_ns)) / iterations_f;
        const avg_encrypt_time_ns = @as(f64, @floatFromInt(total_encrypt_time_ns)) / iterations_f;
        const avg_decrypt_time_ns = @as(f64, @floatFromInt(total_decrypt_time_ns)) / iterations_f;
        
        try writer.print("                \"iterations_completed\": {d},\n", .{iterations});
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
        const algo_params = utils.getAlgorithmParams(getAlgorithmName(algo_type), key_size);
        try writer.print("                \"thread_count\": 1,\n", .{});
        try writer.print("                \"process_priority\": 0,\n", .{});
        try writer.print("                \"block_size_bytes\": {d},\n", .{algo_params.block_size});
        try writer.print("                \"iv_size_bytes\": 16,\n", .{});
        try writer.print("                \"num_rounds\": {d},\n", .{algo_params.rounds});
        try writer.print("                \"is_custom_implementation\": {},\n", .{is_custom});
        try writer.print("                \"library_version\": \"{s}\",\n", .{if (is_custom) "custom" else "zig_std"});
        
        // Throughput metrics
        const dataset_size_f = @as(f64, @floatFromInt(dataset_size_bytes));
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
        try writer.print("                \"total_num_keys\": {d},\n", .{iterations});
        try writer.print("                \"total_key_size_bytes\": {d},\n", .{total_key_size_bytes});
        try writer.print("                \"correctness_failures\": {d}\n", .{correctness_failures});
        
        try writer.writeAll("            },\n");
    }
    
    // Write implementation configuration
    pub fn writeImplementationConfig(self: *JsonResultsWriter, impl: *const ImplementationInfo, description: []const u8, algo_name: []const u8) !void {
        const writer = self.getWriter();
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
        try writer.print("            \"description\": \"{s} {s} Implementation\"\n", .{ description, algo_name });
        
        try writer.writeAll("        }");
    }
    
    // Finalize the JSON and write to file
    pub fn writeToFile(self: *JsonResultsWriter, results_file: []const u8) !void {
        // Close encryption_results and main JSON
        const writer = self.getWriter();
        try writer.writeAll("\n    }\n}");
        
        // Write results to file
        const file = try std.fs.cwd().createFile(results_file, .{});
        defer file.close();
        
        try file.writeAll(self.results_json.items);
    }
    
    // Get the JSON content as a slice (for debugging or other uses)
    pub fn getContent(self: *const JsonResultsWriter) []const u8 {
        return self.results_json.items;
    }
};

// Helper function to get algorithm name (duplicated from main core for independence)
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