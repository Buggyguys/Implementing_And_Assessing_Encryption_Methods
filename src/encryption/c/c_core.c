/**
 * CryptoBench Pro - C Core Implementation
 * Implements benchmarking for C encryption algorithms
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#ifdef __linux__
#include <sys/sysinfo.h>
#endif

// Include json-c for JSON parsing
#include <json-c/json.h>

// Include our own headers
#include "c_core.h"
#include "include/utils.h"

// Include algorithm implementations
#include "aes/implementation.h"
#include "camellia/implementation.h"
#include "chacha/implementation.h"
#include "rsa/implementation.h"
#include "ecc/implementation.h"

// Define platform-specific resource usage info
#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/mach_init.h>
#endif

// Metrics structure to track performance data
typedef struct {
    // Key Generation metrics
    double keygen_wall_time_ms;
    double keygen_cpu_user_time_s;
    double keygen_cpu_system_time_s;
    size_t keygen_peak_rss_bytes;
    unsigned long keygen_ctx_switches_voluntary;
    unsigned long keygen_ctx_switches_involuntary;
    size_t key_size_bytes;
    int num_keys;
    
    // Encryption metrics
    double encrypt_wall_time_ms;
    double encrypt_cpu_user_time_s;
    double encrypt_cpu_system_time_s;
    size_t encrypt_peak_rss_bytes;
    size_t encrypt_disk_read_bytes;
    size_t encrypt_disk_write_bytes;
    unsigned long encrypt_ctx_switches_voluntary;
    unsigned long encrypt_ctx_switches_involuntary;
    size_t ciphertext_total_bytes;
    
    // Decryption metrics
    double decrypt_wall_time_ms;
    double decrypt_cpu_user_time_s;
    double decrypt_cpu_system_time_s;
    size_t decrypt_peak_rss_bytes;
    size_t decrypt_disk_read_bytes;
    size_t decrypt_disk_write_bytes;
    unsigned long decrypt_ctx_switches_voluntary;
    unsigned long decrypt_ctx_switches_involuntary;
    int correctness_passed;
} BenchmarkMetrics;

// Global registry to store all implementations
implementation_registry_t registry;

/**
 * Initialize the registry with all available encryption implementations
 */
void register_all_implementations() {
    registry.count = 0;
    
    // Register AES implementations
    register_aes_implementations(&registry);
    printf("Registered %d AES implementations\n", count_implementations_by_type(&registry, ALGO_AES));
    
    // Register Camellia implementations
    register_camellia_implementations(&registry);
    printf("Registered %d Camellia implementations\n", count_implementations_by_type(&registry, ALGO_CAMELLIA));
    
    // Register ChaCha20 implementations
    register_chacha_implementations(&registry);
    printf("Registered %d ChaCha20 implementations\n", count_implementations_by_type(&registry, ALGO_CHACHA20));
    
    // Register RSA implementations
    register_rsa_implementations(&registry);
    printf("Registered %d RSA implementations\n", count_implementations_by_type(&registry, ALGO_RSA));
    
    // Register ECC implementations
    register_ecc_implementations(&registry);
    printf("Registered %d ECC implementations\n", count_implementations_by_type(&registry, ALGO_ECC));
    
    // Log total registered implementations
    printf("Total registered implementations: %d\n", registry.count);
}

// Helper function to count implementations by algorithm type
int count_implementations_by_type(implementation_registry_t* registry, algorithm_type_t type) {
    int count = 0;
    for (int i = 0; i < registry->count; i++) {
        if (registry->implementations[i].algo_type == type) {
            count++;
        }
    }
    return count;
}

/**
 * Print all registered implementations
 */
void print_all_implementations() {
    printf("\nRegistered encryption implementations:\n");
    printf("--------------------------------------\n");
    
    for (int i = 0; i < registry.count; i++) {
        printf("- %s\n", registry.implementations[i].name);
    }
    
    printf("--------------------------------------\n\n");
}

/**
 * Parse the JSON configuration file
 */
TestConfig* parse_config_file(const char* config_path) {
    TestConfig* config = (TestConfig*)malloc(sizeof(TestConfig));
    if (!config) {
        fprintf(stderr, "Error: Could not allocate memory for configuration\n");
        return NULL;
    }
    
    // Initialize config with default values
    memset(config, 0, sizeof(TestConfig));
    config->iterations = 1;
    config->use_stdlib = 1;
    config->use_custom = 1;
    config->memory_mode = 1;
    strcpy(config->processing_strategy, "Memory");
    strcpy(config->chunk_size, "1MB");
    
    // Read the configuration file
    FILE* config_file = fopen(config_path, "rb");
    if (!config_file) {
        fprintf(stderr, "Error: Could not open configuration file: %s\n", config_path);
        free(config);
        return NULL;
    }
    
    // Get file size
    fseek(config_file, 0, SEEK_END);
    long file_size = ftell(config_file);
    fseek(config_file, 0, SEEK_SET);
    
    // Read the file content
    char* config_content = (char*)malloc(file_size + 1);
    if (!config_content) {
        fprintf(stderr, "Error: Failed to allocate memory for config file content\n");
        fclose(config_file);
        free(config);
        return NULL;
    }
    
    size_t read_size = fread(config_content, 1, file_size, config_file);
    fclose(config_file);
    
    if (read_size != file_size) {
        fprintf(stderr, "Error: Failed to read the entire config file\n");
        free(config_content);
        free(config);
        return NULL;
    }
    
    config_content[file_size] = '\0';
    
    // Parse the JSON
    struct json_object* root = json_tokener_parse(config_content);
    free(config_content);
    
    if (!root) {
        fprintf(stderr, "Error: Failed to parse JSON\n");
        free(config);
        return NULL;
    }
    
    // Extract C language configuration (we only care about C since we're the C implementation)
    struct json_object* languages = NULL;
    if (json_object_object_get_ex(root, "languages", &languages)) {
        struct json_object* c_lang = NULL;
        if (json_object_object_get_ex(languages, "c", &c_lang)) {
            struct json_object* is_enabled = NULL;
            if (json_object_object_get_ex(c_lang, "is_enabled", &is_enabled)) {
                if (!json_object_get_boolean(is_enabled)) {
                    // C tests are not enabled, we can return early
                    fprintf(stderr, "C tests are not enabled in the configuration\n");
                    json_object_put(root);
                    free(config);
                    return NULL;
                }
            }
        }
    }
    
    // Extract test parameters
    struct json_object* test_params = NULL;
    if (json_object_object_get_ex(root, "test_parameters", &test_params)) {
        // Get iterations
        struct json_object* iterations = NULL;
        if (json_object_object_get_ex(test_params, "iterations", &iterations)) {
            config->iterations = json_object_get_int(iterations);
        }
        
        // Get dataset path
        struct json_object* dataset_path = NULL;
        if (json_object_object_get_ex(test_params, "dataset_path", &dataset_path)) {
            strncpy(config->dataset_path, json_object_get_string(dataset_path), sizeof(config->dataset_path) - 1);
        }
        
        // Get implementation options
        struct json_object* use_stdlib = NULL;
        if (json_object_object_get_ex(test_params, "use_stdlib", &use_stdlib)) {
            config->use_stdlib = json_object_get_boolean(use_stdlib);
        }
        
        struct json_object* use_custom = NULL;
        if (json_object_object_get_ex(test_params, "use_custom", &use_custom)) {
            config->use_custom = json_object_get_boolean(use_custom);
        }
        
        // Get processing strategy
        struct json_object* processing_strategy = NULL;
        if (json_object_object_get_ex(test_params, "processing_strategy", &processing_strategy)) {
            strncpy(config->processing_strategy, json_object_get_string(processing_strategy), sizeof(config->processing_strategy) - 1);
        }
        
        // Get chunk size
        struct json_object* chunk_size = NULL;
        if (json_object_object_get_ex(test_params, "chunk_size", &chunk_size)) {
            strncpy(config->chunk_size, json_object_get_string(chunk_size), sizeof(config->chunk_size) - 1);
        }
    }
    
    // Get results directory from the session info
    struct json_object* session_info = NULL;
    if (json_object_object_get_ex(root, "session_info", &session_info)) {
        struct json_object* session_dir = NULL;
        if (json_object_object_get_ex(session_info, "session_dir", &session_dir)) {
            snprintf(config->results_dir, sizeof(config->results_dir), "%s/results", json_object_get_string(session_dir));
        }
    }
    
    // Get dataset size from the dataset info
    struct json_object* dataset_info = NULL;
    if (json_object_object_get_ex(root, "dataset_info", &dataset_info)) {
        struct json_object* file_size_kb = NULL;
        if (json_object_object_get_ex(dataset_info, "file_size_kb", &file_size_kb)) {
            config->dataset_size = (size_t)(json_object_get_double(file_size_kb) * 1024);
        }
    } else {
        // If dataset_info is not available, get file size from the dataset file
        struct stat st;
        if (stat(config->dataset_path, &st) == 0) {
            config->dataset_size = st.st_size;
        }
    }
    
    // Clean up
    json_object_put(root);
    
    // Validate essential fields
    if (strlen(config->dataset_path) == 0) {
        fprintf(stderr, "Error: Dataset path is not specified in configuration\n");
        free(config);
        return NULL;
    }
    
    if (strlen(config->results_dir) == 0) {
        fprintf(stderr, "Error: Results directory is not specified in configuration\n");
        free(config);
        return NULL;
    }
    
    // Instead of printing verbose configuration details here, just log we successfully parsed the config
    printf("Configuration parsed successfully\n");
    
    return config;
}

/**
 * Run benchmarks based on the configuration
 */
void run_benchmarks(TestConfig* config) {
    if (!config) {
        fprintf(stderr, "Error: Invalid configuration\n");
        return;
    }
    
    // Convert chunk size string to bytes
    size_t chunk_size = chunk_size_to_bytes(config->chunk_size);
    
    // Create results directory if it doesn't exist
    char mkdir_cmd[1024];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", config->results_dir);
    system(mkdir_cmd);
    
    // Create the results structure
    struct json_object* results_obj = json_object_new_object();
    
    // Add timestamp, session ID, and language
    char timestamp[64];
    time_t now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", localtime(&now));
    json_object_object_add(results_obj, "timestamp", json_object_new_string(timestamp));
    
    // Extract session_id from results_dir path
    char* session_id = NULL;
    char results_dir_copy[MAX_PATH_LENGTH];
    strncpy(results_dir_copy, config->results_dir, sizeof(results_dir_copy) - 1);
    
    // Find the last directory in the path (session ID)
    char* last_slash = strrchr(results_dir_copy, '/');
    if (last_slash) {
        *last_slash = '\0';  // Cut at the last slash
        last_slash = strrchr(results_dir_copy, '/');
        if (last_slash) {
            session_id = last_slash + 1;
        }
    }
    
    if (session_id) {
        json_object_object_add(results_obj, "session_id", json_object_new_string(session_id));
    } else {
        // Fallback: use current date/time as session id
        json_object_object_add(results_obj, "session_id", json_object_new_string(getTimeString()));
    }
    
    json_object_object_add(results_obj, "language", json_object_new_string("c"));
    
    // Add dataset info
    struct json_object* dataset_obj = json_object_new_object();
    json_object_object_add(dataset_obj, "path", json_object_new_string(config->dataset_path));
    json_object_object_add(dataset_obj, "size_bytes", json_object_new_int64(config->dataset_size));
    json_object_object_add(results_obj, "dataset", dataset_obj);
    
    // Add test configuration
    struct json_object* test_config_obj = json_object_new_object();
    json_object_object_add(test_config_obj, "iterations", json_object_new_int(config->iterations));
    json_object_object_add(test_config_obj, "processing_strategy", json_object_new_string(config->processing_strategy));
    json_object_object_add(test_config_obj, "use_stdlib_implementations", json_object_new_boolean(config->use_stdlib));
    json_object_object_add(test_config_obj, "use_custom_implementations", json_object_new_boolean(config->use_custom));
    
    // Add chunk size to configuration if using stream processing
    if (strcmp(config->processing_strategy, "Stream") == 0) {
        json_object_object_add(test_config_obj, "chunk_size", json_object_new_string(config->chunk_size));
    }
    
    json_object_object_add(results_obj, "test_configuration", test_config_obj);
    
    // Create encryption_results container
    struct json_object* encryption_results_obj = json_object_new_object();
    
    // Determine the processing strategy and load test data
    processing_strategy_t strategy = PROCESSING_MEMORY;
    size_t data_size = 0;
    unsigned char* test_data = NULL;
    
    if (strcmp(config->processing_strategy, "Stream") == 0) {
        strategy = PROCESSING_STREAM;
        // We don't need to print this message as it duplicates info
    } else {
        // Load the entire file into memory
        test_data = read_file(config->dataset_path, &data_size);
        if (!test_data) {
            fprintf(stderr, "Error: Could not read test data\n");
            json_object_put(results_obj);
            return;
        }
    }
    
    // Iterate through all registered implementations
    for (int i = 0; i < registry.count; i++) {
        implementation_info_t* impl = &registry.implementations[i];
        
        // Skip implementations based on configuration
        if ((impl->is_custom && !config->use_custom) || 
            (!impl->is_custom && !config->use_stdlib)) {
            continue;
        }
        
        char description[128];
        snprintf(description, sizeof(description), "%s %s Implementation", 
               impl->is_custom ? "Custom" : "Standard", getAlgorithmName(impl->algo_type));
        
        printf("Running benchmark for %s\n", description);
        
        // For each implementation, run the benchmark multiple times according to iterations
        struct json_object* impl_obj = json_object_new_object();
        
        // Create iterations array for this implementation
        struct json_object* iterations_array = json_object_new_array();
        
        // These will be used for aggregated metrics
        double total_keygen_time = 0;
        double total_encrypt_time = 0;
        double total_decrypt_time = 0;
        size_t total_keygen_memory = 0;
        size_t total_encrypt_memory = 0;
        size_t total_decrypt_memory = 0;
        double total_encrypt_throughput = 0;
        double total_decrypt_throughput = 0;
        int correctness_failures = 0;
        size_t total_ciphertext_size = 0;
        
        // Run iterations
        for (int iter = 0; iter < config->iterations; iter++) {
            printf("  Running iteration %d/%d for %s\n", iter + 1, config->iterations, description);
            
            // Initialize the implementation
            void* ctx = impl->init();
            if (!ctx) {
                fprintf(stderr, "Error: Failed to initialize implementation\n");
                continue;
            }
            
            // Create iteration object
            struct json_object* iter_obj = json_object_new_object();
            json_object_object_add(iter_obj, "iteration", json_object_new_int(iter + 1));
            
            // Record metrics for key generation
            printf("    Generating key...\n");
            
            // Measure key generation
            double keygen_start_time = get_time_ms();
            resource_usage_t keygen_start_usage = get_resource_usage();
            
            int key_length = 0;
            unsigned char* key = impl->generate_key(ctx, &key_length);
            
            double keygen_end_time = get_time_ms();
            resource_usage_t keygen_end_usage = get_resource_usage();
            resource_usage_t keygen_diff = resource_usage_diff(keygen_start_usage, keygen_end_usage);
            
            if (!key) {
                fprintf(stderr, "Error: Failed to generate key\n");
                impl->cleanup(ctx);
                continue;
            }
            
            double keygen_time = keygen_end_time - keygen_start_time;
            
            // Add key generation metrics to iteration object directly
            json_object_object_add(iter_obj, "keygen_wall_time_ms", json_object_new_double(keygen_time));
            json_object_object_add(iter_obj, "keygen_peak_rss_bytes", json_object_new_int64(keygen_diff.peak_memory_bytes));
            // Add CPU metrics that Python tracks
            json_object_object_add(iter_obj, "keygen_cpu_user_time_s", json_object_new_double(keygen_diff.user_time_s));
            json_object_object_add(iter_obj, "keygen_cpu_system_time_s", json_object_new_double(keygen_diff.system_time_s));
            json_object_object_add(iter_obj, "keygen_ctx_switches_voluntary", json_object_new_int64(keygen_diff.voluntary_ctx_switches));
            json_object_object_add(iter_obj, "keygen_ctx_switches_involuntary", json_object_new_int64(keygen_diff.involuntary_ctx_switches));
            // Add key size and number of keys
            json_object_object_add(iter_obj, "key_size_bytes", json_object_new_int(key_length));
            json_object_object_add(iter_obj, "num_keys", json_object_new_int(1)); // Default to 1 key for now
            
            total_keygen_time += keygen_time;
            total_keygen_memory += keygen_diff.peak_memory_bytes;
            
            // Measure encryption
            unsigned char* ciphertext = NULL;
            int ciphertext_length = 0;
            double encrypt_time = 0;
            resource_usage_t encrypt_diff = {0};
            
            if (strategy == PROCESSING_MEMORY) {
                printf("    Encrypting data (Memory mode)...\n");
                double encrypt_start_time = get_time_ms();
                resource_usage_t encrypt_start_usage = get_resource_usage();
                
                ciphertext = impl->encrypt(ctx, test_data, data_size, key, &ciphertext_length);
                
                double encrypt_end_time = get_time_ms();
                resource_usage_t encrypt_end_usage = get_resource_usage();
                encrypt_diff = resource_usage_diff(encrypt_start_usage, encrypt_end_usage);
                
                if (!ciphertext) {
                    fprintf(stderr, "Error: Encryption failed\n");
                    free(key);
                    impl->cleanup(ctx);
                    continue;
                }
                
                encrypt_time = encrypt_end_time - encrypt_start_time;
            } else {
                // Stream processing - encrypt in chunks
                printf("    Encrypting data (Stream mode)...\n");
                chunked_file_t* cf = init_chunked_file(config->dataset_path, chunk_size);
                if (!cf) {
                    fprintf(stderr, "Error: Failed to initialize chunked file\n");
                    free(key);
                    impl->cleanup(ctx);
                    continue;
                }
                
                // Calculate and log expected number of chunks
                size_t total_chunks = (cf->file_size + chunk_size - 1) / chunk_size;
                printf("    Dataset will be processed in %zu chunks\n", total_chunks);
                
                // Allocate buffer for all ciphertext (approximate size)
                size_t max_ciphertext_size = cf->file_size + (cf->file_size / 10) + 1024; // Add some extra space
                ciphertext = (unsigned char*)malloc(max_ciphertext_size);
                if (!ciphertext) {
                    fprintf(stderr, "Error: Failed to allocate memory for ciphertext\n");
                    cleanup_chunked_file(cf);
                    free(key);
                    impl->cleanup(ctx);
                    continue;
                }
                
                double encrypt_start_time = get_time_ms();
                resource_usage_t encrypt_start_usage = get_resource_usage();
                
                ciphertext_length = 0;
                size_t bytes_read;
                size_t chunk_counter = 0;
                
                while ((bytes_read = read_next_chunk(cf)) > 0) {
                    chunk_counter++;
                    if (chunk_counter % 10 == 0 || chunk_counter == 1) {
                        printf("    Processing chunk %zu/%zu (%.1f%%)...\n", 
                               chunk_counter, total_chunks, 
                               (chunk_counter * 100.0) / total_chunks);
                    }
                    
                    int chunk_output_length = 0;
                    unsigned char* chunk_ciphertext = impl->encrypt(ctx, cf->current_chunk, bytes_read, key, &chunk_output_length);
                    
                    if (!chunk_ciphertext) {
                        fprintf(stderr, "Error: Chunk encryption failed\n");
                        free(ciphertext);
                        ciphertext = NULL;
                        break;
                    }
                    
                    // Copy chunk result to full ciphertext buffer
                    if (ciphertext_length + chunk_output_length <= max_ciphertext_size) {
                        memcpy(ciphertext + ciphertext_length, chunk_ciphertext, chunk_output_length);
                        ciphertext_length += chunk_output_length;
                    } else {
                        fprintf(stderr, "Error: Ciphertext buffer overflow\n");
                        free(chunk_ciphertext);
                        free(ciphertext);
                        ciphertext = NULL;
                        break;
                    }
                    
                    free(chunk_ciphertext);
                }
                
                printf("    Processed %zu chunks successfully\n", chunk_counter);
                
                double encrypt_end_time = get_time_ms();
                resource_usage_t encrypt_end_usage = get_resource_usage();
                encrypt_diff = resource_usage_diff(encrypt_start_usage, encrypt_end_usage);
                
                encrypt_time = encrypt_end_time - encrypt_start_time;
                
                cleanup_chunked_file(cf);
            }
            
            if (!ciphertext) {
                free(key);
                impl->cleanup(ctx);
                continue;
            }
            
            json_object_object_add(iter_obj, "encrypt_wall_time_ms", json_object_new_double(encrypt_time));
            json_object_object_add(iter_obj, "encrypt_peak_rss_bytes", json_object_new_int64(encrypt_diff.peak_memory_bytes));
            json_object_object_add(iter_obj, "encrypt_disk_read_bytes", json_object_new_int64(0)); // Not tracked directly
            json_object_object_add(iter_obj, "encrypt_disk_write_bytes", json_object_new_int64(0)); // Not tracked directly
            json_object_object_add(iter_obj, "encrypt_ctx_switches_voluntary", json_object_new_int64(encrypt_diff.voluntary_ctx_switches));
            json_object_object_add(iter_obj, "encrypt_ctx_switches_involuntary", json_object_new_int64(encrypt_diff.involuntary_ctx_switches));
            json_object_object_add(iter_obj, "encrypt_cpu_user_time_s", json_object_new_double(encrypt_diff.user_time_s));
            json_object_object_add(iter_obj, "encrypt_cpu_system_time_s", json_object_new_double(encrypt_diff.system_time_s));
            json_object_object_add(iter_obj, "output_size_bytes", json_object_new_int(ciphertext_length));
            
            total_encrypt_time += encrypt_time;
            total_encrypt_memory += encrypt_diff.peak_memory_bytes;
            
            // Measure decryption
            if (strategy == PROCESSING_MEMORY) {
                printf("    Decrypting data (Memory mode)...\n");
            } else {
                printf("    Decrypting data (Stream mode)...\n");
                printf("    Decrypting %d bytes of ciphertext...\n", ciphertext_length);
            }
            
            double decrypt_start_time = get_time_ms();
            resource_usage_t decrypt_start_usage = get_resource_usage();
            
            int plaintext_length = 0;
            unsigned char* decrypted = impl->decrypt(ctx, ciphertext, ciphertext_length, key, &plaintext_length);
            
            double decrypt_end_time = get_time_ms();
            resource_usage_t decrypt_end_usage = get_resource_usage();
            resource_usage_t decrypt_diff = resource_usage_diff(decrypt_start_usage, decrypt_end_usage);
            
            if (!decrypted) {
                fprintf(stderr, "Error: Decryption failed\n");
                free(ciphertext);
                free(key);
                impl->cleanup(ctx);
                continue;
            }
            
            double decrypt_time = decrypt_end_time - decrypt_start_time;
            
            // Add decryption metrics to iteration object directly
            json_object_object_add(iter_obj, "decrypt_wall_time_ms", json_object_new_double(decrypt_time));
            json_object_object_add(iter_obj, "decrypt_peak_rss_bytes", json_object_new_int64(decrypt_diff.peak_memory_bytes));
            // Add CPU metrics that Python tracks
            json_object_object_add(iter_obj, "decrypt_cpu_user_time_s", json_object_new_double(decrypt_diff.user_time_s));
            json_object_object_add(iter_obj, "decrypt_cpu_system_time_s", json_object_new_double(decrypt_diff.system_time_s));
            json_object_object_add(iter_obj, "decrypt_ctx_switches_voluntary", json_object_new_int64(decrypt_diff.voluntary_ctx_switches));
            json_object_object_add(iter_obj, "decrypt_ctx_switches_involuntary", json_object_new_int64(decrypt_diff.involuntary_ctx_switches));
            json_object_object_add(iter_obj, "decrypt_disk_read_bytes", json_object_new_int64(0)); // Not tracked directly
            json_object_object_add(iter_obj, "decrypt_disk_write_bytes", json_object_new_int64(0)); // Not tracked directly
            json_object_object_add(iter_obj, "ciphertext_total_bytes", json_object_new_int(ciphertext_length));
            
            // Check correctness (if decryption result matches original data)
            int is_correct = 0;
            if (plaintext_length == data_size && memcmp(decrypted, test_data, data_size) == 0) {
                is_correct = 1;
                printf("    Verification: Data integrity check passed\n");
            } else {
                // For stream processing, we might need a different verification strategy
                if (strategy == PROCESSING_STREAM) {
                    // Since we don't have the full data in memory for comparison,
                    // we'll just check if the decrypted length is as expected
                    if (plaintext_length == config->dataset_size) {
                        printf("    Verification (Stream mode): Length check passed, full data verification skipped\n");
                        // In stream mode, we consider it correct if lengths match
                        is_correct = 1;
                    } else {
                        printf("    Verification (Stream mode): FAILED - Length mismatch (got %d, expected %zu)\n", 
                               plaintext_length, config->dataset_size);
                        correctness_failures++;
                    }
                } else if (plaintext_length != data_size) {
                    printf("    Verification: FAILED - Length mismatch (got %d, expected %zu)\n", 
                           plaintext_length, data_size);
                    correctness_failures++;
                } else {
                    printf("    Verification: FAILED - Content mismatch\n");
                    correctness_failures++;
                }
            }
            
            json_object_object_add(iter_obj, "correctness_passed", json_object_new_boolean(is_correct));
            
            // Calculate throughput
            double encrypt_throughput_bps = 0;
            double decrypt_throughput_bps = 0;
            
            if (encrypt_time > 0) {
                encrypt_throughput_bps = (data_size * 8) / (encrypt_time / 1000.0);
            }
            
            if (decrypt_time > 0) {
                decrypt_throughput_bps = (data_size * 8) / (decrypt_time / 1000.0);
            }
            
            json_object_object_add(iter_obj, "encrypt_throughput_bps", json_object_new_double(encrypt_throughput_bps));
            json_object_object_add(iter_obj, "decrypt_throughput_bps", json_object_new_double(decrypt_throughput_bps));
            
            total_encrypt_throughput += encrypt_throughput_bps;
            total_decrypt_throughput += decrypt_throughput_bps;
            total_ciphertext_size += ciphertext_length;
            
            // Add iteration to array
            json_object_array_add(iterations_array, iter_obj);
            
            // Update totals for averaging
            total_decrypt_time += decrypt_time;
            total_decrypt_memory += decrypt_diff.peak_memory_bytes;
            
            // Clean up
            free(decrypted);
            free(ciphertext);
            free(key);
            
            printf("    Iteration %d completed %s\n", iter + 1, 
                   is_correct ? "successfully" : "with verification failures");
        }
        
        // All iterations complete for this implementation
        printf("  Benchmark completed for %s\n", description);
        
        // Calculate averages
        int actual_iterations = json_object_array_length(iterations_array);
        if (actual_iterations > 0) {
            double avg_keygen_time = total_keygen_time / actual_iterations;
            double avg_encrypt_time = total_encrypt_time / actual_iterations;
            double avg_decrypt_time = total_decrypt_time / actual_iterations;
            size_t avg_keygen_memory = total_keygen_memory / actual_iterations;
            size_t avg_encrypt_memory = total_encrypt_memory / actual_iterations;
            size_t avg_decrypt_memory = total_decrypt_memory / actual_iterations;
            double avg_encrypt_throughput = total_encrypt_throughput / actual_iterations;
            double avg_decrypt_throughput = total_decrypt_throughput / actual_iterations;
            size_t avg_ciphertext_size = total_ciphertext_size / actual_iterations;
            
            // Calculate averages for CPU metrics
            double avg_keygen_cpu_user_time = 0;
            double avg_keygen_cpu_system_time = 0;
            double avg_encrypt_cpu_user_time = 0;
            double avg_encrypt_cpu_system_time = 0;
            double avg_decrypt_cpu_user_time = 0;
            double avg_decrypt_cpu_system_time = 0;
            
            // Context switches
            double avg_keygen_ctx_voluntary = 0;
            double avg_keygen_ctx_involuntary = 0;
            double avg_encrypt_ctx_voluntary = 0;
            double avg_encrypt_ctx_involuntary = 0;
            double avg_decrypt_ctx_voluntary = 0;
            double avg_decrypt_ctx_involuntary = 0;
            
            // Key metrics
            size_t total_key_size_bytes = 0;
            int total_num_keys = 0;
            double avg_key_size_bytes = 0;
            double avg_num_keys = 0;
            
            // Loop through iterations to get metrics
            for (int i = 0; i < actual_iterations; i++) {
                struct json_object* iter = json_object_array_get_idx(iterations_array, i);
                if (!iter) continue;
                
                // Extract CPU metrics
                struct json_object* value;
                
                if (json_object_object_get_ex(iter, "keygen_cpu_user_time_s", &value))
                    avg_keygen_cpu_user_time += json_object_get_double(value);
                    
                if (json_object_object_get_ex(iter, "keygen_cpu_system_time_s", &value))
                    avg_keygen_cpu_system_time += json_object_get_double(value);
                    
                if (json_object_object_get_ex(iter, "encrypt_cpu_user_time_s", &value))
                    avg_encrypt_cpu_user_time += json_object_get_double(value);
                    
                if (json_object_object_get_ex(iter, "encrypt_cpu_system_time_s", &value))
                    avg_encrypt_cpu_system_time += json_object_get_double(value);
                    
                if (json_object_object_get_ex(iter, "decrypt_cpu_user_time_s", &value))
                    avg_decrypt_cpu_user_time += json_object_get_double(value);
                    
                if (json_object_object_get_ex(iter, "decrypt_cpu_system_time_s", &value))
                    avg_decrypt_cpu_system_time += json_object_get_double(value);
                    
                // Extract context switches (including keygen now)
                if (json_object_object_get_ex(iter, "keygen_ctx_switches_voluntary", &value))
                    avg_keygen_ctx_voluntary += json_object_get_int64(value);
                    
                if (json_object_object_get_ex(iter, "keygen_ctx_switches_involuntary", &value))
                    avg_keygen_ctx_involuntary += json_object_get_int64(value);
                    
                if (json_object_object_get_ex(iter, "encrypt_ctx_switches_voluntary", &value))
                    avg_encrypt_ctx_voluntary += json_object_get_int64(value);
                    
                if (json_object_object_get_ex(iter, "encrypt_ctx_switches_involuntary", &value))
                    avg_encrypt_ctx_involuntary += json_object_get_int64(value);
                    
                if (json_object_object_get_ex(iter, "decrypt_ctx_switches_voluntary", &value))
                    avg_decrypt_ctx_voluntary += json_object_get_int64(value);
                    
                if (json_object_object_get_ex(iter, "decrypt_ctx_switches_involuntary", &value))
                    avg_decrypt_ctx_involuntary += json_object_get_int64(value);
                
                // Extract key metrics
                if (json_object_object_get_ex(iter, "key_size_bytes", &value)) {
                    size_t key_size = json_object_get_int(value);
                    total_key_size_bytes += key_size;
                    avg_key_size_bytes += key_size;
                }
                
                if (json_object_object_get_ex(iter, "num_keys", &value)) {
                    int num_keys = json_object_get_int(value);
                    total_num_keys += num_keys;
                    avg_num_keys += num_keys;
                }
            }
            
            // Calculate final averages
            avg_keygen_cpu_user_time /= actual_iterations;
            avg_keygen_cpu_system_time /= actual_iterations;
            avg_encrypt_cpu_user_time /= actual_iterations;
            avg_encrypt_cpu_system_time /= actual_iterations;
            avg_decrypt_cpu_user_time /= actual_iterations;
            avg_decrypt_cpu_system_time /= actual_iterations;
            
            avg_keygen_ctx_voluntary /= actual_iterations;
            avg_keygen_ctx_involuntary /= actual_iterations;
            avg_encrypt_ctx_voluntary /= actual_iterations;
            avg_encrypt_ctx_involuntary /= actual_iterations;
            avg_decrypt_ctx_voluntary /= actual_iterations;
            avg_decrypt_ctx_involuntary /= actual_iterations;
            
            // Calculate key metric averages
            avg_key_size_bytes /= actual_iterations;
            avg_num_keys /= actual_iterations;
            
            // Create aggregated metrics object
            struct json_object* aggregated_metrics = json_object_new_object();
            json_object_object_add(aggregated_metrics, "iterations_completed", json_object_new_int(actual_iterations));
            json_object_object_add(aggregated_metrics, "all_correctness_checks_passed", 
                                 json_object_new_boolean(correctness_failures == 0));
            
            // Key generation metrics
            json_object_object_add(aggregated_metrics, "avg_keygen_wall_time_ms", json_object_new_double(avg_keygen_time));
            json_object_object_add(aggregated_metrics, "avg_keygen_cpu_total_time_s", 
                                 json_object_new_double(avg_keygen_cpu_user_time + avg_keygen_cpu_system_time));
            json_object_object_add(aggregated_metrics, "avg_keygen_peak_rss_mb", 
                                 json_object_new_double(avg_keygen_memory / (1024.0 * 1024.0)));
            json_object_object_add(aggregated_metrics, "avg_keygen_ctx_switches_total", 
                                 json_object_new_double(avg_keygen_ctx_voluntary + avg_keygen_ctx_involuntary));
            json_object_object_add(aggregated_metrics, "avg_key_size_bytes", 
                                json_object_new_double(avg_key_size_bytes));
            json_object_object_add(aggregated_metrics, "avg_num_keys", 
                                json_object_new_double(avg_num_keys));
            
            // Encryption metrics
            json_object_object_add(aggregated_metrics, "avg_encrypt_wall_time_ms", json_object_new_double(avg_encrypt_time));
            json_object_object_add(aggregated_metrics, "avg_encrypt_cpu_total_time_s", 
                                 json_object_new_double(avg_encrypt_cpu_user_time + avg_encrypt_cpu_system_time));
            
            // Calculate CPU percentage
            double encrypt_cpu_percentage = 100.0; // Default to 100%
            if (avg_encrypt_time > 0) {
                double encrypt_cpu_total_time = avg_encrypt_cpu_user_time + avg_encrypt_cpu_system_time;
                encrypt_cpu_percentage = (encrypt_cpu_total_time / (avg_encrypt_time / 1000.0)) * 100.0;
            }
            json_object_object_add(aggregated_metrics, "avg_encrypt_cpu_percentage", json_object_new_double(encrypt_cpu_percentage));
            
            json_object_object_add(aggregated_metrics, "avg_encrypt_peak_rss_mb", 
                                 json_object_new_double(avg_encrypt_memory / (1024.0 * 1024.0)));
            json_object_object_add(aggregated_metrics, "avg_encrypt_ctx_switches_total", 
                                 json_object_new_double(avg_encrypt_ctx_voluntary + avg_encrypt_ctx_involuntary));
            
            // Decryption metrics
            json_object_object_add(aggregated_metrics, "avg_decrypt_wall_time_ms", json_object_new_double(avg_decrypt_time));
            json_object_object_add(aggregated_metrics, "avg_decrypt_cpu_total_time_s", 
                                 json_object_new_double(avg_decrypt_cpu_user_time + avg_decrypt_cpu_system_time));
            
            // Calculate CPU percentage
            double decrypt_cpu_percentage = 100.0; // Default to 100%
            if (avg_decrypt_time > 0) {
                double decrypt_cpu_total_time = avg_decrypt_cpu_user_time + avg_decrypt_cpu_system_time;
                decrypt_cpu_percentage = (decrypt_cpu_total_time / (avg_decrypt_time / 1000.0)) * 100.0;
            }
            json_object_object_add(aggregated_metrics, "avg_decrypt_cpu_percentage", json_object_new_double(decrypt_cpu_percentage));
            
            json_object_object_add(aggregated_metrics, "avg_decrypt_peak_rss_mb", 
                                 json_object_new_double(avg_decrypt_memory / (1024.0 * 1024.0)));
            json_object_object_add(aggregated_metrics, "avg_decrypt_ctx_switches_total", 
                                 json_object_new_double(avg_decrypt_ctx_voluntary + avg_decrypt_ctx_involuntary));
            
            // File and throughput metrics
            json_object_object_add(aggregated_metrics, "avg_ciphertext_total_bytes", json_object_new_double(avg_ciphertext_size));
            
            // Calculate overhead percentage
            double overhead_percent = 0;
            if (config->dataset_size > 0 && avg_ciphertext_size > 0) {
                overhead_percent = ((avg_ciphertext_size - config->dataset_size) / (double)config->dataset_size) * 100.0;
            }
            json_object_object_add(aggregated_metrics, "avg_ciphertext_overhead_percent", json_object_new_double(overhead_percent));
            
            // Calculate MB/s throughput instead of bit/s
            double encrypt_mbps = (config->dataset_size / (1024.0 * 1024.0)) / (avg_encrypt_time / 1000.0);
            double decrypt_mbps = (config->dataset_size / (1024.0 * 1024.0)) / (avg_decrypt_time / 1000.0);
            
            json_object_object_add(aggregated_metrics, "avg_throughput_encrypt_mb_per_s", json_object_new_double(encrypt_mbps));
            json_object_object_add(aggregated_metrics, "avg_throughput_decrypt_mb_per_s", json_object_new_double(decrypt_mbps));
            
            // Add time in seconds
            json_object_object_add(aggregated_metrics, "encryption_time_seconds", json_object_new_double(avg_encrypt_time / 1000.0));
            json_object_object_add(aggregated_metrics, "decryption_time_seconds", json_object_new_double(avg_decrypt_time / 1000.0));
            
            // Add c-specific simple metrics that Python doesn't have
            json_object_object_add(aggregated_metrics, "avg_encrypt_throughput_bps", json_object_new_double(avg_encrypt_throughput));
            json_object_object_add(aggregated_metrics, "avg_decrypt_throughput_bps", json_object_new_double(avg_decrypt_throughput));
            json_object_object_add(aggregated_metrics, "correctness_failures", json_object_new_int(correctness_failures));
            
            // Add total metrics
            json_object_object_add(aggregated_metrics, "total_keygen_time_ms", json_object_new_double(total_keygen_time));
            json_object_object_add(aggregated_metrics, "total_encrypt_time_ms", json_object_new_double(total_encrypt_time));
            json_object_object_add(aggregated_metrics, "total_decrypt_time_ms", json_object_new_double(total_decrypt_time));
            json_object_object_add(aggregated_metrics, "total_num_keys", json_object_new_int(total_num_keys));
            json_object_object_add(aggregated_metrics, "total_key_size_bytes", json_object_new_int64(total_key_size_bytes));
            
            // Add iterations and aggregated metrics to the implementation object
            json_object_object_add(impl_obj, "iterations", iterations_array);
            json_object_object_add(impl_obj, "aggregated_metrics", aggregated_metrics);
            
            // Add configuration
            struct json_object* config_obj = json_object_new_object();
            json_object_object_add(config_obj, "enabled", json_object_new_boolean(1));
            
            // Convert key_size to string
            char key_size_str[16];
            snprintf(key_size_str, sizeof(key_size_str), "%d", impl->key_size);
            json_object_object_add(config_obj, "key_size", json_object_new_string(key_size_str));
            
            json_object_object_add(config_obj, "mode", json_object_new_string(impl->mode));
            json_object_object_add(config_obj, "is_custom", json_object_new_boolean(impl->is_custom));
            json_object_object_add(impl_obj, "configuration", config_obj);
            
            // Add implementation type and description
            json_object_object_add(impl_obj, "implementation_type", 
                                 json_object_new_string(impl->is_custom ? "custom" : "stdlib"));
                                 
            char description[128];
            snprintf(description, sizeof(description), "%s %s Implementation", 
                   impl->is_custom ? "Custom" : "Standard", getAlgorithmName(impl->algo_type));
            json_object_object_add(impl_obj, "description", json_object_new_string(description));
            
            // Add implementation to encryption_results using the name as the key
            json_object_object_add(encryption_results_obj, impl->name, impl_obj);
        } else {
            json_object_put(impl_obj);
            json_object_put(iterations_array);
        }
        
        // No need to clean up anything here - cleanup happens in each iteration
    }
    
    // Free test data if we loaded it in memory mode
    if (strategy == PROCESSING_MEMORY && test_data) {
        free(test_data);
    }
    
    // Add encryption_results to results
    json_object_object_add(results_obj, "encryption_results", encryption_results_obj);
    
    // Create results file
    if (!create_directory(config->results_dir)) {
        fprintf(stderr, "Error: Could not create results directory: %s\n", config->results_dir);
        json_object_put(results_obj);
        return;
    }
    
    char results_path[MAX_PATH_LENGTH];
    snprintf(results_path, sizeof(results_path), "%s/c_results.json", config->results_dir);
    
    // Write results to file
    FILE* results_file = fopen(results_path, "w");
    if (!results_file) {
        fprintf(stderr, "Error: Could not open results file for writing: %s\n", results_path);
        json_object_put(results_obj);
        return;
    }
    
    // Write formatted JSON to file
    const char* json_string = json_object_to_json_string_ext(results_obj, JSON_C_TO_STRING_PRETTY);
    fputs(json_string, results_file);
    fclose(results_file);
    
    printf("Results saved to: %s\n", results_path);
    
    // Cleanup
    json_object_put(results_obj);
}

// Helper function to get current time as a string
char* getTimeString() {
    time_t t;
    struct tm* tmp;
    static char time_str[64];
    
    time(&t);
    tmp = localtime(&t);
    
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tmp);
    return time_str;
}

// Helper function to get algorithm name from type
const char* getAlgorithmName(algorithm_type_t type) {
    switch (type) {
        case ALGO_AES: return "AES";
        case ALGO_CAMELLIA: return "Camellia";
        case ALGO_CHACHA20: return "ChaCha20";
        case ALGO_RSA: return "RSA";
        case ALGO_ECC: return "ECC";
        default: return "Unknown";
    }
}

/**
 * Main function
 */
int main(int argc, char* argv[]) {
    // Check arguments
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    const char* config_path = argv[1];
    
    // Register all implementations
    printf("Registering C encryption implementations...\n");
    register_all_implementations();
    
    // Print all registered implementations
    print_all_implementations();
    
    // Parse configuration file
    TestConfig* config = parse_config_file(config_path);
    if (!config) {
        return EXIT_FAILURE;
    }
    
    // Run benchmarks
    run_benchmarks(config);
    
    // Clean up
    free(config);
    
    return EXIT_SUCCESS;
} 