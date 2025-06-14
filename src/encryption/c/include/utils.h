#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "crypto_utils.h"

// Maximum input size for chunked processing
#define MAX_CHUNK_SIZE (16 * 1024 * 1024)  // 16MB default chunk size

/**
 * Resource usage metrics structure
 */
typedef struct {
    // Time measurements
    uint64_t wall_time_ns;         // Wall clock time in nanoseconds
    uint64_t cpu_time_ns;          // Total CPU time in nanoseconds
    double user_time_s;            // User CPU time in seconds (for compatibility)
    double system_time_s;          // System CPU time in seconds (for compatibility)
    double cpu_percent;            // CPU utilization percentage
    
    // Memory usage
    size_t peak_memory_bytes;      // Peak resident set size (RSS)
    size_t allocated_memory_bytes; // Estimated allocated memory
    
    // System metrics
    unsigned long voluntary_ctx_switches;   // Voluntary context switches
    unsigned long involuntary_ctx_switches; // Involuntary context switches
    unsigned long page_faults;              // Number of page faults
    unsigned long cache_misses;             // Cache misses (if available)
    
    // Process info
    int thread_count;              // Number of threads
    int process_priority;          // Process priority/nice value
} resource_usage_t;

/**
 * Get high-resolution time in nanoseconds
 */
static inline uint64_t get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/**
 * Get CPU time in nanoseconds
 */
static inline uint64_t get_cpu_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/**
 * Get current thread count
 */
static inline int get_thread_count() {
#ifdef __linux__
    char buf[256];
    int count = 0;
    FILE* fp = fopen("/proc/self/stat", "r");
    if (fp) {
        if (fgets(buf, sizeof(buf), fp)) {
            // The 20th field is the number of threads
            char* token = strtok(buf, " ");
            for (int i = 1; i < 20 && token != NULL; i++) {
                token = strtok(NULL, " ");
            }
            if (token) {
                count = atoi(token);
            }
        }
        fclose(fp);
    }
    return count > 0 ? count : 1;
#else
    // For non-Linux platforms, just return 1 for now
    // In production, you'd use platform-specific APIs
    return 1;
#endif
}

/**
 * Get process priority (nice value)
 */
static inline int get_process_priority() {
    return getpriority(PRIO_PROCESS, 0);
}

/**
 * Get current resource usage
 */
static inline resource_usage_t get_resource_usage() {
    resource_usage_t usage = {0};
    struct rusage ru;
    
    // Get wall time in nanoseconds
    usage.wall_time_ns = get_time_ns();
    
    // Get CPU time in nanoseconds
    usage.cpu_time_ns = get_cpu_time_ns();
    
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        // CPU time (compatibility fields)
        usage.user_time_s = ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1000000.0;
        usage.system_time_s = ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1000000.0;
        
        // Memory
        #ifdef __APPLE__
        // macOS reports in bytes
        usage.peak_memory_bytes = (size_t)ru.ru_maxrss;
        #else
        // Linux reports in kilobytes
        usage.peak_memory_bytes = (size_t)ru.ru_maxrss * 1024;
        #endif
        
        // Estimate allocated memory (not perfect but best we can do)
        usage.allocated_memory_bytes = usage.peak_memory_bytes;
        
        // Context switches
        usage.voluntary_ctx_switches = ru.ru_nvcsw;
        usage.involuntary_ctx_switches = ru.ru_nivcsw;
        
        // Page faults
        usage.page_faults = ru.ru_majflt + ru.ru_minflt;
        
        // Cache misses - not available through rusage
        usage.cache_misses = 0;
        
        // CPU percentage will be calculated in diff
        usage.cpu_percent = 0.0;
        
        // Thread count
        usage.thread_count = get_thread_count();
        
        // Process priority
        usage.process_priority = get_process_priority();
    }
    
    return usage;
}

/**
 * Calculate difference between two resource usage snapshots
 */
static inline resource_usage_t resource_usage_diff(resource_usage_t start, resource_usage_t end) {
    resource_usage_t diff;
    
    // Time differences
    diff.wall_time_ns = end.wall_time_ns - start.wall_time_ns;
    diff.cpu_time_ns = end.cpu_time_ns - start.cpu_time_ns;
    diff.user_time_s = end.user_time_s - start.user_time_s;
    diff.system_time_s = end.system_time_s - start.system_time_s;
    
    // Calculate CPU percentage
    if (diff.wall_time_ns > 0) {
        diff.cpu_percent = ((double)diff.cpu_time_ns / (double)diff.wall_time_ns) * 100.0;
        // Cap at 100% for single-threaded or 100% * thread_count for multi-threaded
        double max_cpu = 100.0 * end.thread_count;
        if (diff.cpu_percent > max_cpu) {
            diff.cpu_percent = max_cpu;
        }
    } else {
        diff.cpu_percent = 0.0;
    }
    
    // Memory - take the peak difference
    diff.peak_memory_bytes = end.peak_memory_bytes > start.peak_memory_bytes ? 
                           end.peak_memory_bytes : start.peak_memory_bytes;
    diff.allocated_memory_bytes = end.allocated_memory_bytes > start.allocated_memory_bytes ?
                                end.allocated_memory_bytes - start.allocated_memory_bytes : 0;
    
    // System metrics
    diff.voluntary_ctx_switches = end.voluntary_ctx_switches - start.voluntary_ctx_switches;
    diff.involuntary_ctx_switches = end.involuntary_ctx_switches - start.involuntary_ctx_switches;
    diff.page_faults = end.page_faults - start.page_faults;
    diff.cache_misses = end.cache_misses - start.cache_misses;
    
    // Process info - use end values
    diff.thread_count = end.thread_count;
    diff.process_priority = end.process_priority;
    
    return diff;
}

/**
 * Enumeration for the processing strategy
 */
typedef enum {
    PROCESSING_MEMORY = 0,  // Process the entire data in memory
    PROCESSING_STREAM       // Process the data in chunks (stream)
} processing_strategy_t;

/**
 * Structure to handle processing chunks
 */
typedef struct {
    FILE* file;
    char filename[1024];
    size_t file_size;
    size_t chunk_size;
    unsigned char* current_chunk;
    size_t position;
    int eof;
} chunked_file_t;

/**
 * Get current timestamp in milliseconds
 */
static inline double get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
}

/**
 * Get current CPU time in milliseconds
 */
static inline double get_cpu_time_ms() {
    clock_t time = clock();
    return (double)time * 1000.0 / CLOCKS_PER_SEC;
}

/**
 * Get current memory usage in bytes - simplified version without using mach headers
 */
static inline size_t get_memory_usage() {
    // Use getrusage which is more portable across systems
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        // Return resident set size (RSS) in bytes
        #ifdef __APPLE__
        // macOS reports in bytes
        return (size_t)usage.ru_maxrss;
        #else
        // Linux reports in kilobytes
        return (size_t)usage.ru_maxrss * 1024;
        #endif
    }
    return 0;
}

/**
 * Convert a chunk size string to bytes
 */
static inline size_t chunk_size_to_bytes(const char* chunk_size_str) {
    size_t value = 0;
    char unit[3] = {0};
    
    // Parse the string (e.g., "1MB", "64KB", etc.)
    if (sscanf(chunk_size_str, "%zu%2s", &value, unit) != 2) {
        return 1024 * 1024; // Default to 1MB if parsing fails
    }
    
    // Convert based on unit
    if (strcmp(unit, "KB") == 0) {
        return value * 1024;
    } else if (strcmp(unit, "MB") == 0) {
        return value * 1024 * 1024;
    } else if (strcmp(unit, "GB") == 0) {
        return value * 1024 * 1024 * 1024;
    } else {
        return 1024 * 1024; // Default to 1MB for unknown units
    }
}

/**
 * Create a directory and its parent directories if they don't exist
 */
static inline int create_directory(const char* path) {
    char tmp[1024];
    char* p = NULL;
    size_t len;
    
    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    
    // Remove trailing slash
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }
    
    // Create path components
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            
            #if defined(_WIN32) || defined(_WIN64)
            mkdir(tmp);
            #else
            mkdir(tmp, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
            #endif
            
            *p = '/';
        }
    }
    
    #if defined(_WIN32) || defined(_WIN64)
    return mkdir(tmp);
    #else
    return mkdir(tmp, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    #endif
}

/**
 * Initialize a chunked file for stream processing
 */
static inline chunked_file_t* init_chunked_file(const char* filename, size_t chunk_size) {
    chunked_file_t* cf = (chunked_file_t*)malloc(sizeof(chunked_file_t));
    if (!cf) {
        fprintf(stderr, "Error: Could not allocate memory for chunked file\n");
        return NULL;
    }
    
    // Initialize the struct
    memset(cf, 0, sizeof(chunked_file_t));
    strncpy(cf->filename, filename, sizeof(cf->filename) - 1);
    cf->chunk_size = chunk_size;
    cf->position = 0;
    cf->eof = 0;
    
    // Open the file
    cf->file = fopen(filename, "rb");
    if (!cf->file) {
        fprintf(stderr, "Error: Could not open file %s: %s\n", filename, strerror(errno));
        free(cf);
        return NULL;
    }
    
    // Get file size
    fseek(cf->file, 0, SEEK_END);
    cf->file_size = ftell(cf->file);
    fseek(cf->file, 0, SEEK_SET);
    
    // Allocate memory for the chunk
    cf->current_chunk = (unsigned char*)malloc(chunk_size);
    if (!cf->current_chunk) {
        fprintf(stderr, "Error: Could not allocate memory for file chunk\n");
        fclose(cf->file);
        free(cf);
        return NULL;
    }
    
    return cf;
}

/**
 * Read the next chunk from a chunked file
 * Returns the number of bytes read, or 0 if EOF
 */
static inline size_t read_next_chunk(chunked_file_t* cf) {
    if (!cf || !cf->file || cf->eof) {
        return 0;
    }
    
    // Read next chunk
    size_t bytes_to_read = cf->chunk_size;
    if (cf->position + bytes_to_read > cf->file_size) {
        bytes_to_read = cf->file_size - cf->position;
    }
    
    if (bytes_to_read == 0) {
        cf->eof = 1;
        return 0;
    }
    
    size_t bytes_read = fread(cf->current_chunk, 1, bytes_to_read, cf->file);
    if (bytes_read < bytes_to_read) {
        cf->eof = 1;
    }
    
    cf->position += bytes_read;
    return bytes_read;
}

/**
 * Clean up a chunked file
 */
static inline void cleanup_chunked_file(chunked_file_t* cf) {
    if (!cf) {
        return;
    }
    
    if (cf->file) {
        fclose(cf->file);
    }
    
    if (cf->current_chunk) {
        free(cf->current_chunk);
    }
    
    free(cf);
}

/**
 * Read an entire file into memory
 */
static inline unsigned char* read_file(const char* filename, size_t* size) {
    struct stat st;
    if (stat(filename, &st) != 0) {
        fprintf(stderr, "Error: Could not stat file %s: %s\n", filename, strerror(errno));
        return NULL;
    }
    
    *size = st.st_size;
    
    FILE* file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Could not open file %s: %s\n", filename, strerror(errno));
        return NULL;
    }
    
    printf("[DEBUG] read_file: attempting to allocate %zu bytes (%.2f MB) for file %s\n", 
           *size, *size / (1024.0 * 1024.0), filename);
    
    unsigned char* buffer = (unsigned char*)crypto_secure_alloc(*size);
    if (!buffer) {
        fprintf(stderr, "Error: Could not allocate memory for file %s (size: %zu bytes)\n", filename, *size);
        fclose(file);
        return NULL;
    }
    
    printf("[DEBUG] read_file: allocation successful, reading file...\n");
    size_t bytes_read = fread(buffer, 1, *size, file);
    fclose(file);
    
    if (bytes_read != *size) {
        fprintf(stderr, "Error: Could not read entire file %s (expected %zu bytes, got %zu bytes)\n", 
                filename, *size, bytes_read);
        crypto_secure_free(buffer, *size);
        return NULL;
    }
    
    printf("[DEBUG] read_file: successfully read %zu bytes\n", bytes_read);
    return buffer;
}

/**
 * Write data to a file
 */
static inline int write_file(const char* filename, const unsigned char* data, size_t size) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "Error: Could not open file %s for writing: %s\n", filename, strerror(errno));
        return 0;
    }
    
    size_t bytes_written = fwrite(data, 1, size, file);
    fclose(file);
    
    if (bytes_written != size) {
        fprintf(stderr, "Error: Could not write entire data to file %s\n", filename);
        return 0;
    }
    
    return 1;
}

/**
 * Print a byte array as hex
 */
static inline void print_hex(const unsigned char* data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/**
 * Generate random bytes
 */
static inline void generate_random_bytes(unsigned char* buffer, size_t size) {
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        size_t bytes_read = fread(buffer, 1, size, urandom);
        fclose(urandom);
        
        if (bytes_read == size) {
            return;
        }
    }
    
    // Fallback to pseudo-random if /dev/urandom is not available
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < size; i++) {
        buffer[i] = (unsigned char)(rand() % 256);
    }
}

/**
 * Compare two byte arrays for equality
 */
static inline int byte_arrays_equal(const unsigned char* a, const unsigned char* b, size_t size) {
    return memcmp(a, b, size) == 0;
}

#endif /* UTILS_H */ 