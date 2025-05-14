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

// Maximum input size for chunked processing
#define MAX_CHUNK_SIZE (16 * 1024 * 1024)  // 16MB default chunk size

/**
 * Resource usage metrics structure
 */
typedef struct {
    double user_time_s;
    double system_time_s;
    size_t peak_memory_bytes;
    unsigned long voluntary_ctx_switches;
    unsigned long involuntary_ctx_switches;
} resource_usage_t;

/**
 * Get current resource usage
 */
static inline resource_usage_t get_resource_usage() {
    resource_usage_t usage = {0};
    struct rusage ru;
    
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        // CPU time
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
        
        // Context switches
        usage.voluntary_ctx_switches = ru.ru_nvcsw;
        usage.involuntary_ctx_switches = ru.ru_nivcsw;
    }
    
    return usage;
}

/**
 * Calculate difference between two resource usage snapshots
 */
static inline resource_usage_t resource_usage_diff(resource_usage_t start, resource_usage_t end) {
    resource_usage_t diff;
    
    diff.user_time_s = end.user_time_s - start.user_time_s;
    diff.system_time_s = end.system_time_s - start.system_time_s;
    diff.peak_memory_bytes = end.peak_memory_bytes > start.peak_memory_bytes ? 
                           end.peak_memory_bytes - start.peak_memory_bytes : 0;
    diff.voluntary_ctx_switches = end.voluntary_ctx_switches - start.voluntary_ctx_switches;
    diff.involuntary_ctx_switches = end.involuntary_ctx_switches - start.involuntary_ctx_switches;
    
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
    
    unsigned char* buffer = (unsigned char*)malloc(*size);
    if (!buffer) {
        fprintf(stderr, "Error: Could not allocate memory for file %s\n", filename);
        fclose(file);
        return NULL;
    }
    
    size_t bytes_read = fread(buffer, 1, *size, file);
    fclose(file);
    
    if (bytes_read != *size) {
        fprintf(stderr, "Error: Could not read entire file %s\n", filename);
        free(buffer);
        return NULL;
    }
    
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