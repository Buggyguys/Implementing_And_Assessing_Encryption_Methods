#ifndef C_CORE_H
#define C_CORE_H

#include "include/cJSON.h"

// Define maximum path length
#define MAX_PATH_LENGTH 1024

// Maximum number of implementations we can register
#define MAX_IMPLEMENTATIONS 100

// Encryption algorithm types
typedef enum {
    ALGO_UNDEFINED = 0,
    ALGO_AES,
    ALGO_CAMELLIA,
    ALGO_CHACHA20,
    ALGO_RSA,
    ALGO_ECC
} algorithm_type_t;

// Implementation info structure
typedef struct {
    char name[64];                // Implementation name
    algorithm_type_t algo_type;   // Algorithm type
    int is_custom;                // Whether this is a custom implementation
    int key_size;                 // Key size in bits
    char mode[16];                // Mode of operation (CBC, GCM, CFB, OFB)
    
    // Function pointers for algorithm operations
    void* (*init)(void);
    void (*cleanup)(void*);
    unsigned char* (*generate_key)(void*, int*);
    unsigned char* (*encrypt)(void*, const unsigned char*, size_t, const unsigned char*, size_t*);
    unsigned char* (*decrypt)(void*, const unsigned char*, size_t, const unsigned char*, size_t*);
    
    // Stream processing functions
    unsigned char* (*encrypt_stream)(void*, const unsigned char*, int, const unsigned char*, int, int*);
    unsigned char* (*decrypt_stream)(void*, const unsigned char*, int, const unsigned char*, int, int*);
} implementation_info_t;

// Implementation registry structure
typedef struct {
    implementation_info_t implementations[MAX_IMPLEMENTATIONS];
    int count;
} implementation_registry_t;

// Dataset information structure
typedef struct {
    char path[1024];
    size_t size_bytes;
} dataset_info_t;

// Test configuration structure
typedef struct {
    // Test parameters
    int iterations;
    char processing_strategy[32];
    char chunk_size[32];
    int use_stdlib;
    int use_custom;
    
    // Dataset information - dual datasets for symmetric and asymmetric
    dataset_info_t symmetric_dataset;
    dataset_info_t asymmetric_dataset;
    
    // Legacy single dataset support (for backward compatibility)
    char dataset_path[1024];
    size_t dataset_size_bytes;
    int dataset_size_kb;
    
    // C-specific parameters
    int memory_mode;
    
    // Session directory
    char session_dir[1024];
    
    // AES configuration - Updated modes: CBC, GCM, CFB, OFB
    char aes_key_size[16];  // "128", "192", or "256"
    char aes_mode[16];      // "CBC", "GCM", "CFB", or "OFB"
    
    // Algorithm enabled flags
    int aes_enabled;
    int chacha20_enabled;
    int rsa_enabled;
    int ecc_enabled;
    int camellia_enabled;
    
    // Algorithm-specific configurations
    char rsa_key_size[16];
    char rsa_padding[16];
    
    char ecc_curve[32];
    
    // Camellia configuration - Updated modes: CBC, GCM, CFB, OFB (note: GCM not supported in stdlib)
    char camellia_key_size[16];
    char camellia_mode[16];
} TestConfig;

// Function prototypes
void register_all_implementations(TestConfig* config);
void register_aes_implementations(implementation_registry_t* registry);
void register_camellia_implementations(implementation_registry_t* registry);
void register_chacha_implementations(implementation_registry_t* registry);
void register_rsa_implementations(implementation_registry_t* registry);
void register_ecc_implementations(implementation_registry_t* registry);
void print_all_implementations();
TestConfig* parse_config_file(const char* config_path);
void run_benchmarks(TestConfig* config);
char* getTimeString();
const char* getAlgorithmName(algorithm_type_t type);

/**
 * Count implementations by algorithm type
 */
int count_implementations_by_type(implementation_registry_t* registry, algorithm_type_t type);

#endif /* C_CORE_H */ 