#ifndef C_CORE_H
#define C_CORE_H

#include <json-c/json.h>

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
    char mode[16];                // Mode of operation (CBC, CTR, etc.)
    
    // Function pointers for algorithm operations
    void* (*init)(void);
    void (*cleanup)(void*);
    unsigned char* (*generate_key)(void*, int*);
    unsigned char* (*encrypt)(void*, const unsigned char*, int, const unsigned char*, int*);
    unsigned char* (*decrypt)(void*, const unsigned char*, int, const unsigned char*, int*);
    
    // Stream processing functions
    unsigned char* (*encrypt_stream)(void*, const unsigned char*, int, const unsigned char*, int, int*);
    unsigned char* (*decrypt_stream)(void*, const unsigned char*, int, const unsigned char*, int, int*);
} implementation_info_t;

// Implementation registry structure
typedef struct {
    implementation_info_t implementations[MAX_IMPLEMENTATIONS];
    int count;
} implementation_registry_t;

// Test configuration structure
typedef struct {
    // Test parameters
    int iterations;
    char dataset_path[1024];
    size_t dataset_size;
    int use_stdlib;
    int use_custom;
    char processing_strategy[32];
    char chunk_size[32];
    
    // C-specific parameters
    int memory_mode;
    
    // Results directory
    char results_dir[1024];
} TestConfig;

// Function prototypes
void register_all_implementations();
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