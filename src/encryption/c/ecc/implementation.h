#ifndef ECC_IMPLEMENTATION_H
#define ECC_IMPLEMENTATION_H

#include "../c_core.h"
#include <stdint.h>

// ECC chunk header structure for managing large file encryption
typedef struct {
    uint32_t magic;           // Magic number for validation (0xECC12345)
    uint32_t chunk_index;     // Index of this chunk
    uint32_t total_chunks;    // Total number of chunks
    uint32_t original_size;   // Original size of this chunk before encryption
    uint32_t encrypted_size;  // Size of encrypted data
    uint32_t curve_id;        // Curve identifier (0=P256, 1=P384, 2=P521)
    uint32_t implementation_type; // 0=standard, 1=custom
    uint32_t reserved[1];     // Reserved for future use
} ecc_chunk_header_t;

#define ECC_CHUNK_MAGIC 0xECC12345

// Maximum data size per chunk based on curve (conservative estimates)
#define ECC_P256_MAX_CHUNK 32    // ~32 bytes per chunk for P-256
#define ECC_P384_MAX_CHUNK 48    // ~48 bytes per chunk for P-384  
#define ECC_P521_MAX_CHUNK 66    // ~66 bytes per chunk for P-521

// Function prototypes for ECC standard implementations
void* ecc_p256_init(void);
void* ecc_p384_init(void);
void* ecc_p521_init(void);
void ecc_cleanup(void* context);
unsigned char* ecc_generate_key(void* context, int* key_length);
unsigned char* ecc_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);
unsigned char* ecc_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);
unsigned char* ecc_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* ecc_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);

// Function prototypes for ECC custom implementations  
void* ecc_custom_p256_init(void);
void* ecc_custom_p384_init(void);
void* ecc_custom_p521_init(void);
void ecc_custom_cleanup(void* context);
unsigned char* ecc_custom_generate_key(void* context, int* key_length);
unsigned char* ecc_custom_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);
unsigned char* ecc_custom_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length);
unsigned char* ecc_custom_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);
unsigned char* ecc_custom_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length);

// Utility functions for chunk management
size_t ecc_get_max_chunk_size(int curve_id);
size_t ecc_estimate_encrypted_size(size_t input_size, int curve_id);
int ecc_split_data_into_chunks(const unsigned char* data, size_t data_length, int curve_id, unsigned char*** chunks, size_t** chunk_sizes, int* num_chunks);
unsigned char* ecc_combine_encrypted_chunks(unsigned char** encrypted_chunks, size_t* encrypted_sizes, int num_chunks, int curve_id, int is_custom, size_t* total_output_size);
int ecc_extract_chunks_from_encrypted(const unsigned char* encrypted_data, size_t encrypted_size, unsigned char*** chunks, size_t** chunk_sizes, int* num_chunks, ecc_chunk_header_t* first_header);

// Register ECC implementations in the registry
void register_ecc_implementations(implementation_registry_t* registry);

#endif /* ECC_IMPLEMENTATION_H */ 