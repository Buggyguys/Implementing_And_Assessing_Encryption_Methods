#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "implementation.h"
#include "../include/utils.h"
#include "ecc_common.h"

// Global registry for storing implementation registry pointer
static implementation_registry_t* g_registry = NULL;

// Register ECC implementations based on configuration
void register_ecc_implementations(implementation_registry_t* registry) {
    g_registry = registry;
    int index = registry->count;
    
    // Get the configuration from environment variables
    char* use_stdlib_str = getenv("USE_STDLIB");
    char* use_custom_str = getenv("USE_CUSTOM");
    char* curve_str = getenv("ECC_CURVE");
    char* ecc_enabled_str = getenv("ECC_ENABLED");
    
    // Default values if environment variables are not set
    int use_stdlib = use_stdlib_str ? atoi(use_stdlib_str) : 1;
    int use_custom = use_custom_str ? atoi(use_custom_str) : 1;
    int ecc_enabled = ecc_enabled_str ? atoi(ecc_enabled_str) : 1;
    
    // Check if ECC is enabled in the configuration
    if (!ecc_enabled) {
        printf("ECC implementations disabled in configuration\n");
        return;
    }
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Define curves to register
    ecc_curve_type_t curves_to_register[3];
    const char* curve_names[3];
    int key_sizes[3];
    int num_curves = 0;
    
    // If specific curve is requested, only register that one
    if (curve_str) {
        // Normalize curve name
        char normalized_curve[32] = {0};
        int j = 0;
        for (int i = 0; curve_str[i] && j < sizeof(normalized_curve)-1; i++) {
            if (curve_str[i] != ' ' && curve_str[i] != '-') {
                normalized_curve[j++] = toupper(curve_str[i]);
            }
        }
        
        if (strcmp(normalized_curve, "P256") == 0 || strcmp(normalized_curve, "SECP256R1") == 0) {
            curves_to_register[0] = CURVE_P256;
            curve_names[0] = "P-256";
            key_sizes[0] = 256;
            num_curves = 1;
        } else if (strcmp(normalized_curve, "P384") == 0 || strcmp(normalized_curve, "SECP384R1") == 0) {
            curves_to_register[0] = CURVE_P384;
            curve_names[0] = "P-384";
            key_sizes[0] = 384;
            num_curves = 1;
        } else if (strcmp(normalized_curve, "P521") == 0 || strcmp(normalized_curve, "SECP521R1") == 0) {
            curves_to_register[0] = CURVE_P521;
            curve_names[0] = "P-521";
            key_sizes[0] = 521;
            num_curves = 1;
        } else {
            fprintf(stderr, "Warning: Unrecognized ECC curve '%s', registering all curves\n", curve_str);
            // Fall through to register all curves
        }
    }
    
    // If no specific curve or unrecognized curve, register all three
    if (num_curves == 0) {
        curves_to_register[0] = CURVE_P256;
        curve_names[0] = "P-256";
        key_sizes[0] = 256;
        
        curves_to_register[1] = CURVE_P384;
        curve_names[1] = "P-384";
        key_sizes[1] = 384;
        
        curves_to_register[2] = CURVE_P521;
        curve_names[2] = "P-521";
        key_sizes[2] = 521;
        
        num_curves = 3;
    }
    
    // Register standard implementations
    if (use_stdlib) {
        for (int i = 0; i < num_curves; i++) {
            if (registry->count >= MAX_IMPLEMENTATIONS) break;
            
            char impl_name[64];
            snprintf(impl_name, sizeof(impl_name), "ecc_%s", curve_names[i]);
            
            strcpy(registry->implementations[registry->count].name, impl_name);
            registry->implementations[registry->count].algo_type = ALGO_ECC;
            registry->implementations[registry->count].is_custom = 0;
            registry->implementations[registry->count].key_size = key_sizes[i];
            strcpy(registry->implementations[registry->count].mode, curve_names[i]);
            
            // Set function pointers based on curve
            switch (curves_to_register[i]) {
                case CURVE_P256:
                    registry->implementations[registry->count].init = ecc_p256_init;
                    break;
        case CURVE_P384:
                    registry->implementations[registry->count].init = ecc_p384_init;
            break;
        case CURVE_P521:
                    registry->implementations[registry->count].init = ecc_p521_init;
            break;
    }
    
            registry->implementations[registry->count].cleanup = ecc_cleanup;
            registry->implementations[registry->count].generate_key = ecc_generate_key;
            registry->implementations[registry->count].encrypt = ecc_encrypt;
            registry->implementations[registry->count].decrypt = ecc_decrypt;
            registry->implementations[registry->count].encrypt_stream = ecc_encrypt_stream;
            registry->implementations[registry->count].decrypt_stream = ecc_decrypt_stream;
            
        registry->count++;
        }
    }
    
    // Register custom implementations
    if (use_custom) {
        for (int i = 0; i < num_curves; i++) {
            if (registry->count >= MAX_IMPLEMENTATIONS) break;
            
        char impl_name[64];
            snprintf(impl_name, sizeof(impl_name), "ecc_%s_custom", curve_names[i]);
            
            strcpy(registry->implementations[registry->count].name, impl_name);
            registry->implementations[registry->count].algo_type = ALGO_ECC;
            registry->implementations[registry->count].is_custom = 1;
            registry->implementations[registry->count].key_size = key_sizes[i];
            strcpy(registry->implementations[registry->count].mode, curve_names[i]);
            
            // Set function pointers based on curve
            switch (curves_to_register[i]) {
                case CURVE_P256:
                    registry->implementations[registry->count].init = ecc_custom_p256_init;
                    break;
                case CURVE_P384:
                    registry->implementations[registry->count].init = ecc_custom_p384_init;
                    break;
                case CURVE_P521:
                    registry->implementations[registry->count].init = ecc_custom_p521_init;
                    break;
            }
            
            registry->implementations[registry->count].cleanup = ecc_custom_cleanup;
            registry->implementations[registry->count].generate_key = ecc_custom_generate_key;
            registry->implementations[registry->count].encrypt = ecc_custom_encrypt;
            registry->implementations[registry->count].decrypt = ecc_custom_decrypt;
            registry->implementations[registry->count].encrypt_stream = ecc_custom_encrypt_stream;
            registry->implementations[registry->count].decrypt_stream = ecc_custom_decrypt_stream;
            
        registry->count++;
    }
}

    printf("Registered %d ECC implementations\n", registry->count - index);
}

// =============================================================================
// STANDARD IMPLEMENTATION FUNCTIONS (OpenSSL-based)
// =============================================================================

void* ecc_p256_init(void) {
    ecc_context_t* context = (ecc_context_t*)malloc(sizeof(ecc_context_t));
    if (!context) {
        fprintf(stderr, "Error: Could not allocate ECC context\n");
        return NULL;
    }
    
    memset(context, 0, sizeof(ecc_context_t));
    context->is_custom = 0;
    context->curve = CURVE_P256;
    return context;
}

void* ecc_p384_init(void) {
    ecc_context_t* context = (ecc_context_t*)malloc(sizeof(ecc_context_t));
    if (!context) {
        fprintf(stderr, "Error: Could not allocate ECC context\n");
        return NULL;
    }
    
    memset(context, 0, sizeof(ecc_context_t));
    context->is_custom = 0;
            context->curve = CURVE_P384;
    return context;
}

void* ecc_p521_init(void) {
    ecc_context_t* context = (ecc_context_t*)malloc(sizeof(ecc_context_t));
    if (!context) {
        fprintf(stderr, "Error: Could not allocate ECC context\n");
        return NULL;
    }
    
    memset(context, 0, sizeof(ecc_context_t));
    context->is_custom = 0;
    context->curve = CURVE_P521;
    return context;
}

void ecc_cleanup(void* context) {
    if (!context) return;
    
    ecc_context_t* ecc_context = (ecc_context_t*)context;
    
    // Free EC key
    if (ecc_context->ec_key) {
        EC_KEY_free(ecc_context->ec_key);
        ecc_context->ec_key = NULL;
    }
    
    // Free private key
    if (ecc_context->private_key) {
        free(ecc_context->private_key);
        ecc_context->private_key = NULL;
    }
    
    // Free public key
    if (ecc_context->public_key) {
        free(ecc_context->public_key);
        ecc_context->public_key = NULL;
    }
    
    free(context);
}

unsigned char* ecc_generate_key(void* context, int* key_length) {
    if (!context || !key_length) return NULL;
    
    ecc_context_t* ecc_context = (ecc_context_t*)context;
    
    // Generate key pair
    ecc_context->ec_key = ecc_generate_key_pair(ecc_context->curve);
    if (!ecc_context->ec_key) {
        fprintf(stderr, "Error: Failed to generate ECC key pair\n");
        return NULL;
    }
    
    // Export public key
    if (ecc_context->public_key) {
        free(ecc_context->public_key);
    }
    ecc_context->public_key = ecc_export_public_key(ecc_context->ec_key, &ecc_context->public_key_length);
    
    // Export private key
    if (ecc_context->private_key) {
        free(ecc_context->private_key);
    }
    ecc_context->private_key = ecc_export_private_key(ecc_context->ec_key, &ecc_context->private_key_length);
    
    if (!ecc_context->public_key || !ecc_context->private_key) {
        fprintf(stderr, "Error: Failed to export ECC keys\n");
        return NULL;
    }
    
    // Return public key (for sharing)
    *key_length = ecc_context->public_key_length;
    unsigned char* key_copy = (unsigned char*)malloc(*key_length);
    if (key_copy) {
        memcpy(key_copy, ecc_context->public_key, *key_length);
    }
    
    return key_copy;
}

unsigned char* ecc_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length) {
    if (!context || !data || data_length == 0 || !output_length) return NULL;
    
    ecc_context_t* ecc_context = (ecc_context_t*)context;
    
    // Handle memory mode: split data into chunks and encrypt each
    size_t max_chunk_size = ecc_get_max_chunk_size(ecc_context->curve);
    
    if (data_length <= max_chunk_size) {
        // Single chunk encryption
        return ecc_pure_encrypt_data(data, data_length, key ? key : ecc_context->public_key, 
                                   key ? strlen((const char*)key) : ecc_context->public_key_length,
                                   ecc_context->curve, output_length);
    } else {
        // Multi-chunk encryption
        unsigned char** chunks;
        size_t* chunk_sizes;
        int num_chunks;
        
        if (ecc_split_data_into_chunks(data, data_length, ecc_context->curve, &chunks, &chunk_sizes, &num_chunks) != 0) {
            fprintf(stderr, "Error: Failed to split data into chunks\n");
            return NULL;
        }
        
        // Encrypt each chunk
        unsigned char** encrypted_chunks = (unsigned char**)malloc(num_chunks * sizeof(unsigned char*));
        size_t* encrypted_sizes = (size_t*)malloc(num_chunks * sizeof(size_t));
        
        if (!encrypted_chunks || !encrypted_sizes) {
            fprintf(stderr, "Error: Memory allocation failed for encrypted chunks\n");
            // Clean up
            for (int i = 0; i < num_chunks; i++) {
                free(chunks[i]);
            }
            free(chunks);
            free(chunk_sizes);
            free(encrypted_chunks);
            free(encrypted_sizes);
            return NULL;
        }
        
        int success = 1;
        for (int i = 0; i < num_chunks; i++) {
            encrypted_chunks[i] = ecc_pure_encrypt_data(chunks[i], chunk_sizes[i],
                                                      key ? key : ecc_context->public_key,
                                                      key ? strlen((const char*)key) : ecc_context->public_key_length,
                                                      ecc_context->curve, &encrypted_sizes[i]);
            if (!encrypted_chunks[i]) {
                success = 0;
                break;
            }
        }
        
        // Clean up original chunks
        for (int i = 0; i < num_chunks; i++) {
            free(chunks[i]);
        }
        free(chunks);
        free(chunk_sizes);
        
        if (!success) {
            // Clean up encrypted chunks
            for (int i = 0; i < num_chunks; i++) {
                if (encrypted_chunks[i]) free(encrypted_chunks[i]);
            }
            free(encrypted_chunks);
            free(encrypted_sizes);
            return NULL;
        }
        
        // Combine encrypted chunks
        unsigned char* combined = ecc_combine_encrypted_chunks(encrypted_chunks, encrypted_sizes, num_chunks,
                                                             ecc_context->curve, 0, output_length);
        
        // Clean up
        for (int i = 0; i < num_chunks; i++) {
            free(encrypted_chunks[i]);
        }
        free(encrypted_chunks);
        free(encrypted_sizes);
        
        return combined;
    }
}

unsigned char* ecc_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length) {
    if (!context || !data || data_length == 0 || !output_length) return NULL;
    
    ecc_context_t* ecc_context = (ecc_context_t*)context;
    
    // Check if this is multi-chunk data
    if (data_length >= sizeof(ecc_chunk_header_t)) {
        ecc_chunk_header_t* header = (ecc_chunk_header_t*)data;
        if (header->magic == ECC_CHUNK_MAGIC) {
            // Multi-chunk decryption
            unsigned char** chunks;
            size_t* chunk_sizes;
            int num_chunks;
            ecc_chunk_header_t first_header;
            
            if (ecc_extract_chunks_from_encrypted(data, data_length, &chunks, &chunk_sizes, &num_chunks, &first_header) != 0) {
                fprintf(stderr, "Error: Failed to extract chunks from encrypted data\n");
                return NULL;
            }
            
            // Decrypt each chunk
            unsigned char** decrypted_chunks = (unsigned char**)malloc(num_chunks * sizeof(unsigned char*));
            size_t* decrypted_sizes = (size_t*)malloc(num_chunks * sizeof(size_t));
            
            if (!decrypted_chunks || !decrypted_sizes) {
                fprintf(stderr, "Error: Memory allocation failed for decrypted chunks\n");
                // Clean up
                for (int i = 0; i < num_chunks; i++) {
                    free(chunks[i]);
                }
                free(chunks);
                free(chunk_sizes);
                free(decrypted_chunks);
                free(decrypted_sizes);
                return NULL;
            }
            
            int success = 1;
            size_t total_decrypted_size = 0;
            
            for (int i = 0; i < num_chunks; i++) {
                decrypted_chunks[i] = ecc_pure_decrypt_data(chunks[i], chunk_sizes[i],
                                                          ecc_context->private_key, ecc_context->private_key_length,
                                                          ecc_context->curve, &decrypted_sizes[i]);
                if (!decrypted_chunks[i]) {
                    success = 0;
                    break;
                }
                total_decrypted_size += decrypted_sizes[i];
            }
            
            // Clean up chunks
            for (int i = 0; i < num_chunks; i++) {
                free(chunks[i]);
            }
            free(chunks);
            free(chunk_sizes);
            
            if (!success) {
                // Clean up decrypted chunks
                for (int i = 0; i < num_chunks; i++) {
                    if (decrypted_chunks[i]) free(decrypted_chunks[i]);
                }
                free(decrypted_chunks);
                free(decrypted_sizes);
                return NULL;
            }
            
            // Combine decrypted chunks
            unsigned char* combined = (unsigned char*)malloc(total_decrypted_size);
            if (!combined) {
                // Clean up
                for (int i = 0; i < num_chunks; i++) {
                    free(decrypted_chunks[i]);
                }
                free(decrypted_chunks);
                free(decrypted_sizes);
                return NULL;
            }
            
            size_t offset = 0;
            for (int i = 0; i < num_chunks; i++) {
                memcpy(combined + offset, decrypted_chunks[i], decrypted_sizes[i]);
                offset += decrypted_sizes[i];
                free(decrypted_chunks[i]);
            }
            
            free(decrypted_chunks);
            free(decrypted_sizes);
            
            *output_length = total_decrypted_size;
            return combined;
        }
    }
    
    // Single chunk decryption
    return ecc_pure_decrypt_data(data, data_length, ecc_context->private_key, ecc_context->private_key_length,
                               ecc_context->curve, output_length);
}

unsigned char* ecc_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    // For stream mode, process the chunk as-is but add chunk header for reconstruction
    size_t output_len = 0;
    unsigned char* result = ecc_encrypt(context, data, (size_t)data_length, key, &output_len);
    if (output_length) *output_length = (int)output_len;
    return result;
}

unsigned char* ecc_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    // For stream mode, decrypt the chunk
    size_t output_len = 0;
    unsigned char* result = ecc_decrypt(context, data, (size_t)data_length, key, &output_len);
    if (output_length) *output_length = (int)output_len;
    return result;
}

// =============================================================================
// CUSTOM IMPLEMENTATION FUNCTIONS
// =============================================================================

void* ecc_custom_p256_init(void) {
    ecc_context_t* context = (ecc_context_t*)malloc(sizeof(ecc_context_t));
    if (!context) {
        fprintf(stderr, "Error: Could not allocate ECC custom context\n");
        return NULL;
    }
    
    memset(context, 0, sizeof(ecc_context_t));
    context->is_custom = 1;
    context->curve = CURVE_P256;
    context->field_size_bits = 256;
    context->field_size_words = 4;  // 256 bits / 64 bits per word
    
    ecc_custom_init_curve_params(context);
    
    return context;
}

void* ecc_custom_p384_init(void) {
    ecc_context_t* context = (ecc_context_t*)malloc(sizeof(ecc_context_t));
    if (!context) {
        fprintf(stderr, "Error: Could not allocate ECC custom context\n"); 
        return NULL;
    }
    
    memset(context, 0, sizeof(ecc_context_t));
    context->is_custom = 1;
    context->curve = CURVE_P384;
    context->field_size_bits = 384;
    context->field_size_words = 6;  // 384 bits / 64 bits per word
    
    ecc_custom_init_curve_params(context);
    
    return context;
}

void* ecc_custom_p521_init(void) {
    ecc_context_t* context = (ecc_context_t*)malloc(sizeof(ecc_context_t));
    if (!context) {
        fprintf(stderr, "Error: Could not allocate ECC custom context\n");
        return NULL;
    }
    
    memset(context, 0, sizeof(ecc_context_t));
    context->is_custom = 1;
    context->curve = CURVE_P521;
    context->field_size_bits = 521;
    context->field_size_words = 9;  // 521 bits / 64 bits per word (rounded up)
    
    ecc_custom_init_curve_params(context);
    
    return context;
}

void ecc_custom_cleanup(void* context) {
    if (!context) return;
    
    ecc_context_t* ecc_context = (ecc_context_t*)context;
    
    ecc_custom_cleanup_curve_params(ecc_context);
    
    // Free custom keys
    if (ecc_context->custom_private_key) {
        free(ecc_context->custom_private_key);
        ecc_context->custom_private_key = NULL;
    }
    
    if (ecc_context->custom_public_key) {
        free(ecc_context->custom_public_key);
        ecc_context->custom_public_key = NULL;
    }
    
    free(context);
}

unsigned char* ecc_custom_generate_key(void* context, int* key_length) {
    if (!context || !key_length) return NULL;
    
    ecc_context_t* ecc_context = (ecc_context_t*)context;
    
    if (ecc_custom_generate_keypair(ecc_context) != 0) {
        fprintf(stderr, "Error: Failed to generate custom ECC key pair\n");
        return NULL;
    }
    
    // Serialize public key for return
    // For simplicity, we'll return the x,y coordinates as bytes
    int coord_size = (ecc_context->field_size_bits + 7) / 8;
    *key_length = 1 + 2 * coord_size;  // 1 byte for format + x + y
    
    unsigned char* key_data = (unsigned char*)malloc(*key_length);
    if (!key_data) {
        fprintf(stderr, "Error: Memory allocation failed for key data\n");
        return NULL;
    }
    
    // Format: 0x04 (uncompressed) + x + y
    key_data[0] = 0x04;
    
    // Convert coordinates to bytes (little-endian)
    for (int i = 0; i < coord_size; i++) {
        int word_idx = i / 8;
        int byte_idx = i % 8;
        if (word_idx < ecc_context->field_size_words) {
            key_data[1 + i] = (ecc_context->custom_public_key->point.x[word_idx] >> (byte_idx * 8)) & 0xFF;
            key_data[1 + coord_size + i] = (ecc_context->custom_public_key->point.y[word_idx] >> (byte_idx * 8)) & 0xFF;
        } else {
            key_data[1 + i] = 0;
            key_data[1 + coord_size + i] = 0;
        }
    }
    
    return key_data;
}

unsigned char* ecc_custom_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length) {
    if (!context || !data || data_length == 0 || !output_length) return NULL;
    
    ecc_context_t* ecc_context = (ecc_context_t*)context;
    
    // Handle memory mode: split data into chunks and encrypt each (similar to standard implementation)
    size_t max_chunk_size = ecc_get_max_chunk_size(ecc_context->curve);
    
    if (data_length <= max_chunk_size) {
        // Single chunk encryption
        return ecc_custom_pure_encrypt(data, data_length, ecc_context, output_length);
    } else {
        // Multi-chunk encryption (similar logic to standard implementation)
        unsigned char** chunks;
        size_t* chunk_sizes;
        int num_chunks;
        
        if (ecc_split_data_into_chunks(data, data_length, ecc_context->curve, &chunks, &chunk_sizes, &num_chunks) != 0) {
            fprintf(stderr, "Error: Failed to split data into chunks\n");
            return NULL;
        }
        
        // Encrypt each chunk
        unsigned char** encrypted_chunks = (unsigned char**)malloc(num_chunks * sizeof(unsigned char*));
        size_t* encrypted_sizes = (size_t*)malloc(num_chunks * sizeof(size_t));
        
        if (!encrypted_chunks || !encrypted_sizes) {
            fprintf(stderr, "Error: Memory allocation failed for encrypted chunks\n");
            // Clean up
            for (int i = 0; i < num_chunks; i++) {
                free(chunks[i]);
            }
            free(chunks);
            free(chunk_sizes);
            free(encrypted_chunks);
            free(encrypted_sizes);
            return NULL;
        }
        
        int success = 1;
        for (int i = 0; i < num_chunks; i++) {
            encrypted_chunks[i] = ecc_custom_pure_encrypt(chunks[i], chunk_sizes[i], ecc_context, &encrypted_sizes[i]);
            if (!encrypted_chunks[i]) {
                success = 0;
                break;
            }
        }
        
        // Clean up original chunks
        for (int i = 0; i < num_chunks; i++) {
            free(chunks[i]);
        }
        free(chunks);
        free(chunk_sizes);
        
        if (!success) {
            // Clean up encrypted chunks
            for (int i = 0; i < num_chunks; i++) {
                if (encrypted_chunks[i]) free(encrypted_chunks[i]);
            }
            free(encrypted_chunks);
            free(encrypted_sizes);
            return NULL;
        }
        
        // Combine encrypted chunks
        unsigned char* combined = ecc_combine_encrypted_chunks(encrypted_chunks, encrypted_sizes, num_chunks,
                                                             ecc_context->curve, 1, output_length);
        
        // Clean up
        for (int i = 0; i < num_chunks; i++) {
            free(encrypted_chunks[i]);
        }
        free(encrypted_chunks);
        free(encrypted_sizes);
        
        return combined;
    }
}

unsigned char* ecc_custom_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length) {
    if (!context || !data || data_length == 0 || !output_length) return NULL;
    
    ecc_context_t* ecc_context = (ecc_context_t*)context;
    
    // Check if this is multi-chunk data (similar to standard implementation)
    if (data_length >= sizeof(ecc_chunk_header_t)) {
        ecc_chunk_header_t* header = (ecc_chunk_header_t*)data;
        if (header->magic == ECC_CHUNK_MAGIC && header->implementation_type == 1) {
            // Multi-chunk decryption
            unsigned char** chunks;
            size_t* chunk_sizes;
            int num_chunks;
            ecc_chunk_header_t first_header;
            
            if (ecc_extract_chunks_from_encrypted(data, data_length, &chunks, &chunk_sizes, &num_chunks, &first_header) != 0) {
                fprintf(stderr, "Error: Failed to extract chunks from encrypted data\n");
                return NULL;
            }
            
            // Decrypt each chunk
            unsigned char** decrypted_chunks = (unsigned char**)malloc(num_chunks * sizeof(unsigned char*));
            size_t* decrypted_sizes = (size_t*)malloc(num_chunks * sizeof(size_t));
            
            if (!decrypted_chunks || !decrypted_sizes) {
                fprintf(stderr, "Error: Memory allocation failed for decrypted chunks\n");
                // Clean up
                for (int i = 0; i < num_chunks; i++) {
                    free(chunks[i]);
                }
                free(chunks);
                free(chunk_sizes);
                free(decrypted_chunks);
                free(decrypted_sizes);
                return NULL;
            }
            
            int success = 1;
            size_t total_decrypted_size = 0;
            
            for (int i = 0; i < num_chunks; i++) {
                decrypted_chunks[i] = ecc_custom_pure_decrypt(chunks[i], chunk_sizes[i], ecc_context, &decrypted_sizes[i]);
                if (!decrypted_chunks[i]) {
                    success = 0;
                    break;
                }
                total_decrypted_size += decrypted_sizes[i];
            }
            
            // Clean up chunks
            for (int i = 0; i < num_chunks; i++) {
                free(chunks[i]);
            }
            free(chunks);
            free(chunk_sizes);
            
            if (!success) {
                // Clean up decrypted chunks
                for (int i = 0; i < num_chunks; i++) {
                    if (decrypted_chunks[i]) free(decrypted_chunks[i]);
                }
                free(decrypted_chunks);
                free(decrypted_sizes);
                return NULL;
            }
            
            // Combine decrypted chunks
            unsigned char* combined = (unsigned char*)malloc(total_decrypted_size);
            if (!combined) {
                // Clean up
                for (int i = 0; i < num_chunks; i++) {
                    free(decrypted_chunks[i]);
                }
                free(decrypted_chunks);
                free(decrypted_sizes);
                return NULL;
            }
            
            size_t offset = 0;
            for (int i = 0; i < num_chunks; i++) {
                memcpy(combined + offset, decrypted_chunks[i], decrypted_sizes[i]);
                offset += decrypted_sizes[i];
                free(decrypted_chunks[i]);
            }
            
            free(decrypted_chunks);
            free(decrypted_sizes);
            
            *output_length = total_decrypted_size;
            return combined;
        }
    }
    
    // Single chunk decryption
    return ecc_custom_pure_decrypt(data, data_length, ecc_context, output_length);
}

unsigned char* ecc_custom_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    // For stream mode, process the chunk as-is
    size_t output_len = 0;
    unsigned char* result = ecc_custom_encrypt(context, data, (size_t)data_length, key, &output_len);
    if (output_length) *output_length = (int)output_len;
    return result;
}

unsigned char* ecc_custom_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    // For stream mode, decrypt the chunk
    size_t output_len = 0;
    unsigned char* result = ecc_custom_decrypt(context, data, (size_t)data_length, key, &output_len);
    if (output_length) *output_length = (int)output_len;
    return result;
}

// =============================================================================
// UTILITY FUNCTIONS FOR CHUNK MANAGEMENT
// =============================================================================

size_t ecc_get_max_chunk_size(int curve_id) {
    switch (curve_id) {
        case CURVE_P256:
            return ECC_P256_MAX_CHUNK;
        case CURVE_P384:
            return ECC_P384_MAX_CHUNK;
        case CURVE_P521:
            return ECC_P521_MAX_CHUNK;
        default:
            return ECC_P256_MAX_CHUNK;
    }
}

size_t ecc_estimate_encrypted_size(size_t input_size, int curve_id) {
    size_t max_chunk_size = ecc_get_max_chunk_size(curve_id);
    size_t num_chunks = (input_size + max_chunk_size - 1) / max_chunk_size;
    
    // Each encrypted chunk will be larger than the original
    // Estimate: 2x the original size plus headers
    size_t estimated_chunk_overhead = max_chunk_size * 2;
    size_t total_header_size = num_chunks * sizeof(ecc_chunk_header_t);
    
    return input_size * 2 + total_header_size + estimated_chunk_overhead;
}

int ecc_split_data_into_chunks(const unsigned char* data, size_t data_length, int curve_id, unsigned char*** chunks, size_t** chunk_sizes, int* num_chunks) {
    if (!data || !chunks || !chunk_sizes || !num_chunks) return -1;
    
    size_t max_chunk_size = ecc_get_max_chunk_size(curve_id);
    *num_chunks = (data_length + max_chunk_size - 1) / max_chunk_size;
    
    *chunks = (unsigned char**)malloc(*num_chunks * sizeof(unsigned char*));
    *chunk_sizes = (size_t*)malloc(*num_chunks * sizeof(size_t));
    
    if (!*chunks || !*chunk_sizes) {
        free(*chunks);
        free(*chunk_sizes);
        return -1;
    }
    
    for (int i = 0; i < *num_chunks; i++) {
        size_t chunk_start = i * max_chunk_size;
        size_t chunk_size = (chunk_start + max_chunk_size <= data_length) ? 
                           max_chunk_size : (data_length - chunk_start);
        
        (*chunks)[i] = (unsigned char*)malloc(chunk_size);
        if (!(*chunks)[i]) {
            // Clean up on failure
            for (int j = 0; j < i; j++) {
                free((*chunks)[j]);
            }
            free(*chunks);
            free(*chunk_sizes);
            return -1;
        }
        
        memcpy((*chunks)[i], data + chunk_start, chunk_size);
        (*chunk_sizes)[i] = chunk_size;
    }
    
    return 0;
}

unsigned char* ecc_combine_encrypted_chunks(unsigned char** encrypted_chunks, size_t* encrypted_sizes, int num_chunks, int curve_id, int is_custom, size_t* total_output_size) {
    if (!encrypted_chunks || !encrypted_sizes || num_chunks <= 0 || !total_output_size) return NULL;
    
    // Calculate total size needed
    size_t total_size = 0;
    for (int i = 0; i < num_chunks; i++) {
        total_size += sizeof(ecc_chunk_header_t) + encrypted_sizes[i];
    }
    
    unsigned char* combined = (unsigned char*)malloc(total_size);
    if (!combined) return NULL;
    
    size_t offset = 0;
    for (int i = 0; i < num_chunks; i++) {
        // Create chunk header
        ecc_chunk_header_t header;
        header.magic = ECC_CHUNK_MAGIC;
        header.chunk_index = i;
        header.total_chunks = num_chunks;
        header.original_size = 0; // Will be filled during decryption
        header.encrypted_size = encrypted_sizes[i];
        header.curve_id = curve_id;
        header.implementation_type = is_custom ? 1 : 0;
        header.reserved[0] = 0;
        
        // Copy header and encrypted data
        memcpy(combined + offset, &header, sizeof(ecc_chunk_header_t));
        offset += sizeof(ecc_chunk_header_t);
        
        memcpy(combined + offset, encrypted_chunks[i], encrypted_sizes[i]);
        offset += encrypted_sizes[i];
    }
    
    *total_output_size = total_size;
    return combined;
}

int ecc_extract_chunks_from_encrypted(const unsigned char* encrypted_data, size_t encrypted_size, unsigned char*** chunks, size_t** chunk_sizes, int* num_chunks, ecc_chunk_header_t* first_header) {
    if (!encrypted_data || !chunks || !chunk_sizes || !num_chunks) return -1;
    
    // Read first header to get total number of chunks
    if (encrypted_size < sizeof(ecc_chunk_header_t)) return -1;
    
    ecc_chunk_header_t header;
    memcpy(&header, encrypted_data, sizeof(ecc_chunk_header_t));
    
    if (header.magic != ECC_CHUNK_MAGIC) return -1;
    
    *num_chunks = header.total_chunks;
    if (first_header) *first_header = header;
    
    *chunks = (unsigned char**)malloc(*num_chunks * sizeof(unsigned char*));
    *chunk_sizes = (size_t*)malloc(*num_chunks * sizeof(size_t));
    
    if (!*chunks || !*chunk_sizes) {
        free(*chunks);
        free(*chunk_sizes);
        return -1;
    }
    
    size_t offset = 0;
    for (int i = 0; i < *num_chunks; i++) {
        if (offset + sizeof(ecc_chunk_header_t) > encrypted_size) {
            // Clean up and return error
            for (int j = 0; j < i; j++) {
                free((*chunks)[j]);
            }
            free(*chunks);
            free(*chunk_sizes);
            return -1;
        }
        
        memcpy(&header, encrypted_data + offset, sizeof(ecc_chunk_header_t));
        offset += sizeof(ecc_chunk_header_t);
        
        if (header.chunk_index != i || header.magic != ECC_CHUNK_MAGIC) {
            // Chunk order/integrity error
            for (int j = 0; j < i; j++) {
                free((*chunks)[j]);
            }
            free(*chunks);
            free(*chunk_sizes);
            return -1;
        }
        
        if (offset + header.encrypted_size > encrypted_size) {
            // Not enough data
            for (int j = 0; j < i; j++) {
                free((*chunks)[j]);
            }
            free(*chunks);
            free(*chunk_sizes);
            return -1;
        }
        
        (*chunks)[i] = (unsigned char*)malloc(header.encrypted_size);
        if (!(*chunks)[i]) {
            // Memory allocation failed
            for (int j = 0; j < i; j++) {
                free((*chunks)[j]);
            }
            free(*chunks);
            free(*chunk_sizes);
            return -1;
        }
        
        memcpy((*chunks)[i], encrypted_data + offset, header.encrypted_size);
        (*chunk_sizes)[i] = header.encrypted_size;
        offset += header.encrypted_size;
    }
    
    return 0;
} 