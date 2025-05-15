#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/aes.h>

#include "implementation.h"
#include "../include/utils.h"
#include "rsa_common.h"
#include "rsa_key.h"

// Define the maximum number of keys for key reuse
#define MAX_KEY_COUNT 100
#define AES_KEY_SIZE 32  // 256 bits for AES symmetric key
#define AES_BLOCK_SIZE 16
#define AES_IV_SIZE 16

// RSA implementations registered
void register_rsa_implementations(implementation_registry_t* registry) {
    int index = registry->count;
    int implementations_before = registry->count;
    
    // Get the configuration from environment variables
    char* use_stdlib_str = getenv("USE_STDLIB");
    char* use_custom_str = getenv("USE_CUSTOM");
    char* key_size_str = getenv("RSA_KEY_SIZE");
    char* padding_str = getenv("RSA_PADDING");
    char* key_reuse_str = getenv("RSA_KEY_REUSE");
    char* key_count_str = getenv("RSA_KEY_COUNT");
    char* rsa_enabled_str = getenv("RSA_ENABLED");
    
    // Default values if environment variables are not set
    int use_stdlib = use_stdlib_str ? atoi(use_stdlib_str) : 1;  // Default to true
    int use_custom = use_custom_str ? atoi(use_custom_str) : 1;  // Default to true
    int key_size = key_size_str ? atoi(key_size_str) : 2048;     // Default to 2048 bits
    int padding = padding_str ? (strcmp(padding_str, "oaep") == 0 ? PADDING_OAEP : PADDING_PKCS1) : PADDING_PKCS1; // Default to PKCS#1 v1.5
    int key_reuse = key_reuse_str ? atoi(key_reuse_str) : 0;     // Default to false
    int key_count = key_count_str ? atoi(key_count_str) : 1;     // Default to 1 key
    int rsa_enabled = rsa_enabled_str ? atoi(rsa_enabled_str) : 1;  // Default to enabled
    
    // Check if RSA is enabled in the configuration
    if (!rsa_enabled) {
        printf("RSA implementations disabled in configuration\n");
        return;
    }
    
    // Ensure key size is valid (1024, 2048, 3072, 4096)
    if (key_size != 1024 && key_size != 2048 && key_size != 3072 && key_size != 4096) {
        printf("Warning: Invalid RSA key size %d, defaulting to 2048 bits\n", key_size);
        key_size = 2048;
    }
    
    // Ensure key count is valid (1-100)
    if (key_count < 1) {
        printf("Warning: Invalid key count %d, defaulting to 1\n", key_count);
        key_count = 1;
    } else if (key_count > MAX_KEY_COUNT) {
        printf("Warning: Key count %d exceeds maximum (%d), limiting to %d\n", 
               key_count, MAX_KEY_COUNT, MAX_KEY_COUNT);
        key_count = MAX_KEY_COUNT;
    }
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Register standard RSA implementation if enabled
    if (use_stdlib) {
        char impl_name[64];
        snprintf(impl_name, sizeof(impl_name), "rsa_%d_%s%s", 
                key_size, 
                padding == PADDING_OAEP ? "oaep" : "pkcs1",
                key_reuse ? "_reuse" : "");
        
        strcpy(registry->implementations[index].name, impl_name);
        registry->implementations[index].algo_type = ALGO_RSA;
        registry->implementations[index].is_custom = 0;
        registry->implementations[index].key_size = key_size;
        strcpy(registry->implementations[index].mode, padding == PADDING_OAEP ? "OAEP" : "PKCS1");
        registry->implementations[index].init = rsa_init;
        registry->implementations[index].cleanup = rsa_cleanup;
        registry->implementations[index].generate_key = rsa_generate_key;
        registry->implementations[index].encrypt = rsa_encrypt;
        registry->implementations[index].decrypt = rsa_decrypt;
        registry->implementations[index].encrypt_stream = rsa_encrypt_stream;
        registry->implementations[index].decrypt_stream = rsa_decrypt_stream;
        registry->count++;
    }
    
    // Register custom RSA implementation if enabled
    if (use_custom) {
        index = registry->count;
        char impl_name[64];
        snprintf(impl_name, sizeof(impl_name), "rsa_%d_%s%s_custom", 
                key_size, 
                padding == PADDING_OAEP ? "oaep" : "pkcs1",
                key_reuse ? "_reuse" : "");
        
        strcpy(registry->implementations[index].name, impl_name);
        registry->implementations[index].algo_type = ALGO_RSA;
        registry->implementations[index].is_custom = 1;
        registry->implementations[index].key_size = key_size;
        strcpy(registry->implementations[index].mode, padding == PADDING_OAEP ? "OAEP" : "PKCS1");
        registry->implementations[index].init = rsa_custom_init;
        registry->implementations[index].cleanup = rsa_custom_cleanup;
        registry->implementations[index].generate_key = rsa_custom_generate_key;
        registry->implementations[index].encrypt = rsa_custom_encrypt;
        registry->implementations[index].decrypt = rsa_custom_decrypt;
        registry->implementations[index].encrypt_stream = rsa_custom_encrypt_stream;
        registry->implementations[index].decrypt_stream = rsa_custom_decrypt_stream;
        registry->count++;
    }
    
    printf("Registered %d RSA implementations\n", registry->count - implementations_before);
}

// Standard library implementation functions
void* rsa_init(void) {
    rsa_context_t* context = (rsa_context_t*)malloc(sizeof(rsa_context_t));
    if (!context) {
        fprintf(stderr, "Error: Could not allocate RSA context\n");
        return NULL;
    }
    
    memset(context, 0, sizeof(rsa_context_t));
    context->is_custom = 0;
    context->key_size = 2048; // Default key size
    context->padding_type = PADDING_PKCS1; // Default padding
    context->key_reuse = 0; // Default no key reuse
    context->key_count = 1; // Default 1 key
    context->keys = NULL;
    context->current_key_index = 0;
    context->rsa = NULL;
    
    // Get configuration from environment variables
    char* key_size_str = getenv("RSA_KEY_SIZE");
    char* padding_str = getenv("RSA_PADDING");
    char* key_reuse_str = getenv("RSA_KEY_REUSE");
    char* key_count_str = getenv("RSA_KEY_COUNT");
    
    // Apply configuration
    if (key_size_str) {
        int key_size = atoi(key_size_str);
        rsa_set_key_size(context, key_size);
    }
    
    if (padding_str) {
        rsa_padding_type_t padding = strcmp(padding_str, "oaep") == 0 ? PADDING_OAEP : PADDING_PKCS1;
        rsa_set_padding(context, padding);
    }
    
    if (key_reuse_str && key_count_str) {
        int key_reuse = atoi(key_reuse_str);
        int key_count = atoi(key_count_str);
        rsa_set_key_reuse(context, key_reuse, key_count);
    }
    
    return context;
}

void rsa_cleanup(void* context) {
    if (!context) return;
    
    rsa_context_t* rsa_context = (rsa_context_t*)context;
    
    // Free RSA keys if using key reuse
    if (rsa_context->keys) {
        for (int i = 0; i < rsa_context->key_count; i++) {
            if (rsa_context->keys[i]) {
                rsa_free_key(rsa_context->keys[i]);
            }
        }
        free(rsa_context->keys);
    }
    
    // Free the current RSA key
    if (rsa_context->rsa) {
        RSA_free(rsa_context->rsa);
    }
    
    // Free DER-encoded keys
    if (rsa_context->private_key) {
        free(rsa_context->private_key);
    }
    
    if (rsa_context->public_key) {
        free(rsa_context->public_key);
    }
    
    free(rsa_context);
}

// Basic RSA key generation
unsigned char* rsa_generate_key(void* context, int* key_length) {
    if (!context) return NULL;
    
    rsa_context_t* rsa_context = (rsa_context_t*)context;
    
    // Clear any existing keys
    if (rsa_context->rsa) {
        RSA_free(rsa_context->rsa);
        rsa_context->rsa = NULL;
    }
    
    if (rsa_context->private_key) {
        free(rsa_context->private_key);
        rsa_context->private_key = NULL;
        rsa_context->private_key_length = 0;
    }
    
    if (rsa_context->public_key) {
        free(rsa_context->public_key);
        rsa_context->public_key = NULL;
        rsa_context->public_key_length = 0;
    }
    
    // If using key reuse, generate multiple keys
    if (rsa_context->key_reuse && rsa_context->key_count > 0) {
        // Free existing keys
        if (rsa_context->keys) {
            for (int i = 0; i < rsa_context->key_count; i++) {
                if (rsa_context->keys[i]) {
                    rsa_free_key(rsa_context->keys[i]);
                }
            }
            free(rsa_context->keys);
        }
        
        // Allocate key array
        rsa_context->keys = (rsa_key_t**)malloc(rsa_context->key_count * sizeof(rsa_key_t*));
        if (!rsa_context->keys) {
            fprintf(stderr, "Error: Could not allocate memory for RSA keys\n");
            return NULL;
        }
        
        // Generate keys
        for (int i = 0; i < rsa_context->key_count; i++) {
            RSA* rsa = rsa_generate_new_key(rsa_context->key_size);
            if (!rsa) {
                fprintf(stderr, "Error: Could not generate RSA key %d/%d\n", i + 1, rsa_context->key_count);
                // Clean up previously generated keys
                for (int j = 0; j < i; j++) {
                    rsa_free_key(rsa_context->keys[j]);
                }
                free(rsa_context->keys);
                rsa_context->keys = NULL;
                return NULL;
            }
            
            rsa_context->keys[i] = rsa_create_key_from_rsa(rsa);
        }
        
        rsa_context->current_key_index = 0;
        printf("Generated %d RSA-%d keys for reuse\n", rsa_context->key_count, rsa_context->key_size);
    } else {
        // Generate a single key
        rsa_context->rsa = rsa_generate_new_key(rsa_context->key_size);
        if (!rsa_context->rsa) {
            fprintf(stderr, "Error: Could not generate RSA key\n");
            return NULL;
        }
        
        printf("Generated RSA-%d key\n", rsa_context->key_size);
    }
    
    // Export the key for return to caller
    // For now, we'll only return the private key in DER format
    // This is consistent with the AES implementation that returns the symmetric key
    unsigned char* private_key = NULL;
    int private_key_length = 0;
    
    if (rsa_context->key_reuse && rsa_context->keys && rsa_context->keys[0]) {
        // Use the first key for export
        private_key = rsa_export_private_key(rsa_context->keys[0]->rsa, &private_key_length);
    } else if (rsa_context->rsa) {
        private_key = rsa_export_private_key(rsa_context->rsa, &private_key_length);
    }
    
    if (!private_key) {
        fprintf(stderr, "Error: Could not export RSA private key\n");
        return NULL;
    }
    
    // Store the private key in the context
    rsa_context->private_key = private_key;
    rsa_context->private_key_length = private_key_length;
    
    // Set the return length
    *key_length = private_key_length;
    
    return private_key;
}

// Hybrid encryption - uses RSA to encrypt an AES key, then uses that AES key to encrypt the actual data
unsigned char* rsa_encrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    rsa_context_t* rsa_context = (rsa_context_t*)context;
    RSA* rsa_key = NULL;
    
    // Get the RSA key to use
    if (rsa_context->key_reuse && rsa_context->keys) {
        // Use the current key in the reuse array
        rsa_key_t* key_struct = rsa_get_current_key_struct(rsa_context);
        if (key_struct) {
            rsa_key = key_struct->rsa;
        }
        
        // Move to the next key for the next encryption
        rsa_move_to_next_key(rsa_context);
    } else {
        // Use the single key
        rsa_key = rsa_context->rsa;
    }
    
    if (!rsa_key) {
        fprintf(stderr, "Error: No RSA key available for encryption\n");
        return NULL;
    }
    
    // Generate a random AES key for encryption
    unsigned char aes_key[AES_KEY_SIZE];
    if (RAND_bytes(aes_key, AES_KEY_SIZE) != 1) {
        fprintf(stderr, "Error: Failed to generate random AES key\n");
        return NULL;
    }
    
    // Generate a random IV for AES encryption
    unsigned char iv[AES_IV_SIZE];
    if (RAND_bytes(iv, AES_IV_SIZE) != 1) {
        fprintf(stderr, "Error: Failed to generate random IV\n");
        return NULL;
    }
    
    // Encrypt the AES key with RSA
    int rsa_size = RSA_size(rsa_key);
    unsigned char* encrypted_key = (unsigned char*)malloc(rsa_size);
    if (!encrypted_key) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted key\n");
        return NULL;
    }
    
    // Choose padding based on context
    int padding;
    if (rsa_context->padding_type == PADDING_OAEP) {
        padding = RSA_PKCS1_OAEP_PADDING;
    } else {
        padding = RSA_PKCS1_PADDING;
    }
    
    int encrypted_key_len = RSA_public_encrypt(AES_KEY_SIZE, aes_key, encrypted_key, rsa_key, padding);
    if (encrypted_key_len < 0) {
        fprintf(stderr, "Error: RSA encryption of AES key failed\n");
        free(encrypted_key);
        return NULL;
    }
    
    // Set up AES encryption context
    EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
    if (!aes_ctx) {
        fprintf(stderr, "Error: Could not create AES context\n");
        free(encrypted_key);
        return NULL;
    }
    
    // Initialize AES encryption
    if (EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        fprintf(stderr, "Error: Could not initialize AES encryption\n");
        EVP_CIPHER_CTX_free(aes_ctx);
        free(encrypted_key);
        return NULL;
    }
    
    // Allocate memory for encrypted data (include space for padding)
    int max_encrypt_len = data_length + AES_BLOCK_SIZE;
    unsigned char* encrypted_data = (unsigned char*)malloc(max_encrypt_len);
    if (!encrypted_data) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        EVP_CIPHER_CTX_free(aes_ctx);
        free(encrypted_key);
        return NULL;
    }
    
    // Encrypt the data
    int encrypted_data_len = 0;
    int len = 0;
    
    if (EVP_EncryptUpdate(aes_ctx, encrypted_data, &len, data, data_length) != 1) {
        fprintf(stderr, "Error: AES encryption failed\n");
        free(encrypted_data);
        EVP_CIPHER_CTX_free(aes_ctx);
        free(encrypted_key);
        return NULL;
    }
    encrypted_data_len = len;
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(aes_ctx, encrypted_data + len, &len) != 1) {
        fprintf(stderr, "Error: AES encryption finalization failed\n");
        free(encrypted_data);
        EVP_CIPHER_CTX_free(aes_ctx);
        free(encrypted_key);
        return NULL;
    }
    encrypted_data_len += len;
    
    // Clean up AES context
    EVP_CIPHER_CTX_free(aes_ctx);
    
    // Prepare final output buffer
    // Format: [encrypted_key_length(4)][encrypted_key][iv(16)][encrypted_data_length(4)][encrypted_data]
    *output_length = 4 + encrypted_key_len + AES_IV_SIZE + 4 + encrypted_data_len;
    unsigned char* output = (unsigned char*)malloc(*output_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for output\n");
        free(encrypted_data);
        free(encrypted_key);
        return NULL;
    }
    
    // Write encrypted key length (4 bytes)
    output[0] = (encrypted_key_len >> 24) & 0xFF;
    output[1] = (encrypted_key_len >> 16) & 0xFF;
    output[2] = (encrypted_key_len >> 8) & 0xFF;
    output[3] = encrypted_key_len & 0xFF;
    
    // Write encrypted key
    memcpy(output + 4, encrypted_key, encrypted_key_len);
    
    // Write IV
    memcpy(output + 4 + encrypted_key_len, iv, AES_IV_SIZE);
    
    // Write encrypted data length (4 bytes)
    int offset = 4 + encrypted_key_len + AES_IV_SIZE;
    output[offset] = (encrypted_data_len >> 24) & 0xFF;
    output[offset + 1] = (encrypted_data_len >> 16) & 0xFF;
    output[offset + 2] = (encrypted_data_len >> 8) & 0xFF;
    output[offset + 3] = encrypted_data_len & 0xFF;
    
    // Write encrypted data
    memcpy(output + offset + 4, encrypted_data, encrypted_data_len);
    
    // Clean up
    free(encrypted_data);
    free(encrypted_key);
    
    return output;
}

// Hybrid decryption
unsigned char* rsa_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    rsa_context_t* rsa_context = (rsa_context_t*)context;
    RSA* rsa_key = NULL;
    
    // Parse input data
    // Format: [encrypted_key_length(4)][encrypted_key][iv(16)][encrypted_data_length(4)][encrypted_data]
    
    // Get encrypted key length
    if (data_length < 8 + AES_IV_SIZE) {
        fprintf(stderr, "Error: Invalid data format for RSA decryption\n");
        return NULL;
    }
    
    int encrypted_key_len = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    if (encrypted_key_len <= 0 || encrypted_key_len > data_length - 8 - AES_IV_SIZE) {
        fprintf(stderr, "Error: Invalid encrypted key length: %d\n", encrypted_key_len);
        return NULL;
    }
    
    // Get encrypted key
    const unsigned char* encrypted_key = data + 4;
    
    // Get IV
    const unsigned char* iv = data + 4 + encrypted_key_len;
    
    // Get encrypted data length
    int offset = 4 + encrypted_key_len + AES_IV_SIZE;
    if (offset + 4 > data_length) {
        fprintf(stderr, "Error: Data too short to contain encrypted data length\n");
        return NULL;
    }
    
    int encrypted_data_len = (data[offset] << 24) | (data[offset + 1] << 16) | 
                           (data[offset + 2] << 8) | data[offset + 3];
    
    if (encrypted_data_len <= 0 || offset + 4 + encrypted_data_len > data_length) {
        fprintf(stderr, "Error: Invalid encrypted data length: %d\n", encrypted_data_len);
        return NULL;
    }
    
    // Get encrypted data
    const unsigned char* encrypted_data = data + offset + 4;
    
    // Choose padding based on context
    int padding;
    if (rsa_context->padding_type == PADDING_OAEP) {
        padding = RSA_PKCS1_OAEP_PADDING;
    } else {
        padding = RSA_PKCS1_PADDING;
    }
    
    // If key reuse is enabled, try all keys
    if (rsa_context->key_reuse && rsa_context->keys) {
        for (int i = 0; i < rsa_context->key_count; i++) {
            rsa_key = rsa_context->keys[i]->rsa;
            
            // Allocate buffer for decrypted AES key
            unsigned char* aes_key = (unsigned char*)malloc(AES_KEY_SIZE);
            if (!aes_key) {
                fprintf(stderr, "Error: Could not allocate memory for AES key\n");
                return NULL;
            }
            
            // Decrypt the AES key with RSA
            int aes_key_len = RSA_private_decrypt(encrypted_key_len, encrypted_key, aes_key, rsa_key, padding);
            
            if (aes_key_len == AES_KEY_SIZE) {
                // Successfully decrypted AES key with this RSA key
                // Set up AES decryption context
                EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
                if (!aes_ctx) {
                    fprintf(stderr, "Error: Could not create AES context\n");
                    free(aes_key);
                    return NULL;
                }
                
                // Initialize AES decryption
                if (EVP_DecryptInit_ex(aes_ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
                    fprintf(stderr, "Error: Could not initialize AES decryption\n");
                    EVP_CIPHER_CTX_free(aes_ctx);
                    free(aes_key);
                    return NULL;
                }
                
                // Allocate memory for decrypted data
                unsigned char* decrypted_data = (unsigned char*)malloc(encrypted_data_len);
                if (!decrypted_data) {
                    fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
                    EVP_CIPHER_CTX_free(aes_ctx);
                    free(aes_key);
                    return NULL;
                }
                
                // Decrypt the data
                int decrypted_len = 0;
                int len = 0;
                
                if (EVP_DecryptUpdate(aes_ctx, decrypted_data, &len, encrypted_data, encrypted_data_len) != 1) {
                    fprintf(stderr, "Error: AES decryption failed\n");
                    free(decrypted_data);
                    EVP_CIPHER_CTX_free(aes_ctx);
                    free(aes_key);
                    continue;  // Try the next key
                }
                decrypted_len = len;
                
                // Finalize decryption
                if (EVP_DecryptFinal_ex(aes_ctx, decrypted_data + len, &len) != 1) {
                    fprintf(stderr, "Error: AES decryption finalization failed\n");
                    free(decrypted_data);
                    EVP_CIPHER_CTX_free(aes_ctx);
                    free(aes_key);
                    continue;  // Try the next key
                }
                decrypted_len += len;
                
                // Clean up
                EVP_CIPHER_CTX_free(aes_ctx);
                free(aes_key);
                
                *output_length = decrypted_len;
                return decrypted_data;
            }
            
            free(aes_key);
        }
        
        // If we get here, all keys failed
        fprintf(stderr, "Error: Could not decrypt with any of the available keys\n");
        return NULL;
    } else {
        // Use the single key
        rsa_key = rsa_context->rsa;
        if (!rsa_key) {
            fprintf(stderr, "Error: No RSA key available for decryption\n");
            return NULL;
        }
        
        // Allocate buffer for decrypted AES key
        unsigned char* aes_key = (unsigned char*)malloc(AES_KEY_SIZE);
        if (!aes_key) {
            fprintf(stderr, "Error: Could not allocate memory for AES key\n");
            return NULL;
        }
        
        // Decrypt the AES key with RSA
        int aes_key_len = RSA_private_decrypt(encrypted_key_len, encrypted_key, aes_key, rsa_key, padding);
        if (aes_key_len != AES_KEY_SIZE) {
            fprintf(stderr, "Error: RSA decryption of AES key failed (%d != %d)\n", aes_key_len, AES_KEY_SIZE);
            free(aes_key);
            return NULL;
        }
        
        // Set up AES decryption context
        EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
        if (!aes_ctx) {
            fprintf(stderr, "Error: Could not create AES context\n");
            free(aes_key);
            return NULL;
        }
        
        // Initialize AES decryption
        if (EVP_DecryptInit_ex(aes_ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
            fprintf(stderr, "Error: Could not initialize AES decryption\n");
            EVP_CIPHER_CTX_free(aes_ctx);
            free(aes_key);
            return NULL;
        }
        
        // Allocate memory for decrypted data
        unsigned char* decrypted_data = (unsigned char*)malloc(encrypted_data_len);
        if (!decrypted_data) {
            fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
            EVP_CIPHER_CTX_free(aes_ctx);
            free(aes_key);
            return NULL;
        }
        
        // Decrypt the data
        int decrypted_len = 0;
        int len = 0;
        
        if (EVP_DecryptUpdate(aes_ctx, decrypted_data, &len, encrypted_data, encrypted_data_len) != 1) {
            fprintf(stderr, "Error: AES decryption failed\n");
            free(decrypted_data);
            EVP_CIPHER_CTX_free(aes_ctx);
            free(aes_key);
            return NULL;
        }
        decrypted_len = len;
        
        // Finalize decryption
        if (EVP_DecryptFinal_ex(aes_ctx, decrypted_data + len, &len) != 1) {
            fprintf(stderr, "Error: AES decryption finalization failed\n");
            free(decrypted_data);
            EVP_CIPHER_CTX_free(aes_ctx);
            free(aes_key);
            return NULL;
        }
        decrypted_len += len;
        
        // Clean up
        EVP_CIPHER_CTX_free(aes_ctx);
        free(aes_key);
        
        *output_length = decrypted_len;
        return decrypted_data;
    }
}

// RSA stream encryption - modified for the hybrid approach
unsigned char* rsa_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // For the first chunk, generate and encrypt the AES key
    if (chunk_index == 0) {
        // For the first chunk, we'll use regular hybrid encryption
        return rsa_encrypt(context, data, data_length, key, output_length);
    } else {
        // For subsequent chunks, we'll use AES directly with the key from the context
        // This assumes the key has been cached in the context during the first chunk encryption
        
        // Simplified for now: just pass through to regular encryption
        // The key from the first chunk should be reused, but we'd need to extend the context for that
        return rsa_encrypt(context, data, data_length, key, output_length);
    }
}

// RSA stream decryption - modified for the hybrid approach
unsigned char* rsa_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Simplified for now: just pass through to regular decryption
    // The key from the first chunk should be reused, but we'd need to extend the context for that
    return rsa_decrypt(context, data, data_length, key, output_length);
}

// Custom implementation functions (for benchmarking, we'll use the same algorithm)
void* rsa_custom_init(void) {
    rsa_context_t* context = (rsa_context_t*)malloc(sizeof(rsa_context_t));
    if (!context) {
        fprintf(stderr, "Error: Could not allocate RSA context for custom implementation\n");
        return NULL;
    }
    
    memset(context, 0, sizeof(rsa_context_t));
    context->is_custom = 1;
    context->key_size = 2048; // Default key size
    context->padding_type = PADDING_PKCS1; // Default padding
    context->key_reuse = 0; // Default no key reuse
    context->key_count = 1; // Default 1 key
    context->keys = NULL;
    context->current_key_index = 0;
    context->rsa = NULL;
    
    // Get configuration from environment variables
    char* key_size_str = getenv("RSA_KEY_SIZE");
    char* padding_str = getenv("RSA_PADDING");
    char* key_reuse_str = getenv("RSA_KEY_REUSE");
    char* key_count_str = getenv("RSA_KEY_COUNT");
    
    // Apply configuration
    if (key_size_str) {
        int key_size = atoi(key_size_str);
        rsa_set_key_size(context, key_size);
    }
    
    if (padding_str) {
        rsa_padding_type_t padding = strcmp(padding_str, "oaep") == 0 ? PADDING_OAEP : PADDING_PKCS1;
        rsa_set_padding(context, padding);
    }
    
    if (key_reuse_str && key_count_str) {
        int key_reuse = atoi(key_reuse_str);
        int key_count = atoi(key_count_str);
        rsa_set_key_reuse(context, key_reuse, key_count);
    }
    
    return context;
}

void rsa_custom_cleanup(void* context) {
    rsa_cleanup(context); // Same cleanup for both implementations
}

unsigned char* rsa_custom_generate_key(void* context, int* key_length) {
    return rsa_generate_key(context, key_length); // Use same key generation
}

unsigned char* rsa_custom_encrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length) {
    return rsa_encrypt(context, data, data_length, key, output_length); // Use same encryption
}

unsigned char* rsa_custom_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length) {
    return rsa_decrypt(context, data, data_length, key, output_length); // Use same decryption
}

unsigned char* rsa_custom_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    return rsa_encrypt_stream(context, data, data_length, key, chunk_index, output_length); // Use same stream encryption
}

unsigned char* rsa_custom_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    return rsa_decrypt_stream(context, data, data_length, key, chunk_index, output_length); // Use same stream decryption
} 