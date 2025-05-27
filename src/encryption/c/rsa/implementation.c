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
#include "../include/crypto_utils.h"
#include "rsa_common.h"
#include "rsa_key.h"


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
    char* rsa_enabled_str = getenv("RSA_ENABLED");
    
    // Default values if environment variables are not set
    int use_stdlib = use_stdlib_str ? atoi(use_stdlib_str) : 1;  // Default to true
    int use_custom = use_custom_str ? atoi(use_custom_str) : 1;  // Default to true
    int key_size = key_size_str ? atoi(key_size_str) : 2048;     // Default to 2048 bits
    int padding = padding_str ? (strcmp(padding_str, "oaep") == 0 ? PADDING_OAEP : PADDING_PKCS1) : PADDING_PKCS1; // Default to PKCS#1 v1.5
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
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Register standard RSA implementation if enabled
    if (use_stdlib) {
        char impl_name[64];
        snprintf(impl_name, sizeof(impl_name), "rsa_%d_%s", 
                key_size, 
                padding == PADDING_OAEP ? "oaep" : "pkcs1");
        
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
        snprintf(impl_name, sizeof(impl_name), "rsa_%d_%s_custom", 
                key_size, 
                padding == PADDING_OAEP ? "oaep" : "pkcs1");
        
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
    context->rsa = NULL;
    context->private_key = NULL;
    context->private_key_length = 0;
    context->public_key = NULL;
    context->public_key_length = 0;
    
    // Get configuration from environment variables
    char* key_size_str = getenv("RSA_KEY_SIZE");
    char* padding_str = getenv("RSA_PADDING");
    
    // Apply configuration
    if (key_size_str) {
        int key_size = atoi(key_size_str);
        rsa_set_key_size(context, key_size);
    }
    
    if (padding_str) {
        rsa_padding_type_t padding = strcmp(padding_str, "oaep") == 0 ? PADDING_OAEP : PADDING_PKCS1;
        rsa_set_padding(context, padding);
    }
    
    return context;
}

void rsa_cleanup(void* context) {
    if (!context) return;
    
    rsa_context_t* rsa_context = (rsa_context_t*)context;
    
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
    
    // Generate a single key
    rsa_context->rsa = rsa_generate_new_key(rsa_context->key_size);
    if (!rsa_context->rsa) {
        fprintf(stderr, "Error: Could not generate RSA key\n");
        return NULL;
    }
    
    printf("Generated RSA-%d key\n", rsa_context->key_size);
    
    // Export the key for return to caller
    // For now, we'll only return the private key in DER format
    // This is consistent with the AES implementation that returns the symmetric key
    unsigned char* private_key = NULL;
    int private_key_length = 0;
    
    private_key = rsa_export_private_key(rsa_context->rsa, &private_key_length);
    
    if (!private_key) {
        fprintf(stderr, "Error: Could not export RSA private key\n");
        return NULL;
    }
    
    // Store the private key in the context
    rsa_context->private_key = private_key;
    rsa_context->private_key_length = private_key_length;
    
    // Also store the public key for encryption
    rsa_context->public_key = rsa_export_public_key(rsa_context->rsa, &rsa_context->public_key_length);
    
    // Set the return length
    *key_length = private_key_length;
    
    return private_key;
}

// Hybrid encryption - uses RSA to encrypt an AES key, then uses that AES key to encrypt the actual data
unsigned char* rsa_encrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    rsa_context_t* rsa_context = (rsa_context_t*)context;
    
    // For public key encryption, we use a hybrid approach due to RSA size limitations
    // 1. Generate a random AES key
    // 2. Encrypt the data with AES
    // 3. Encrypt the AES key with RSA
    // 4. Combine the encrypted key and data
    
    // Generate a random AES key (256 bits)
    unsigned char* aes_key = (unsigned char*)crypto_secure_alloc(AES_KEY_SIZE);
    if (!aes_key) {
        fprintf(stderr, "Error: Could not allocate memory for AES key\n");
        return NULL;
    }
    
    if (!crypto_random_bytes(aes_key, AES_KEY_SIZE)) {
        fprintf(stderr, "Error: Failed to generate random AES key\n");
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        return NULL;
    }
    
    // Generate random IV
    unsigned char* iv = (unsigned char*)crypto_secure_alloc(AES_IV_SIZE);
    if (!iv) {
        fprintf(stderr, "Error: Could not allocate memory for IV\n");
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        return NULL;
    }
    
    if (!crypto_random_bytes(iv, AES_IV_SIZE)) {
        fprintf(stderr, "Error: Failed to generate random IV\n");
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        crypto_secure_free(iv, AES_IV_SIZE);
        return NULL;
    }
    
    // Calculate tag size for authentication
    int tag_size = 16; // 16 bytes (128 bits) for authentication tag
    
    // Use OpenSSL for AES encryption
    EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
    if (!aes_ctx) {
        fprintf(stderr, "Error: Could not create AES context\n");
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        crypto_secure_free(iv, AES_IV_SIZE);
        return NULL;
    }
    
    if (EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        fprintf(stderr, "Error: Could not initialize AES encryption\n");
        EVP_CIPHER_CTX_free(aes_ctx);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        crypto_secure_free(iv, AES_IV_SIZE);
        return NULL;
    }
    
    // Allocate memory for encrypted data (with padding)
    int aes_data_len = data_length + AES_BLOCK_SIZE;
    unsigned char* aes_data = (unsigned char*)crypto_secure_alloc(aes_data_len);
    if (!aes_data) {
        fprintf(stderr, "Error: Could not allocate memory for AES data\n");
        EVP_CIPHER_CTX_free(aes_ctx);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        crypto_secure_free(iv, AES_IV_SIZE);
        return NULL;
    }
    
    // Encrypt the data with AES
    int len = 0;
    if (EVP_EncryptUpdate(aes_ctx, aes_data, &len, data, data_length) != 1) {
        fprintf(stderr, "Error: AES encryption failed\n");
        crypto_secure_free(aes_data, aes_data_len);
        EVP_CIPHER_CTX_free(aes_ctx);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        crypto_secure_free(iv, AES_IV_SIZE);
        return NULL;
    }
    aes_data_len = len;
    
    // Finalize AES encryption
    if (EVP_EncryptFinal_ex(aes_ctx, aes_data + len, &len) != 1) {
        fprintf(stderr, "Error: AES encryption finalization failed\n");
        crypto_secure_free(aes_data, aes_data_len);
        EVP_CIPHER_CTX_free(aes_ctx);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        crypto_secure_free(iv, AES_IV_SIZE);
        return NULL;
    }
    aes_data_len += len;
    
    // Clean up AES context
    EVP_CIPHER_CTX_free(aes_ctx);
    
    // Generate authentication tag for the encrypted data
    unsigned char* tag = (unsigned char*)crypto_secure_alloc(tag_size);
    if (!tag) {
        fprintf(stderr, "Error: Could not allocate memory for authentication tag\n");
        crypto_secure_free(aes_data, aes_data_len);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        crypto_secure_free(iv, AES_IV_SIZE);
        return NULL;
    }
    
    if (!crypto_generate_authentication_tag(tag, tag_size, aes_data, aes_data_len, aes_key, AES_KEY_SIZE)) {
        fprintf(stderr, "Error: Failed to generate authentication tag\n");
        crypto_secure_free(tag, tag_size);
        crypto_secure_free(aes_data, aes_data_len);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        crypto_secure_free(iv, AES_IV_SIZE);
        return NULL;
    }
    
    // Encrypt the AES key with RSA
    // Get or load the RSA key
    RSA* rsa = NULL;
    int should_free_rsa = 0; // Flag to track if we need to free the RSA object
    
    // Use the context's key
    if (rsa_context->rsa) {
        rsa = rsa_context->rsa;
    }
    // If we still don't have a key, try to use the provided key parameter
    else if (!rsa && key && key[0] != '\0') {
        // This might be a DER-encoded key or a file path
        if (strstr((const char*)key, "BEGIN RSA PUBLIC KEY") || strstr((const char*)key, "BEGIN PUBLIC KEY")) {
            // This looks like a PEM format key, not DER
            fprintf(stderr, "Error: PEM format not supported, expected DER\n");
        } else {
            // Try to import the key
            rsa = rsa_import_public_key(key, strlen((const char*)key));
            if (rsa) {
                should_free_rsa = 1; // We'll need to free this later
            }
        }
    }
    
    // If we still don't have a key, error out
    if (!rsa) {
        fprintf(stderr, "Error: No RSA key available for encryption\n");
        crypto_secure_free(tag, tag_size);
        crypto_secure_free(aes_data, aes_data_len);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        crypto_secure_free(iv, AES_IV_SIZE);
        return NULL;
    }
    
    // Encrypt the AES key with RSA
    int rsa_size = RSA_size(rsa);
    unsigned char* encrypted_key = (unsigned char*)crypto_secure_alloc(rsa_size);
    if (!encrypted_key) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted key\n");
        crypto_secure_free(tag, tag_size);
        crypto_secure_free(aes_data, aes_data_len);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        crypto_secure_free(iv, AES_IV_SIZE);
        if (should_free_rsa) RSA_free(rsa);
        return NULL;
    }
    
    int encrypted_key_len = 0;
    
    if (rsa_context->padding_type == PADDING_OAEP) {
        // OAEP padding provides better security
        encrypted_key_len = RSA_public_encrypt(AES_KEY_SIZE, aes_key, encrypted_key, rsa, RSA_PKCS1_OAEP_PADDING);
    } else {
        // PKCS#1 v1.5 padding (default)
        encrypted_key_len = RSA_public_encrypt(AES_KEY_SIZE, aes_key, encrypted_key, rsa, RSA_PKCS1_PADDING);
    }
    
    // We don't need the AES key anymore, securely free it
    crypto_secure_free(aes_key, AES_KEY_SIZE);
    
    if (encrypted_key_len < 0) {
        fprintf(stderr, "Error: RSA encryption failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        crypto_secure_free(tag, tag_size);
        crypto_secure_free(encrypted_key, rsa_size);
        crypto_secure_free(aes_data, aes_data_len);
        crypto_secure_free(iv, AES_IV_SIZE);
        if (should_free_rsa) RSA_free(rsa);
        return NULL;
    }
    
    // Free the RSA object if we created it
    if (should_free_rsa) RSA_free(rsa);
    
    // Combine everything into final output:
    // [RSA key length (4 bytes)][Encrypted RSA key][IV length (4 bytes)][IV]
    // [AES data length (4 bytes)][AES data][Tag length (4 bytes)][Tag]
    
    // Calculate total output size
    int total_length = 4 + encrypted_key_len + 4 + AES_IV_SIZE + 4 + aes_data_len + 4 + tag_size;
    
    // Allocate memory for final output
    unsigned char* output = (unsigned char*)crypto_secure_alloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for final output\n");
        crypto_secure_free(tag, tag_size);
        crypto_secure_free(encrypted_key, rsa_size);
        crypto_secure_free(aes_data, aes_data_len);
        crypto_secure_free(iv, AES_IV_SIZE);
        return NULL;
    }
    
    // Write RSA key length
    *(int*)output = encrypted_key_len;
    
    // Write encrypted RSA key
    memcpy(output + 4, encrypted_key, encrypted_key_len);
    
    // Write IV length
    *(int*)(output + 4 + encrypted_key_len) = AES_IV_SIZE;
    
    // Write IV
    memcpy(output + 4 + encrypted_key_len + 4, iv, AES_IV_SIZE);
    
    // Write AES data length
    *(int*)(output + 4 + encrypted_key_len + 4 + AES_IV_SIZE) = aes_data_len;
    
    // Write AES data
    memcpy(output + 4 + encrypted_key_len + 4 + AES_IV_SIZE + 4, aes_data, aes_data_len);
    
    // Write tag length
    *(int*)(output + 4 + encrypted_key_len + 4 + AES_IV_SIZE + 4 + aes_data_len) = tag_size;
    
    // Write tag
    memcpy(output + 4 + encrypted_key_len + 4 + AES_IV_SIZE + 4 + aes_data_len + 4, tag, tag_size);
    
    // Clean up
    crypto_secure_free(tag, tag_size);
    crypto_secure_free(encrypted_key, rsa_size);
    crypto_secure_free(aes_data, aes_data_len);
    crypto_secure_free(iv, AES_IV_SIZE);
    
    // Set the output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

// Hybrid decryption
unsigned char* rsa_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    rsa_context_t* rsa_context = (rsa_context_t*)context;
    
    // Parse the combined data:
    // [RSA key length (4 bytes)][Encrypted RSA key][IV length (4 bytes)][IV]
    // [AES data length (4 bytes)][AES data][Tag length (4 bytes)][Tag]
    
    int pos = 0;
    
    // Read RSA key length
    if (pos + 4 > data_length) {
        fprintf(stderr, "Error: Invalid data format (RSA key length)\n");
        return NULL;
    }
    int encrypted_key_len = *(int*)(data + pos);
    pos += 4;
    
    // Read encrypted RSA key
    if (pos + encrypted_key_len > data_length) {
        fprintf(stderr, "Error: Invalid data format (encrypted RSA key)\n");
        return NULL;
    }
    const unsigned char* encrypted_key = data + pos;
    pos += encrypted_key_len;
    
    // Read IV length
    if (pos + 4 > data_length) {
        fprintf(stderr, "Error: Invalid data format (IV length)\n");
        return NULL;
    }
    int iv_len = *(int*)(data + pos);
    pos += 4;
    
    // Read IV
    if (pos + iv_len > data_length) {
        fprintf(stderr, "Error: Invalid data format (IV)\n");
        return NULL;
    }
    const unsigned char* iv = data + pos;
    pos += iv_len;
    
    // Read AES data length
    if (pos + 4 > data_length) {
        fprintf(stderr, "Error: Invalid data format (AES data length)\n");
        return NULL;
    }
    int aes_data_len = *(int*)(data + pos);
    pos += 4;
    
    // Read AES data
    if (pos + aes_data_len > data_length) {
        fprintf(stderr, "Error: Invalid data format (AES data)\n");
        return NULL;
    }
    const unsigned char* aes_data = data + pos;
    pos += aes_data_len;
    
    // Read tag length
    if (pos + 4 > data_length) {
        fprintf(stderr, "Error: Invalid data format (tag length)\n");
        return NULL;
    }
    int tag_size = *(int*)(data + pos);
    pos += 4;
    
    // Read tag
    if (pos + tag_size > data_length) {
        fprintf(stderr, "Error: Invalid data format (tag)\n");
        return NULL;
    }
    const unsigned char* tag = data + pos;
    
    // Get or load the RSA key
    RSA* rsa = NULL;
    int should_free_rsa = 0; // Flag to track if we need to free the RSA object
    
    // Use the context's key
    if (rsa_context->rsa) {
        rsa = rsa_context->rsa;
    }
    // If we still don't have a key, try to use the provided key parameter
    else if (!rsa && key && key[0] != '\0') {
        // This might be a DER-encoded key or a file path
        if (strstr((const char*)key, "BEGIN RSA PRIVATE KEY") || strstr((const char*)key, "BEGIN PRIVATE KEY")) {
            // This looks like a PEM format key, not DER
            fprintf(stderr, "Error: PEM format not supported, expected DER\n");
        } else {
            // Try to import the key
            rsa = rsa_import_private_key(key, strlen((const char*)key));
            if (rsa) {
                should_free_rsa = 1; // We'll need to free this later
            }
        }
    }
    // Last resort: try using the private key stored in the context
    else if (!rsa && rsa_context->private_key && rsa_context->private_key_length > 0) {
        rsa = rsa_import_private_key(rsa_context->private_key, rsa_context->private_key_length);
        if (rsa) {
            should_free_rsa = 1;
        }
    }
    
    // If we still don't have a key, error out
    if (!rsa) {
        fprintf(stderr, "Error: No RSA private key available for decryption\n");
        return NULL;
    }
    
    // Decrypt the AES key with RSA
    unsigned char* aes_key = (unsigned char*)crypto_secure_alloc(AES_KEY_SIZE);
    if (!aes_key) {
        fprintf(stderr, "Error: Could not allocate memory for AES key\n");
        if (should_free_rsa) RSA_free(rsa);
        return NULL;
    }
    
    int aes_key_len = 0;
    
    if (rsa_context->padding_type == PADDING_OAEP) {
        // OAEP padding
        aes_key_len = RSA_private_decrypt(encrypted_key_len, encrypted_key, aes_key, rsa, RSA_PKCS1_OAEP_PADDING);
    } else {
        // PKCS#1 v1.5 padding (default)
        aes_key_len = RSA_private_decrypt(encrypted_key_len, encrypted_key, aes_key, rsa, RSA_PKCS1_PADDING);
    }
    
    if (aes_key_len < 0) {
        fprintf(stderr, "Error: RSA decryption failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        if (should_free_rsa) RSA_free(rsa);
        return NULL;
    }
    
    // Free the RSA object if we created it
    if (should_free_rsa) {
        RSA_free(rsa);
        rsa = NULL;
    }
    
    // Verify the authentication tag first
    if (!crypto_verify_authentication_tag(tag, tag_size, aes_data, aes_data_len, aes_key, aes_key_len)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        return NULL; // Fail securely on authentication failure
    }
    
    // Use OpenSSL for AES decryption
    EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
    if (!aes_ctx) {
        fprintf(stderr, "Error: Could not create AES context\n");
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        return NULL;
    }
    
    if (EVP_DecryptInit_ex(aes_ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        fprintf(stderr, "Error: Could not initialize AES decryption\n");
        EVP_CIPHER_CTX_free(aes_ctx);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        return NULL;
    }
    
    // Allocate memory for decrypted data
    unsigned char* output = (unsigned char*)crypto_secure_alloc(aes_data_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        EVP_CIPHER_CTX_free(aes_ctx);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        return NULL;
    }
    
    // Decrypt the data with AES
    int len = 0;
    int output_len = 0;
    
    if (EVP_DecryptUpdate(aes_ctx, output, &len, aes_data, aes_data_len) != 1) {
        fprintf(stderr, "Error: AES decryption failed\n");
        crypto_secure_free(output, aes_data_len);
        EVP_CIPHER_CTX_free(aes_ctx);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        return NULL;
    }
    output_len = len;
    
    // Finalize AES decryption
    if (EVP_DecryptFinal_ex(aes_ctx, output + len, &len) != 1) {
        fprintf(stderr, "Error: AES decryption finalization failed\n");
        crypto_secure_free(output, aes_data_len);
        EVP_CIPHER_CTX_free(aes_ctx);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        return NULL;
    }
    output_len += len;
    
    // Clean up
    EVP_CIPHER_CTX_free(aes_ctx);
    crypto_secure_free(aes_key, AES_KEY_SIZE);
    
    // Set the output length
    if (output_length) {
        *output_length = output_len;
    }
    
    return output;
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

// Custom implementation functions - simplified wrappers for benchmarking
void* rsa_custom_init(void) {
    void* context = rsa_init();
    if (context) {
        ((rsa_context_t*)context)->is_custom = 1;
    }
    return context;
}

void rsa_custom_cleanup(void* context) {
    rsa_cleanup(context);
}

unsigned char* rsa_custom_generate_key(void* context, int* key_length) {
    return rsa_generate_key(context, key_length);
}

unsigned char* rsa_custom_encrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length) {
    return rsa_encrypt(context, data, data_length, key, output_length);
}

unsigned char* rsa_custom_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length) {
    return rsa_decrypt(context, data, data_length, key, output_length);
}

unsigned char* rsa_custom_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    return rsa_encrypt_stream(context, data, data_length, key, chunk_index, output_length);
}

unsigned char* rsa_custom_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    return rsa_decrypt_stream(context, data, data_length, key, chunk_index, output_length);
} 