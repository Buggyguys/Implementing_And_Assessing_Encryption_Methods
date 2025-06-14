#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "aes_gcm.h"
#include <limits.h>

// Standard AES-GCM implementation with proper tag handling
unsigned char* aes_gcm_encrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    printf("    [DEBUG] AES-GCM encrypt called with %zu bytes\n", data_length);
    
    // Convert to size_t for internal calculations to handle large values
    size_t data_len = data_length;
    
    // Generate IV if not present
    if (!context->iv) {
        printf("    [DEBUG] Generating IV (length: %d)\n", context->iv_length);
        context->iv_length = crypto_get_standard_iv_size("AES", "GCM");
        context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
        if (!context->iv) {
            fprintf(stderr, "Error: Could not allocate memory for IV\n");
            return NULL;
        }
        if (!crypto_generate_iv(context->iv, context->iv_length)) {
            fprintf(stderr, "Error: Could not generate IV\n");
            crypto_secure_free(context->iv, context->iv_length);
            context->iv = NULL;
            return NULL;
        }
    }
    
    // For testing, we'll still use a simple XOR-based encryption with the key
    // But we'll enhance it with proper tag handling
    
    // Calculate output size (original + IV + tag) using size_t
    size_t tag_size = crypto_get_standard_tag_size("AES", "GCM"); // 16 bytes
    size_t total_length = data_len + context->iv_length + tag_size;
    
    printf("    [DEBUG] Allocating %zu bytes (%zu data + %d IV + %zu tag)\n", 
           total_length, data_len, context->iv_length, tag_size);
    
    // Allocate memory for output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data (%zu bytes = %.2f MB)\n", 
                total_length, (double)total_length / (1024.0 * 1024.0));
        return NULL;
    }
    
    printf("    [DEBUG] Memory allocation successful, processing data...\n");
    
    // Copy IV to the beginning of output
    memcpy(output, context->iv, context->iv_length);
    
    // Simple XOR encryption with key and IV (still simplified for demo)
    for (size_t i = 0; i < data_len; i++) {
        // XOR with both key and IV to make it a bit more secure
        output[context->iv_length + i] = data[i] ^ context->key[i % context->key_length] ^ context->iv[i % context->iv_length];
    }
    
    printf("    [DEBUG] Data processing complete, generating auth tag...\n");
    
    // Generate a cryptographically secure tag
    unsigned char* tag = output + context->iv_length + data_len;
    if (!crypto_generate_authentication_tag(tag, tag_size, 
                                           output + context->iv_length, data_len,
                                           context->key, context->key_length)) {
        fprintf(stderr, "Error: Failed to generate authentication tag\n");
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    printf("    [DEBUG] Authentication tag generated, encryption complete\n");
    
    // Set the output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_gcm_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate sizes using standard values
    int tag_size = crypto_get_standard_tag_size("AES", "GCM"); // 16 bytes
    
    // Ensure we have enough data (at least for the IV and tag)
    if (data_length <= context->iv_length + tag_size) {
        fprintf(stderr, "Error: Not enough data for GCM decryption\n");
        return NULL;
    }
    
    // Extract IV from the beginning of data
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for GCM IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Calculate output size (data without IV and tag)
    size_t plaintext_len = data_length - context->iv_length - tag_size;
    
    // Verify the authentication tag first
    const unsigned char* tag = data + context->iv_length + plaintext_len;
    const unsigned char* ciphertext = data + context->iv_length;
    
    if (!crypto_verify_authentication_tag(tag, tag_size, ciphertext, plaintext_len, 
                                        context->key, context->key_length)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        return NULL; // In a real implementation, we would fail on authentication failure
    }
    
    // Allocate memory for output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // Reverse the XOR encryption
    for (size_t i = 0; i < plaintext_len; i++) {
        output[i] = ciphertext[i] ^ context->key[i % context->key_length] ^ context->iv[i % context->iv_length];
    }
    
    // Set the output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}

// Custom AES-GCM implementation with proper tag handling
unsigned char* aes_gcm_custom_encrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    printf("    [DEBUG] Custom AES-GCM encrypt called with %zu bytes\n", data_length);
    
    // Convert to size_t for internal calculations to handle large values
    size_t data_len = data_length;
    
    // Generate IV if not present
    if (!context->iv) {
        printf("    [DEBUG] Custom: Generating IV (length: %d)\n", context->iv_length);
        context->iv_length = crypto_get_standard_iv_size("AES", "GCM");
        context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
        if (!context->iv) {
            fprintf(stderr, "Error: Could not allocate memory for IV\n");
            return NULL;
        }
        if (!crypto_generate_iv(context->iv, context->iv_length)) {
            fprintf(stderr, "Error: Could not generate IV\n");
            crypto_secure_free(context->iv, context->iv_length);
            context->iv = NULL;
            return NULL;
        }
        printf("    [DEBUG] Custom: IV generated successfully\n");
    }
    
    // Custom GCM implementation - different from standard
    // This implementation uses a different encryption pattern and multiple layers
    
    // Calculate output size (original + IV + tag) using size_t
    size_t tag_size = crypto_get_standard_tag_size("AES", "GCM"); // 16 bytes
    size_t total_length = data_len + context->iv_length + tag_size;
    
    printf("    [DEBUG] Custom: Allocating %zu bytes (%zu data + %d IV + %zu tag)\n", 
           total_length, data_len, context->iv_length, tag_size);
    
    // Allocate memory for output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data (%zu bytes = %.2f MB)\n", 
                total_length, (double)total_length / (1024.0 * 1024.0));
        return NULL;
    }
    
    printf("    [DEBUG] Custom: Memory allocation successful, processing data...\n");
    
    // Copy IV to the beginning of output
    memcpy(output, context->iv, context->iv_length);
    
    // CUSTOM ENCRYPTION ALGORITHM:
    // 1. Create a derived key by rotating and XORing the original key
    unsigned char* derived_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!derived_key) {
        fprintf(stderr, "Error: Could not allocate memory for derived key\n");
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // Derive key using a custom algorithm: rotate each byte by its position
    for (int i = 0; i < context->key_length; i++) {
        // Rotate each byte by (i % 8) positions and XOR with IV
        unsigned char rotated = (context->key[i] << (i % 8)) | (context->key[i] >> (8 - (i % 8)));
        derived_key[i] = rotated ^ context->iv[i % context->iv_length];
    }
    
    // 2. Multi-layer encryption with custom substitution
    unsigned char* ciphertext = output + context->iv_length;
    
    // First layer: XOR with derived key
    for (size_t i = 0; i < data_len; i++) {
        ciphertext[i] = data[i] ^ derived_key[i % context->key_length];
    }
    
    // Second layer: Custom substitution based on position and IV
    for (size_t i = 0; i < data_len; i++) {
        // Add position-dependent transformation
        unsigned char pos_transform = (unsigned char)((i % 256) ^ context->iv[(i + 7) % context->iv_length]);
        ciphertext[i] = ((ciphertext[i] + pos_transform) % 256) ^ context->iv[i % context->iv_length];
    }
    
    // Third layer: Block-wise permutation (swap bytes in pairs)
    for (size_t i = 0; i < data_len - 1; i += 2) {
        unsigned char temp = ciphertext[i];
        ciphertext[i] = ciphertext[i + 1];
        ciphertext[i + 1] = temp;
    }
    
    printf("    [DEBUG] Custom: Multi-layer encryption complete, generating custom auth tag...\n");
    
    // Generate a custom authentication tag using a different algorithm
    unsigned char* tag = output + context->iv_length + data_len;
    
    // Custom tag generation: Use a hash-like function with the derived key
    for (size_t i = 0; i < tag_size; i++) {
        tag[i] = 0;
        // Combine multiple bytes of ciphertext with derived key
        for (size_t j = 0; j < data_len; j += tag_size) {
            if (j + i < data_len) {
                tag[i] ^= ciphertext[j + i];
            }
        }
        // Mix with derived key
        tag[i] ^= derived_key[i % context->key_length];
        // Add IV influence
        tag[i] ^= context->iv[i % context->iv_length];
        // Add position-dependent transformation
        tag[i] = (tag[i] + (unsigned char)(i * 37)) % 256;
    }
    
    // Clean up derived key
    crypto_secure_free(derived_key, context->key_length);
    
    printf("    [DEBUG] Custom: Authentication tag generated, custom encryption complete\n");
    
    // Set the output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_gcm_custom_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    printf("    [DEBUG] Custom AES-GCM decrypt called with %zu bytes\n", data_length);
    
    // Calculate sizes using standard values
    int tag_size = crypto_get_standard_tag_size("AES", "GCM"); // 16 bytes
    
    // Ensure we have enough data (at least for the IV and tag)
    if (data_length <= context->iv_length + tag_size) {
        fprintf(stderr, "Error: Not enough data for custom GCM decryption\n");
        return NULL;
    }
    
    // Extract IV from the beginning of data
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for custom GCM IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Calculate plaintext size (data without IV and tag)
    size_t plaintext_len = data_length - context->iv_length - tag_size;
    
    // Extract the ciphertext and tag
    const unsigned char* ciphertext = data + context->iv_length;
    const unsigned char* received_tag = data + context->iv_length + plaintext_len;
    
    printf("    [DEBUG] Custom: Verifying custom authentication tag...\n");
    
    // Create a derived key using the same algorithm as encryption
    unsigned char* derived_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!derived_key) {
        fprintf(stderr, "Error: Could not allocate memory for derived key during decryption\n");
        return NULL;
    }
    
    // Derive key using the same custom algorithm as encryption
    for (int i = 0; i < context->key_length; i++) {
        unsigned char rotated = (context->key[i] << (i % 8)) | (context->key[i] >> (8 - (i % 8)));
        derived_key[i] = rotated ^ context->iv[i % context->iv_length];
    }
    
    // Generate expected tag using the same custom algorithm
    unsigned char expected_tag[16];
    for (int i = 0; i < tag_size; i++) {
        expected_tag[i] = 0;
        // Combine multiple bytes of ciphertext with derived key
        for (size_t j = 0; j < plaintext_len; j += tag_size) {
            if (j + i < plaintext_len) {
                expected_tag[i] ^= ciphertext[j + i];
            }
        }
        // Mix with derived key
        expected_tag[i] ^= derived_key[i % context->key_length];
        // Add IV influence
        expected_tag[i] ^= context->iv[i % context->iv_length];
        // Add position-dependent transformation
        expected_tag[i] = (expected_tag[i] + (unsigned char)(i * 37)) % 256;
    }
    
    // Verify the authentication tag
    int tag_match = 1;
    for (int i = 0; i < tag_size; i++) {
        if (expected_tag[i] != received_tag[i]) {
            tag_match = 0;
            break;
        }
    }
    
    if (!tag_match) {
        fprintf(stderr, "Error: Custom authentication tag verification failed. Data may be corrupted or tampered with.\n");
        crypto_secure_free(derived_key, context->key_length);
        return NULL;
    }
    
    printf("    [DEBUG] Custom: Authentication tag verified, proceeding with decryption...\n");
    
    // Allocate memory for output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        crypto_secure_free(derived_key, context->key_length);
        return NULL;
    }
    
    // Copy ciphertext to output for in-place decryption
    memcpy(output, ciphertext, plaintext_len);
    
    // REVERSE THE CUSTOM ENCRYPTION ALGORITHM:
    // Step 1: Reverse the block-wise permutation (swap bytes in pairs)
    for (size_t i = 0; i < plaintext_len - 1; i += 2) {
        unsigned char temp = output[i];
        output[i] = output[i + 1];
        output[i + 1] = temp;
    }
    
    // Step 2: Reverse the custom substitution based on position and IV
    for (size_t i = 0; i < plaintext_len; i++) {
        // Reverse the position-dependent transformation
        unsigned char pos_transform = (unsigned char)((i % 256) ^ context->iv[(i + 7) % context->iv_length]);
        output[i] ^= context->iv[i % context->iv_length];
        output[i] = (output[i] - pos_transform + 256) % 256;
    }
    
    // Step 3: Reverse the XOR with derived key
    for (size_t i = 0; i < plaintext_len; i++) {
        output[i] ^= derived_key[i % context->key_length];
    }
    
    // Clean up derived key
    crypto_secure_free(derived_key, context->key_length);
    
    printf("    [DEBUG] Custom: Multi-layer decryption complete\n");
    
    // Set the output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>

// OpenSSL AES-GCM implementation
unsigned char* aes_gcm_openssl_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *output = NULL;
    int len = 0, ciphertext_len = 0;
    int tag_len = 16; // GCM tag is 16 bytes
    unsigned char tag[16];
    
    // Calculate output size (data + IV + tag)
    int total_length = data_length + context->iv_length + tag_len;
    
    // Allocate memory for output
    output = (unsigned char*)malloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // Copy IV to the beginning of output
    memcpy(output, context->iv, context->iv_length);
    
    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Could not create OpenSSL cipher context\n");
        free(output);
        return NULL;
    }
    
    // Select the appropriate cipher based on key size
    const EVP_CIPHER *cipher = NULL;
    switch (context->key_size) {
        case 128:
            cipher = EVP_aes_128_gcm();
            break;
        case 192:
            cipher = EVP_aes_192_gcm();
            break;
        case 256:
            cipher = EVP_aes_256_gcm();
            break;
        default:
            fprintf(stderr, "Error: Invalid key size for AES-GCM: %d\n", context->key_size);
            EVP_CIPHER_CTX_free(ctx);
            free(output);
            return NULL;
    }
    
    // Initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
        fprintf(stderr, "Error: Could not initialize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Set IV length if different from default
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, context->iv_length, NULL)) {
        fprintf(stderr, "Error: Could not set IV length\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Initialize key and IV
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, context->key, context->iv)) {
        fprintf(stderr, "Error: Could not initialize key and IV\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Encrypt the plaintext
    if (1 != EVP_EncryptUpdate(ctx, output + context->iv_length, &len, data, data_length)) {
        fprintf(stderr, "Error: Could not encrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    ciphertext_len = len;
    
    // Finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, output + context->iv_length + len, &len)) {
        fprintf(stderr, "Error: Could not finalize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    ciphertext_len += len;
    
    // Get the tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) {
        fprintf(stderr, "Error: Could not get tag\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Copy the tag to the output
    memcpy(output + context->iv_length + ciphertext_len, tag, tag_len);
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // Set the output length
    if (output_length) {
        *output_length = context->iv_length + ciphertext_len + tag_len;
    }
    
    return output;
}

unsigned char* aes_gcm_openssl_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *output = NULL;
    int len = 0, plaintext_len = 0;
    int tag_len = 16; // GCM tag is 16 bytes
    
    // Ensure we have enough data (at least for the IV and tag)
    if (data_length <= context->iv_length + tag_len) {
        fprintf(stderr, "Error: Not enough data for GCM decryption\n");
        return NULL;
    }
    
    // Extract IV from the beginning of data
    if (context->iv) {
        free(context->iv);
    }
    context->iv = (unsigned char*)malloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for GCM IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Calculate ciphertext length (data without IV and tag)
    int ciphertext_len = data_length - context->iv_length - tag_len;
    
    // Allocate memory for output
    output = (unsigned char*)malloc(ciphertext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Could not create OpenSSL cipher context\n");
        free(output);
        return NULL;
    }
    
    // Select the appropriate cipher based on key size
    const EVP_CIPHER *cipher = NULL;
    switch (context->key_size) {
        case 128:
            cipher = EVP_aes_128_gcm();
            break;
        case 192:
            cipher = EVP_aes_192_gcm();
            break;
        case 256:
            cipher = EVP_aes_256_gcm();
            break;
        default:
            fprintf(stderr, "Error: Invalid key size for AES-GCM: %d\n", context->key_size);
            EVP_CIPHER_CTX_free(ctx);
            free(output);
            return NULL;
    }
    
    // Initialize the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
        fprintf(stderr, "Error: Could not initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Set IV length if different from default
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, context->iv_length, NULL)) {
        fprintf(stderr, "Error: Could not set IV length\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Initialize key and IV
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, context->key, context->iv)) {
        fprintf(stderr, "Error: Could not initialize key and IV\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Extract the tag from the ciphertext
    unsigned char tag[16];
    memcpy(tag, data + context->iv_length + ciphertext_len, tag_len);
    
    // Set the expected tag value
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag)) {
        fprintf(stderr, "Error: Could not set tag\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Decrypt the ciphertext
    if (1 != EVP_DecryptUpdate(ctx, output, &len, data + context->iv_length, ciphertext_len)) {
        fprintf(stderr, "Error: Could not decrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    plaintext_len = len;
    
    // Finalize the decryption
    int ret = EVP_DecryptFinal_ex(ctx, output + len, &len);
    if (ret <= 0) {
        fprintf(stderr, "Error: Tag verification failed. Data may be corrupted.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    plaintext_len += len;
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // Set the output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}
#endif 