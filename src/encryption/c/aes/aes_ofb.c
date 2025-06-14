#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "aes_ofb.h"
#include "aes_core.h"

#ifdef USE_OPENSSL
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#endif

// standardimplementation 
unsigned char* aes_ofb_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // calculate standard IV size if not already set
    if (context->iv_length == 0) {
        context->iv_length = crypto_get_standard_iv_size("AES", "OFB"); // 16 bytes
    }
    
    // calculate tag size for authentication
    int tag_size = 16; // 16 bytes (128 bits) for authentication tag
    
    // calculate output size (original + IV + tag)
    int total_length = data_length + context->iv_length + tag_size;
    
    // allocate memory for output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // copy IV to the beginning of output
    memcpy(output, context->iv, context->iv_length);
    
    // initialize AES context
    aes_core_context_t aes_ctx;
    aes_key_expansion(context->key, context->key_length, &aes_ctx);
    
    // proper AES-OFB encryption - output feedback mode
    unsigned char feedback[16] = {0};
    memcpy(feedback, context->iv, 16);
    
    for (int i = 0; i < data_length; i++) {
        // encrypt feedback block with proper AES to create keystream 
        unsigned char keystream_block[16];
        aes_encrypt_block(feedback, keystream_block, &aes_ctx);
        
        // XOR plaintext with keystream
        output[context->iv_length + i] = data[i] ^ keystream_block[0];
        
        // update feedback with encrypted feedback 
        // shift feedback left and add new keystream byte
        memmove(feedback, feedback + 1, 15);
        feedback[15] = keystream_block[0];
    }
    
    // generate authentication tag for the ciphertext
    unsigned char* tag = output + context->iv_length + data_length;
    if (!crypto_generate_authentication_tag(tag, tag_size, 
                                          output + context->iv_length, data_length,
                                          context->key, context->key_length)) {
        fprintf(stderr, "Error: Failed to generate authentication tag\n");
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // set the output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_ofb_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // calculate tag size for authentication
    int tag_size = 16; 
    
    // ensure we have enough data (at least for the IV and tag)
    if (data_length <= context->iv_length + tag_size) {
        fprintf(stderr, "Error: Not enough data for OFB decryption\n");
        return NULL;
    }
    
    // Extract IV from the beginning of data
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for OFB IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Calculate output size (data without IV and tag)
    int plaintext_len = data_length - context->iv_length - tag_size;
    
    // Verify the authentication tag first
    const unsigned char* tag = data + context->iv_length + plaintext_len;
    const unsigned char* ciphertext = data + context->iv_length;
    
    if (!crypto_verify_authentication_tag(tag, tag_size, ciphertext, plaintext_len, 
                                        context->key, context->key_length)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        return NULL; // Fail securely on authentication failure
    }
    
    // Allocate memory for output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // Initialize AES context
    aes_core_context_t aes_ctx;
    aes_key_expansion(context->key, context->key_length, &aes_ctx);
    
    // Proper AES-OFB decryption - output feedback mode (same as encryption)
    unsigned char feedback[16] = {0};
    memcpy(feedback, context->iv, 16);
    
    for (int i = 0; i < plaintext_len; i++) {
        // Encrypt feedback block with proper AES to create keystream (same as encryption)
        unsigned char keystream_block[16];
        aes_encrypt_block(feedback, keystream_block, &aes_ctx);
        
        // XOR ciphertext with keystream to get plaintext
        output[i] = data[context->iv_length + i] ^ keystream_block[0];
        
        // Update feedback with encrypted feedback (same as encryption)
        // Shift feedback left and add new keystream byte
        memmove(feedback, feedback + 1, 15);
        feedback[15] = keystream_block[0];
    }
    
    // Set the output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}

// Custom AES-OFB implementation with enhanced output feedback mechanism
unsigned char* aes_ofb_custom_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate standard IV size if not already set
    if (context->iv_length == 0) {
        context->iv_length = crypto_get_standard_iv_size("AES", "OFB"); // 16 bytes
    }
    
    // Calculate tag size for authentication
    int tag_size = 16; // 16 bytes (128 bits) for authentication tag
    
    // Calculate output size (original + IV + tag)
    int total_length = data_length + context->iv_length + tag_size;
    
    // Allocate memory for output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // Copy IV to the beginning of output
    memcpy(output, context->iv, context->iv_length);
    
    // Create a custom derived key (this is the "custom" part)
    unsigned char* derived_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!derived_key) {
        fprintf(stderr, "Error: Could not allocate memory for derived key\n");
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // Custom key derivation: different pattern than CFB
    for (int i = 0; i < context->key_length; i++) {
        unsigned char rotated = (context->key[i] << 1) | (context->key[i] >> 7);
        derived_key[i] = rotated ^ (0x55 + (i * 3 % 16)) ^ context->iv[i % context->iv_length];
    }
    
    // Initialize AES context with derived key
    aes_core_context_t aes_ctx;
    aes_key_expansion(derived_key, context->key_length, &aes_ctx);
    
    // Proper AES-OFB encryption with custom derived key
    unsigned char feedback[16] = {0};
    memcpy(feedback, context->iv, 16);
    
    for (int i = 0; i < data_length; i++) {
        // Encrypt feedback block with proper AES to create keystream
        unsigned char keystream_block[16];
        aes_encrypt_block(feedback, keystream_block, &aes_ctx);
        
        // XOR plaintext with keystream (with custom twist - mix multiple keystream bytes)
        unsigned char keystream_byte = keystream_block[0] ^ keystream_block[(i * 3) % 16];
        output[context->iv_length + i] = data[i] ^ keystream_byte;
        
        // Update feedback with encrypted feedback (OFB mode characteristic)
        // Shift feedback left and add new keystream byte
        memmove(feedback, feedback + 1, 15);
        feedback[15] = keystream_block[0];
    }
    
    // Generate authentication tag using derived key
    unsigned char* tag = output + context->iv_length + data_length;
    if (!crypto_generate_authentication_tag(tag, tag_size, 
                                          output + context->iv_length, data_length,
                                          derived_key, context->key_length)) {
        fprintf(stderr, "Error: Failed to generate authentication tag\n");
        crypto_secure_free(derived_key, context->key_length);
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // Clean up
    crypto_secure_free(derived_key, context->key_length);
    
    // Set the output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_ofb_custom_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate tag size for authentication
    int tag_size = 16; // 16 bytes (128 bits) for authentication tag
    
    // Ensure we have enough data (at least for the IV and tag)
    if (data_length <= context->iv_length + tag_size) {
        fprintf(stderr, "Error: Not enough data for custom OFB decryption\n");
        return NULL;
    }
    
    // Extract IV from the beginning of data
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for OFB IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Calculate output size (data without IV and tag)
    int plaintext_len = data_length - context->iv_length - tag_size;
    
    // Create the same custom derived key as in encryption
    unsigned char* derived_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!derived_key) {
        fprintf(stderr, "Error: Could not allocate memory for derived key\n");
        return NULL;
    }
    
    // Custom key derivation: different pattern than CFB (same as encryption)
    for (int i = 0; i < context->key_length; i++) {
        unsigned char rotated = (context->key[i] << 1) | (context->key[i] >> 7);
        derived_key[i] = rotated ^ (0x55 + (i * 3 % 16)) ^ context->iv[i % context->iv_length];
    }
    
    // Verify the authentication tag first
    const unsigned char* tag = data + context->iv_length + plaintext_len;
    const unsigned char* ciphertext = data + context->iv_length;
    
    if (!crypto_verify_authentication_tag(tag, tag_size, ciphertext, plaintext_len, 
                                        derived_key, context->key_length)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        crypto_secure_free(derived_key, context->key_length);
        return NULL; // Fail securely on authentication failure
    }
    
    // Allocate memory for output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        crypto_secure_free(derived_key, context->key_length);
        return NULL;
    }
    
    // Initialize AES context with derived key
    aes_core_context_t aes_ctx;
    aes_key_expansion(derived_key, context->key_length, &aes_ctx);
    
    // Proper AES-OFB decryption with custom derived key
    unsigned char feedback[16] = {0};
    memcpy(feedback, context->iv, 16);
    
    for (int i = 0; i < plaintext_len; i++) {
        // Encrypt feedback block with proper AES to create keystream
        unsigned char keystream_block[16];
        aes_encrypt_block(feedback, keystream_block, &aes_ctx);
        
        // XOR ciphertext with keystream (with custom twist - mix multiple keystream bytes)
        unsigned char keystream_byte = keystream_block[0] ^ keystream_block[(i * 3) % 16];
        output[i] = data[context->iv_length + i] ^ keystream_byte;
        
        // Update feedback with encrypted feedback (OFB mode characteristic)
        // Shift feedback left and add new keystream byte
        memmove(feedback, feedback + 1, 15);
        feedback[15] = keystream_block[0];
    }
    
    // Clean up
    crypto_secure_free(derived_key, context->key_length);
    
    // Set the output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}

#ifdef USE_OPENSSL
// OpenSSL-based AES-OFB implementation
unsigned char* aes_ofb_openssl_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate standard IV size if not already set
    if (context->iv_length == 0) {
        context->iv_length = AES_BLOCK_SIZE; // 16 bytes
    }
    
    // Calculate output size (original + IV)
    int total_length = data_length + context->iv_length;
    
    // Allocate memory for output
    unsigned char* output = (unsigned char*)crypto_secure_alloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // Copy IV to the beginning of output
    memcpy(output, context->iv, context->iv_length);
    
    // Initialize OpenSSL context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create OpenSSL context\n");
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // Initialize encryption operation
    const EVP_CIPHER* cipher;
    if (context->key_length == 16) {
        cipher = EVP_aes_128_ofb();
    } else if (context->key_length == 24) {
        cipher = EVP_aes_192_ofb();
    } else if (context->key_length == 32) {
        cipher = EVP_aes_256_ofb();
    } else {
        fprintf(stderr, "Error: Unsupported key size for OpenSSL AES-OFB\n");
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, context->key, context->iv) != 1) {
        fprintf(stderr, "Error: Failed to initialize OpenSSL OFB encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // Encrypt data
    int len;
    if (EVP_EncryptUpdate(ctx, output + context->iv_length, &len, data, data_length) != 1) {
        fprintf(stderr, "Error: Failed to encrypt data with OpenSSL OFB\n");
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    int ciphertext_len = len;
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, output + context->iv_length + len, &len) != 1) {
        fprintf(stderr, "Error: Failed to finalize OpenSSL OFB encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    ciphertext_len += len;
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // Set the actual output length
    if (output_length) {
        *output_length = context->iv_length + ciphertext_len;
    }
    
    return output;
}

unsigned char* aes_ofb_openssl_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Ensure we have enough data (at least for the IV)
    if (data_length <= context->iv_length) {
        fprintf(stderr, "Error: Not enough data for OpenSSL OFB decryption\n");
        return NULL;
    }
    
    // Extract IV from the beginning of data
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for OFB IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Calculate output size (data without IV)
    int ciphertext_len = data_length - context->iv_length;
    
    // Allocate memory for output
    unsigned char* output = (unsigned char*)crypto_secure_alloc(ciphertext_len + AES_BLOCK_SIZE);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // Initialize OpenSSL context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create OpenSSL context\n");
        crypto_secure_free(output, ciphertext_len + AES_BLOCK_SIZE);
        return NULL;
    }
    
    // Initialize decryption operation
    const EVP_CIPHER* cipher;
    if (context->key_length == 16) {
        cipher = EVP_aes_128_ofb();
    } else if (context->key_length == 24) {
        cipher = EVP_aes_192_ofb();
    } else if (context->key_length == 32) {
        cipher = EVP_aes_256_ofb();
    } else {
        fprintf(stderr, "Error: Unsupported key size for OpenSSL AES-OFB\n");
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_free(output, ciphertext_len + AES_BLOCK_SIZE);
        return NULL;
    }
    
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, context->key, context->iv) != 1) {
        fprintf(stderr, "Error: Failed to initialize OpenSSL OFB decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_free(output, ciphertext_len + AES_BLOCK_SIZE);
        return NULL;
    }
    
    // Decrypt data
    int len;
    if (EVP_DecryptUpdate(ctx, output, &len, data + context->iv_length, ciphertext_len) != 1) {
        fprintf(stderr, "Error: Failed to decrypt data with OpenSSL OFB\n");
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_free(output, ciphertext_len + AES_BLOCK_SIZE);
        return NULL;
    }
    
    int plaintext_len = len;
    
    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, output + len, &len) != 1) {
        fprintf(stderr, "Error: Failed to finalize OpenSSL OFB decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_free(output, ciphertext_len + AES_BLOCK_SIZE);
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
#else
// Stub implementations when OpenSSL is not available
unsigned char* aes_ofb_openssl_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    fprintf(stderr, "Error: OpenSSL not available - AES-OFB OpenSSL implementation not supported\n");
    return NULL;
}

unsigned char* aes_ofb_openssl_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    fprintf(stderr, "Error: OpenSSL not available - AES-OFB OpenSSL implementation not supported\n");
    return NULL;
}
#endif 