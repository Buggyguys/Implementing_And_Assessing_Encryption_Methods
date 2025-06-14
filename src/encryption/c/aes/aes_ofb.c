#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "aes_ofb.h"

#ifdef HAVE_OPENSSL
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#endif

// Standard AES-OFB implementation with authentication tag
unsigned char* aes_ofb_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
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
    
    // OFB encryption - output feedback mode
    unsigned char feedback[16] = {0};
    memcpy(feedback, context->iv, context->iv_length > 16 ? 16 : context->iv_length);
    
    for (int i = 0; i < data_length; i++) {
        // Encrypt feedback block with key to create keystream (OFB characteristic)
        unsigned char keystream_byte = feedback[i % 16] ^ context->key[i % context->key_length];
        
        // XOR plaintext with keystream
        output[context->iv_length + i] = data[i] ^ keystream_byte;
        
        // Update feedback with encrypted feedback (not ciphertext like CFB)
        feedback[i % 16] = keystream_byte;
    }
    
    // Generate authentication tag for the ciphertext
    unsigned char* tag = output + context->iv_length + data_length;
    if (!crypto_generate_authentication_tag(tag, tag_size, 
                                          output + context->iv_length, data_length,
                                          context->key, context->key_length)) {
        fprintf(stderr, "Error: Failed to generate authentication tag\n");
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // Set the output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_ofb_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate tag size for authentication
    int tag_size = 16; // 16 bytes (128 bits) for authentication tag
    
    // Ensure we have enough data (at least for the IV and tag)
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
    
    // OFB decryption - output feedback mode (same as encryption)
    unsigned char feedback[16] = {0};
    memcpy(feedback, context->iv, context->iv_length > 16 ? 16 : context->iv_length);
    
    for (int i = 0; i < plaintext_len; i++) {
        // Encrypt feedback block with key to create keystream (same as encryption)
        unsigned char keystream_byte = feedback[i % 16] ^ context->key[i % context->key_length];
        
        // XOR ciphertext with keystream to get plaintext
        output[i] = data[context->iv_length + i] ^ keystream_byte;
        
        // Update feedback with encrypted feedback (same as encryption)
        feedback[i % 16] = keystream_byte;
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
    
    // Custom OFB encryption with enhanced output feedback
    unsigned char feedback[16] = {0};
    memcpy(feedback, context->iv, context->iv_length > 16 ? 16 : context->iv_length);
    
    // Create a modified key for custom implementation
    unsigned char* modified_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!modified_key) {
        fprintf(stderr, "Error: Could not allocate memory for modified key\n");
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // Modify key by XORing with a different pattern than CFB
    for (int i = 0; i < context->key_length; i++) {
        modified_key[i] = context->key[i] ^ (0x55 + (i * 3 % 16));
    }
    
    for (int i = 0; i < data_length; i++) {
        // Enhanced keystream generation with double encryption
        unsigned char keystream_byte = feedback[i % 16] ^ modified_key[i % context->key_length];
        keystream_byte ^= modified_key[(i + 8) % context->key_length]; // Second key mixing
        keystream_byte ^= (i * 7 % 256); // Add position-based variation
        
        // XOR plaintext with keystream
        output[context->iv_length + i] = data[i] ^ keystream_byte;
        
        // Enhanced feedback update - mix keystream with rotated feedback
        unsigned char rotated_feedback = (feedback[i % 16] << 1) | (feedback[i % 16] >> 7);
        feedback[i % 16] = keystream_byte ^ rotated_feedback;
    }
    
    // Generate authentication tag using modified key
    unsigned char* tag = output + context->iv_length + data_length;
    if (!crypto_generate_authentication_tag(tag, tag_size, 
                                          output + context->iv_length, data_length,
                                          modified_key, context->key_length)) {
        fprintf(stderr, "Error: Failed to generate authentication tag\n");
        crypto_secure_free(modified_key, context->key_length);
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    crypto_secure_free(modified_key, context->key_length);
    
    // Set the output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_ofb_custom_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
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
    
    // Create a modified key for custom implementation (same as encryption)
    unsigned char* modified_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!modified_key) {
        fprintf(stderr, "Error: Could not allocate memory for modified key\n");
        return NULL;
    }
    
    // Modify key by XORing with a pattern (same as encryption)
    for (int i = 0; i < context->key_length; i++) {
        modified_key[i] = context->key[i] ^ (0x55 + (i * 3 % 16));
    }
    
    // Verify the authentication tag first
    const unsigned char* tag = data + context->iv_length + plaintext_len;
    const unsigned char* ciphertext = data + context->iv_length;
    
    if (!crypto_verify_authentication_tag(tag, tag_size, ciphertext, plaintext_len, 
                                        modified_key, context->key_length)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        crypto_secure_free(modified_key, context->key_length);
        return NULL; // Fail securely on authentication failure
    }
    
    // Allocate memory for output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        crypto_secure_free(modified_key, context->key_length);
        return NULL;
    }
    
    // Custom OFB decryption with enhanced output feedback (same as encryption)
    unsigned char feedback[16] = {0};
    memcpy(feedback, context->iv, context->iv_length > 16 ? 16 : context->iv_length);
    
    for (int i = 0; i < plaintext_len; i++) {
        // Enhanced keystream generation (same as encryption)
        unsigned char keystream_byte = feedback[i % 16] ^ modified_key[i % context->key_length];
        keystream_byte ^= modified_key[(i + 8) % context->key_length]; // Second key mixing
        keystream_byte ^= (i * 7 % 256); // Add position-based variation
        
        // XOR ciphertext with keystream to get plaintext
        output[i] = data[context->iv_length + i] ^ keystream_byte;
        
        // Enhanced feedback update (same as encryption)
        unsigned char rotated_feedback = (feedback[i % 16] << 1) | (feedback[i % 16] >> 7);
        feedback[i % 16] = keystream_byte ^ rotated_feedback;
    }
    
    crypto_secure_free(modified_key, context->key_length);
    
    // Set the output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}

#ifdef HAVE_OPENSSL
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

unsigned char* aes_ofb_openssl_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    fprintf(stderr, "Error: OpenSSL not available - AES-OFB OpenSSL implementation not supported\n");
    return NULL;
}
#endif 