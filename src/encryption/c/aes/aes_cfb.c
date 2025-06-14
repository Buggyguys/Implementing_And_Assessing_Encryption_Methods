#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "aes_cfb.h"
#include "aes_core.h"

#ifdef USE_OPENSSL
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#endif

// standard 
unsigned char* aes_cfb_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // calculate standard IV size 
    if (context->iv_length == 0) {
        context->iv_length = crypto_get_standard_iv_size("AES", "CFB"); 
    }
    
    // calculate tag size for authentication
    int tag_size = 16; 
    
    // calculate output size 
    int total_length = data_length + context->iv_length + tag_size;
    
    // allocate memory for output 
    unsigned char* output = (unsigned char*)crypto_secure_alloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // append IV to output
    memcpy(output, context->iv, context->iv_length);
    
    // initialize context
    aes_core_context_t aes_ctx;
    aes_key_expansion(context->key, context->key_length, &aes_ctx);
    
    // encryption
    unsigned char feedback[16] = {0};
    memcpy(feedback, context->iv, 16);
    
    for (int i = 0; i < data_length; i++) {
        // encrypt feedback block 
        unsigned char keystream_block[16];
        aes_encrypt_block(feedback, keystream_block, &aes_ctx);
        
        // XOR plaintext with keystream
        output[context->iv_length + i] = data[i] ^ keystream_block[0];
        
        // update feedback with ciphertext 
        memmove(feedback, feedback + 1, 15);
        feedback[15] = output[context->iv_length + i];
    }
    
    // generate authentication tag 
    unsigned char* tag = output + context->iv_length + data_length;
    if (!crypto_generate_authentication_tag(tag, tag_size, 
                                          output + context->iv_length, data_length,
                                          context->key, context->key_length)) {
        fprintf(stderr, "Error: Failed to generate authentication tag\n");
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_cfb_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // calculate tag size for authentication
    int tag_size = 16; 
    
    // ensure we have enough data 
    if (data_length <= context->iv_length + tag_size) {
        fprintf(stderr, "Error: Not enough data for CFB decryption\n");
        return NULL;
    }
    
    // extract IV 
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for CFB IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // calculate output size 
    int plaintext_len = data_length - context->iv_length - tag_size;
    
    // verify the authentication tag 
    const unsigned char* tag = data + context->iv_length + plaintext_len;
    const unsigned char* ciphertext = data + context->iv_length;
    
    if (!crypto_verify_authentication_tag(tag, tag_size, ciphertext, plaintext_len, 
                                        context->key, context->key_length)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        return NULL; 
    }
    
    // allocate memory for output 
    unsigned char* output = (unsigned char*)crypto_secure_alloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // initialize context
    aes_core_context_t aes_ctx;
    aes_key_expansion(context->key, context->key_length, &aes_ctx);
    
    // decryption
    unsigned char feedback[16] = {0};
    memcpy(feedback, context->iv, 16);
    
    for (int i = 0; i < plaintext_len; i++) {
        // encrypt feedback block 
        unsigned char keystream_block[16];
        aes_encrypt_block(feedback, keystream_block, &aes_ctx);
        
        // XOR ciphertext with keystream to get plaintext
        output[i] = data[context->iv_length + i] ^ keystream_block[0];
        
        // update feedback with ciphertext 
        memmove(feedback, feedback + 1, 15);
        feedback[15] = data[context->iv_length + i];
    }
    
    // output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}

// custom 
unsigned char* aes_cfb_custom_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // calculate standard IV size if not already set
    if (context->iv_length == 0) {
        context->iv_length = crypto_get_standard_iv_size("AES", "CFB"); 
    }
    
    // calculate tag size for authentication
    int tag_size = 16; 
    
    // calculate output size 
    int total_length = data_length + context->iv_length + tag_size;
    
    // allocate memory for output 
    unsigned char* output = (unsigned char*)crypto_secure_alloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // append IV to output
    memcpy(output, context->iv, context->iv_length);
    
    // create a custom derived key 
    unsigned char* derived_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!derived_key) {
        fprintf(stderr, "Error: Could not allocate memory for derived key\n");
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // XOR with pattern and rotate
    for (int i = 0; i < context->key_length; i++) {
        unsigned char rotated = (context->key[i] << 3) | (context->key[i] >> 5);
        derived_key[i] = rotated ^ (0xAA + (i % 16)) ^ context->iv[i % context->iv_length];
    }
    
    // initialize context with derived key
    aes_core_context_t aes_ctx;
    aes_key_expansion(derived_key, context->key_length, &aes_ctx);
    
    // encryption
    unsigned char feedback[16] = {0};
    memcpy(feedback, context->iv, 16);
    
    for (int i = 0; i < data_length; i++) {
        // encrypt feedback block 
        unsigned char keystream_block[16];
        aes_encrypt_block(feedback, keystream_block, &aes_ctx);
        
        // XOR plaintext with keystream 
        unsigned char keystream_byte = keystream_block[0] ^ keystream_block[i % 16];
        output[context->iv_length + i] = data[i] ^ keystream_byte;
        
        // update feedback with ciphertext 
        memmove(feedback, feedback + 1, 15);
        feedback[15] = output[context->iv_length + i];
    }
    
    // generate authentication tag 
    unsigned char* tag = output + context->iv_length + data_length;
    if (!crypto_generate_authentication_tag(tag, tag_size, 
                                          output + context->iv_length, data_length,
                                          derived_key, context->key_length)) {
        fprintf(stderr, "Error: Failed to generate authentication tag\n");
        crypto_secure_free(derived_key, context->key_length);
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // clean up
    crypto_secure_free(derived_key, context->key_length);
    
    // output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_cfb_custom_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // calculate tag size for authentication
    int tag_size = 16; 
    
    // ensure we have enough data 
    if (data_length <= context->iv_length + tag_size) {
        fprintf(stderr, "Error: Not enough data for custom CFB decryption\n");
        return NULL;
    }
    
    // extract IV 
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for CFB IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // calculate output size 
    int plaintext_len = data_length - context->iv_length - tag_size;
    
    // create the same custom derived key 
    unsigned char* derived_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!derived_key) {
        fprintf(stderr, "Error: Could not allocate memory for derived key\n");
        return NULL;
    }
    
    // XOR with pattern and rotate 
    for (int i = 0; i < context->key_length; i++) {
        unsigned char rotated = (context->key[i] << 3) | (context->key[i] >> 5);
        derived_key[i] = rotated ^ (0xAA + (i % 16)) ^ context->iv[i % context->iv_length];
    }
    
    // verify the authentication tag 
    const unsigned char* tag = data + context->iv_length + plaintext_len;
    const unsigned char* ciphertext = data + context->iv_length;
    
    if (!crypto_verify_authentication_tag(tag, tag_size, ciphertext, plaintext_len, 
                                        derived_key, context->key_length)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        crypto_secure_free(derived_key, context->key_length);
        return NULL; // Fail securely on authentication failure
    }
    
    // allocate memory for output 
    unsigned char* output = (unsigned char*)crypto_secure_alloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        crypto_secure_free(derived_key, context->key_length);
        return NULL;
    }
    
    // initialize context with derived key
    aes_core_context_t aes_ctx;
    aes_key_expansion(derived_key, context->key_length, &aes_ctx);
    
    // decryption
    unsigned char feedback[16] = {0};
    memcpy(feedback, context->iv, 16);
    
    for (int i = 0; i < plaintext_len; i++) {
        // encrypt feedback block 
        unsigned char keystream_block[16];
        aes_encrypt_block(feedback, keystream_block, &aes_ctx);
        
        // XOR ciphertext with keystream 
        unsigned char keystream_byte = keystream_block[0] ^ keystream_block[i % 16];
        output[i] = data[context->iv_length + i] ^ keystream_byte;
        
        // update feedback with ciphertext 
        memmove(feedback, feedback + 1, 15);
        feedback[15] = data[context->iv_length + i];
    }
    
    // clean up
    crypto_secure_free(derived_key, context->key_length);
    
    // output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}

#ifdef USE_OPENSSL
unsigned char* aes_cfb_openssl_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // calculate standard IV size if not already set
    if (context->iv_length == 0) {
        context->iv_length = AES_BLOCK_SIZE; 
    }
    
    // calculate output size 
    int total_length = data_length + context->iv_length;
    
    // allocate memory for output
    unsigned char* output = (unsigned char*)crypto_secure_alloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // append IV to output
    memcpy(output, context->iv, context->iv_length);
    
    // initialize context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create OpenSSL context\n");
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // initialize encryption operation
    const EVP_CIPHER* cipher;
    if (context->key_length == 16) {
        cipher = EVP_aes_128_cfb();
    } else if (context->key_length == 24) {
        cipher = EVP_aes_192_cfb();
    } else if (context->key_length == 32) {
        cipher = EVP_aes_256_cfb();
    } else {
        fprintf(stderr, "Error: Unsupported key size for OpenSSL AES-CFB\n");
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, context->key, context->iv) != 1) {
        fprintf(stderr, "Error: Failed to initialize OpenSSL CFB encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // encrypt data
    int len;
    if (EVP_EncryptUpdate(ctx, output + context->iv_length, &len, data, data_length) != 1) {
        fprintf(stderr, "Error: Failed to encrypt data with OpenSSL CFB\n");
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    int ciphertext_len = len;
    
    // finalize encryption
    if (EVP_EncryptFinal_ex(ctx, output + context->iv_length + len, &len) != 1) {
        fprintf(stderr, "Error: Failed to finalize OpenSSL CFB encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    ciphertext_len += len;
    
    // clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // output length
    if (output_length) {
        *output_length = context->iv_length + ciphertext_len;
    }
    
    return output;
}

unsigned char* aes_cfb_openssl_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // ensure we have enough data 
    if (data_length <= context->iv_length) {
        fprintf(stderr, "Error: Not enough data for OpenSSL CFB decryption\n");
        return NULL;
    }
    
    // extract IV 
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for CFB IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // calculate output size 
    int ciphertext_len = data_length - context->iv_length;
    
    // allocate memory for output
    unsigned char* output = (unsigned char*)crypto_secure_alloc(ciphertext_len + AES_BLOCK_SIZE);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // initialize context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create OpenSSL context\n");
        crypto_secure_free(output, ciphertext_len + AES_BLOCK_SIZE);
        return NULL;
    }
    
    // initialize decryption operation
    const EVP_CIPHER* cipher;
    if (context->key_length == 16) {
        cipher = EVP_aes_128_cfb();
    } else if (context->key_length == 24) {
        cipher = EVP_aes_192_cfb();
    } else if (context->key_length == 32) {
        cipher = EVP_aes_256_cfb();
    } else {
        fprintf(stderr, "Error: Unsupported key size for OpenSSL AES-CFB\n");
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_free(output, ciphertext_len + AES_BLOCK_SIZE);
        return NULL;
    }
    
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, context->key, context->iv) != 1) {
        fprintf(stderr, "Error: Failed to initialize OpenSSL CFB decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_free(output, ciphertext_len + AES_BLOCK_SIZE);
        return NULL;
    }
    
    // decrypt data
    int len;
    if (EVP_DecryptUpdate(ctx, output, &len, data + context->iv_length, ciphertext_len) != 1) {
        fprintf(stderr, "Error: Failed to decrypt data with OpenSSL CFB\n");
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_free(output, ciphertext_len + AES_BLOCK_SIZE);
        return NULL;
    }
    
    int plaintext_len = len;
    
    // finalize decryption
    if (EVP_DecryptFinal_ex(ctx, output + len, &len) != 1) {
        fprintf(stderr, "Error: Failed to finalize OpenSSL CFB decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_free(output, ciphertext_len + AES_BLOCK_SIZE);
        return NULL;
    }
    
    plaintext_len += len;
    
    // clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}
#else
unsigned char* aes_cfb_openssl_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    fprintf(stderr, "Error: OpenSSL not available - AES-CFB OpenSSL implementation not supported\n");
    return NULL;
}

#endif 