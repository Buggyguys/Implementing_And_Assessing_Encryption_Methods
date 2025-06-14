#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "aes_gcm.h"
#include "aes_core.h"
#include <limits.h>
#include <stdint.h>

// standard implementation 
unsigned char* aes_gcm_encrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    size_t data_len = data_length;
    
    // generate IV 
    if (!context->iv) {

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
    
    // initializ context
    aes_core_context_t aes_ctx;
    aes_key_expansion(context->key, context->key_length, &aes_ctx);
    
    // calculate output size 
    size_t tag_size = crypto_get_standard_tag_size("AES", "GCM"); // 16 bytes
    size_t total_length = data_len + context->iv_length + tag_size;
    
    // check if allocation size is reasonable 
    if (total_length > (size_t)(4ULL * 1024 * 1024 * 1024)) {
        fprintf(stderr, "Error: Data too large for encryption (%zu bytes = %.2f GB)\n", 
                total_length, (double)total_length / (1024.0 * 1024.0 * 1024.0));
        return NULL;
    }
    
    // allocate memory for output 
    unsigned char* output = (unsigned char*)malloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data (%zu bytes = %.2f MB)\n", 
                total_length, (double)total_length / (1024.0 * 1024.0));
        return NULL;
    }
    
    // append IV
    memcpy(output, context->iv, context->iv_length);
    
    // encryption
    unsigned char counter[16];
    memset(counter, 0, 16);
    memcpy(counter, context->iv, context->iv_length < 16 ? context->iv_length : 12); 
    
    unsigned char keystream[16];
    size_t offset = 0;
    uint32_t counter_val = 1; 
    
    while (offset < data_len) {
        // set counter value in the last 4 bytes 
        counter[12] = (counter_val >> 24) & 0xFF;
        counter[13] = (counter_val >> 16) & 0xFF;
        counter[14] = (counter_val >> 8) & 0xFF;
        counter[15] = counter_val & 0xFF;
        
        // encrypt counter to generate keystream
        aes_encrypt_block(counter, keystream, &aes_ctx);
        
        // XOR keystream with plaintext 
        size_t block_size = (data_len - offset) < 16 ? (data_len - offset) : 16;
        for (size_t i = 0; i < block_size; i++) {
            output[context->iv_length + offset + i] = data[offset + i] ^ keystream[i];
        }
        
        offset += block_size;
        counter_val++;
    }
        
    // generate a cryptographically secure tag
    unsigned char* tag = output + context->iv_length + data_len;
    if (!crypto_generate_authentication_tag(tag, tag_size, 
                                           output + context->iv_length, data_len,
                                           context->key, context->key_length)) {
        fprintf(stderr, "Error: Failed to generate authentication tag\n");
        free(output);
        return NULL;
    }
    
    // output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_gcm_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    // calculate sizes using standard values
    int tag_size = crypto_get_standard_tag_size("AES", "GCM"); 
    
    // ensure we have enough data 
    if (data_length <= context->iv_length + tag_size) {
        fprintf(stderr, "Error: Not enough data for GCM decryption\n");
        return NULL;
    }
    
    // extract IV from the beginning of data
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for GCM IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // calculate output size 
    size_t plaintext_len = data_length - context->iv_length - tag_size;
    
    // verify the authentication tag first
    const unsigned char* tag = data + context->iv_length + plaintext_len;
    const unsigned char* ciphertext = data + context->iv_length;
    
    if (!crypto_verify_authentication_tag(tag, tag_size, ciphertext, plaintext_len, 
                                        context->key, context->key_length)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        return NULL;
    }
    
    // initialize proper AES core context
    aes_core_context_t aes_ctx;
    aes_key_expansion(context->key, context->key_length, &aes_ctx);
    
    // allocate memory for output 
    unsigned char* output = (unsigned char*)malloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // decryption 
    unsigned char counter[16];
    memset(counter, 0, 16);
    memcpy(counter, context->iv, context->iv_length < 16 ? context->iv_length : 12); 
    
    unsigned char keystream[16];
    size_t offset = 0;
    uint32_t counter_val = 1; 
    
    while (offset < plaintext_len) {
        // set counter value in the last 4 bytes 
        counter[12] = (counter_val >> 24) & 0xFF;
        counter[13] = (counter_val >> 16) & 0xFF;
        counter[14] = (counter_val >> 8) & 0xFF;
        counter[15] = counter_val & 0xFF;
        
        // encrypt counter to generate keystream
        aes_encrypt_block(counter, keystream, &aes_ctx);
        
        // xor keystream with ciphertext to get plaintext
        size_t block_size = (plaintext_len - offset) < 16 ? (plaintext_len - offset) : 16;
        for (size_t i = 0; i < block_size; i++) {
            output[offset + i] = ciphertext[offset + i] ^ keystream[i];
        }
        
        offset += block_size;
        counter_val++;
    }
    
    // output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}

unsigned char* aes_gcm_custom_encrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;    
    // convert to size_t for internal calculations to handle large values
    size_t data_len = data_length;
    
    // generate IV if not present
    if (!context->iv) {

        context->iv_length = crypto_get_standard_iv_size("AES", "GCM");
        context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
        if (!context->iv) {
            fprintf(stderr, "Error: Could not allocate memory for custom IV\n");
            return NULL;
        }
        if (!crypto_generate_iv(context->iv, context->iv_length)) {
            fprintf(stderr, "Error: Could not generate custom IV\n");
            crypto_secure_free(context->iv, context->iv_length);
            context->iv = NULL;
            return NULL;
        }
    }
    
    // custom key derivation 
    unsigned char* derived_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!derived_key) {
        fprintf(stderr, "Error: Could not allocate memory for derived key\n");
        return NULL;
    }
    
    //  XOR key with IV and apply bit rotation
    for (int i = 0; i < context->key_length; i++) {
        unsigned char rotated = (context->key[i] << (i % 8)) | (context->key[i] >> (8 - (i % 8)));
        derived_key[i] = rotated ^ context->iv[i % context->iv_length];
    }
    
    // initialize context with derived key
    aes_core_context_t aes_ctx;
    aes_key_expansion(derived_key, context->key_length, &aes_ctx);
    
    // calculate output size 
    size_t tag_size = crypto_get_standard_tag_size("AES", "GCM"); 
    size_t total_length = data_len + context->iv_length + tag_size;
    
    // check if allocation size is reasonable
    if (total_length > (size_t)(4ULL * 1024 * 1024 * 1024)) {
        fprintf(stderr, "Error: Data too large for custom encryption (%zu bytes = %.2f GB)\n", 
                total_length, (double)total_length / (1024.0 * 1024.0 * 1024.0));
        crypto_secure_free(derived_key, context->key_length);
        return NULL;
    }
    
    // allocate memory for output
    unsigned char* output = (unsigned char*)malloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for custom encrypted data (%zu bytes = %.2f MB)\n", 
                total_length, (double)total_length / (1024.0 * 1024.0));
        crypto_secure_free(derived_key, context->key_length);
        return NULL;
    }
    
    // copy IV
    memcpy(output, context->iv, context->iv_length);
    
    // encryption 
    unsigned char counter[16];
    memset(counter, 0, 16);
    // use IV as nonce 
    memcpy(counter, context->iv, context->iv_length < 12 ? context->iv_length : 12);
    // add custom counter initialization based on derived key
    counter[12] ^= derived_key[0];
    counter[13] ^= derived_key[1];
    counter[14] ^= derived_key[2];
    counter[15] ^= derived_key[3];
    
    unsigned char keystream[16];
    size_t offset = 0;
    uint32_t counter_val = 1; 
    
    while (offset < data_len) {
        // set counter value in the last 4 bytes (big-endian) with custom twist
        counter[12] = ((counter_val >> 24) & 0xFF) ^ derived_key[0];
        counter[13] = ((counter_val >> 16) & 0xFF) ^ derived_key[1];
        counter[14] = ((counter_val >> 8) & 0xFF) ^ derived_key[2];
        counter[15] = (counter_val & 0xFF) ^ derived_key[3];
        
        // encrypt counter to generate keystream
        aes_encrypt_block(counter, keystream, &aes_ctx);
        
        // xor keystream with plaintext
        size_t block_size = (data_len - offset) < 16 ? (data_len - offset) : 16;
        for (size_t i = 0; i < block_size; i++) {
            output[context->iv_length + offset + i] = data[offset + i] ^ keystream[i];
        }
        
        offset += block_size;
        counter_val++;
    }
    
    // generate a custom authentication tag 
    unsigned char* tag = output + context->iv_length + data_len;
    unsigned char* ciphertext = output + context->iv_length;
    
    // custom tag generation
    for (size_t i = 0; i < tag_size; i++) {
        tag[i] = 0;
        // combine multiple bytes of ciphertext with derived key
        for (size_t j = 0; j < data_len; j += tag_size) {
            if (j + i < data_len) {
                tag[i] ^= ciphertext[j + i];
            }
        }
        // mix with derived key
        tag[i] ^= derived_key[i % context->key_length];
        // add IV influence
        tag[i] ^= context->iv[i % context->iv_length];
        // add position-dependent transformation
        tag[i] = (tag[i] + (unsigned char)(i * 37)) % 256;
    }
    
    // clean up derived key
    crypto_secure_free(derived_key, context->key_length);
    
    // set the output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_gcm_custom_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // calculate sizes using standard values
    int tag_size = crypto_get_standard_tag_size("AES", "GCM"); 
    
    // ensure we have enough data 
    if (data_length <= context->iv_length + tag_size) {
        fprintf(stderr, "Error: Not enough data for custom GCM decryption\n");
        return NULL;
    }
    
    // extract IV 
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for custom GCM IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // calculate ciphertext size 
    size_t ciphertext_len = data_length - context->iv_length - tag_size;
    
    // extract the ciphertext and tag
    const unsigned char* ciphertext = data + context->iv_length;
    const unsigned char* received_tag = data + context->iv_length + ciphertext_len;
    
    // create a derived key 
    unsigned char* derived_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!derived_key) {
        fprintf(stderr, "Error: Could not allocate memory for derived key during decryption\n");
        return NULL;
    }
    
    // derive key 
    for (int i = 0; i < context->key_length; i++) {
        unsigned char rotated = (context->key[i] << (i % 8)) | (context->key[i] >> (8 - (i % 8)));
        derived_key[i] = rotated ^ context->iv[i % context->iv_length];
    }
    
    // generate expected tag 
    unsigned char expected_tag[16];
    for (int i = 0; i < tag_size; i++) {
        expected_tag[i] = 0;
        // combine multiple bytes of ciphertext with derived key
        for (size_t j = 0; j < ciphertext_len; j += tag_size) {
            if (j + i < ciphertext_len) {
                expected_tag[i] ^= ciphertext[j + i];
            }
        }
        // mix with derived key
        expected_tag[i] ^= derived_key[i % context->key_length];
        // add IV influence
        expected_tag[i] ^= context->iv[i % context->iv_length];
        // add position-dependent transformation
        expected_tag[i] = (expected_tag[i] + (unsigned char)(i * 37)) % 256;
    }
    
    // verify the authentication tag
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
    
    // initialize proper AES core context with derived key
    aes_core_context_t aes_ctx;
    aes_key_expansion(derived_key, context->key_length, &aes_ctx);
    
    // allocate memory for plaintext 
    unsigned char* output = (unsigned char*)malloc(ciphertext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        crypto_secure_free(derived_key, context->key_length);
        return NULL;
    }
    
    // decryption
    unsigned char counter[16];
    memset(counter, 0, 16);
    // use IV as nonce and add a custom twist
    memcpy(counter, context->iv, context->iv_length < 12 ? context->iv_length : 12);
    // add custom counter initialization based on derived key
    counter[12] ^= derived_key[0];
    counter[13] ^= derived_key[1];
    counter[14] ^= derived_key[2];
    counter[15] ^= derived_key[3];
    
    unsigned char keystream[16];
    size_t offset = 0;
    uint32_t counter_val = 1; 
    
    while (offset < ciphertext_len) {
        // set counter value in the last 4 bytes (big-endian) with custom twist
        counter[12] = ((counter_val >> 24) & 0xFF) ^ derived_key[0];
        counter[13] = ((counter_val >> 16) & 0xFF) ^ derived_key[1];
        counter[14] = ((counter_val >> 8) & 0xFF) ^ derived_key[2];
        counter[15] = (counter_val & 0xFF) ^ derived_key[3];
        
        // encrypt counter to generate keystream
        aes_encrypt_block(counter, keystream, &aes_ctx);
        
        // xor keystream with ciphertext to get plaintext
        size_t block_size = (ciphertext_len - offset) < 16 ? (ciphertext_len - offset) : 16;
        for (size_t i = 0; i < block_size; i++) {
            output[offset + i] = ciphertext[offset + i] ^ keystream[i];
        }
        
        offset += block_size;
        counter_val++;
    }
    
    // clean up derived key
    crypto_secure_free(derived_key, context->key_length);
    
    // set the output length
    if (output_length) {
        *output_length = ciphertext_len;
    }
    
    return output;
}

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>

// OpenSSL implementation
unsigned char* aes_gcm_openssl_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *output = NULL;
    int len = 0, ciphertext_len = 0;
    int tag_len = 16; 
    unsigned char tag[16];
    
    // calculate output size 
    int total_length = data_length + context->iv_length + tag_len;
    
    // allocate memory for output
    output = (unsigned char*)malloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // copy IV to the beginning of output
    memcpy(output, context->iv, context->iv_length);
    
    // create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Could not create OpenSSL cipher context\n");
        free(output);
        return NULL;
    }
    
    // select the appropriate cipher based on key size
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
    
    // initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
        fprintf(stderr, "Error: Could not initialize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // set IV length if different from default
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, context->iv_length, NULL)) {
        fprintf(stderr, "Error: Could not set IV length\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // initialize key and IV
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, context->key, context->iv)) {
        fprintf(stderr, "Error: Could not initialize key and IV\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // encrypt the plaintext
    if (1 != EVP_EncryptUpdate(ctx, output + context->iv_length, &len, data, data_length)) {
        fprintf(stderr, "Error: Could not encrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    ciphertext_len = len;
    
    // finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, output + context->iv_length + len, &len)) {
        fprintf(stderr, "Error: Could not finalize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    ciphertext_len += len;
    
    // get the tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) {
        fprintf(stderr, "Error: Could not get tag\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // copy the tag to the output
    memcpy(output + context->iv_length + ciphertext_len, tag, tag_len);
    
    // clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // set the output length
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
    int tag_len = 16; 
    
    // ensure we have enough data 
    if (data_length <= context->iv_length + tag_len) {
        fprintf(stderr, "Error: Not enough data for GCM decryption\n");
        return NULL;
    }
    
    // extract IV from the beginning of data
    if (context->iv) {
        free(context->iv);
    }
    context->iv = (unsigned char*)malloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for GCM IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // calculate ciphertext length (data without IV and tag)
    int ciphertext_len = data_length - context->iv_length - tag_len;
    
    // allocate memory for output
    output = (unsigned char*)malloc(ciphertext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Could not create OpenSSL cipher context\n");
        free(output);
        return NULL;
    }
    
    // select the appropriate cipher based on key size
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
    
    // initialize the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
        fprintf(stderr, "Error: Could not initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // set IV length if different from default
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, context->iv_length, NULL)) {
        fprintf(stderr, "Error: Could not set IV length\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // initialize key and IV
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, context->key, context->iv)) {
        fprintf(stderr, "Error: Could not initialize key and IV\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // extract the tag from the ciphertext
    unsigned char tag[16];
    memcpy(tag, data + context->iv_length + ciphertext_len, tag_len);
    
    // set the expected tag value
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag)) {
        fprintf(stderr, "Error: Could not set tag\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // decrypt the ciphertext
    if (1 != EVP_DecryptUpdate(ctx, output, &len, data + context->iv_length, ciphertext_len)) {
        fprintf(stderr, "Error: Could not decrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    plaintext_len = len;
    
    // finalize the decryption
    int ret = EVP_DecryptFinal_ex(ctx, output + len, &len);
    if (ret <= 0) {
        fprintf(stderr, "Error: Tag verification failed. Data may be corrupted.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    plaintext_len += len;
    
    // clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // set the output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}
#endif 