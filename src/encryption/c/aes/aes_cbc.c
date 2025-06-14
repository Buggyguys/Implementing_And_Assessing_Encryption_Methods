#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "aes_cbc.h"
#include "aes_core.h"

// standard AES-CBC 
unsigned char* aes_cbc_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // calculate IV size
    if (context->iv_length == 0) {
        context->iv_length = crypto_get_standard_iv_size("AES", "CBC"); // 16 bytes
    }
    
    // calculate tag size 
    int tag_size = 16; 
    
    // PKCS#7 padding
    int padding_len = 16 - (data_length % 16);
    int padded_len = data_length + padding_len;
    
    // calculate output size (padded data + IV + tag)
    int total_length = padded_len + context->iv_length + tag_size;
    
    // allocate memory 
    unsigned char* output = (unsigned char*)crypto_secure_alloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // append IV output
    memcpy(output, context->iv, context->iv_length);
    
    // create padded data
    unsigned char* padded_data = (unsigned char*)crypto_secure_alloc(padded_len);
    if (!padded_data) {
        fprintf(stderr, "Error: Could not allocate memory for padded data\n");
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    memcpy(padded_data, data, data_length);
    // apply PKCS#7 padding
    for (int i = 0; i < padding_len; i++) {
        padded_data[data_length + i] = padding_len;
    }
    
    // initialize context
    aes_core_context_t aes_ctx;
    aes_key_expansion(context->key, context->key_length, &aes_ctx);
    
    unsigned char prev_block[16];
    memcpy(prev_block, context->iv, 16);
    
    for (int i = 0; i < padded_len; i += 16) {
        unsigned char block[16];
        
        // XOR with previous block (CBC mode)
        for (int j = 0; j < 16; j++) {
            block[j] = padded_data[i + j] ^ prev_block[j];
        }
        
        aes_encrypt_block(block, output + context->iv_length + i, &aes_ctx);
        
        // save block for next iteration
        memcpy(prev_block, output + context->iv_length + i, 16);
    }
    
    // generate authentication tag for the ciphertext
    unsigned char* tag = output + context->iv_length + padded_len;
    if (!crypto_generate_authentication_tag(tag, tag_size, 
                                          output + context->iv_length, padded_len,
                                          context->key, context->key_length)) {
        fprintf(stderr, "Error: Failed to generate authentication tag\n");
        crypto_secure_free(padded_data, padded_len);
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // clean up
    crypto_secure_free(padded_data, padded_len);
    
    // output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_cbc_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // calculate tag size for authentication
    int tag_size = 16; 
    
    // ensure we have enough data 
    if (data_length <= context->iv_length + tag_size) {
        fprintf(stderr, "Error: Not enough data for CBC decryption\n");
        return NULL;
    }
    
    // extract IV 
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for CBC IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // calculate ciphertext size
    int ciphertext_len = data_length - context->iv_length - tag_size;
    
    // verify the authentication tag 
    const unsigned char* tag = data + context->iv_length + ciphertext_len;
    const unsigned char* ciphertext = data + context->iv_length;
    
    if (!crypto_verify_authentication_tag(tag, tag_size, ciphertext, ciphertext_len, 
                                        context->key, context->key_length)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        return NULL; 
    }
    
    // allocate memory for decrypted data 
    unsigned char* decrypted = (unsigned char*)crypto_secure_alloc(ciphertext_len);
    if (!decrypted) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // initialize context
    aes_core_context_t aes_ctx;
    aes_key_expansion(context->key, context->key_length, &aes_ctx);
    
    // decryption
    unsigned char prev_block[16];
    memcpy(prev_block, context->iv, 16);
    
    for (int i = 0; i < ciphertext_len; i += 16) {
        unsigned char block[16];
        
        // decrypt block 
        aes_decrypt_block(ciphertext + i, block, &aes_ctx);
        
        // XOR with previous block 
        for (int j = 0; j < 16; j++) {
            decrypted[i + j] = block[j] ^ prev_block[j];
        }
        
        // save block for next iteration
        memcpy(prev_block, ciphertext + i, 16);
    }
    
    // remove PKCS#7 padding
    int padding_len = decrypted[ciphertext_len - 1];
    if (padding_len < 1 || padding_len > 16) {
        fprintf(stderr, "Error: Invalid padding in decrypted data\n");
        crypto_secure_free(decrypted, ciphertext_len);
        return NULL;
    }
    
    // verify padding
    for (int i = 0; i < padding_len; i++) {
        if (decrypted[ciphertext_len - 1 - i] != padding_len) {
            fprintf(stderr, "Error: Invalid padding in decrypted data\n");
            crypto_secure_free(decrypted, ciphertext_len);
            return NULL;
        }
    }
    
    int plaintext_len = ciphertext_len - padding_len;
    
    // allocate final output
    unsigned char* output = (unsigned char*)crypto_secure_alloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for final output\n");
        crypto_secure_free(decrypted, ciphertext_len);
        return NULL;
    }
    
    memcpy(output, decrypted, plaintext_len);
    crypto_secure_free(decrypted, ciphertext_len);
    
    // output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}

// custom 
unsigned char* aes_cbc_custom_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    // calculate standard IV size 
    if (context->iv_length == 0) {
        context->iv_length = crypto_get_standard_iv_size("AES", "CBC"); 
    }
    
    // calculate tag size for authentication
    int tag_size = 16; 
    
    // calculate output size (original + IV + tag)
    int total_length = data_length + context->iv_length + tag_size;
    
    // allocate memory
    unsigned char* output = (unsigned char*)crypto_secure_alloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // append IV to output
    memcpy(output, context->iv, context->iv_length);
    
    // PKCS#7 padding 
    int padding_len = 16 - (data_length % 16);
    int padded_len = data_length + padding_len;
    
    // create padded data
    unsigned char* padded_data = (unsigned char*)crypto_secure_alloc(padded_len);
    if (!padded_data) {
        fprintf(stderr, "Error: Could not allocate memory for padded data\n");
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    memcpy(padded_data, data, data_length);
    // apply PKCS#7 padding
    for (int i = 0; i < padding_len; i++) {
        padded_data[data_length + i] = padding_len;
    }
    
    // create a custom derived key 
    unsigned char* derived_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!derived_key) {
        fprintf(stderr, "Error: Could not allocate memory for derived key\n");
        crypto_secure_free(padded_data, padded_len);
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // rotate and XOR with IV
    for (int i = 0; i < context->key_length; i++) {
        unsigned char rotated = (context->key[i] << 2) | (context->key[i] >> 6);
        derived_key[i] = rotated ^ context->iv[i % context->iv_length];
    }
    
    // initialize context with derived key
    aes_core_context_t aes_ctx;
    aes_key_expansion(derived_key, context->key_length, &aes_ctx);
    
    // encryption
    unsigned char prev_block[16];
    memcpy(prev_block, context->iv, 16);
    
    for (int i = 0; i < padded_len; i += 16) {
        unsigned char block[16];
        
        // XOR with previous block 
        for (int j = 0; j < 16; j++) {
            block[j] = padded_data[i + j] ^ prev_block[j];
        }
        
        // encrypt block 
        aes_encrypt_block(block, output + context->iv_length + i, &aes_ctx);
        
        // save block for next iteration
        memcpy(prev_block, output + context->iv_length + i, 16);
    }
    
    // update total_length for padded data
    total_length = padded_len + context->iv_length + tag_size;
    
    // generate authentication tag 
    unsigned char* tag = output + context->iv_length + padded_len;
    if (!crypto_generate_authentication_tag(tag, tag_size, 
                                          output + context->iv_length, padded_len,
                                          derived_key, context->key_length)) {
        fprintf(stderr, "Error: Failed to generate authentication tag\n");
        crypto_secure_free(derived_key, context->key_length);
        crypto_secure_free(padded_data, padded_len);
        crypto_secure_free(output, total_length);
        return NULL;
    }
    
    // clean up
    crypto_secure_free(derived_key, context->key_length);
    crypto_secure_free(padded_data, padded_len);
    
    // output length
    if (output_length) {
        *output_length = total_length;
    }
    
    return output;
}

unsigned char* aes_cbc_custom_decrypt(aes_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // calculate tag size for authentication
    int tag_size = 16; 
    
    // ensure we have enough data 
    if (data_length <= context->iv_length + tag_size) {
        fprintf(stderr, "Error: Not enough data for CBC decryption\n");
        return NULL;
    }
    
    // extract IV 
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for CBC IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // calculate ciphertext size 
    int ciphertext_len = data_length - context->iv_length - tag_size;
    
    // create the same custom derived key 
    unsigned char* derived_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!derived_key) {
        fprintf(stderr, "Error: Could not allocate memory for derived key\n");
        return NULL;
    }
    
    // rotate and XOR with IV 
    for (int i = 0; i < context->key_length; i++) {
        unsigned char rotated = (context->key[i] << 2) | (context->key[i] >> 6);
        derived_key[i] = rotated ^ context->iv[i % context->iv_length];
    }
    
    // verify the authentication tag 
    const unsigned char* tag = data + context->iv_length + ciphertext_len;
    const unsigned char* ciphertext = data + context->iv_length;
    
    if (!crypto_verify_authentication_tag(tag, tag_size, ciphertext, ciphertext_len, 
                                        derived_key, context->key_length)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        crypto_secure_free(derived_key, context->key_length);
        return NULL; 
    }
    
    // allocate memory for decrypted data 
    unsigned char* decrypted = (unsigned char*)crypto_secure_alloc(ciphertext_len);
    if (!decrypted) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        crypto_secure_free(derived_key, context->key_length);
        return NULL;
    }
    
    // initialize context with derived key
    aes_core_context_t aes_ctx;
    aes_key_expansion(derived_key, context->key_length, &aes_ctx);
    
    // decryption
    unsigned char prev_block[16];
    memcpy(prev_block, context->iv, 16);
    
    for (int i = 0; i < ciphertext_len; i += 16) {
        unsigned char block[16];
        
        // decrypt block 
        aes_decrypt_block(ciphertext + i, block, &aes_ctx);
        
        // XOR with previous block 
        for (int j = 0; j < 16; j++) {
            decrypted[i + j] = block[j] ^ prev_block[j];
        }
        
        // save block for next iteration
        memcpy(prev_block, ciphertext + i, 16);
    }
    
    // remove PKCS#7 padding
    int padding_len = decrypted[ciphertext_len - 1];
    if (padding_len < 1 || padding_len > 16) {
        fprintf(stderr, "Error: Invalid padding in decrypted data\n");
        crypto_secure_free(derived_key, context->key_length);
        crypto_secure_free(decrypted, ciphertext_len);
        return NULL;
    }
    
    // verify padding
    for (int i = 0; i < padding_len; i++) {
        if (decrypted[ciphertext_len - 1 - i] != padding_len) {
            fprintf(stderr, "Error: Invalid padding in decrypted data\n");
            crypto_secure_free(derived_key, context->key_length);
            crypto_secure_free(decrypted, ciphertext_len);
            return NULL;
        }
    }
    
    int plaintext_len = ciphertext_len - padding_len;
    
    // allocate final output
    unsigned char* output = (unsigned char*)crypto_secure_alloc(plaintext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for final output\n");
        crypto_secure_free(derived_key, context->key_length);
        crypto_secure_free(decrypted, ciphertext_len);
        return NULL;
    }
    
    memcpy(output, decrypted, plaintext_len);
    
    // clean up
    crypto_secure_free(derived_key, context->key_length);
    crypto_secure_free(decrypted, ciphertext_len);
    
    // output length
    if (output_length) {
        *output_length = plaintext_len;
    }
    
    return output;
}

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>

// openssl 
unsigned char* aes_cbc_openssl_encrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *output = NULL;
    int len = 0, ciphertext_len = 0;
    int block_size = 16; 
    
    // calculate output size 
    int padding_len = block_size - (data_length % block_size);
    int total_length = data_length + padding_len + context->iv_length;
    
    // allocate memory for output
    output = (unsigned char*)malloc(total_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for encrypted data\n");
        return NULL;
    }
    
    // append IV to output
    memcpy(output, context->iv, context->iv_length);
    
    // create and initialize context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Could not create OpenSSL cipher context\n");
        free(output);
        return NULL;
    }
    
    // select the appropriate cipher based on key size
    const EVP_CIPHER *cipher = NULL;
    switch (context->key_size) {
        case 128:
            cipher = EVP_aes_128_cbc();
            break;
        case 192:
            cipher = EVP_aes_192_cbc();
            break;
        case 256:
            cipher = EVP_aes_256_cbc();
            break;
        default:
            fprintf(stderr, "Error: Invalid key size for AES-CBC: %d\n", context->key_size);
            EVP_CIPHER_CTX_free(ctx);
            free(output);
            return NULL;
    }
    
    // initialize the encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, context->key, context->iv)) {
        fprintf(stderr, "Error: Could not initialize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // encrypt
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
    
    // clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // output length
    if (output_length) {
        *output_length = context->iv_length + ciphertext_len;
    }
    
    return output;
}

unsigned char* aes_cbc_openssl_decrypt(aes_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *output = NULL;
    int len = 0, plaintext_len = 0;
    
    // ensure we have enough data 
    if (data_length <= context->iv_length) {
        fprintf(stderr, "Error: Not enough data for CBC decryption\n");
        return NULL;
    }
    
    // extract IV 
    if (context->iv) {
        free(context->iv);
    }
    context->iv = (unsigned char*)malloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for CBC IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // calculate ciphertext length 
    int ciphertext_len = data_length - context->iv_length;
    
    // allocate memory for output 
    output = (unsigned char*)malloc(ciphertext_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        return NULL;
    }
    
    // create and initialize context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Could not create OpenSSL cipher context\n");
        free(output);
        return NULL;
    }
    
    // select key size
    const EVP_CIPHER *cipher = NULL;
    switch (context->key_size) {
        case 128:
            cipher = EVP_aes_128_cbc();
            break;
        case 192:
            cipher = EVP_aes_192_cbc();
            break;
        case 256:
            cipher = EVP_aes_256_cbc();
            break;
        default:
            fprintf(stderr, "Error: Invalid key size for AES-CBC: %d\n", context->key_size);
            EVP_CIPHER_CTX_free(ctx);
            free(output);
            return NULL;
    }
    
    // initialize the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, context->key, context->iv)) {
        fprintf(stderr, "Error: Could not initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // decrypt
    if (1 != EVP_DecryptUpdate(ctx, output, &len, data + context->iv_length, ciphertext_len)) {
        fprintf(stderr, "Error: Could not decrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    plaintext_len = len;
    
    // finalize the decryption 
    if (1 != EVP_DecryptFinal_ex(ctx, output + len, &len)) {
        fprintf(stderr, "Error: Padding verification failed. Data may be corrupted.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
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
#endif 