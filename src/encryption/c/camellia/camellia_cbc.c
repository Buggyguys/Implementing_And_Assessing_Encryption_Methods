#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "camellia_common.h"
#include "camellia_cbc.h"
#include "implementation.h"

#define AUTH_TAG_SIZE 16 // 16 bytes (128 bits) for authentication tag
#define CAMELLIA_BLOCK_SIZE 16

// forward declarations for internal functions
extern void camellia_encrypt_128(const uint8_t* input, uint8_t* output, const uint64_t subkeys[26]);
extern void camellia_decrypt_128(const uint8_t* input, uint8_t* output, const uint64_t subkeys[26]);
extern void camellia_key_schedule_128(const uint8_t* key, uint64_t subkeys[26]);

// cbc encryption function with authentication
unsigned char* camellia_cbc_encrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length == 0) return NULL;
    
    // set mode to cbc
    strcpy(context->mode, "CBC");
    
    // use main implementation functions
    if (context->is_custom) {
        return camellia_custom_encrypt(context, data, data_length, context->key, output_length);
    } else {
        return camellia_encrypt(context, data, data_length, context->key, output_length);
    }
}

// cbc decryption function with authentication verification
unsigned char* camellia_cbc_decrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length == 0) return NULL;
    
    // set mode to cbc
    strcpy(context->mode, "CBC");
    
    // use main implementation functions
    if (context->is_custom) {
        return camellia_custom_decrypt(context, data, data_length, context->key, output_length);
    } else {
        return camellia_decrypt(context, data, data_length, context->key, output_length);
    }
}

// custom cbc encryption function using real block cipher
unsigned char* camellia_cbc_custom_encrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length == 0) return NULL;
    
    // only support 128-bit keys for custom implementation
    if (context->key_size != 128) {
        fprintf(stderr, "Custom CBC: Only 128-bit keys supported\n");
        return NULL;
    }
    
    // generate subkeys
    uint64_t subkeys[26];
    camellia_key_schedule_128(context->key, subkeys);
    
    // generate iv if not present
    if (!context->iv) {
        context->iv_length = 16;
        context->iv = (unsigned char*)malloc(16);
        if (!context->iv) return NULL;
        
        // generate random iv
        for (int i = 0; i < 16; i++) {
            context->iv[i] = rand() & 0xFF;
        }
    }
    
    // calculate output size (iv + padded data)
    size_t padded_length = ((data_length + 15) / 16) * 16;
    size_t total_length = 16 + padded_length;
    unsigned char* output = (unsigned char*)malloc(total_length);
    if (!output) return NULL;
    
    // copy iv to output
    memcpy(output, context->iv, 16);
    
    // previous block starts with iv
    uint8_t prev_block[16];
    memcpy(prev_block, context->iv, 16);
    
    // encrypt block by block
    for (size_t i = 0; i < data_length; i += 16) {
        uint8_t block[16];
        memset(block, 0, 16);
        
        size_t copy_len = (data_length - i < 16) ? data_length - i : 16;
        memcpy(block, data + i, copy_len);
        
        // pkcs#7 padding for last block
        if (copy_len < 16) {
            uint8_t pad_value = 16 - copy_len;
            for (size_t j = copy_len; j < 16; j++) {
                block[j] = pad_value;
            }
        }
        
        // xor with previous block (cbc mode)
        for (int j = 0; j < 16; j++) {
            block[j] ^= prev_block[j];
        }
        
        // encrypt the xored block
        camellia_encrypt_128(block, output + 16 + i, subkeys);
        
        // update previous block
        memcpy(prev_block, output + 16 + i, 16);
    }
    
    *output_length = total_length;
    return output;
}

// custom cbc decryption function using real block cipher
unsigned char* camellia_cbc_custom_decrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length < 32 || (data_length - 16) % 16 != 0) return NULL;
    
    // only support 128-bit keys for custom implementation
    if (context->key_size != 128) {
        fprintf(stderr, "Custom CBC: Only 128-bit keys supported\n");
        return NULL;
    }
    
    // generate subkeys
    uint64_t subkeys[26];
    camellia_key_schedule_128(context->key, subkeys);
    
    // extract iv
    uint8_t iv[16];
    memcpy(iv, data, 16);
    
    size_t ciphertext_length = data_length - 16;
    unsigned char* output = (unsigned char*)malloc(ciphertext_length);
    if (!output) return NULL;
    
    // previous block starts with iv
    uint8_t prev_block[16];
    memcpy(prev_block, iv, 16);
    
    // decrypt block by block
    for (size_t i = 0; i < ciphertext_length; i += 16) {
        uint8_t decrypted_block[16];
        
        // decrypt the block
        camellia_decrypt_128(data + 16 + i, decrypted_block, subkeys);
        
        // xor with previous block (cbc mode)
        for (int j = 0; j < 16; j++) {
            output[i + j] = decrypted_block[j] ^ prev_block[j];
        }
        
        // update previous block
        memcpy(prev_block, data + 16 + i, 16);
    }
    
    // remove pkcs#7 padding
    if (ciphertext_length > 0) {
        uint8_t pad_value = output[ciphertext_length - 1];
        if (pad_value <= 16) {
            *output_length = ciphertext_length - pad_value;
        } else {
            *output_length = ciphertext_length;
        }
    } else {
        *output_length = 0;
    }
    
    return output;
}

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>

// openssl cbc encryption function
unsigned char* camellia_cbc_openssl_encrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char *ciphertext;
    
    // calculate output length (data + iv + padding)
    int block_size = CAMELLIA_BLOCK_SIZE;
    int padded_length = ((data_length + block_size - 1) / block_size) * block_size;
    *output_length = padded_length + context->iv_length;
    
    // allocate memory for output
    ciphertext = (unsigned char*)malloc(*output_length);
    if (!ciphertext) {
        fprintf(stderr, "Error: Could not allocate memory for CBC encryption output\n");
        return NULL;
    }
    
    // copy the iv to the output
    memcpy(ciphertext, context->iv, context->iv_length);
    
    // create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Could not create OpenSSL cipher context\n");
        free(ciphertext);
        return NULL;
    }
    
    // initialize the encryption operation
    const EVP_CIPHER *cipher = NULL;
    switch(context->key_size) {
        case 128:
            cipher = EVP_camellia_128_cbc();
            break;
        case 192:
            cipher = EVP_camellia_192_cbc();
            break;
        case 256:
            cipher = EVP_camellia_256_cbc();
            break;
        default:
            fprintf(stderr, "Error: Invalid Camellia key size %d\n", context->key_size);
            EVP_CIPHER_CTX_free(ctx);
            free(ciphertext);
            return NULL;
    }
    
    if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, context->key, context->iv)) {
        fprintf(stderr, "Error: Could not initialize OpenSSL encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    
    // provide the message to be encrypted, and obtain the encrypted output
    if(1 != EVP_EncryptUpdate(ctx, ciphertext + context->iv_length, &len, data, data_length)) {
        fprintf(stderr, "Error: Could not update OpenSSL encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    ciphertext_len = len;
    
    // finalize the encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + context->iv_length + len, &len)) {
        fprintf(stderr, "Error: Could not finalize OpenSSL encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    ciphertext_len += len;
    
    // clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // update the output length
    *output_length = context->iv_length + ciphertext_len;
    
    return ciphertext;
}

// openssl cbc decryption function
unsigned char* camellia_cbc_openssl_decrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    unsigned char *plaintext;
    
    // check if the data is large enough to contain the iv
    if (data_length < context->iv_length) {
        fprintf(stderr, "Error: Invalid Camellia-CBC ciphertext length\n");
        return NULL;
    }
    
    // calculate the plaintext length (including padding)
    int padded_length = data_length - context->iv_length;
    
    // allocate memory for the plaintext
    plaintext = (unsigned char*)malloc(padded_length);
    if (!plaintext) {
        fprintf(stderr, "Error: Could not allocate memory for CBC decryption output\n");
        return NULL;
    }
    
    // create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Could not create OpenSSL cipher context\n");
        free(plaintext);
        return NULL;
    }
    
    // initialize the decryption operation
    const EVP_CIPHER *cipher = NULL;
    switch(context->key_size) {
        case 128:
            cipher = EVP_camellia_128_cbc();
            break;
        case 192:
            cipher = EVP_camellia_192_cbc();
            break;
        case 256:
            cipher = EVP_camellia_256_cbc();
            break;
        default:
            fprintf(stderr, "Error: Invalid Camellia key size %d\n", context->key_size);
            EVP_CIPHER_CTX_free(ctx);
            free(plaintext);
            return NULL;
    }
    
    if(1 != EVP_DecryptInit_ex(ctx, cipher, NULL, context->key, data)) {
        fprintf(stderr, "Error: Could not initialize OpenSSL decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }
    
    // provide the message to be decrypted, and obtain the plaintext output
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, data + context->iv_length, padded_length)) {
        fprintf(stderr, "Error: Could not update OpenSSL decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }
    plaintext_len = len;
    
    // finalize the decryption
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        fprintf(stderr, "Error: Could not finalize OpenSSL decryption (padding error)\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }
    plaintext_len += len;
    
    // clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // update the output length
    *output_length = plaintext_len;
    
    return plaintext;
}
#endif 