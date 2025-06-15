#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "camellia_common.h"
#include "camellia_ecb.h"
#include "implementation.h"

#define AUTH_TAG_SIZE 16 // 16 bytes (128 bits) for authentication tag
#define CAMELLIA_BLOCK_SIZE 16

// forward declarations for internal functions
extern void camellia_encrypt_128(const uint8_t* input, uint8_t* output, const uint64_t subkeys[26]);
extern void camellia_decrypt_128(const uint8_t* input, uint8_t* output, const uint64_t subkeys[26]);
extern void camellia_key_schedule_128(const uint8_t* key, uint64_t subkeys[26]);

// ecb encryption function
unsigned char* camellia_ecb_encrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length == 0) return NULL;
    
    // set mode to ecb
    strcpy(context->mode, "ECB");
    
    // use main implementation functions
    if (context->is_custom) {
        return camellia_custom_encrypt(context, data, data_length, context->key, output_length);
    } else {
        return camellia_encrypt(context, data, data_length, context->key, output_length);
    }
}

// ecb decryption function
unsigned char* camellia_ecb_decrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length == 0) return NULL;
    
    // set mode to ecb
    strcpy(context->mode, "ECB");
    
    // use main implementation functions
    if (context->is_custom) {
        return camellia_custom_decrypt(context, data, data_length, context->key, output_length);
    } else {
        return camellia_decrypt(context, data, data_length, context->key, output_length);
    }
}

// custom ecb encryption function using real block cipher
unsigned char* camellia_ecb_custom_encrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length == 0) return NULL;
    
    // only support 128-bit keys for custom implementation
    if (context->key_size != 128) {
        fprintf(stderr, "Custom ECB: Only 128-bit keys supported\n");
        return NULL;
    }
    
    // generate subkeys
    uint64_t subkeys[26];
    camellia_key_schedule_128(context->key, subkeys);
    
    // calculate output size (padded to 16-byte blocks)
    size_t padded_length = ((data_length + 15) / 16) * 16;
    unsigned char* output = (unsigned char*)malloc(padded_length);
    if (!output) return NULL;
    
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
        
        // encrypt the block
        camellia_encrypt_128(block, output + i, subkeys);
    }
    
    *output_length = padded_length;
    return output;
}

// custom ecb decryption function using real block cipher
unsigned char* camellia_ecb_custom_decrypt(camellia_context_t* context, const unsigned char* data, size_t data_length, size_t* output_length) {
    if (!context || !data || data_length == 0 || data_length % 16 != 0) return NULL;
    
    // only support 128-bit keys for custom implementation
    if (context->key_size != 128) {
        fprintf(stderr, "Custom ECB: Only 128-bit keys supported\n");
        return NULL;
    }
    
    // generate subkeys
    uint64_t subkeys[26];
    camellia_key_schedule_128(context->key, subkeys);
    
    unsigned char* output = (unsigned char*)malloc(data_length);
    if (!output) return NULL;
    
    // decrypt block by block
    for (size_t i = 0; i < data_length; i += 16) {
        camellia_decrypt_128(data + i, output + i, subkeys);
    }
    
    // remove pkcs#7 padding
    if (data_length > 0) {
        uint8_t pad_value = output[data_length - 1];
        if (pad_value <= 16) {
            *output_length = data_length - pad_value;
        } else {
            *output_length = data_length;
        }
    } else {
        *output_length = 0;
    }
    
    return output;
} 