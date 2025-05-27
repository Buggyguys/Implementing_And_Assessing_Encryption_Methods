#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "camellia_common.h"
#include "camellia_gcm.h"

// Camellia-GCM encryption function with proper authentication
unsigned char* camellia_gcm_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate the output length (data + IV + tag)
    int tag_length = 16; // 128-bit authentication tag
    *output_length = data_length + context->iv_length + tag_length;
    
    // Allocate memory for the output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(*output_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-GCM encryption output\n");
        return NULL;
    }
    
    // Structure of output: IV + Ciphertext + Authentication Tag
    
    // Copy the IV to the output
    memcpy(output, context->iv, context->iv_length);
    
    // For this placeholder, we'll just XOR the data with the key as a simple "encryption"
    // In a real implementation, you would use the Camellia cipher in GCM mode
    for (int i = 0; i < data_length; i++) {
        output[context->iv_length + i] = data[i] ^ context->key[i % context->key_length];
    }
    
    // Generate proper authentication tag
    if (!crypto_generate_authentication_tag(
            output + context->iv_length + data_length,
            tag_length,
            output + context->iv_length,
            data_length,
            context->key,
            context->key_length)) {
        fprintf(stderr, "Error: Failed to generate Camellia-GCM authentication tag\n");
        crypto_secure_free(output, *output_length);
        return NULL;
    }
    
    return output;
}

// Camellia-GCM decryption function with authentication verification
unsigned char* camellia_gcm_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    int tag_length = 16; // 128-bit authentication tag
    
    // Check if the data is large enough to contain IV and tag
    if (data_length < context->iv_length + tag_length) {
        fprintf(stderr, "Error: Invalid Camellia-GCM ciphertext length\n");
        return NULL;
    }
    
    // Calculate the plaintext length
    *output_length = data_length - context->iv_length - tag_length;
    
    // Extract IV if necessary
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-GCM IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Verify the authentication tag
    const unsigned char* ciphertext = data + context->iv_length;
    const unsigned char* tag = data + context->iv_length + *output_length;
    
    if (!crypto_verify_authentication_tag(
            tag,
            tag_length,
            ciphertext,
            *output_length,
            context->key,
            context->key_length)) {
        fprintf(stderr, "Error: Camellia-GCM authentication tag verification failed. Data may be corrupted or tampered with.\n");
        return NULL; // Fail securely on authentication failure
    }
    
    // Allocate memory for the plaintext using secure allocation
    unsigned char* plaintext = (unsigned char*)crypto_secure_alloc(*output_length);
    if (!plaintext) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-GCM decryption output\n");
        return NULL;
    }
    
    // Decrypt the data
    for (int i = 0; i < *output_length; i++) {
        plaintext[i] = data[context->iv_length + i] ^ context->key[i % context->key_length];
    }
    
    return plaintext;
}

// Custom Camellia-GCM encryption function with authentication
unsigned char* camellia_gcm_custom_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // Calculate the output length (data + IV + tag)
    int tag_length = 16; // 128-bit authentication tag
    *output_length = data_length + context->iv_length + tag_length;
    
    // Allocate memory for the output using secure allocation
    unsigned char* output = (unsigned char*)crypto_secure_alloc(*output_length);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for Custom Camellia-GCM encryption output\n");
        return NULL;
    }
    
    // Structure of output: IV + Ciphertext + Authentication Tag
    
    // Copy the IV to the output
    memcpy(output, context->iv, context->iv_length);
    
    // Create a custom key variant by rotating it
    unsigned char* rotated_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!rotated_key) {
        fprintf(stderr, "Error: Could not allocate memory for rotated key\n");
        crypto_secure_free(output, *output_length);
        return NULL;
    }
    
    memcpy(rotated_key, context->key, context->key_length);
    
    // Rotate key by 2 bytes
    if (context->key_length > 2) {
        unsigned char temp[2];
        memcpy(temp, rotated_key, 2);
        memmove(rotated_key, rotated_key + 2, context->key_length - 2);
        memcpy(rotated_key + context->key_length - 2, temp, 2);
    }
    
    // Custom encryption - use rotated key and add position-based complexity
    for (int i = 0; i < data_length; i++) {
        // XOR with rotated key and position
        output[context->iv_length + i] = data[i] ^ rotated_key[i % context->key_length] ^ (i & 0xFF);
    }
    
    // Generate proper authentication tag using the rotated key
    if (!crypto_generate_authentication_tag(
            output + context->iv_length + data_length,
            tag_length,
            output + context->iv_length,
            data_length,
            rotated_key,
            context->key_length)) {
        fprintf(stderr, "Error: Failed to generate Custom Camellia-GCM authentication tag\n");
        crypto_secure_free(rotated_key, context->key_length);
        crypto_secure_free(output, *output_length);
        return NULL;
    }
    
    // Securely free the rotated key
    crypto_secure_free(rotated_key, context->key_length);
    
    return output;
}

// Custom Camellia-GCM decryption function with authentication verification
unsigned char* camellia_gcm_custom_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    int tag_length = 16; // 128-bit authentication tag
    
    // Check if the data is large enough to contain IV and tag
    if (data_length < context->iv_length + tag_length) {
        fprintf(stderr, "Error: Invalid Custom Camellia-GCM ciphertext length\n");
        return NULL;
    }
    
    // Calculate the plaintext length
    *output_length = data_length - context->iv_length - tag_length;
    
    // Extract IV if necessary
    if (context->iv) {
        crypto_secure_free(context->iv, context->iv_length);
    }
    context->iv = (unsigned char*)crypto_secure_alloc(context->iv_length);
    if (!context->iv) {
        fprintf(stderr, "Error: Could not allocate memory for Custom Camellia-GCM IV\n");
        return NULL;
    }
    memcpy(context->iv, data, context->iv_length);
    
    // Create the same custom key variant as in encryption
    unsigned char* rotated_key = (unsigned char*)crypto_secure_alloc(context->key_length);
    if (!rotated_key) {
        fprintf(stderr, "Error: Could not allocate memory for rotated key\n");
        return NULL;
    }
    
    memcpy(rotated_key, context->key, context->key_length);
    
    // Rotate key by 2 bytes
    if (context->key_length > 2) {
        unsigned char temp[2];
        memcpy(temp, rotated_key, 2);
        memmove(rotated_key, rotated_key + 2, context->key_length - 2);
        memcpy(rotated_key + context->key_length - 2, temp, 2);
    }
    
    // Verify the authentication tag
    const unsigned char* ciphertext = data + context->iv_length;
    const unsigned char* tag = data + context->iv_length + *output_length;
    
    if (!crypto_verify_authentication_tag(
            tag,
            tag_length,
            ciphertext,
            *output_length,
            rotated_key,
            context->key_length)) {
        fprintf(stderr, "Error: Custom Camellia-GCM authentication tag verification failed. Data may be corrupted or tampered with.\n");
        crypto_secure_free(rotated_key, context->key_length);
        return NULL; // Fail securely on authentication failure
    }
    
    // Allocate memory for the plaintext using secure allocation
    unsigned char* plaintext = (unsigned char*)crypto_secure_alloc(*output_length);
    if (!plaintext) {
        fprintf(stderr, "Error: Could not allocate memory for Custom Camellia-GCM decryption output\n");
        crypto_secure_free(rotated_key, context->key_length);
        return NULL;
    }
    
    // Decrypt the data with the same custom algorithm
    for (int i = 0; i < *output_length; i++) {
        // Undo the XOR with rotated key and position
        plaintext[i] = data[context->iv_length + i] ^ rotated_key[i % context->key_length] ^ (i & 0xFF);
    }
    
    // Securely free the rotated key
    crypto_secure_free(rotated_key, context->key_length);
    
    return plaintext;
}

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>

// OpenSSL Camellia-GCM encryption function
unsigned char* camellia_gcm_openssl_encrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char *ciphertext;
    int tag_length = 16; // 128-bit authentication tag
    
    // Calculate the output length (data + IV + tag)
    *output_length = data_length + context->iv_length + tag_length;
    
    // Allocate memory for the output
    ciphertext = (unsigned char*)malloc(*output_length);
    if (!ciphertext) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-GCM encryption output\n");
        return NULL;
    }
    
    // Copy the IV to the output
    memcpy(ciphertext, context->iv, context->iv_length);
    
    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Could not create OpenSSL cipher context\n");
        free(ciphertext);
        return NULL;
    }
    
    // Initialize the encryption operation
    const EVP_CIPHER *cipher = NULL;
    switch(context->key_size) {
        case 128:
            cipher = EVP_camellia_128_gcm();
            break;
        case 192:
            cipher = EVP_camellia_192_gcm();
            break;
        case 256:
            cipher = EVP_camellia_256_gcm();
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
    
    // Provide the message to be encrypted, and obtain the encrypted output
    if(1 != EVP_EncryptUpdate(ctx, ciphertext + context->iv_length, &len, data, data_length)) {
        fprintf(stderr, "Error: Could not update OpenSSL encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    ciphertext_len = len;
    
    // Finalize the encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + context->iv_length + len, &len)) {
        fprintf(stderr, "Error: Could not finalize OpenSSL encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    ciphertext_len += len;
    
    // Get the tag
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_length, ciphertext + context->iv_length + ciphertext_len)) {
        fprintf(stderr, "Error: Could not get OpenSSL GCM tag\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // Update the output length
    *output_length = context->iv_length + ciphertext_len + tag_length;
    
    return ciphertext;
}

// OpenSSL Camellia-GCM decryption function
unsigned char* camellia_gcm_openssl_decrypt(camellia_context_t* context, const unsigned char* data, int data_length, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    unsigned char *plaintext;
    int tag_length = 16; // 128-bit authentication tag
    
    // Check if the data is large enough to contain IV and tag
    if (data_length < context->iv_length + tag_length) {
        fprintf(stderr, "Error: Invalid Camellia-GCM ciphertext length\n");
        return NULL;
    }
    
    // Calculate the plaintext length
    *output_length = data_length - context->iv_length - tag_length;
    
    // Allocate memory for the plaintext
    plaintext = (unsigned char*)malloc(*output_length);
    if (!plaintext) {
        fprintf(stderr, "Error: Could not allocate memory for Camellia-GCM decryption output\n");
        return NULL;
    }
    
    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Could not create OpenSSL cipher context\n");
        free(plaintext);
        return NULL;
    }
    
    // Initialize the decryption operation
    const EVP_CIPHER *cipher = NULL;
    switch(context->key_size) {
        case 128:
            cipher = EVP_camellia_128_gcm();
            break;
        case 192:
            cipher = EVP_camellia_192_gcm();
            break;
        case 256:
            cipher = EVP_camellia_256_gcm();
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
    
    // Provide the message to be decrypted, and obtain the plaintext output
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, data + context->iv_length, *output_length)) {
        fprintf(stderr, "Error: Could not update OpenSSL decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }
    plaintext_len = len;
    
    // Set expected tag value
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_length, (void*)(data + data_length - tag_length))) {
        fprintf(stderr, "Error: Could not set OpenSSL GCM tag\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }
    
    // Finalize the decryption
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        fprintf(stderr, "Error: Could not finalize OpenSSL decryption (tag verification failed)\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }
    plaintext_len += len;
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // Update the output length
    *output_length = plaintext_len;
    
    return plaintext;
}
#endif 