#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

#include "implementation.h"
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "ecc_common.h"
#include "ecc_key.h"

// Define constants for ECC hybrid encryption
#define AES_KEY_SIZE 32  // 256 bits for AES symmetric key
#define AES_BLOCK_SIZE 16
#define AES_IV_SIZE 16
#define AUTH_TAG_SIZE 16 // 16 bytes (128 bits) for authentication tag

// ECIES (Elliptic Curve Integrated Encryption Scheme) for hybrid decryption
unsigned char* ecc_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    ecc_context_t* ecc_context = (ecc_context_t*)context;
    
    // Parse input data
    // Format: [ephemeral_pubkey_len(4)][ephemeral_pubkey][iv(16)][encrypted_data_len(4)][encrypted_data][tag(16)]
    
    // Minimum data length check
    if (data_length < 8 + AES_IV_SIZE + AUTH_TAG_SIZE) {
        fprintf(stderr, "Error: Invalid data format for ECC decryption (too short)\n");
        return NULL;
    }
    
    // Get ephemeral public key length
    int ephemeral_pubkey_len = *(int*)data;
    
    // Validate ephemeral key length
    if (ephemeral_pubkey_len <= 0 || ephemeral_pubkey_len > data_length - 8 - AES_IV_SIZE - AUTH_TAG_SIZE) {
        fprintf(stderr, "Error: Invalid ephemeral public key length: %d\n", ephemeral_pubkey_len);
        return NULL;
    }
    
    // Get ephemeral public key
    const unsigned char* ephemeral_pubkey = data + 4;
    
    // Get IV
    const unsigned char* iv = data + 4 + ephemeral_pubkey_len;
    
    // Get encrypted data length
    int encrypted_data_len = *(int*)(data + 4 + ephemeral_pubkey_len + AES_IV_SIZE);
    
    // Validate encrypted data length
    if (encrypted_data_len <= 0 || 
        4 + ephemeral_pubkey_len + AES_IV_SIZE + 4 + encrypted_data_len + AUTH_TAG_SIZE > data_length) {
        fprintf(stderr, "Error: Invalid encrypted data length: %d\n", encrypted_data_len);
        return NULL;
    }
    
    // Get encrypted data
    const unsigned char* encrypted_data = data + 4 + ephemeral_pubkey_len + AES_IV_SIZE + 4;
    
    // Get authentication tag
    const unsigned char* tag = data + 4 + ephemeral_pubkey_len + AES_IV_SIZE + 4 + encrypted_data_len;
    
    // Make sure we have our private key
    if (!ecc_context->ec_key || !EC_KEY_get0_private_key(ecc_context->ec_key)) {
        fprintf(stderr, "Error: No private key available for decryption\n");
        return NULL;
    }
    
    // Import ephemeral public key
    EC_KEY* ephemeral_key = ecc_import_public_key(ephemeral_pubkey, ephemeral_pubkey_len, ecc_context->curve);
    if (!ephemeral_key) {
        fprintf(stderr, "Error: Could not import ephemeral public key\n");
        return NULL;
    }
    
    // Get ephemeral public key point
    const EC_POINT* ephemeral_pubkey_point = EC_KEY_get0_public_key(ephemeral_key);
    if (!ephemeral_pubkey_point) {
        fprintf(stderr, "Error: Could not get ephemeral public key point\n");
        EC_KEY_free(ephemeral_key);
        return NULL;
    }
    
    // Compute shared secret using ECDH
    const EC_GROUP* group = EC_KEY_get0_group(ecc_context->ec_key);
    int shared_secret_length = (EC_GROUP_get_degree(group) + 7) / 8;
    unsigned char* shared_secret = (unsigned char*)crypto_secure_alloc(shared_secret_length);
    if (!shared_secret) {
        fprintf(stderr, "Error: Memory allocation failed for shared secret\n");
        EC_KEY_free(ephemeral_key);
        return NULL;
    }
    
    int field_size = ECDH_compute_key(shared_secret, shared_secret_length, 
                                     ephemeral_pubkey_point, ecc_context->ec_key, NULL);
    
    if (field_size <= 0) {
        fprintf(stderr, "Error: ECDH key computation failed\n");
        EC_KEY_free(ephemeral_key);
        crypto_secure_free(shared_secret, shared_secret_length);
        return NULL;
    }
    
    // Derive symmetric encryption key from shared secret
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        fprintf(stderr, "Error: Could not create message digest context\n");
        EC_KEY_free(ephemeral_key);
        crypto_secure_free(shared_secret, shared_secret_length);
        return NULL;
    }
    
    unsigned char* aes_key = (unsigned char*)crypto_secure_alloc(AES_KEY_SIZE);
    if (!aes_key) {
        fprintf(stderr, "Error: Could not allocate memory for AES key\n");
        EVP_MD_CTX_free(md_ctx);
        EC_KEY_free(ephemeral_key);
        crypto_secure_free(shared_secret, shared_secret_length);
        return NULL;
    }
    
    unsigned int aes_key_length = AES_KEY_SIZE;
    
    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(md_ctx, shared_secret, field_size) != 1 ||
        EVP_DigestFinal_ex(md_ctx, aes_key, &aes_key_length) != 1) {
        
        fprintf(stderr, "Error: Could not derive AES key\n");
        EVP_MD_CTX_free(md_ctx);
        EC_KEY_free(ephemeral_key);
        crypto_secure_free(shared_secret, shared_secret_length);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        return NULL;
    }
    
    EVP_MD_CTX_free(md_ctx);
    
    // Verify the authentication tag first
    if (!crypto_verify_authentication_tag(tag, AUTH_TAG_SIZE, encrypted_data, encrypted_data_len, 
                                        aes_key, AES_KEY_SIZE)) {
        fprintf(stderr, "Error: Authentication tag verification failed. Data may be corrupted or tampered with.\n");
        EC_KEY_free(ephemeral_key);
        crypto_secure_free(shared_secret, shared_secret_length);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        return NULL; // Fail securely on authentication failure
    }
    
    // Initialize AES decryption
    EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
    if (!aes_ctx) {
        fprintf(stderr, "Error: Could not create AES context\n");
        EC_KEY_free(ephemeral_key);
        crypto_secure_free(shared_secret, shared_secret_length);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        return NULL;
    }
    
    if (EVP_DecryptInit_ex(aes_ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        fprintf(stderr, "Error: Could not initialize AES decryption\n");
        EVP_CIPHER_CTX_free(aes_ctx);
        EC_KEY_free(ephemeral_key);
        crypto_secure_free(shared_secret, shared_secret_length);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        return NULL;
    }
    
    // Allocate memory for decrypted data
    unsigned char* output = (unsigned char*)crypto_secure_alloc(encrypted_data_len);
    if (!output) {
        fprintf(stderr, "Error: Could not allocate memory for decrypted data\n");
        EVP_CIPHER_CTX_free(aes_ctx);
        EC_KEY_free(ephemeral_key);
        crypto_secure_free(shared_secret, shared_secret_length);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        return NULL;
    }
    
    // Decrypt the data
    int output_len = 0;
    int len = 0;
    
    if (EVP_DecryptUpdate(aes_ctx, output, &len, encrypted_data, encrypted_data_len) != 1) {
        fprintf(stderr, "Error: AES decryption failed\n");
        crypto_secure_free(output, encrypted_data_len);
        EVP_CIPHER_CTX_free(aes_ctx);
        EC_KEY_free(ephemeral_key);
        crypto_secure_free(shared_secret, shared_secret_length);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        return NULL;
    }
    output_len = len;
    
    // Finalize decryption
    if (EVP_DecryptFinal_ex(aes_ctx, output + len, &len) != 1) {
        fprintf(stderr, "Error: AES decryption finalization failed\n");
        crypto_secure_free(output, encrypted_data_len);
        EVP_CIPHER_CTX_free(aes_ctx);
        EC_KEY_free(ephemeral_key);
        crypto_secure_free(shared_secret, shared_secret_length);
        crypto_secure_free(aes_key, AES_KEY_SIZE);
        return NULL;
    }
    output_len += len;
    
    // Clean up
    EVP_CIPHER_CTX_free(aes_ctx);
    EC_KEY_free(ephemeral_key);
    crypto_secure_free(shared_secret, shared_secret_length);
    crypto_secure_free(aes_key, AES_KEY_SIZE);
    
    // Set output length
    if (output_length) {
        *output_length = output_len;
    }
    
    return output;
}

// Stream decryption - just uses regular decryption for each chunk
unsigned char* ecc_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    // For simplicity, just use regular decryption
    // In a real implementation, this would maintain state across chunks
    return ecc_decrypt(context, data, data_length, key, output_length);
}

// Custom implementation decryption (wrapper around standard implementation)
unsigned char* ecc_custom_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length) {
    return ecc_decrypt(context, data, data_length, key, output_length);
}

// Custom implementation stream decryption (wrapper around standard implementation)
unsigned char* ecc_custom_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    return ecc_decrypt_stream(context, data, data_length, key, chunk_index, output_length);
} 