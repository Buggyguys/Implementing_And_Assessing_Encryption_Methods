#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include "ecc_common.h"
#include "ecc_key.h"

// Key generation wrapper for the implementation interface
unsigned char* ecc_generate_key(void* context, int* key_length) {
    if (!context) return NULL;
    
    ecc_context_t* ecc_context = (ecc_context_t*)context;
    
    // Clean up any existing keys
    if (ecc_context->ec_key) {
        EC_KEY_free(ecc_context->ec_key);
        ecc_context->ec_key = NULL;
    }
    
    if (ecc_context->private_key) {
        free(ecc_context->private_key);
        ecc_context->private_key = NULL;
        ecc_context->private_key_length = 0;
    }
    
    if (ecc_context->public_key) {
        free(ecc_context->public_key);
        ecc_context->public_key = NULL;
        ecc_context->public_key_length = 0;
    }
    
    // Generate a new key pair
    ecc_context->ec_key = ecc_generate_key_pair(ecc_context->curve);
    if (!ecc_context->ec_key) {
        fprintf(stderr, "Error: Failed to generate EC key pair\n");
        return NULL;
    }
    
    // Export the private key (for return value)
    unsigned char* private_key = ecc_export_private_key(ecc_context->ec_key, &ecc_context->private_key_length);
    if (!private_key) {
        fprintf(stderr, "Error: Failed to export private key\n");
        EC_KEY_free(ecc_context->ec_key);
        ecc_context->ec_key = NULL;
        return NULL;
    }
    
    // Store in context
    ecc_context->private_key = (unsigned char*)malloc(ecc_context->private_key_length);
    if (!ecc_context->private_key) {
        fprintf(stderr, "Error: Memory allocation failed for private key\n");
        free(private_key);
        EC_KEY_free(ecc_context->ec_key);
        ecc_context->ec_key = NULL;
        return NULL;
    }
    
    memcpy(ecc_context->private_key, private_key, ecc_context->private_key_length);
    
    // Export the public key (for context)
    ecc_context->public_key = ecc_export_public_key(ecc_context->ec_key, &ecc_context->public_key_length);
    if (!ecc_context->public_key) {
        fprintf(stderr, "Error: Failed to export public key\n");
        free(private_key);
        free(ecc_context->private_key);
        ecc_context->private_key = NULL;
        EC_KEY_free(ecc_context->ec_key);
        ecc_context->ec_key = NULL;
        return NULL;
    }
    
    // Set the output key length
    *key_length = ecc_context->private_key_length;
    
    return private_key;
}

// Custom implementation key generation (wrapper around standard implementation)
unsigned char* ecc_custom_generate_key(void* context, int* key_length) {
    return ecc_generate_key(context, key_length);
}

// Compute shared secret using ECDH
int ecc_compute_shared_secret(ecc_context_t* context, const unsigned char* peer_public_key, int peer_public_key_length, unsigned char** shared_secret) {
    if (!context || !peer_public_key || peer_public_key_length <= 0 || !shared_secret) {
        return -1;
    }
    
    // Make sure we have our private key
    if (!context->ec_key) {
        fprintf(stderr, "Error: No private key available for ECDH\n");
        return -1;
    }
    
    // Import peer public key
    EC_KEY* peer_key = ecc_import_public_key(peer_public_key, peer_public_key_length, context->curve);
    if (!peer_key) {
        fprintf(stderr, "Error: Could not import peer public key\n");
        return -1;
    }
    
    // Get peer public key point
    const EC_POINT* peer_point = EC_KEY_get0_public_key(peer_key);
    if (!peer_point) {
        fprintf(stderr, "Error: Could not get peer public key point\n");
        EC_KEY_free(peer_key);
        return -1;
    }
    
    // Compute shared secret using ECDH
    const EC_GROUP* group = EC_KEY_get0_group(context->ec_key);
    int field_size = (EC_GROUP_get_degree(group) + 7) / 8;
    
    // Allocate memory for shared secret
    unsigned char* secret = (unsigned char*)malloc(field_size);
    if (!secret) {
        fprintf(stderr, "Error: Memory allocation failed for shared secret\n");
        EC_KEY_free(peer_key);
        return -1;
    }
    
    // Compute the shared secret
    int secret_len = ECDH_compute_key(secret, field_size, peer_point, context->ec_key, NULL);
    if (secret_len <= 0) {
        fprintf(stderr, "Error: ECDH key computation failed\n");
        free(secret);
        EC_KEY_free(peer_key);
        return -1;
    }
    
    // Clean up
    EC_KEY_free(peer_key);
    
    // Store the secret in the provided pointer
    *shared_secret = secret;
    
    // Clean up any previously stored shared secret
    if (context->shared_secret) {
        free(context->shared_secret);
    }
    
    // Store the shared secret in the context for later use
    context->shared_secret = (unsigned char*)malloc(secret_len);
    if (context->shared_secret) {
        memcpy(context->shared_secret, secret, secret_len);
        context->shared_secret_length = secret_len;
    }
    
    return secret_len;
}

// Digital signature functions using ECDSA
unsigned char* ecc_sign_data(ecc_context_t* context, const unsigned char* data, int data_length, int* signature_length) {
    if (!context || !data || data_length <= 0) {
        return NULL;
    }
    
    // Make sure we have our private key
    if (!context->ec_key) {
        fprintf(stderr, "Error: No private key available for signing\n");
        return NULL;
    }
    
    // Create a digest of the data
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(data, data_length, digest);
    
    // Allocate memory for the signature
    unsigned char* signature = (unsigned char*)malloc(ECDSA_size(context->ec_key));
    if (!signature) {
        fprintf(stderr, "Error: Memory allocation failed for signature\n");
        return NULL;
    }
    
    // Sign the digest
    unsigned int sig_len = 0;
    if (ECDSA_sign(0, digest, SHA256_DIGEST_LENGTH, signature, &sig_len, context->ec_key) != 1) {
        fprintf(stderr, "Error: ECDSA signing failed\n");
        free(signature);
        return NULL;
    }
    
    *signature_length = sig_len;
    return signature;
}

// Verify a digital signature using ECDSA
int ecc_verify_signature(ecc_context_t* context, const unsigned char* data, int data_length, const unsigned char* signature, int signature_length) {
    if (!context || !data || data_length <= 0 || !signature || signature_length <= 0) {
        return -1;
    }
    
    // Make sure we have a key with public part
    if (!context->ec_key) {
        fprintf(stderr, "Error: No key available for signature verification\n");
        return -1;
    }
    
    // Create a digest of the data
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(data, data_length, digest);
    
    // Verify the signature
    int result = ECDSA_verify(0, digest, SHA256_DIGEST_LENGTH, signature, signature_length, context->ec_key);
    
    return result;
} 