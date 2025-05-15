#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>

#include "ecc_common.h"

// Get the OpenSSL NID for a specified curve
int ecc_get_nid_for_curve(ecc_curve_type_t curve) {
    switch(curve) {
        case CURVE_P256:
            return NID_X9_62_prime256v1;  // Same as secp256r1 / NIST P-256
        case CURVE_P384:
            return NID_secp384r1;  // NIST P-384
        case CURVE_P521:
            return NID_secp521r1;  // NIST P-521
        default:
            return NID_X9_62_prime256v1;  // Default to P-256
    }
}

// Get the name of a curve
const char* ecc_get_curve_name(ecc_curve_type_t curve) {
    switch(curve) {
        case CURVE_P256:
            return "P-256";
        case CURVE_P384:
            return "P-384";
        case CURVE_P521:
            return "P-521";
        default:
            return "unknown";
    }
}

// Set the curve for an ECC context
int ecc_set_curve(ecc_context_t* context, ecc_curve_type_t curve) {
    if (!context) return 0;
    
    // If there's an existing key, free it
    if (context->ec_key) {
        EC_KEY_free(context->ec_key);
        context->ec_key = NULL;
    }
    
    // Set the new curve
    context->curve = curve;
    
    return 1;
}

// Generate an ECC key pair
EC_KEY* ecc_generate_key_pair(ecc_curve_type_t curve) {
    int nid = ecc_get_nid_for_curve(curve);
    EC_KEY* key = EC_KEY_new_by_curve_name(nid);
    if (!key) {
        fprintf(stderr, "Error: Could not create EC key object\n");
        return NULL;
    }
    
    if (EC_KEY_generate_key(key) != 1) {
        fprintf(stderr, "Error: Could not generate EC key pair\n");
        EC_KEY_free(key);
        return NULL;
    }
    
    return key;
}

// Export public key in DER format
unsigned char* ecc_export_public_key(EC_KEY* key, int* key_length) {
    if (!key) {
        fprintf(stderr, "Error: Cannot export public key from NULL key\n");
        return NULL;
    }
    
    // Use direct i2d function instead of BIO
    unsigned char* temp = NULL;
    int len = i2d_EC_PUBKEY(key, &temp);
    
    if (len <= 0 || !temp) {
        fprintf(stderr, "Error: Could not export public key\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    // Make a copy of the key data (since OpenSSL allocates it)
    unsigned char* output = (unsigned char*)malloc(len);
    if (!output) {
        fprintf(stderr, "Error: Memory allocation failed for public key export\n");
        OPENSSL_free(temp);
        return NULL;
    }
    
    memcpy(output, temp, len);
    *key_length = len;
    
    // Free OpenSSL allocated memory
    OPENSSL_free(temp);
    
    return output;
}

// Export private key in DER format
unsigned char* ecc_export_private_key(EC_KEY* key, int* key_length) {
    if (!key) {
        fprintf(stderr, "Error: Cannot export private key from NULL key\n");
        return NULL;
    }
    
    // Use direct i2d function instead of BIO
    unsigned char* temp = NULL;
    int len = i2d_ECPrivateKey(key, &temp);
    
    if (len <= 0 || !temp) {
        fprintf(stderr, "Error: Could not export private key\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    // Make a copy of the key data (since OpenSSL allocates it)
    unsigned char* output = (unsigned char*)malloc(len);
    if (!output) {
        fprintf(stderr, "Error: Memory allocation failed for private key export\n");
        OPENSSL_free(temp);
        return NULL;
    }
    
    memcpy(output, temp, len);
    *key_length = len;
    
    // Free OpenSSL allocated memory
    OPENSSL_free(temp);
    
    return output;
}

// Import private key from DER format
EC_KEY* ecc_import_private_key(const unsigned char* key_data, int key_length, ecc_curve_type_t curve) {
    if (!key_data || key_length <= 0) {
        fprintf(stderr, "Error: Invalid key data for import\n");
        return NULL;
    }
    
    // Make a copy of the key data since d2i_ECPrivateKey modifies the pointer
    const unsigned char* p = key_data;
    
    // Use direct d2i function
    EC_KEY* key = d2i_ECPrivateKey(NULL, &p, key_length);
    
    if (!key) {
        fprintf(stderr, "Error: Could not import private key\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    // Set the curve if needed (in case the key doesn't specify it)
    const EC_GROUP* key_group = EC_KEY_get0_group(key);
    if (!key_group) {
        int nid = ecc_get_nid_for_curve(curve);
        EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
        if (!group) {
            fprintf(stderr, "Error: Could not create EC group for curve\n");
            EC_KEY_free(key);
            return NULL;
        }
        
        if (EC_KEY_set_group(key, group) != 1) {
            fprintf(stderr, "Error: Could not set group for key\n");
            EC_GROUP_free(group);
            EC_KEY_free(key);
            return NULL;
        }
        
        EC_GROUP_free(group);
    }
    
    return key;
}

// Import public key from DER format
EC_KEY* ecc_import_public_key(const unsigned char* key_data, int key_length, ecc_curve_type_t curve) {
    if (!key_data || key_length <= 0) {
        fprintf(stderr, "Error: Invalid key data for import\n");
        return NULL;
    }
    
    // Make a copy of the key data since d2i_EC_PUBKEY modifies the pointer
    const unsigned char* p = key_data;
    
    // Use direct d2i function
    EC_KEY* key = d2i_EC_PUBKEY(NULL, &p, key_length);
    
    if (!key) {
        fprintf(stderr, "Error: Could not import public key\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    // Set the curve if needed (in case the key doesn't specify it)
    const EC_GROUP* key_group = EC_KEY_get0_group(key);
    if (!key_group) {
        int nid = ecc_get_nid_for_curve(curve);
        EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
        if (!group) {
            fprintf(stderr, "Error: Could not create EC group for curve\n");
            EC_KEY_free(key);
            return NULL;
        }
        
        if (EC_KEY_set_group(key, group) != 1) {
            fprintf(stderr, "Error: Could not set group for key\n");
            EC_GROUP_free(group);
            EC_KEY_free(key);
            return NULL;
        }
        
        EC_GROUP_free(group);
    }
    
    return key;
} 