#ifndef ECC_COMMON_H
#define ECC_COMMON_H

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>

// ECC curve types
typedef enum {
    CURVE_P256 = 0,  // NIST P-256
    CURVE_P384 = 1,  // NIST P-384
    CURVE_P521 = 2   // NIST P-521
} ecc_curve_type_t;

// ECC context structure
typedef struct {
    int is_custom;            // Flag to indicate if this is a custom implementation
    ecc_curve_type_t curve;   // The selected curve
    EC_KEY* ec_key;           // The EC key for OpenSSL implementation
    unsigned char* private_key; // Encoded private key
    int private_key_length;    // Length of encoded private key
    unsigned char* public_key;  // Encoded public key
    int public_key_length;      // Length of encoded public key
    unsigned char* shared_secret; // Shared secret for current session
    int shared_secret_length;     // Length of shared secret
} ecc_context_t;

// Helper functions
int ecc_get_nid_for_curve(ecc_curve_type_t curve);
const char* ecc_get_curve_name(ecc_curve_type_t curve);

// Basic ECC operations
EC_KEY* ecc_generate_key_pair(ecc_curve_type_t curve);
unsigned char* ecc_export_public_key(EC_KEY* key, int* key_length);
unsigned char* ecc_export_private_key(EC_KEY* key, int* key_length);
EC_KEY* ecc_import_private_key(const unsigned char* key_data, int key_length, ecc_curve_type_t curve);
EC_KEY* ecc_import_public_key(const unsigned char* key_data, int key_length, ecc_curve_type_t curve);

#endif // ECC_COMMON_H 