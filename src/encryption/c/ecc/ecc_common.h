#ifndef ECC_COMMON_H
#define ECC_COMMON_H

#include <stdint.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>

// ECC curve types
typedef enum {
    CURVE_P256 = 0,  // NIST P-256 (secp256r1)
    CURVE_P384 = 1,  // NIST P-384 (secp384r1)
    CURVE_P521 = 2   // NIST P-521 (secp521r1)
} ecc_curve_type_t;

// Custom ECC point structure for pure custom implementation
typedef struct {
    uint64_t x[9];  // Large enough for P-521 (ceil(521/64) = 9 uint64_t)
    uint64_t y[9];
    uint64_t z[9];  // For projective coordinates
    int is_infinity;
    int curve_id;
} ecc_custom_point_t;

// Custom ECC private key structure
typedef struct {
    uint64_t d[9];  // Private key scalar
    int curve_id;
} ecc_custom_private_key_t;

// Custom ECC public key structure
typedef struct {
    ecc_custom_point_t point;
    int curve_id;
} ecc_custom_public_key_t;

// ECC context structure - supports both standard and custom implementations
typedef struct {
    int is_custom;                    // Flag to indicate if this is a custom implementation
    ecc_curve_type_t curve;          // The selected curve
    
    // Standard implementation fields (OpenSSL)
    EC_KEY* ec_key;                  // The EC key for OpenSSL implementation
    unsigned char* private_key;       // Encoded private key
    int private_key_length;          // Length of encoded private key
    unsigned char* public_key;       // Encoded public key
    int public_key_length;           // Length of encoded public key
    
    // Custom implementation fields
    ecc_custom_private_key_t* custom_private_key;
    ecc_custom_public_key_t* custom_public_key;
    
    // Curve parameters for custom implementation
    uint64_t* curve_p;               // Prime modulus
    uint64_t* curve_a;               // Curve parameter a
    uint64_t* curve_b;               // Curve parameter b
    uint64_t* curve_n;               // Order of the base point
    ecc_custom_point_t* curve_g;     // Base point
    int field_size_bits;             // Size of the field in bits
    int field_size_words;            // Size of the field in 64-bit words
} ecc_context_t;

// Helper functions for standard implementation
int ecc_get_nid_for_curve(ecc_curve_type_t curve);
const char* ecc_get_curve_name(ecc_curve_type_t curve);
EC_KEY* ecc_generate_key_pair(ecc_curve_type_t curve);
unsigned char* ecc_export_public_key(EC_KEY* key, int* key_length);
unsigned char* ecc_export_private_key(EC_KEY* key, int* key_length);
EC_KEY* ecc_import_private_key(const unsigned char* key_data, int key_length, ecc_curve_type_t curve);
EC_KEY* ecc_import_public_key(const unsigned char* key_data, int key_length, ecc_curve_type_t curve);

// Pure ECC encryption/decryption functions (no hybrid mode)
unsigned char* ecc_pure_encrypt_data(const unsigned char* data, size_t data_len, 
                                   const unsigned char* public_key, size_t public_key_len,
                                   ecc_curve_type_t curve, size_t* output_len);
unsigned char* ecc_pure_decrypt_data(const unsigned char* encrypted_data, size_t encrypted_len,
                                   const unsigned char* private_key, size_t private_key_len,
                                   ecc_curve_type_t curve, size_t* output_len);

// Custom ECC implementation functions
void ecc_custom_init_curve_params(ecc_context_t* context);
void ecc_custom_cleanup_curve_params(ecc_context_t* context);
int ecc_custom_generate_keypair(ecc_context_t* context);
unsigned char* ecc_custom_pure_encrypt(const unsigned char* data, size_t data_len,
                                     ecc_context_t* context, size_t* output_len);
unsigned char* ecc_custom_pure_decrypt(const unsigned char* encrypted_data, size_t encrypted_len,
                                     ecc_context_t* context, size_t* output_len);

// Low-level custom ECC operations
void ecc_custom_point_add(const ecc_custom_point_t* p1, const ecc_custom_point_t* p2, 
                         ecc_custom_point_t* result, const ecc_context_t* context);
void ecc_custom_point_double(const ecc_custom_point_t* p, ecc_custom_point_t* result, 
                           const ecc_context_t* context);
void ecc_custom_point_multiply(const ecc_custom_point_t* point, const uint64_t* scalar,
                             ecc_custom_point_t* result, const ecc_context_t* context);
int ecc_custom_point_is_valid(const ecc_custom_point_t* point, const ecc_context_t* context);

// Modular arithmetic for custom implementation
void ecc_mod_add(const uint64_t* a, const uint64_t* b, uint64_t* result, 
                const uint64_t* modulus, int words);
void ecc_mod_sub(const uint64_t* a, const uint64_t* b, uint64_t* result,
                const uint64_t* modulus, int words);
void ecc_mod_mult(const uint64_t* a, const uint64_t* b, uint64_t* result,
                 const uint64_t* modulus, int words);
void ecc_mod_inv(const uint64_t* a, uint64_t* result, const uint64_t* modulus, int words);

#endif // ECC_COMMON_H 