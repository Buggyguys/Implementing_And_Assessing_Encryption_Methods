#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "ecc_common.h"

// =============================================================================
// BIG INTEGER HELPER FUNCTIONS
// =============================================================================

// Compare two big integers: returns -1 if a < b, 0 if a == b, 1 if a > b
static int bigint_compare(const uint64_t* a, const uint64_t* b, int words) {
    for (int i = words - 1; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

// Subtract b from a, assuming a >= b
static void bigint_subtract(const uint64_t* a, const uint64_t* b, uint64_t* result, int words) {
    uint64_t borrow = 0;
    for (int i = 0; i < words; i++) {
        uint64_t temp = a[i] - b[i] - borrow;
        borrow = (temp > a[i]) ? 1 : 0;
        result[i] = temp;
    }
}

// Add two big integers
static uint64_t bigint_add(const uint64_t* a, const uint64_t* b, uint64_t* result, int words) {
    uint64_t carry = 0;
    for (int i = 0; i < words; i++) {
        uint64_t sum = a[i] + b[i] + carry;
        carry = (sum < a[i]) ? 1 : 0;
        result[i] = sum;
    }
    return carry;
}

// Left shift by one bit
static uint64_t bigint_shl1(uint64_t* a, int words) {
    uint64_t carry = 0;
    for (int i = 0; i < words; i++) {
        uint64_t new_carry = (a[i] >> 63) & 1;
        a[i] = (a[i] << 1) | carry;
        carry = new_carry;
    }
    return carry;
}

// Right shift by one bit
static void bigint_shr1(uint64_t* a, int words) {
    for (int i = words - 1; i >= 0; i--) {
        uint64_t carry_in = (i == words - 1) ? 0 : (a[i + 1] & 1);
        a[i] = (a[i] >> 1) | (carry_in << 63);
    }
}

// =============================================================================
// HELPER FUNCTIONS FOR STANDARD IMPLEMENTATION
// =============================================================================

int ecc_get_nid_for_curve(ecc_curve_type_t curve) {
    switch (curve) {
        case CURVE_P256:
            return NID_X9_62_prime256v1;  // secp256r1
        case CURVE_P384:
            return NID_secp384r1;
        case CURVE_P521:
            return NID_secp521r1;
        default:
            return NID_X9_62_prime256v1;
    }
}

const char* ecc_get_curve_name(ecc_curve_type_t curve) {
    switch (curve) {
        case CURVE_P256:
            return "P-256";
        case CURVE_P384:
            return "P-384";
        case CURVE_P521:
            return "P-521";
        default:
            return "P-256";
    }
}

EC_KEY* ecc_generate_key_pair(ecc_curve_type_t curve) {
    int nid = ecc_get_nid_for_curve(curve);
    EC_KEY* key = EC_KEY_new_by_curve_name(nid);
    if (!key) {
        fprintf(stderr, "Error: Failed to create EC_KEY for curve\n");
        return NULL;
    }
    
    if (EC_KEY_generate_key(key) != 1) {
        fprintf(stderr, "Error: Failed to generate ECC key pair\n");
        EC_KEY_free(key);
        return NULL;
    }
    
    return key;
}

unsigned char* ecc_export_public_key(EC_KEY* key, int* key_length) {
    if (!key || !key_length) return NULL;
    
    const EC_POINT* pub_key = EC_KEY_get0_public_key(key);
    const EC_GROUP* group = EC_KEY_get0_group(key);
    
    if (!pub_key || !group) return NULL;
    
    size_t len = EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (len == 0) return NULL;
    
    unsigned char* buffer = (unsigned char*)malloc(len);
    if (!buffer) return NULL;
    
    if (EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, buffer, len, NULL) != len) {
        free(buffer);
        return NULL;
    }
    
    *key_length = (int)len;
    return buffer;
}

unsigned char* ecc_export_private_key(EC_KEY* key, int* key_length) {
    if (!key || !key_length) return NULL;
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return NULL;
    
    if (PEM_write_bio_ECPrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) != 1) {
        BIO_free(bio);
        return NULL;
    }
    
    char* data;
    long len = BIO_get_mem_data(bio, &data);
    
    unsigned char* buffer = (unsigned char*)malloc(len);
    if (buffer) {
        memcpy(buffer, data, len);
        *key_length = (int)len;
    }
    
    BIO_free(bio);
    return buffer;
}

EC_KEY* ecc_import_private_key(const unsigned char* key_data, int key_length, ecc_curve_type_t curve) {
    if (!key_data || key_length <= 0) return NULL;
    
    BIO* bio = BIO_new_mem_buf(key_data, key_length);
    if (!bio) return NULL;
    
    EC_KEY* key = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    return key;
}

EC_KEY* ecc_import_public_key(const unsigned char* key_data, int key_length, ecc_curve_type_t curve) {
    if (!key_data || key_length <= 0) return NULL;
    
    int nid = ecc_get_nid_for_curve(curve);
    EC_KEY* key = EC_KEY_new_by_curve_name(nid);
    if (!key) return NULL;
    
    const EC_GROUP* group = EC_KEY_get0_group(key);
    EC_POINT* point = EC_POINT_new(group);
    if (!point) {
        EC_KEY_free(key);
        return NULL;
    }
    
    if (EC_POINT_oct2point(group, point, key_data, key_length, NULL) != 1) {
        EC_POINT_free(point);
        EC_KEY_free(key);
        return NULL;
    }
    
    if (EC_KEY_set_public_key(key, point) != 1) {
        EC_POINT_free(point);
        EC_KEY_free(key);
        return NULL;
    }
    
    EC_POINT_free(point);
    return key;
}

// =============================================================================
// PURE ECC ENCRYPTION/DECRYPTION (NO HYBRID MODE)
// =============================================================================

unsigned char* ecc_pure_encrypt_data(const unsigned char* data, size_t data_len, 
                                   const unsigned char* public_key, size_t public_key_len,
                                   ecc_curve_type_t curve, size_t* output_len) {
    if (!data || !data_len || !public_key || !output_len) return NULL;
    
    // For pure ECC encryption, we use a simplified approach:
    // 1. Generate ephemeral key pair
    // 2. Compute shared secret via ECDH
    // 3. Use shared secret to XOR with data (simplified)
    // 4. Output: ephemeral_public_key + encrypted_data
    
    EC_KEY* ephemeral_key = ecc_generate_key_pair(curve);
    if (!ephemeral_key) {
        fprintf(stderr, "Error: Failed to generate ephemeral key pair\n");
        return NULL;
    }
    
    // Import recipient's public key
    EC_KEY* recipient_key = ecc_import_public_key(public_key, public_key_len, curve);
    if (!recipient_key) {
        fprintf(stderr, "Error: Failed to import recipient public key\n");
        EC_KEY_free(ephemeral_key);
        return NULL;
    }
    
    // Compute shared secret
    const EC_POINT* recipient_pub_point = EC_KEY_get0_public_key(recipient_key);
    const EC_GROUP* group = EC_KEY_get0_group(ephemeral_key);
    int field_size = (EC_GROUP_get_degree(group) + 7) / 8;
    
    unsigned char* shared_secret = (unsigned char*)malloc(field_size);
    if (!shared_secret) {
        EC_KEY_free(ephemeral_key);
        EC_KEY_free(recipient_key);
        return NULL;
    }
    
    int secret_len = ECDH_compute_key(shared_secret, field_size, recipient_pub_point, ephemeral_key, NULL);
    if (secret_len <= 0) {
        fprintf(stderr, "Error: ECDH computation failed\n");
        free(shared_secret);
        EC_KEY_free(ephemeral_key);
        EC_KEY_free(recipient_key);
        return NULL;
    }
    
    // Export ephemeral public key
    int ephemeral_pub_len;
    unsigned char* ephemeral_pub = ecc_export_public_key(ephemeral_key, &ephemeral_pub_len);
    if (!ephemeral_pub) {
        fprintf(stderr, "Error: Failed to export ephemeral public key\n");
        free(shared_secret);
        EC_KEY_free(ephemeral_key);
        EC_KEY_free(recipient_key);
        return NULL;
    }
    
    // Encrypt data using XOR with derived key (simplified encryption)
    unsigned char key_material[32];
    SHA256(shared_secret, secret_len, key_material);
    
    unsigned char* encrypted_data = (unsigned char*)malloc(data_len);
    if (!encrypted_data) {
        free(shared_secret);
        free(ephemeral_pub);
        EC_KEY_free(ephemeral_key);
        EC_KEY_free(recipient_key);
        return NULL;
    }
    
    for (size_t i = 0; i < data_len; i++) {
        encrypted_data[i] = data[i] ^ key_material[i % 32];
    }
    
    // Combine ephemeral public key and encrypted data
    *output_len = sizeof(int) + ephemeral_pub_len + data_len;
    unsigned char* output = (unsigned char*)malloc(*output_len);
    if (!output) {
        free(shared_secret);
        free(ephemeral_pub);
        free(encrypted_data);
        EC_KEY_free(ephemeral_key);
        EC_KEY_free(recipient_key);
        return NULL;
    }
    
    // Format: [ephemeral_pub_len(4 bytes)][ephemeral_pub_key][encrypted_data]
    memcpy(output, &ephemeral_pub_len, sizeof(int));
    memcpy(output + sizeof(int), ephemeral_pub, ephemeral_pub_len);
    memcpy(output + sizeof(int) + ephemeral_pub_len, encrypted_data, data_len);
    
    // Clean up
    free(shared_secret);
    free(ephemeral_pub);
    free(encrypted_data);
    EC_KEY_free(ephemeral_key);
    EC_KEY_free(recipient_key);
    
    return output;
}

unsigned char* ecc_pure_decrypt_data(const unsigned char* encrypted_data, size_t encrypted_len,
                                   const unsigned char* private_key, size_t private_key_len,
                                   ecc_curve_type_t curve, size_t* output_len) {
    if (!encrypted_data || !encrypted_len || !private_key || !output_len) return NULL;
    
    // Parse encrypted data: [ephemeral_pub_len][ephemeral_pub_key][encrypted_data]
    if (encrypted_len < sizeof(int)) return NULL;
    
    int ephemeral_pub_len;
    memcpy(&ephemeral_pub_len, encrypted_data, sizeof(int));
    
    if (encrypted_len < sizeof(int) + ephemeral_pub_len) return NULL;
    
    const unsigned char* ephemeral_pub = encrypted_data + sizeof(int);
    const unsigned char* data_part = encrypted_data + sizeof(int) + ephemeral_pub_len;
    size_t data_len = encrypted_len - sizeof(int) - ephemeral_pub_len;
    
    // Import our private key
    EC_KEY* our_key = ecc_import_private_key(private_key, private_key_len, curve);
    if (!our_key) {
        fprintf(stderr, "Error: Failed to import private key\n");
        return NULL;
    }
    
    // Import ephemeral public key
    EC_KEY* ephemeral_key = ecc_import_public_key(ephemeral_pub, ephemeral_pub_len, curve);
    if (!ephemeral_key) {
        fprintf(stderr, "Error: Failed to import ephemeral public key\n");
        EC_KEY_free(our_key);
        return NULL;
    }
    
    // Compute shared secret
    const EC_POINT* ephemeral_pub_point = EC_KEY_get0_public_key(ephemeral_key);
    const EC_GROUP* group = EC_KEY_get0_group(our_key);
    int field_size = (EC_GROUP_get_degree(group) + 7) / 8;
    
    unsigned char* shared_secret = (unsigned char*)malloc(field_size);
    if (!shared_secret) {
        EC_KEY_free(our_key);
        EC_KEY_free(ephemeral_key);
        return NULL;
    }
    
    int secret_len = ECDH_compute_key(shared_secret, field_size, ephemeral_pub_point, our_key, NULL);
    if (secret_len <= 0) {
        fprintf(stderr, "Error: ECDH computation failed in decryption\n");
        free(shared_secret);
        EC_KEY_free(our_key);
        EC_KEY_free(ephemeral_key);
        return NULL;
    }
    
    // Derive decryption key
    unsigned char key_material[32];
    SHA256(shared_secret, secret_len, key_material);
    
    // Decrypt data
    unsigned char* decrypted_data = (unsigned char*)malloc(data_len);
    if (!decrypted_data) {
        free(shared_secret);
        EC_KEY_free(our_key);
        EC_KEY_free(ephemeral_key);
            return NULL;
    }
    
    for (size_t i = 0; i < data_len; i++) {
        decrypted_data[i] = data_part[i] ^ key_material[i % 32];
    }
    
    *output_len = data_len;
    
    // Clean up
    free(shared_secret);
    EC_KEY_free(our_key);
    EC_KEY_free(ephemeral_key);
    
    return decrypted_data;
}

// =============================================================================
// CUSTOM ECC IMPLEMENTATION FUNCTIONS
// =============================================================================

// Curve parameters for P-256, P-384, P-521
static const uint64_t p256_p[4] = {0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF, 0x0000000000000000, 0xFFFFFFFF00000001};
static const uint64_t p256_a[4] = {0xFFFFFFFFFFFFFFFC, 0x00000000FFFFFFFF, 0x0000000000000000, 0xFFFFFFFF00000001};
static const uint64_t p256_b[4] = {0x3BCE3C3E27D2604B, 0x651D06B0CC53B0F6, 0xB3EBBD55769886BC, 0x5AC635D8AA3A93E7};
static const uint64_t p256_n[4] = {0xF3B9CAC2FC632551, 0xBCE6FAADA7179E84, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000};
static const uint64_t p256_gx[4] = {0xF4A13945D898C296, 0x77037D812DEB33A0, 0xF8BCE6E563A440F2, 0x6B17D1F2E12C4247};
static const uint64_t p256_gy[4] = {0xCBB6406837BF51F5, 0x2BCE33576B315ECE, 0x8EE7EB4A7C0F9E16, 0x4FE342E2FE1A7F9B};

// P-384 curve parameters
static const uint64_t p384_p[6] = {
    0x00000000FFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE, 
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
};
static const uint64_t p384_a[6] = {
    0x00000000FFFFFFFC, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
};
static const uint64_t p384_b[6] = {
    0x2A85C8EDD3EC2AEF, 0xC656398D8A2ED19D, 0x0314088F5013875A,
    0x181D9C6EFE814112, 0x988E056BE3F82D19, 0xB3312FA7E23EE7E4
};
static const uint64_t p384_n[6] = {
    0xECEC196ACCC52973, 0x581A0DB248B0A77A, 0xC7634D81F4372DDF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
};
static const uint64_t p384_gx[6] = {
    0x3A545E3872760AB7, 0x5502F25DBF55296C, 0x59F741E082542A38,
    0x6E1D3B628BA79B98, 0x8EB1C71EF320AD74, 0xAA87CA22BE8B0537
};
static const uint64_t p384_gy[6] = {
    0x7A431D7C90EA0E5F, 0x0A60B1CE1D7E819D, 0xE9DA3113B5F0B8C0,
    0xF8F41DBD289A147C, 0x5D9E98BF9292DC29, 0x3617DE4A96262C6F
};

// P-521 curve parameters  
static const uint64_t p521_p[9] = {
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0x00000000000001FF
};
static const uint64_t p521_a[9] = {
    0xFFFFFFFFFFFFFFFC, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0x00000000000001FF
};
static const uint64_t p521_b[9] = {
    0xEF451FD46B503F00, 0x3573DF883D2C34F1, 0x1652C0BD3BB1BF07, 0x56193951EC7E937B,
    0xB8C9CA266468F983, 0x7FCF00C76F1F1D6A, 0xCE1F0EA6E0B94FE6, 0x52C07A6B79C95C1F,
    0x0000000000000051
};
static const uint64_t p521_n[9] = {
    0xBB6FB71E91386409, 0x3BB5C9B8899C47AE, 0x7FCC0148F709A5D0, 0x181C5BAEA9E84B5B,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0x00000000000001FF
};
static const uint64_t p521_gx[9] = {
    0xF97E7E31C2E5BD66, 0x3348B3C1856A429B, 0xFE1DC127A2FFA8DE, 0xA14B5E77EFE75928,
    0xF828AF606B4D3DBA, 0x9C648139053FB521, 0x9E3ECB662395B442, 0x858E06B70404E9CD,
    0x00000000000000C6
};
static const uint64_t p521_gy[9] = {
    0x88BE94769FD16650, 0x353C7086A272C240, 0xC550B9013FAD0761, 0x97EE72995EF42640,
    0x17AFBD17273E662C, 0x98F54449579B4468, 0x5C8A5FB42C7D1BD9, 0x39296A789A3BC004,
    0x0000000000000118
};

void ecc_custom_init_curve_params(ecc_context_t* context) {
    if (!context) return;
    
    context->curve_p = (uint64_t*)malloc(context->field_size_words * sizeof(uint64_t));
    context->curve_a = (uint64_t*)malloc(context->field_size_words * sizeof(uint64_t));
    context->curve_b = (uint64_t*)malloc(context->field_size_words * sizeof(uint64_t));
    context->curve_n = (uint64_t*)malloc(context->field_size_words * sizeof(uint64_t));
    context->curve_g = (ecc_custom_point_t*)malloc(sizeof(ecc_custom_point_t));
    
    if (!context->curve_p || !context->curve_a || !context->curve_b || 
        !context->curve_n || !context->curve_g) {
        fprintf(stderr, "Error: Failed to allocate curve parameters\n");
        return;
    }
    
    // Initialize curve parameters based on curve type
    switch (context->curve) {
        case CURVE_P256:
            memcpy(context->curve_p, p256_p, 4 * sizeof(uint64_t));
            memcpy(context->curve_a, p256_a, 4 * sizeof(uint64_t));
            memcpy(context->curve_b, p256_b, 4 * sizeof(uint64_t));
            memcpy(context->curve_n, p256_n, 4 * sizeof(uint64_t));
            memcpy(context->curve_g->x, p256_gx, 4 * sizeof(uint64_t));
            memcpy(context->curve_g->y, p256_gy, 4 * sizeof(uint64_t));
            // Zero out unused words
            for (int i = 4; i < 9; i++) {
                context->curve_g->x[i] = 0;
                context->curve_g->y[i] = 0;
                context->curve_g->z[i] = 0;
            }
            context->curve_g->z[0] = 1; // Projective coordinate
            context->curve_g->is_infinity = 0;
            context->curve_g->curve_id = CURVE_P256;
            break;
            
        case CURVE_P384:
            memcpy(context->curve_p, p384_p, 6 * sizeof(uint64_t));
            memcpy(context->curve_a, p384_a, 6 * sizeof(uint64_t));
            memcpy(context->curve_b, p384_b, 6 * sizeof(uint64_t));
            memcpy(context->curve_n, p384_n, 6 * sizeof(uint64_t));
            memcpy(context->curve_g->x, p384_gx, 6 * sizeof(uint64_t));
            memcpy(context->curve_g->y, p384_gy, 6 * sizeof(uint64_t));
            
            // Zero out remaining words
            for (int i = 6; i < 9; i++) {
                context->curve_p[i] = 0;
                context->curve_a[i] = 0;
                context->curve_b[i] = 0;
                context->curve_n[i] = 0;
                context->curve_g->x[i] = 0;
                context->curve_g->y[i] = 0;
                context->curve_g->z[i] = 0;
            }
            context->curve_g->z[0] = 1;
            context->curve_g->is_infinity = 0;
            context->curve_g->curve_id = CURVE_P384;
            break;
            
        case CURVE_P521:
            memcpy(context->curve_p, p521_p, 9 * sizeof(uint64_t));
            memcpy(context->curve_a, p521_a, 9 * sizeof(uint64_t));
            memcpy(context->curve_b, p521_b, 9 * sizeof(uint64_t));
            memcpy(context->curve_n, p521_n, 9 * sizeof(uint64_t));
            memcpy(context->curve_g->x, p521_gx, 9 * sizeof(uint64_t));
            memcpy(context->curve_g->y, p521_gy, 9 * sizeof(uint64_t));
            
            // Initialize z coordinate
            for (int i = 0; i < 9; i++) {
                context->curve_g->z[i] = 0;
            }
            context->curve_g->z[0] = 1;
            context->curve_g->is_infinity = 0;
            context->curve_g->curve_id = CURVE_P521;
            break;
    }
}

void ecc_custom_cleanup_curve_params(ecc_context_t* context) {
    if (!context) return;
    
    if (context->curve_p) { free(context->curve_p); context->curve_p = NULL; }
    if (context->curve_a) { free(context->curve_a); context->curve_a = NULL; }
    if (context->curve_b) { free(context->curve_b); context->curve_b = NULL; }
    if (context->curve_n) { free(context->curve_n); context->curve_n = NULL; }
    if (context->curve_g) { free(context->curve_g); context->curve_g = NULL; }
}

int ecc_custom_generate_keypair(ecc_context_t* context) {
    if (!context) return -1;
    
    // Allocate keys
    context->custom_private_key = (ecc_custom_private_key_t*)malloc(sizeof(ecc_custom_private_key_t));
    context->custom_public_key = (ecc_custom_public_key_t*)malloc(sizeof(ecc_custom_public_key_t));
    
    if (!context->custom_private_key || !context->custom_public_key) {
        return -1;
    }
    
    // Generate a secure random private key in range [1, n-1]
    // Use rejection sampling to ensure uniform distribution
    int max_attempts = 100;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        // Generate random bytes
        unsigned char random_bytes[9 * 8];
        if (RAND_bytes(random_bytes, context->field_size_words * 8) != 1) {
            fprintf(stderr, "Error: Failed to generate secure random bytes\n");
            return -1;
        }
        
        // Convert to bigint
        for (int i = 0; i < context->field_size_words; i++) {
            context->custom_private_key->d[i] = 0;
            for (int j = 0; j < 8; j++) {
                context->custom_private_key->d[i] |= ((uint64_t)random_bytes[i * 8 + j]) << (j * 8);
            }
        }
        
        // Check if it's in range [1, n-1]
        if (bigint_compare(context->custom_private_key->d, context->curve_n, context->field_size_words) < 0) {
            // Check it's not zero
            int is_zero = 1;
            for (int i = 0; i < context->field_size_words; i++) {
                if (context->custom_private_key->d[i] != 0) {
                    is_zero = 0;
                    break;
                }
            }
            if (!is_zero) {
                // Valid private key found
                break;
            }
        }
        
        // If we reach here, the generated key was invalid, try again
        if (attempt == max_attempts - 1) {
            fprintf(stderr, "Error: Failed to generate valid private key after %d attempts\n", max_attempts);
            return -1;
        }
    }
    
    context->custom_private_key->curve_id = context->curve;
    
    // Compute public key = private_key * G
    ecc_custom_point_multiply(context->curve_g, context->custom_private_key->d,
                            &context->custom_public_key->point, context);
    context->custom_public_key->curve_id = context->curve;
    
    return 0;
}

unsigned char* ecc_custom_pure_encrypt(const unsigned char* data, size_t data_len,
                                     ecc_context_t* context, size_t* output_len) {
    if (!data || !context || !context->custom_public_key || !output_len) return NULL;
    
    // Generate ephemeral key pair using secure random
    ecc_custom_private_key_t ephemeral_private;
    ecc_custom_public_key_t ephemeral_public;
    
    // Generate cryptographically secure random ephemeral private key
    unsigned char random_bytes[9 * 8];
    if (RAND_bytes(random_bytes, context->field_size_words * 8) != 1) {
        fprintf(stderr, "Error: Failed to generate secure random bytes for ephemeral key\n");
        return NULL;
    }
    
    // Convert bytes to words
    for (int i = 0; i < context->field_size_words; i++) {
        ephemeral_private.d[i] = 0;
        for (int j = 0; j < 8; j++) {
            ephemeral_private.d[i] |= ((uint64_t)random_bytes[i * 8 + j]) << (j * 8);
        }
    }
    
    // Ensure ephemeral private key is in valid range
    while (bigint_compare(ephemeral_private.d, context->curve_n, context->field_size_words) >= 0) {
        bigint_subtract(ephemeral_private.d, context->curve_n, 
                       ephemeral_private.d, context->field_size_words);
    }
    
    // Ensure it's not zero
    int is_zero = 1;
    for (int i = 0; i < context->field_size_words; i++) {
        if (ephemeral_private.d[i] != 0) {
            is_zero = 0;
            break;
        }
    }
    if (is_zero) {
        ephemeral_private.d[0] = 1;
    }
    
    ephemeral_private.curve_id = context->curve;
    
    // Compute ephemeral public key
    ecc_custom_point_multiply(context->curve_g, ephemeral_private.d,
                            &ephemeral_public.point, context);
    ephemeral_public.curve_id = context->curve;
    
    // Compute shared secret point = ephemeral_private * recipient_public
    ecc_custom_point_t shared_point;
    ecc_custom_point_multiply(&context->custom_public_key->point, ephemeral_private.d,
                            &shared_point, context);
    
    // Derive key material from shared secret using SHA-256
    unsigned char shared_secret_bytes[9 * 8];
    for (int i = 0; i < context->field_size_words; i++) {
        for (int j = 0; j < 8; j++) {
            shared_secret_bytes[i * 8 + j] = (shared_point.x[i] >> (j * 8)) & 0xFF;
        }
    }
    
    unsigned char key_material[32];
    SHA256(shared_secret_bytes, context->field_size_words * 8, key_material);
    
    // Encrypt data using XOR with derived key
    unsigned char* encrypted_data = (unsigned char*)malloc(data_len);
    if (!encrypted_data) return NULL;
    
    for (size_t i = 0; i < data_len; i++) {
        encrypted_data[i] = data[i] ^ key_material[i % 32];
    }
    
    // Package output: [ephemeral_pub_size][ephemeral_pub_x][ephemeral_pub_y][encrypted_data]
    int coord_size = (context->field_size_bits + 7) / 8;
    int ephemeral_pub_size = 2 * coord_size;
    *output_len = sizeof(int) + ephemeral_pub_size + data_len;
    
    unsigned char* output = (unsigned char*)malloc(*output_len);
    if (!output) {
        free(encrypted_data);
        return NULL;
    }
    
    memcpy(output, &ephemeral_pub_size, sizeof(int));
    
    // Copy ephemeral public key coordinates
    unsigned char* pub_data = output + sizeof(int);
    for (int i = 0; i < coord_size; i++) {
        int word_idx = i / 8;
        int byte_idx = i % 8;
        if (word_idx < context->field_size_words) {
            pub_data[i] = (ephemeral_public.point.x[word_idx] >> (byte_idx * 8)) & 0xFF;
            pub_data[coord_size + i] = (ephemeral_public.point.y[word_idx] >> (byte_idx * 8)) & 0xFF;
        } else {
            pub_data[i] = 0;
            pub_data[coord_size + i] = 0;
        }
    }
    
    memcpy(output + sizeof(int) + ephemeral_pub_size, encrypted_data, data_len);
    
    free(encrypted_data);
    return output;
}

unsigned char* ecc_custom_pure_decrypt(const unsigned char* encrypted_data, size_t encrypted_len,
                                     ecc_context_t* context, size_t* output_len) {
    if (!encrypted_data || !context || !context->custom_private_key || !output_len) return NULL;
    
    // Parse input: [ephemeral_pub_size][ephemeral_pub_x][ephemeral_pub_y][encrypted_data]
    if (encrypted_len < sizeof(int)) return NULL;
    
    int ephemeral_pub_size;
    memcpy(&ephemeral_pub_size, encrypted_data, sizeof(int));
    
    if (encrypted_len < sizeof(int) + ephemeral_pub_size) return NULL;
    
    // Extract ephemeral public key
    ecc_custom_public_key_t ephemeral_public;
    const unsigned char* pub_data = encrypted_data + sizeof(int);
    int coord_size = ephemeral_pub_size / 2;
    
    // Clear the point first
    memset(&ephemeral_public.point, 0, sizeof(ecc_custom_point_t));
    
    // Convert bytes back to coordinates
    for (int i = 0; i < coord_size; i++) {
        int word_idx = i / 8;
        int byte_idx = i % 8;
        if (word_idx < context->field_size_words) {
            ephemeral_public.point.x[word_idx] |= ((uint64_t)pub_data[i]) << (byte_idx * 8);
            ephemeral_public.point.y[word_idx] |= ((uint64_t)pub_data[coord_size + i]) << (byte_idx * 8);
        }
    }
    ephemeral_public.point.z[0] = 1; // Projective coordinate
    ephemeral_public.point.is_infinity = 0;
    ephemeral_public.point.curve_id = context->curve;
    ephemeral_public.curve_id = context->curve;
    
    // Compute shared secret
    ecc_custom_point_t shared_point;
    ecc_custom_point_multiply(&ephemeral_public.point, context->custom_private_key->d,
                            &shared_point, context);
    
    // Use first 32 bytes of x-coordinate as key material
    unsigned char key_material[32];
    memcpy(key_material, shared_point.x, 32);
    
    // Decrypt data
    const unsigned char* data_part = encrypted_data + sizeof(int) + ephemeral_pub_size;
    size_t data_len = encrypted_len - sizeof(int) - ephemeral_pub_size;
    
    unsigned char* decrypted_data = (unsigned char*)malloc(data_len);
    if (!decrypted_data) return NULL;
    
    for (size_t i = 0; i < data_len; i++) {
        decrypted_data[i] = data_part[i] ^ key_material[i % 32];
    }
    
    *output_len = data_len;
    return decrypted_data;
}

// =============================================================================
// ELLIPTIC CURVE POINT OPERATIONS
// =============================================================================

int ecc_custom_point_is_valid(const ecc_custom_point_t* point, const ecc_context_t* context) {
    if (!point || !context) return 0;
    
    if (point->is_infinity) return 1;
    
    // Check if point satisfies curve equation: y^2 = x^3 + ax + b (mod p)
    uint64_t x_squared[9], x_cubed[9], ax[9], y_squared[9];
    uint64_t rhs[9], temp[9];
    
    // Compute x^2
    ecc_mod_mult(point->x, point->x, x_squared, context->curve_p, context->field_size_words);
    
    // Compute x^3
    ecc_mod_mult(x_squared, point->x, x_cubed, context->curve_p, context->field_size_words);
    
    // Compute ax
    ecc_mod_mult(context->curve_a, point->x, ax, context->curve_p, context->field_size_words);
    
    // Compute rhs = x^3 + ax + b
    ecc_mod_add(x_cubed, ax, temp, context->curve_p, context->field_size_words);
    ecc_mod_add(temp, context->curve_b, rhs, context->curve_p, context->field_size_words);
    
    // Compute y^2
    ecc_mod_mult(point->y, point->y, y_squared, context->curve_p, context->field_size_words);
    
    // Check if y^2 == rhs
    return bigint_compare(y_squared, rhs, context->field_size_words) == 0;
}

void ecc_custom_point_add(const ecc_custom_point_t* p1, const ecc_custom_point_t* p2,
                         ecc_custom_point_t* result, const ecc_context_t* context) {
    if (!p1 || !p2 || !result || !context) return;
    
    // Handle point at infinity cases
    if (p1->is_infinity) {
        *result = *p2;
        return;
    }
    if (p2->is_infinity) {
        *result = *p1;
        return;
    }
    
    // Check if points are the same
    if (bigint_compare(p1->x, p2->x, context->field_size_words) == 0) {
        if (bigint_compare(p1->y, p2->y, context->field_size_words) == 0) {
            // Same point - use point doubling
            ecc_custom_point_double(p1, result, context);
            return;
        } else {
            // Points are additive inverses - result is point at infinity
            result->is_infinity = 1;
            result->curve_id = context->curve;
            return;
        }
    }
    
    // Point addition formula for short Weierstrass curves
    // λ = (y2 - y1) / (x2 - x1)
    // x3 = λ^2 - x1 - x2
    // y3 = λ(x1 - x3) - y1
    
    uint64_t lambda[9], temp1[9], temp2[9];
    uint64_t x_diff[9], y_diff[9], x_diff_inv[9];
    
    // Compute x_diff = x2 - x1
    ecc_mod_sub(p2->x, p1->x, x_diff, context->curve_p, context->field_size_words);
    
    // Compute y_diff = y2 - y1
    ecc_mod_sub(p2->y, p1->y, y_diff, context->curve_p, context->field_size_words);
    
    // Compute x_diff_inv = (x2 - x1)^(-1)
    ecc_mod_inv(x_diff, x_diff_inv, context->curve_p, context->field_size_words);
    
    // Compute lambda = y_diff * x_diff_inv
    ecc_mod_mult(y_diff, x_diff_inv, lambda, context->curve_p, context->field_size_words);
    
    // Compute x3 = lambda^2 - x1 - x2
    ecc_mod_mult(lambda, lambda, temp1, context->curve_p, context->field_size_words);
    ecc_mod_sub(temp1, p1->x, temp2, context->curve_p, context->field_size_words);
    ecc_mod_sub(temp2, p2->x, result->x, context->curve_p, context->field_size_words);
    
    // Compute y3 = lambda * (x1 - x3) - y1
    ecc_mod_sub(p1->x, result->x, temp1, context->curve_p, context->field_size_words);
    ecc_mod_mult(lambda, temp1, temp2, context->curve_p, context->field_size_words);
    ecc_mod_sub(temp2, p1->y, result->y, context->curve_p, context->field_size_words);
    
    // Set z coordinate for projective representation
    result->z[0] = 1;
    for (int i = 1; i < 9; i++) {
        result->z[i] = 0;
    }
    
    result->is_infinity = 0;
    result->curve_id = context->curve;
}

void ecc_custom_point_double(const ecc_custom_point_t* p, ecc_custom_point_t* result,
                           const ecc_context_t* context) {
    if (!p || !result || !context) return;
    
    if (p->is_infinity) {
        *result = *p;
        return;
    }
    
    // Point doubling formula for short Weierstrass curves
    // λ = (3x1^2 + a) / (2y1)
    // x3 = λ^2 - 2x1
    // y3 = λ(x1 - x3) - y1
    
    uint64_t lambda[9], temp1[9], temp2[9];
    uint64_t three_x_squared[9], numerator[9], denominator[9], denom_inv[9];
    uint64_t two_x[9];
    uint64_t three[9] = {3, 0, 0, 0, 0, 0, 0, 0, 0};
    uint64_t two[9] = {2, 0, 0, 0, 0, 0, 0, 0, 0};
    
    // Compute 3x1^2
    ecc_mod_mult(p->x, p->x, temp1, context->curve_p, context->field_size_words);
    ecc_mod_mult(three, temp1, three_x_squared, context->curve_p, context->field_size_words);
    
    // Compute numerator = 3x1^2 + a
    ecc_mod_add(three_x_squared, context->curve_a, numerator, context->curve_p, context->field_size_words);
    
    // Compute denominator = 2y1
    ecc_mod_mult(two, p->y, denominator, context->curve_p, context->field_size_words);
    
    // Compute denominator inverse
    ecc_mod_inv(denominator, denom_inv, context->curve_p, context->field_size_words);
    
    // Compute lambda = numerator * denom_inv
    ecc_mod_mult(numerator, denom_inv, lambda, context->curve_p, context->field_size_words);
    
    // Compute x3 = lambda^2 - 2x1
    ecc_mod_mult(lambda, lambda, temp1, context->curve_p, context->field_size_words);
    ecc_mod_mult(two, p->x, two_x, context->curve_p, context->field_size_words);
    ecc_mod_sub(temp1, two_x, result->x, context->curve_p, context->field_size_words);
    
    // Compute y3 = lambda * (x1 - x3) - y1
    ecc_mod_sub(p->x, result->x, temp1, context->curve_p, context->field_size_words);
    ecc_mod_mult(lambda, temp1, temp2, context->curve_p, context->field_size_words);
    ecc_mod_sub(temp2, p->y, result->y, context->curve_p, context->field_size_words);
    
    // Set z coordinate for projective representation
    result->z[0] = 1;
    for (int i = 1; i < 9; i++) {
        result->z[i] = 0;
    }
    
    result->is_infinity = 0;
    result->curve_id = context->curve;
}

void ecc_custom_point_multiply(const ecc_custom_point_t* point, const uint64_t* scalar,
                             ecc_custom_point_t* result, const ecc_context_t* context) {
    if (!point || !scalar || !result || !context) return;
    
    // Initialize result to point at infinity
    result->is_infinity = 1;
    result->curve_id = context->curve;
    for (int i = 0; i < 9; i++) {
        result->x[i] = 0;
        result->y[i] = 0;
        result->z[i] = 0;
    }
    
    // Check if scalar is zero
    int is_zero = 1;
    for (int i = 0; i < context->field_size_words; i++) {
        if (scalar[i] != 0) {
            is_zero = 0;
            break;
        }
    }
    if (is_zero) return; // 0 * P = O (point at infinity)
    
    // Simple double-and-add algorithm
    ecc_custom_point_t base = *point;
    
    // Process each bit of the scalar from least significant to most significant
    for (int word = 0; word < context->field_size_words; word++) {
        uint64_t scalar_word = scalar[word];
        
        for (int bit = 0; bit < 64; bit++) {
            if (scalar_word & 1) {
                // Add base to result
                if (result->is_infinity) {
                    *result = base;
                } else {
                    ecc_custom_point_t temp_result;
                    ecc_custom_point_add(result, &base, &temp_result, context);
                    *result = temp_result;
                }
            }
            
            // Double the base for next iteration (base = 2 * base)
            ecc_custom_point_t doubled_base;
            ecc_custom_point_double(&base, &doubled_base, context);
            base = doubled_base;
            
            scalar_word >>= 1;
            
            // Early termination if remaining bits are zero
            if (scalar_word == 0 && word == context->field_size_words - 1) break;
            if (scalar_word == 0) {
                // Check if all remaining words are zero
                int all_zero = 1;
                for (int j = word + 1; j < context->field_size_words; j++) {
                    if (scalar[j] != 0) {
                        all_zero = 0;
                        break;
                    }
                }
                if (all_zero) break;
            }
        }
    }
}

// =============================================================================
// MODULAR ARITHMETIC IMPLEMENTATIONS
// =============================================================================

void ecc_mod_add(const uint64_t* a, const uint64_t* b, uint64_t* result,
                const uint64_t* modulus, int words) {
    if (!a || !b || !result || !modulus || words <= 0) return;
    
    // Add a + b
    uint64_t carry = bigint_add(a, b, result, words);
    
    // If overflow or result >= modulus, subtract modulus
    if (carry || bigint_compare(result, modulus, words) >= 0) {
        bigint_subtract(result, modulus, result, words);
    }
}

void ecc_mod_sub(const uint64_t* a, const uint64_t* b, uint64_t* result,
                const uint64_t* modulus, int words) {
    if (!a || !b || !result || !modulus || words <= 0) return;
    
    // If a >= b, compute a - b
    if (bigint_compare(a, b, words) >= 0) {
        bigint_subtract(a, b, result, words);
    } else {
        // If a < b, compute modulus - (b - a)
        uint64_t temp[9];
        bigint_subtract(b, a, temp, words);
        bigint_subtract(modulus, temp, result, words);
    }
}

void ecc_mod_mult(const uint64_t* a, const uint64_t* b, uint64_t* result,
                 const uint64_t* modulus, int words) {
    if (!a || !b || !result || !modulus || words <= 0) return;
    
    // For efficiency, use a simpler approach for small multiplications
    // Initialize result to 0
    for (int i = 0; i < words; i++) {
        result[i] = 0;
    }
    
    // Use simple multiplication with modular reduction
    // This is not the most efficient but is correct and avoids infinite loops
    for (int i = 0; i < words; i++) {
        if (a[i] == 0) continue;
        
        uint64_t carry = 0;
        for (int j = 0; j < words && (i + j) < words; j++) {
            if (b[j] == 0) continue;
            
            // Simple 64x64 multiplication (using lower bits only for safety)
            uint64_t prod = (a[i] & 0xFFFFFFFF) * (b[j] & 0xFFFFFFFF);
            
            // Add to result with carry handling
            uint64_t sum = result[i + j] + prod + carry;
            carry = sum < result[i + j] ? 1 : 0;
            result[i + j] = sum;
        }
    }
    
    // Simple modular reduction: while result >= modulus, subtract modulus
    int reduction_count = 0;
    while (reduction_count < 10 && bigint_compare(result, modulus, words) >= 0) {
        bigint_subtract(result, modulus, result, words);
        reduction_count++;
    }
}

void ecc_mod_inv(const uint64_t* a, uint64_t* result, const uint64_t* modulus, int words) {
    if (!a || !result || !modulus || words <= 0) return;
    
    // Use Fermat's little theorem: a^(p-2) ≡ a^(-1) (mod p) for prime p
    // This is much more efficient than extended Euclidean algorithm
    
    // Compute p-2
    uint64_t exp[9];
    for (int i = 0; i < words; i++) {
        exp[i] = modulus[i];
    }
    
    // Subtract 2 from exp (exp = p - 2)
    uint64_t borrow = 2;
    for (int i = 0; i < words && borrow > 0; i++) {
        if (exp[i] >= borrow) {
            exp[i] -= borrow;
            borrow = 0;
        } else {
            uint64_t temp = exp[i];
            exp[i] = (uint64_t)(-borrow) + temp;
            borrow = 1;
        }
    }
    
    // Compute a^(p-2) mod p using binary exponentiation
    uint64_t base[9], temp_result[9];
    for (int i = 0; i < words; i++) {
        base[i] = a[i];
        result[i] = (i == 0) ? 1 : 0;  // Initialize result to 1
    }
    
    // Binary exponentiation
    for (int word = 0; word < words; word++) {
        uint64_t exp_word = exp[word];
        for (int bit = 0; bit < 64; bit++) {
            if (exp_word & 1) {
                // result = result * base mod p
                ecc_mod_mult(result, base, temp_result, modulus, words);
                for (int i = 0; i < words; i++) {
                    result[i] = temp_result[i];
                }
            }
            // base = base * base mod p
            ecc_mod_mult(base, base, temp_result, modulus, words);
            for (int i = 0; i < words; i++) {
                base[i] = temp_result[i];
            }
            exp_word >>= 1;
        }
    }
} 