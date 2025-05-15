#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "implementation.h"
#include "rsa_key.h"

// Configure RSA key size (bits: 1024, 2048, 3072, 4096)
int rsa_set_key_size(rsa_context_t* context, int key_size) {
    if (!context) return 0;
    
    // Check if key size is valid
    if (key_size != 1024 && key_size != 2048 && key_size != 3072 && key_size != 4096) {
        fprintf(stderr, "Warning: Invalid RSA key size %d (must be 1024, 2048, 3072, or 4096), defaulting to 2048\n", key_size);
        key_size = 2048;
    }
    
    context->key_size = key_size;
    return 1;
}

// Configure RSA padding type (PKCS#1 v1.5 or OAEP)
int rsa_set_padding(rsa_context_t* context, rsa_padding_type_t padding_type) {
    if (!context) return 0;
    
    context->padding_type = padding_type;
    return 1;
}

// Configure RSA key reuse and key count
int rsa_set_key_reuse(rsa_context_t* context, int key_reuse, int key_count) {
    if (!context) return 0;
    
    context->key_reuse = key_reuse ? 1 : 0;
    
    if (key_count < 1) {
        key_count = 1;
    } else if (key_count > 100) {
        fprintf(stderr, "Warning: Key count %d exceeds maximum (100), limiting to 100\n", key_count);
        key_count = 100;
    }
    
    context->key_count = key_count;
    return 1;
}

// Generate a new RSA key with specified size
RSA* rsa_generate_new_key(int key_size) {
    BIGNUM *bn = BN_new();
    if (!bn) {
        fprintf(stderr, "Error: BN_new failed in RSA key generation\n");
        return NULL;
    }
    
    // Set public exponent to 65537 (standard value)
    if (BN_set_word(bn, RSA_F4) != 1) {
        fprintf(stderr, "Error: BN_set_word failed in RSA key generation\n");
        BN_free(bn);
        return NULL;
    }
    
    // Generate new RSA key
    RSA* rsa = RSA_new();
    if (!rsa) {
        fprintf(stderr, "Error: RSA_new failed in RSA key generation\n");
        BN_free(bn);
        return NULL;
    }
    
    // Set key size
    if (RSA_generate_key_ex(rsa, key_size, bn, NULL) != 1) {
        fprintf(stderr, "Error: RSA_generate_key_ex failed in RSA key generation\n");
        char* err_string = ERR_error_string(ERR_get_error(), NULL);
        if (err_string) {
            fprintf(stderr, "OpenSSL error: %s\n", err_string);
        }
        RSA_free(rsa);
        BN_free(bn);
        return NULL;
    }
    
    // Free the bn now that it's been used
    BN_free(bn);
    
    return rsa;
}

// Free an RSA key
void rsa_free_key(rsa_key_t* key) {
    if (!key) return;
    
    if (key->rsa) {
        RSA_free(key->rsa);
    }
    
    if (key->n) free(key->n);
    if (key->e) free(key->e);
    if (key->d) free(key->d);
    
    free(key);
}

// Create an rsa_key_t structure from an RSA key
rsa_key_t* rsa_create_key_from_rsa(RSA* rsa_key) {
    if (!rsa_key) return NULL;
    
    rsa_key_t* key = (rsa_key_t*)malloc(sizeof(rsa_key_t));
    if (!key) {
        fprintf(stderr, "Error: Could not allocate memory for RSA key structure\n");
        return NULL;
    }
    
    memset(key, 0, sizeof(rsa_key_t));
    
    // Store the RSA key
    key->rsa = rsa_key;
    
    // Get key size
    key->bits = RSA_bits(rsa_key);
    key->size = RSA_size(rsa_key);
    
    // For now, we don't copy the key components (n, e, d)
    // This could be implemented if needed
    
    return key;
}

// Get the current RSA key from the context
RSA* rsa_get_current_key(rsa_context_t* context) {
    if (!context) return NULL;
    
    if (context->key_reuse && context->keys && context->current_key_index < context->key_count) {
        return context->keys[context->current_key_index]->rsa;
    } else {
        return context->rsa;
    }
}

// Get the current RSA key structure from the context
rsa_key_t* rsa_get_current_key_struct(rsa_context_t* context) {
    if (!context) return NULL;
    
    if (context->key_reuse && context->keys && context->current_key_index < context->key_count) {
        return context->keys[context->current_key_index];
    } else {
        return NULL;
    }
}

// Move to the next key in the key reuse array
int rsa_move_to_next_key(rsa_context_t* context) {
    if (!context || !context->key_reuse || !context->keys || context->key_count <= 0) {
        return 0;
    }
    
    context->current_key_index = (context->current_key_index + 1) % context->key_count;
    return 1;
}

// Export a public key in DER format
unsigned char* rsa_export_public_key(RSA* key, int* length) {
    if (!key || !length) return NULL;
    
    // Create a memory BIO
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        fprintf(stderr, "Error: Could not create BIO for RSA key export\n");
        return NULL;
    }
    
    // Write the key in DER format
    if (!i2d_RSAPublicKey_bio(bio, key)) {
        fprintf(stderr, "Error: Could not export RSA public key\n");
        BIO_free(bio);
        return NULL;
    }
    
    // Get the buffer size
    *length = BIO_ctrl_pending(bio);
    
    // Allocate memory for the buffer
    unsigned char* buffer = (unsigned char*)malloc(*length);
    if (!buffer) {
        fprintf(stderr, "Error: Could not allocate memory for RSA key buffer\n");
        BIO_free(bio);
        return NULL;
    }
    
    // Read the buffer
    if (BIO_read(bio, buffer, *length) != *length) {
        fprintf(stderr, "Error: Could not read RSA key from BIO\n");
        free(buffer);
        BIO_free(bio);
        return NULL;
    }
    
    BIO_free(bio);
    return buffer;
}

// Export a private key in DER format
unsigned char* rsa_export_private_key(RSA* key, int* length) {
    if (!key || !length) return NULL;
    
    // Create a memory BIO
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        fprintf(stderr, "Error: Could not create BIO for RSA key export\n");
        return NULL;
    }
    
    // Write the key in DER format
    if (!i2d_RSAPrivateKey_bio(bio, key)) {
        fprintf(stderr, "Error: Could not export RSA private key\n");
        BIO_free(bio);
        return NULL;
    }
    
    // Get the buffer size
    *length = BIO_ctrl_pending(bio);
    
    // Allocate memory for the buffer
    unsigned char* buffer = (unsigned char*)malloc(*length);
    if (!buffer) {
        fprintf(stderr, "Error: Could not allocate memory for RSA key buffer\n");
        BIO_free(bio);
        return NULL;
    }
    
    // Read the buffer
    if (BIO_read(bio, buffer, *length) != *length) {
        fprintf(stderr, "Error: Could not read RSA key from BIO\n");
        free(buffer);
        BIO_free(bio);
        return NULL;
    }
    
    BIO_free(bio);
    return buffer;
}

// Import a public key from DER format
RSA* rsa_import_public_key(const unsigned char* data, int length) {
    if (!data || length <= 0) return NULL;
    
    // Create a memory BIO
    BIO* bio = BIO_new_mem_buf(data, length);
    if (!bio) {
        fprintf(stderr, "Error: Could not create BIO for RSA key import\n");
        return NULL;
    }
    
    // Read the key from DER format
    RSA* key = d2i_RSAPublicKey_bio(bio, NULL);
    if (!key) {
        fprintf(stderr, "Error: Could not import RSA public key\n");
        BIO_free(bio);
        return NULL;
    }
    
    BIO_free(bio);
    return key;
}

// Import a private key from DER format
RSA* rsa_import_private_key(const unsigned char* data, int length) {
    if (!data || length <= 0) return NULL;
    
    // Create a memory BIO
    BIO* bio = BIO_new_mem_buf(data, length);
    if (!bio) {
        fprintf(stderr, "Error: Could not create BIO for RSA key import\n");
        return NULL;
    }
    
    // Read the key from DER format
    RSA* key = d2i_RSAPrivateKey_bio(bio, NULL);
    if (!key) {
        fprintf(stderr, "Error: Could not import RSA private key\n");
        BIO_free(bio);
        return NULL;
    }
    
    BIO_free(bio);
    return key;
} 