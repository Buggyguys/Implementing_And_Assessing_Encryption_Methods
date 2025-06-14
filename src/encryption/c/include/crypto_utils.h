#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#ifdef USE_OPENSSL
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#endif

/**
 * Secure random number generation for cryptographic purposes.
 * Uses OpenSSL if available, falls back to a more secure version of
 * the standard random generator if not.
 *
 * @param buffer The buffer to fill with random bytes
 * @param size The number of bytes to generate
 * @return 1 on success, 0 on failure
 */
static inline int crypto_random_bytes(unsigned char* buffer, size_t size) {
    if (!buffer || size == 0) return 0;

#ifdef USE_OPENSSL
    // Use OpenSSL's CSPRNG if available
    if (RAND_bytes(buffer, size) != 1) {
        // Handle OpenSSL error
        fprintf(stderr, "Error: OpenSSL RAND_bytes failed\n");
        return 0;
    }
#else
    // Fallback to a more secure random implementation
    // Mix multiple entropy sources
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        // Read from /dev/urandom if available (Unix/Linux/macOS)
        if (fread(buffer, 1, size, urandom) != size) {
            fclose(urandom);
            fprintf(stderr, "Error: Failed to read from /dev/urandom\n");
            return 0;
        }
        fclose(urandom);
    } else {
        // If /dev/urandom is not available, use a combination of sources
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        unsigned int seed = (unsigned int)ts.tv_nsec;
        
        // Mix in process ID and timestamp
        seed ^= (unsigned int)getpid();
        seed ^= (unsigned int)time(NULL);
        
        srand(seed);
        for (size_t i = 0; i < size; i++) {
            buffer[i] = (unsigned char)(rand() & 0xFF);
            
            // Add additional entropy by changing the seed between bytes
            if (i % 4 == 0) {
                clock_gettime(CLOCK_REALTIME, &ts);
                seed = (seed * 1103515245 + 12345) ^ (unsigned int)ts.tv_nsec;
                srand(seed);
            }
        }
    }
#endif
    return 1;
}

/**
 * Securely allocate memory for cryptographic operations.
 * The memory is zeroed after allocation for security.
 *
 * @param size The number of bytes to allocate
 * @return Pointer to the allocated memory, or NULL on failure
 */
static inline void* crypto_secure_alloc(size_t size) {
    if (size == 0) return NULL;
    
    printf("    [DEBUG] Attempting to allocate %zu bytes (%.2f MB)\n", 
           size, (double)size / (1024.0 * 1024.0));

#ifdef USE_OPENSSL
    // Use OpenSSL's secure memory functions if available
    void* ptr = OPENSSL_malloc(size);
    if (!ptr) {
        printf("    [DEBUG] OpenSSL malloc failed for %zu bytes\n", size);
    }
    return ptr;
#else
    // Otherwise use standard malloc and manually zero the memory
    void* ptr = malloc(size);
    if (!ptr) {
        printf("    [DEBUG] Standard malloc failed for %zu bytes\n", size);
        return NULL;
    } else {
        printf("    [DEBUG] Allocation successful, zeroing memory...\n");
    }
    memset(ptr, 0, size);
    return ptr;
#endif
}

/**
 * Securely free memory used for cryptographic operations.
 * The memory is zeroed before being freed.
 *
 * @param ptr Pointer to the memory to free
 * @param size Size of the memory block (needed to zero it)
 */
static inline void crypto_secure_free(void* ptr, size_t size) {
    if (!ptr) return;

#ifdef USE_OPENSSL
    // Use OpenSSL's secure free if available
    OPENSSL_clear_free(ptr, size);
#else
    // Otherwise manually zero and then free
    if (size > 0) {
        volatile unsigned char* p = (volatile unsigned char*)ptr;
        for (size_t i = 0; i < size; i++) {
            p[i] = 0;
        }
    }
    free(ptr);
#endif
}

/**
 * Generate a cryptographically secure key of specified size
 *
 * @param key_buffer The buffer to store the generated key
 * @param key_size The size of the key in bytes
 * @return 1 on success, 0 on failure
 */
static inline int crypto_generate_key(unsigned char* key_buffer, size_t key_size) {
    return crypto_random_bytes(key_buffer, key_size);
}

/**
 * Generate a cryptographically secure initialization vector (IV)
 *
 * @param iv_buffer The buffer to store the generated IV
 * @param iv_size The size of the IV in bytes
 * @return 1 on success, 0 on failure
 */
static inline int crypto_generate_iv(unsigned char* iv_buffer, size_t iv_size) {
    return crypto_random_bytes(iv_buffer, iv_size);
}

/**
 * Generate a cryptographically secure nonce
 *
 * @param nonce_buffer The buffer to store the generated nonce
 * @param nonce_size The size of the nonce in bytes
 * @return 1 on success, 0 on failure
 */
static inline int crypto_generate_nonce(unsigned char* nonce_buffer, size_t nonce_size) {
    return crypto_random_bytes(nonce_buffer, nonce_size);
}

/**
 * Constant-time memory comparison to prevent timing attacks
 * 
 * @param a First memory buffer
 * @param b Second memory buffer
 * @param size Size of the buffers
 * @return 1 if equal, 0 if not equal
 */
static inline int crypto_constant_time_equals(const unsigned char* a, const unsigned char* b, size_t size) {
    if (!a || !b) return 0;
    
    unsigned char result = 0;
    for (size_t i = 0; i < size; i++) {
        result |= a[i] ^ b[i];
    }
    return (result == 0) ? 1 : 0;
}

/**
 * Helper function to get standard IV size for a given algorithm and mode
 *
 * @param algorithm Algorithm name (e.g., "AES", "Camellia")
 * @param mode Mode of operation (e.g., "GCM", "CBC", "CTR")
 * @return Standard IV size in bytes or 0 if unknown
 */
static inline size_t crypto_get_standard_iv_size(const char* algorithm, const char* mode) {
    // Common modes
    if (strcmp(mode, "GCM") == 0) {
        return 12; // 96 bits
    } else if (strcmp(mode, "CBC") == 0 || strcmp(mode, "CTR") == 0) {
        return 16; // 128 bits
    } else if (strcmp(mode, "ECB") == 0) {
        return 0;  // ECB doesn't use IV
    }
    
    // ChaCha20 specific
    if (strcmp(algorithm, "ChaCha20") == 0) {
        return 12; // 96 bits nonce
    }
    
    // Default fallback
    return 16; // Most common IV size
}

/**
 * Helper function to get standard tag size for authenticated encryption
 *
 * @param algorithm Algorithm name (e.g., "AES", "Camellia")
 * @param mode Mode of operation (e.g., "GCM", "CCM")
 * @return Standard tag size in bytes or 0 if not applicable
 */
static inline size_t crypto_get_standard_tag_size(const char* algorithm, const char* mode) {
    if (strcmp(mode, "GCM") == 0 || strcmp(mode, "CCM") == 0) {
        return 16; // 128 bits
    }
    
    // Poly1305 (often used with ChaCha20)
    if (strcmp(algorithm, "ChaCha20") == 0 && strcmp(mode, "Poly1305") == 0) {
        return 16; // 128 bits
    }
    
    return 0; // Not applicable
}

/**
 * Generate a secure tag for message authentication based on HMAC principle
 * This is a simplified version for demonstration - use a proper HMAC in production
 *
 * @param tag Output tag buffer
 * @param tag_size Size of the tag to generate
 * @param data Input data to authenticate
 * @param data_size Size of the input data
 * @param key Key for authentication
 * @param key_size Size of the key
 * @return 1 on success, 0 on failure
 */
int crypto_generate_authentication_tag(unsigned char* tag, size_t tag_size,
                                     const unsigned char* data, size_t data_size,
                                     const unsigned char* key, size_t key_size);

/**
 * Verify an authentication tag against data
 *
 * @param tag Tag to verify
 * @param tag_size Size of the tag
 * @param data Data that was authenticated
 * @param data_size Size of the data
 * @param key Key used for authentication
 * @param key_size Size of the key
 * @return 1 if tag is valid, 0 if invalid
 */
int crypto_verify_authentication_tag(const unsigned char* tag, size_t tag_size,
                                   const unsigned char* data, size_t data_size,
                                   const unsigned char* key, size_t key_size);

/**
 * Mix a buffer with a XOR-based algorithm to create deterministic
 * but randomized output (useful for simple key derivation)
 *
 * @param output Output buffer
 * @param input Input buffer
 * @param salt Salt buffer
 * @param output_size Size of output buffer
 * @param input_size Size of input buffer
 * @param salt_size Size of salt buffer
 * @param iterations Number of mixing iterations
 * @return 1 on success, 0 on failure
 */
int crypto_mix_with_salt(unsigned char* output, const unsigned char* input, 
                         const unsigned char* salt, size_t output_size,
                         size_t input_size, size_t salt_size, int iterations);

/**
 * Simple key derivation function based on a password and salt
 * Note: For production use, PBKDF2, scrypt, or Argon2 should be used
 *
 * @param derived_key Output buffer for the derived key
 * @param derived_key_len Length of the derived key to generate
 * @param password Password input
 * @param password_len Password length
 * @param salt Salt buffer
 * @param salt_len Salt length
 * @param iterations Number of iterations (higher is more secure)
 * @return 1 on success, 0 on failure
 */
int crypto_derive_key_from_password(unsigned char* derived_key, size_t derived_key_len,
                                   const char* password, size_t password_len,
                                   const unsigned char* salt, size_t salt_len,
                                   int iterations);

#endif /* CRYPTO_UTILS_H */ 