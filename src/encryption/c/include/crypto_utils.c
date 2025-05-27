#include "crypto_utils.h"
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// On macOS, CLOCK_REALTIME might not be defined
#if defined(__APPLE__) && !defined(CLOCK_REALTIME)
#define CLOCK_REALTIME 0
// Simple polyfill for clock_gettime on older macOS versions
int clock_gettime(int clk_id, struct timespec* tp) {
    struct timeval tv;
    if (gettimeofday(&tv, NULL) < 0) return -1;
    tp->tv_sec = tv.tv_sec;
    tp->tv_nsec = tv.tv_usec * 1000;
    return 0;
}
#endif

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
                         size_t input_size, size_t salt_size, int iterations) {
    if (!output || !input || !salt || output_size == 0 || input_size == 0 || salt_size == 0) {
        return 0;
    }
    
    // Initialize output with input (truncate or repeat as needed)
    for (size_t i = 0; i < output_size; i++) {
        output[i] = input[i % input_size];
    }
    
    // Mixing iterations
    for (int iter = 0; iter < iterations; iter++) {
        // First pass - XOR with salt
        for (size_t i = 0; i < output_size; i++) {
            output[i] ^= salt[i % salt_size];
        }
        
        // Second pass - rotate and mix
        unsigned char last = output[output_size - 1];
        for (size_t i = output_size - 1; i > 0; i--) {
            output[i] = ((output[i] << 1) | (output[i-1] >> 7)) ^ output[i-1];
        }
        output[0] = ((output[0] << 1) | (last >> 7)) ^ last;
        
        // Third pass - add iteration number
        for (size_t i = 0; i < output_size; i++) {
            output[i] ^= (unsigned char)(iter & 0xFF);
        }
    }
    
    return 1;
}

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
                                   int iterations) {
    if (!derived_key || !password || !salt || derived_key_len == 0 || password_len == 0 || salt_len == 0) {
        return 0;
    }
    
    // Initialize the derived key with the password
    for (size_t i = 0; i < derived_key_len; i++) {
        derived_key[i] = password[i % password_len];
    }
    
    // Repeatedly mix the key with the salt
    return crypto_mix_with_salt(derived_key, (const unsigned char*)password, 
                               salt, derived_key_len, password_len, salt_len, 
                               iterations);
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
                                     const unsigned char* key, size_t key_size) {
    if (!tag || !data || !key || tag_size == 0 || data_size == 0 || key_size == 0) {
        return 0;
    }
    
    // Initialize tag with zeros
    memset(tag, 0, tag_size);
    
    // Inner mixing (XOR key with inner pad and mix with message)
    unsigned char* inner_pad = (unsigned char*)malloc(key_size);
    if (!inner_pad) return 0;
    
    // Create inner pad (XOR key with 0x36)
    for (size_t i = 0; i < key_size; i++) {
        inner_pad[i] = key[i] ^ 0x36;
    }
    
    // Mix inner pad with data
    for (size_t i = 0; i < data_size; i++) {
        tag[i % tag_size] ^= data[i] ^ inner_pad[i % key_size];
    }
    
    // Outer mixing (XOR key with outer pad and mix with inner result)
    unsigned char* outer_pad = (unsigned char*)malloc(key_size);
    if (!outer_pad) {
        free(inner_pad);
        return 0;
    }
    
    // Create outer pad (XOR key with 0x5C)
    for (size_t i = 0; i < key_size; i++) {
        outer_pad[i] = key[i] ^ 0x5C;
    }
    
    // Mix outer pad with inner result
    for (size_t i = 0; i < tag_size; i++) {
        unsigned char temp = tag[i];
        tag[i] = temp ^ outer_pad[i % key_size];
    }
    
    // Additional mixing for security
    for (size_t i = 0; i < tag_size; i++) {
        for (size_t j = 0; j < tag_size; j++) {
            tag[j] = ((tag[j] << 1) | (tag[(j+1) % tag_size] >> 7)) ^ tag[(i+j) % tag_size];
        }
    }
    
    free(inner_pad);
    free(outer_pad);
    return 1;
}

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
                                   const unsigned char* key, size_t key_size) {
    if (!tag || !data || !key || tag_size == 0 || data_size == 0 || key_size == 0) {
        return 0;
    }
    
    // Generate a new tag to compare with the provided one
    unsigned char* calculated_tag = (unsigned char*)malloc(tag_size);
    if (!calculated_tag) return 0;
    
    int result = 0;
    if (crypto_generate_authentication_tag(calculated_tag, tag_size, data, data_size, key, key_size)) {
        // Constant-time comparison to prevent timing attacks
        result = crypto_constant_time_equals(tag, calculated_tag, tag_size);
    }
    
    // Secure cleanup
    crypto_secure_free(calculated_tag, tag_size);
    return result;
} 