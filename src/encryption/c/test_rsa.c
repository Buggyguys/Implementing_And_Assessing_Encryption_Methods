#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c_core.h"
#include "rsa/implementation.h"

int main() {
    printf("Testing RSA Implementation\n");

    // Initialize RSA context
    void* rsa_context = rsa_init();
    if (!rsa_context) {
        fprintf(stderr, "Error: Could not initialize RSA context\n");
        return 1;
    }

    // Generate key
    printf("Generating RSA key...\n");
    int key_length = 0;
    unsigned char* key = rsa_generate_key(rsa_context, &key_length);
    if (!key) {
        fprintf(stderr, "Error: Could not generate RSA key\n");
        rsa_cleanup(rsa_context);
        return 1;
    }
    printf("Generated RSA key of length %d\n", key_length);

    // Test data
    const char* test_data = "This is a test message for RSA encryption";
    int data_length = strlen(test_data);
    printf("Test data: '%s'\n", test_data);

    // Encrypt
    printf("Encrypting data...\n");
    int encrypted_length = 0;
    unsigned char* encrypted = rsa_encrypt(rsa_context, (unsigned char*)test_data, data_length, NULL, &encrypted_length);
    if (!encrypted) {
        fprintf(stderr, "Error: RSA encryption failed\n");
        free(key);
        rsa_cleanup(rsa_context);
        return 1;
    }
    printf("Encrypted data of length %d\n", encrypted_length);

    // Decrypt
    printf("Decrypting data...\n");
    int decrypted_length = 0;
    unsigned char* decrypted = rsa_decrypt(rsa_context, encrypted, encrypted_length, NULL, &decrypted_length);
    if (!decrypted) {
        fprintf(stderr, "Error: RSA decryption failed\n");
        free(key);
        free(encrypted);
        rsa_cleanup(rsa_context);
        return 1;
    }
    printf("Decrypted data: '%.*s'\n", decrypted_length, decrypted);

    // Verify
    if (decrypted_length == data_length && memcmp(decrypted, test_data, data_length) == 0) {
        printf("Test PASSED! Decrypted data matches original data.\n");
    } else {
        printf("Test FAILED! Decrypted data does not match original data.\n");
    }

    // Cleanup
    free(key);
    free(encrypted);
    free(decrypted);
    rsa_cleanup(rsa_context);

    return 0;
} 