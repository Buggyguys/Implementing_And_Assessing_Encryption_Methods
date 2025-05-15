#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// Temporarily comment out OpenSSL headers for initial testing
// #include <openssl/evp.h>
// #include <openssl/err.h>
// #include <openssl/rand.h>

#include "implementation.h"
#include "../include/utils.h"
#include "camellia_common.h"
#include "camellia_key.h"
#include "camellia_gcm.h"
#include "camellia_cbc.h"
#include "camellia_ctr.h"
#include "camellia_ecb.h"

// Register Camellia implementations - simplified to only register standard and custom
void register_camellia_implementations(implementation_registry_t* registry) {
    int index = registry->count;
    int implementations_before = registry->count;
    
    // Get the configuration to determine Camellia parameters
    char* key_size_str = getenv("CAMELLIA_KEY_SIZE");
    char* mode_str = getenv("CAMELLIA_MODE");
    char* use_stdlib_str = getenv("USE_STDLIB");
    char* use_custom_str = getenv("USE_CUSTOM");
    char* camellia_enabled_str = getenv("CAMELLIA_ENABLED");
    
    // Default values if environment variables are not set
    int key_size = key_size_str ? atoi(key_size_str) : 256;  // Default to 256
    char mode[16] = "GCM";  // Default to GCM
    int use_stdlib = use_stdlib_str ? atoi(use_stdlib_str) : 1;  // Default to true
    int use_custom = use_custom_str ? atoi(use_custom_str) : 1;  // Default to true
    int camellia_enabled = camellia_enabled_str ? atoi(camellia_enabled_str) : 1;  // Default to enabled
    
    // Check if Camellia is enabled in the configuration
    if (!camellia_enabled) {
        printf("Camellia implementations disabled in configuration\n");
        return;
    }
    
    if (mode_str) {
        strncpy(mode, mode_str, sizeof(mode) - 1);
    }
    
    // Register standard Camellia implementation if enabled
    if (use_stdlib) {
        strcpy(registry->implementations[index].name, "camellia");
        registry->implementations[index].algo_type = ALGO_CAMELLIA;
        registry->implementations[index].is_custom = 0;
        registry->implementations[index].key_size = key_size;
        strcpy(registry->implementations[index].mode, mode);
        registry->implementations[index].init = camellia_init;
        registry->implementations[index].cleanup = camellia_cleanup;
        registry->implementations[index].generate_key = camellia_generate_key;
        registry->implementations[index].encrypt = camellia_encrypt;
        registry->implementations[index].decrypt = camellia_decrypt;
        registry->implementations[index].encrypt_stream = camellia_encrypt_stream;
        registry->implementations[index].decrypt_stream = camellia_decrypt_stream;
        registry->count++;
    }
    
    // Register custom Camellia implementation if enabled
    if (use_custom) {
        index = registry->count;
        strcpy(registry->implementations[index].name, "camellia_custom");
        registry->implementations[index].algo_type = ALGO_CAMELLIA;
        registry->implementations[index].is_custom = 1;
        registry->implementations[index].key_size = key_size;
        strcpy(registry->implementations[index].mode, mode);
        registry->implementations[index].init = camellia_custom_init;
        registry->implementations[index].cleanup = camellia_custom_cleanup;
        registry->implementations[index].generate_key = camellia_custom_generate_key;
        registry->implementations[index].encrypt = camellia_custom_encrypt;
        registry->implementations[index].decrypt = camellia_custom_decrypt;
        registry->implementations[index].encrypt_stream = camellia_encrypt_stream;
        registry->implementations[index].decrypt_stream = camellia_decrypt_stream;
        registry->count++;
    }
    
    printf("Registered %d Camellia implementations\n", registry->count - implementations_before);
}

// Standard library implementation functions
void* camellia_init(void) {
    camellia_context_t* context = (camellia_context_t*)malloc(sizeof(camellia_context_t));
    if (!context) {
        fprintf(stderr, "Error: Could not allocate Camellia context\n");
        return NULL;
    }
    
    memset(context, 0, sizeof(camellia_context_t));
    context->key_size = 256;
    strcpy(context->mode, "GCM");
    context->is_custom = 0;
    context->key = NULL;
    context->key_length = 0;
    context->iv = NULL;
    context->iv_length = 0;
    
    return context;
}

void camellia_cleanup(void* context) {
    if (!context) return;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    if (camellia_context->key) {
        free(camellia_context->key);
        camellia_context->key = NULL;
    }
    
    if (camellia_context->iv) {
        free(camellia_context->iv);
        camellia_context->iv = NULL;
    }
    
    free(camellia_context);
}

unsigned char* camellia_encrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // If key is provided, use it instead of the context key
    if (key) {
        if (camellia_context->key) {
            free(camellia_context->key);
        }
        
        camellia_context->key_length = camellia_context->key_size / 8;
        camellia_context->key = (unsigned char*)malloc(camellia_context->key_length);
        if (!camellia_context->key) {
            fprintf(stderr, "Error: Could not allocate memory for Camellia key\n");
            return NULL;
        }
        
        memcpy(camellia_context->key, key, camellia_context->key_length);
    }
    
    // Check if key exists
    if (!camellia_context->key) {
        fprintf(stderr, "Error: Camellia key not set\n");
        return NULL;
    }
    
    // Encrypt based on mode
    if (strcmp(camellia_context->mode, "GCM") == 0) {
        #ifdef USE_OPENSSL
        return camellia_gcm_openssl_encrypt(camellia_context, data, data_length, output_length);
        #else
        return camellia_gcm_encrypt(camellia_context, data, data_length, output_length);
        #endif
    } else if (strcmp(camellia_context->mode, "CBC") == 0) {
        #ifdef USE_OPENSSL
        return camellia_cbc_openssl_encrypt(camellia_context, data, data_length, output_length);
        #else
        return camellia_cbc_encrypt(camellia_context, data, data_length, output_length);
        #endif
    } else if (strcmp(camellia_context->mode, "CTR") == 0) {
        #ifdef USE_OPENSSL
        return camellia_ctr_openssl_encrypt(camellia_context, data, data_length, output_length);
        #else
        return camellia_ctr_encrypt(camellia_context, data, data_length, output_length);
        #endif
    } else if (strcmp(camellia_context->mode, "ECB") == 0) {
        #ifdef USE_OPENSSL
        return camellia_ecb_openssl_encrypt(camellia_context, data, data_length, output_length);
        #else
        return camellia_ecb_encrypt(camellia_context, data, data_length, output_length);
        #endif
    } else {
        fprintf(stderr, "Error: Unsupported Camellia mode: %s\n", camellia_context->mode);
        return NULL;
    }
}

unsigned char* camellia_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // If key is provided, use it instead of the context key
    if (key) {
        if (camellia_context->key) {
            free(camellia_context->key);
        }
        
        camellia_context->key_length = camellia_context->key_size / 8;
        camellia_context->key = (unsigned char*)malloc(camellia_context->key_length);
        if (!camellia_context->key) {
            fprintf(stderr, "Error: Could not allocate memory for Camellia key\n");
            return NULL;
        }
        
        memcpy(camellia_context->key, key, camellia_context->key_length);
    }
    
    // Check if key exists
    if (!camellia_context->key) {
        fprintf(stderr, "Error: Camellia key not set\n");
        return NULL;
    }
    
    // Decrypt based on mode
    if (strcmp(camellia_context->mode, "GCM") == 0) {
        #ifdef USE_OPENSSL
        return camellia_gcm_openssl_decrypt(camellia_context, data, data_length, output_length);
        #else
        return camellia_gcm_decrypt(camellia_context, data, data_length, output_length);
        #endif
    } else if (strcmp(camellia_context->mode, "CBC") == 0) {
        #ifdef USE_OPENSSL
        return camellia_cbc_openssl_decrypt(camellia_context, data, data_length, output_length);
        #else
        return camellia_cbc_decrypt(camellia_context, data, data_length, output_length);
        #endif
    } else if (strcmp(camellia_context->mode, "CTR") == 0) {
        #ifdef USE_OPENSSL
        return camellia_ctr_openssl_decrypt(camellia_context, data, data_length, output_length);
        #else
        return camellia_ctr_decrypt(camellia_context, data, data_length, output_length);
        #endif
    } else if (strcmp(camellia_context->mode, "ECB") == 0) {
        #ifdef USE_OPENSSL
        return camellia_ecb_openssl_decrypt(camellia_context, data, data_length, output_length);
        #else
        return camellia_ecb_decrypt(camellia_context, data, data_length, output_length);
        #endif
    } else {
        fprintf(stderr, "Error: Unsupported Camellia mode: %s\n", camellia_context->mode);
        return NULL;
    }
}

unsigned char* camellia_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    // For simplicity, the stream version just calls the regular encrypt function
    // In a real implementation, this would handle streaming differently
    return camellia_encrypt(context, data, data_length, key, output_length);
}

unsigned char* camellia_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    // For simplicity, the stream version just calls the regular decrypt function
    // In a real implementation, this would handle streaming differently
    return camellia_decrypt(context, data, data_length, key, output_length);
}

// Custom implementation functions
void* camellia_custom_init(void) {
    camellia_context_t* context = (camellia_context_t*)malloc(sizeof(camellia_context_t));
    if (!context) {
        fprintf(stderr, "Error: Could not allocate Camellia custom context\n");
        return NULL;
    }
    
    memset(context, 0, sizeof(camellia_context_t));
    context->key_size = 256;
    strcpy(context->mode, "GCM");
    context->is_custom = 1;
    context->key = NULL;
    context->key_length = 0;
    context->iv = NULL;
    context->iv_length = 0;
    
    return context;
}

void camellia_custom_cleanup(void* context) {
    camellia_cleanup(context); // Reuse standard cleanup
}

unsigned char* camellia_custom_encrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // If key is provided, use it instead of the context key
    if (key) {
        if (camellia_context->key) {
            free(camellia_context->key);
        }
        
        camellia_context->key_length = camellia_context->key_size / 8;
        camellia_context->key = (unsigned char*)malloc(camellia_context->key_length);
        if (!camellia_context->key) {
            fprintf(stderr, "Error: Could not allocate memory for Camellia key\n");
            return NULL;
        }
        
        memcpy(camellia_context->key, key, camellia_context->key_length);
    }
    
    // Check if key exists
    if (!camellia_context->key) {
        fprintf(stderr, "Error: Camellia key not set\n");
        return NULL;
    }
    
    // Custom encrypt based on mode - for now, just use the standard implementations
    // In a real implementation, you would have custom versions of these functions
    if (strcmp(camellia_context->mode, "GCM") == 0) {
        return camellia_gcm_encrypt(camellia_context, data, data_length, output_length);
    } else if (strcmp(camellia_context->mode, "CBC") == 0) {
        return camellia_cbc_encrypt(camellia_context, data, data_length, output_length);
    } else if (strcmp(camellia_context->mode, "CTR") == 0) {
        return camellia_ctr_encrypt(camellia_context, data, data_length, output_length);
    } else if (strcmp(camellia_context->mode, "ECB") == 0) {
        return camellia_ecb_encrypt(camellia_context, data, data_length, output_length);
    } else {
        fprintf(stderr, "Error: Unsupported Camellia mode: %s\n", camellia_context->mode);
        return NULL;
    }
}

unsigned char* camellia_custom_decrypt(void* context, const unsigned char* data, int data_length, const unsigned char* key, int* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    camellia_context_t* camellia_context = (camellia_context_t*)context;
    
    // If key is provided, use it instead of the context key
    if (key) {
        if (camellia_context->key) {
            free(camellia_context->key);
        }
        
        camellia_context->key_length = camellia_context->key_size / 8;
        camellia_context->key = (unsigned char*)malloc(camellia_context->key_length);
        if (!camellia_context->key) {
            fprintf(stderr, "Error: Could not allocate memory for Camellia key\n");
            return NULL;
        }
        
        memcpy(camellia_context->key, key, camellia_context->key_length);
    }
    
    // Check if key exists
    if (!camellia_context->key) {
        fprintf(stderr, "Error: Camellia key not set\n");
        return NULL;
    }
    
    // Custom decrypt based on mode - for now, just use the standard implementations
    // In a real implementation, you would have custom versions of these functions
    if (strcmp(camellia_context->mode, "GCM") == 0) {
        return camellia_gcm_decrypt(camellia_context, data, data_length, output_length);
    } else if (strcmp(camellia_context->mode, "CBC") == 0) {
        return camellia_cbc_decrypt(camellia_context, data, data_length, output_length);
    } else if (strcmp(camellia_context->mode, "CTR") == 0) {
        return camellia_ctr_decrypt(camellia_context, data, data_length, output_length);
    } else if (strcmp(camellia_context->mode, "ECB") == 0) {
        return camellia_ecb_decrypt(camellia_context, data, data_length, output_length);
    } else {
        fprintf(stderr, "Error: Unsupported Camellia mode: %s\n", camellia_context->mode);
        return NULL;
    }
} 