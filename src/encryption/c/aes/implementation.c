#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "implementation.h"
#include "../include/utils.h"
#include "../include/crypto_utils.h"
#include "aes_common.h"
#include "aes_key.h"
#include "aes_gcm.h"
#include "aes_cbc.h"
#include "aes_cfb.h"
#include "aes_ofb.h"

// register AES implementations - simplified to only register standard and custom
void register_aes_implementations(implementation_registry_t* registry) {
    int index = registry->count;
    int implementations_before = registry->count;
    
    // get the configuration to determine AES parameters
    char* key_size_str = getenv("AES_KEY_SIZE");
    char* mode_str = getenv("AES_MODE");
    char* use_stdlib_str = getenv("USE_STDLIB");
    char* use_custom_str = getenv("USE_CUSTOM");
    char* aes_enabled_str = getenv("AES_ENABLED");
    
    // default values if environment variables are not set
    int key_size = key_size_str ? atoi(key_size_str) : 256;  // default to 256
    char mode[16] = "GCM";  // default to GCM
    int use_stdlib = use_stdlib_str ? atoi(use_stdlib_str) : 1;  // default to true
    int use_custom = use_custom_str ? atoi(use_custom_str) : 0;  // default to false for now to match Go
    int aes_enabled = aes_enabled_str ? atoi(aes_enabled_str) : 1;  // Default to enabled
    
    // check if AES is enabled in the configuration
    if (!aes_enabled) {
        printf("AES implementations disabled in configuration\n");
        return;
    }
    
    if (mode_str) {
        strncpy(mode, mode_str, sizeof(mode) - 1);
    }
    
    // register standard AES implementation if enabled
    if (use_stdlib) {
        strcpy(registry->implementations[index].name, "aes");
        registry->implementations[index].algo_type = ALGO_AES;
        registry->implementations[index].is_custom = 0;
        registry->implementations[index].key_size = key_size;
        strcpy(registry->implementations[index].mode, mode);
        registry->implementations[index].init = aes_init;
        registry->implementations[index].cleanup = aes_cleanup;
        registry->implementations[index].generate_key = aes_generate_key;
        registry->implementations[index].encrypt = aes_encrypt;
        registry->implementations[index].decrypt = aes_decrypt;
        registry->implementations[index].encrypt_stream = aes_encrypt_stream;
        registry->implementations[index].decrypt_stream = aes_decrypt_stream;
        registry->count++;
    }
    
    // register custom AES implementation if enabled
    if (use_custom) {
        index = registry->count;
        strcpy(registry->implementations[index].name, "aes_custom");
        registry->implementations[index].algo_type = ALGO_AES;
        registry->implementations[index].is_custom = 1;
        registry->implementations[index].key_size = key_size;
        strcpy(registry->implementations[index].mode, mode);
        registry->implementations[index].init = aes_custom_init;
        registry->implementations[index].cleanup = aes_custom_cleanup;
        registry->implementations[index].generate_key = aes_custom_generate_key;
        registry->implementations[index].encrypt = aes_custom_encrypt;
        registry->implementations[index].decrypt = aes_custom_decrypt;
        registry->implementations[index].encrypt_stream = aes_encrypt_stream;
        registry->implementations[index].decrypt_stream = aes_decrypt_stream;
        registry->count++;
    }
    
    printf("Registered %d AES implementations\n", registry->count - implementations_before);
}

// standard library implementation functions
void* aes_init(void) {
    aes_context_t* context = (aes_context_t*)malloc(sizeof(aes_context_t));
    if (!context) {
        fprintf(stderr, "Error: Could not allocate AES context\n");
        return NULL;
    }
    
    memset(context, 0, sizeof(aes_context_t));
    
    // get configuration from environment variables
    char* key_size_str = getenv("AES_KEY_SIZE");
    char* mode_str = getenv("AES_MODE");
    
    // set key size from environment or default to 256
    context->key_size = key_size_str ? atoi(key_size_str) : 256;
    
    // set mode from environment or default to GCM
    if (mode_str) {
        strncpy(context->mode, mode_str, sizeof(context->mode) - 1);
    } else {
        strcpy(context->mode, "GCM");
    }
    
    context->is_custom = 0;
    context->key = NULL;
    context->key_length = 0;
    context->iv = NULL;
    context->iv_length = crypto_get_standard_iv_size("AES", context->mode);
    
    return context;
}

void aes_cleanup(void* context) {
    if (!context) return;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    if (aes_context->key) {
        free(aes_context->key);
        aes_context->key = NULL;
    }
    
    if (aes_context->iv) {
        free(aes_context->iv);
        aes_context->iv = NULL;
    }
    
    free(aes_context);
}

unsigned char* aes_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // if key is provided, use it instead of the context key
    if (key) {
        if (aes_context->key) {
            free(aes_context->key);
        }
        
        aes_context->key_length = aes_context->key_size / 8;
        aes_context->key = (unsigned char*)malloc(aes_context->key_length);
        if (!aes_context->key) {
            fprintf(stderr, "Error: Could not allocate memory for AES key\n");
            return NULL;
        }
        
        memcpy(aes_context->key, key, aes_context->key_length);
    }
    
    // check if key exists
    if (!aes_context->key) {
        fprintf(stderr, "Error: AES key not set\n");
        return NULL;
    }
    
    // encrypt based on mode
    if (strcmp(aes_context->mode, "GCM") == 0) {
        #ifdef USE_OPENSSL
        int data_len = (int)data_length;
        int out_len = 0;
        unsigned char* result = aes_gcm_openssl_encrypt(aes_context, data, data_len, &out_len);
        if (output_length) *output_length = (size_t)out_len;
        return result;
        #else
        return aes_gcm_encrypt(aes_context, data, data_length, output_length);
        #endif
    } else if (strcmp(aes_context->mode, "CBC") == 0) {
        #ifdef USE_OPENSSL
        int data_len = (int)data_length;
        int out_len = 0;
        unsigned char* result = aes_cbc_openssl_encrypt(aes_context, data, data_len, &out_len);
        if (output_length) *output_length = (size_t)out_len;
        return result;
        #else
        int data_len = (int)data_length;
        int out_len = 0;
        unsigned char* result = aes_cbc_encrypt(aes_context, data, data_len, &out_len);
        if (output_length) *output_length = (size_t)out_len;
        return result;
        #endif
    } else if (strcmp(aes_context->mode, "CFB") == 0) {
        #ifdef USE_OPENSSL
        int data_len = (int)data_length;
        int out_len = 0;
        unsigned char* result = aes_cfb_openssl_encrypt(aes_context, data, data_len, &out_len);
        if (output_length) *output_length = (size_t)out_len;
        return result;
        #else
        int data_len = (int)data_length;
        int out_len = 0;
        unsigned char* result = aes_cfb_encrypt(aes_context, data, data_len, &out_len);
        if (output_length) *output_length = (size_t)out_len;
        return result;
        #endif
    } else if (strcmp(aes_context->mode, "OFB") == 0) {
        #ifdef USE_OPENSSL
        int data_len = (int)data_length;
        int out_len = 0;
        unsigned char* result = aes_ofb_openssl_encrypt(aes_context, data, data_len, &out_len);
        if (output_length) *output_length = (size_t)out_len;
        return result;
        #else
        int data_len = (int)data_length;
        int out_len = 0;
        unsigned char* result = aes_ofb_encrypt(aes_context, data, data_len, &out_len);
        if (output_length) *output_length = (size_t)out_len;
        return result;
        #endif
    } else {
        fprintf(stderr, "Error: Unsupported AES mode: %s\n", aes_context->mode);
        return NULL;
    }
}

unsigned char* aes_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // if key is provided, use it instead of the context key
    if (key) {
        if (aes_context->key) {
            free(aes_context->key);
        }
        
        aes_context->key_length = aes_context->key_size / 8;
        aes_context->key = (unsigned char*)malloc(aes_context->key_length);
        if (!aes_context->key) {
            fprintf(stderr, "Error: Could not allocate memory for AES key\n");
            return NULL;
        }
        
        memcpy(aes_context->key, key, aes_context->key_length);
    }
    
    // check if key exists
    if (!aes_context->key) {
        fprintf(stderr, "Error: AES key not set\n");
        return NULL;
    }
    
    // decrypt based on mode
    if (strcmp(aes_context->mode, "GCM") == 0) {
        #ifdef USE_OPENSSL
        int data_len = (int)data_length;
        int out_len = 0;
        unsigned char* result = aes_gcm_openssl_decrypt(aes_context, data, data_len, &out_len);
        if (output_length) *output_length = (size_t)out_len;
        return result;
        #else
        return aes_gcm_decrypt(aes_context, data, data_length, output_length);
        #endif
    } else if (strcmp(aes_context->mode, "CBC") == 0) {
        #ifdef USE_OPENSSL
        int data_len = (int)data_length;
        int out_len = 0;
        unsigned char* result = aes_cbc_openssl_decrypt(aes_context, data, data_len, &out_len);
        if (output_length) *output_length = (size_t)out_len;
        return result;
        #else
        return aes_cbc_decrypt(aes_context, data, data_length, output_length);
        #endif
    } else if (strcmp(aes_context->mode, "CFB") == 0) {
        #ifdef USE_OPENSSL
        int data_len = (int)data_length;
        int out_len = 0;
        unsigned char* result = aes_cfb_openssl_decrypt(aes_context, data, data_len, &out_len);
        if (output_length) *output_length = (size_t)out_len;
        return result;
        #else
        return aes_cfb_decrypt(aes_context, data, data_length, output_length);
        #endif
    } else if (strcmp(aes_context->mode, "OFB") == 0) {
        #ifdef USE_OPENSSL
        int data_len = (int)data_length;
        int out_len = 0;
        unsigned char* result = aes_ofb_openssl_decrypt(aes_context, data, data_len, &out_len);
        if (output_length) *output_length = (size_t)out_len;
        return result;
        #else
        return aes_ofb_decrypt(aes_context, data, data_length, output_length);
        #endif
    } else {
        fprintf(stderr, "Error: Unsupported AES mode: %s\n", aes_context->mode);
        return NULL;
    }
}



// Custom implementation functions
void* aes_custom_init(void) {
    aes_context_t* context = (aes_context_t*)malloc(sizeof(aes_context_t));
    if (!context) {
        fprintf(stderr, "Error: Could not allocate AES context\n");
        return NULL;
    }
    
    memset(context, 0, sizeof(aes_context_t));
    
    // get configuration from environment variables
    char* key_size_str = getenv("AES_KEY_SIZE");
    char* mode_str = getenv("AES_MODE");
    
    // set key size from environment or default to 256
    context->key_size = key_size_str ? atoi(key_size_str) : 256;
    
    // set mode from environment or default to GCM
    if (mode_str) {
        strncpy(context->mode, mode_str, sizeof(context->mode) - 1);
    } else {
        strcpy(context->mode, "GCM");
    }
    
    context->is_custom = 1;
    context->key = NULL;
    context->key_length = 0;
    context->iv = NULL;
    context->iv_length = crypto_get_standard_iv_size("AES", context->mode);
    
    return context;
}

void aes_custom_cleanup(void* context) {
    aes_cleanup(context); // reuse standard cleanup
}

unsigned char* aes_custom_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // if key is provided, use it instead of the context key
    if (key) {
        if (aes_context->key) {
            free(aes_context->key);
        }
        
        aes_context->key_length = aes_context->key_size / 8;
        aes_context->key = (unsigned char*)malloc(aes_context->key_length);
        if (!aes_context->key) {
            fprintf(stderr, "Error: Could not allocate memory for AES key\n");
            return NULL;
        }
        
        memcpy(aes_context->key, key, aes_context->key_length);
    }
    
    // check if key exists
    if (!aes_context->key) {
        fprintf(stderr, "Error: AES key not set\n");
        return NULL;
    }
    
    // encrypt based on mode using custom implementation
    if (strcmp(aes_context->mode, "GCM") == 0) {
        return aes_gcm_custom_encrypt(aes_context, data, data_length, output_length);
    } else if (strcmp(aes_context->mode, "CBC") == 0) {
        int data_len = (int)data_length;
        int out_len = 0;
        unsigned char* result = aes_cbc_custom_encrypt(aes_context, data, data_len, &out_len);
        if (output_length) *output_length = (size_t)out_len;
        return result;
    } else if (strcmp(aes_context->mode, "CFB") == 0) {
        int data_len = (int)data_length;
        int out_len = 0;
        unsigned char* result = aes_cfb_custom_encrypt(aes_context, data, data_len, &out_len);
        if (output_length) *output_length = (size_t)out_len;
        return result;
    } else if (strcmp(aes_context->mode, "OFB") == 0) {
        int data_len = (int)data_length;
        int out_len = 0;
        unsigned char* result = aes_ofb_custom_encrypt(aes_context, data, data_len, &out_len);
        if (output_length) *output_length = (size_t)out_len;
        return result;
    } else {
        fprintf(stderr, "Error: Unsupported AES mode: %s\n", aes_context->mode);
        return NULL;
    }
}

unsigned char* aes_custom_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length) {
    if (!context || !data || data_length <= 0) return NULL;
    
    aes_context_t* aes_context = (aes_context_t*)context;
    
    // if key is provided, use it instead of the context key
    if (key) {
        if (aes_context->key) {
            free(aes_context->key);
        }
        
        aes_context->key_length = aes_context->key_size / 8;
        aes_context->key = (unsigned char*)malloc(aes_context->key_length);
        if (!aes_context->key) {
            fprintf(stderr, "Error: Could not allocate memory for AES key\n");
            return NULL;
        }
        
        memcpy(aes_context->key, key, aes_context->key_length);
    }
    
    // check if key exists
    if (!aes_context->key) {
        fprintf(stderr, "Error: AES key not set\n");
        return NULL;
    }
    
    // decrypt based on mode using custom implementation
    if (strcmp(aes_context->mode, "GCM") == 0) {
        return aes_gcm_custom_decrypt(aes_context, data, data_length, output_length);
    } else if (strcmp(aes_context->mode, "CBC") == 0) {
        return aes_cbc_custom_decrypt(aes_context, data, data_length, output_length);
    } else if (strcmp(aes_context->mode, "CFB") == 0) {
        return aes_cfb_custom_decrypt(aes_context, data, data_length, output_length);
    } else if (strcmp(aes_context->mode, "OFB") == 0) {
        return aes_ofb_custom_decrypt(aes_context, data, data_length, output_length);
    } else {
        fprintf(stderr, "Error: Unsupported AES mode: %s\n", aes_context->mode);
        return NULL;
    }
}

unsigned char* aes_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    size_t data_len = (size_t)data_length;
    size_t out_len = 0;
    unsigned char* result = aes_encrypt(context, data, data_len, key, &out_len);
    if (output_length) *output_length = (int)out_len;
    return result;
}

unsigned char* aes_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    size_t data_len = (size_t)data_length;
    size_t out_len = 0;
    unsigned char* result = aes_decrypt(context, data, data_len, key, &out_len);
    if (output_length) *output_length = (int)out_len;
    return result;
}