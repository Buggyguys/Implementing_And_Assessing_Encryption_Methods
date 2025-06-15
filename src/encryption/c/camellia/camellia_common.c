#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "camellia_common.h"

// set key size for context
void camellia_set_key_size(camellia_context_t* context, int key_size) {
    if (!context) return;
    
    // validate key size (supports 128, 192, and 256 bits)
    if (key_size != 128 && key_size != 192 && key_size != 256) {
        fprintf(stderr, "Warning: Invalid key size %d, defaulting to 256 bits\n", key_size);
        context->key_size = 256;
    } else {
        context->key_size = key_size;
    }
}

// set mode of operation for context
void camellia_set_mode(camellia_context_t* context, const char* mode) {
    if (!context || !mode) return;
    
    // convert mode to uppercase for case-insensitive comparison
    char mode_upper[16] = {0};
    size_t i;
    for (i = 0; i < strlen(mode) && i < sizeof(mode_upper) - 1; i++) {
        mode_upper[i] = toupper(mode[i]);
    }
    
    // validate and set mode
    if (strcmp(mode_upper, "GCM") == 0 ||
        strcmp(mode_upper, "CBC") == 0 ||
        strcmp(mode_upper, "CTR") == 0 ||
        strcmp(mode_upper, "ECB") == 0) {
        strncpy(context->mode, mode_upper, sizeof(context->mode) - 1);
    } else {
        fprintf(stderr, "Warning: Invalid mode %s, defaulting to GCM\n", mode);
        strncpy(context->mode, "GCM", sizeof(context->mode) - 1);
    }
}

// get appropriate iv length for given mode
int camellia_get_iv_length(const char* mode) {
    if (!mode) return 0;
    
    // convert mode to uppercase for case-insensitive comparison
    char mode_upper[16] = {0};
    size_t i;
    for (i = 0; i < strlen(mode) && i < sizeof(mode_upper) - 1; i++) {
        mode_upper[i] = toupper(mode[i]);
    }
    
    // return appropriate iv length based on mode
    if (strcmp(mode_upper, "GCM") == 0) {
        return 12; // 96 bits for GCM
    } else if (strcmp(mode_upper, "CBC") == 0 || strcmp(mode_upper, "CTR") == 0) {
        return 16; // 128 bits for CBC and CTR
    } else {
        return 0; // ECB doesn't need IV
    }
} 