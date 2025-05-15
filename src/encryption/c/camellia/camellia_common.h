#ifndef CAMELLIA_COMMON_H
#define CAMELLIA_COMMON_H

#include "implementation.h"

// Common Camellia constants
#define CAMELLIA_BLOCK_SIZE 16  // 128 bits

// Common Camellia functions
void camellia_set_key_size(camellia_context_t* context, int key_size);
void camellia_set_mode(camellia_context_t* context, const char* mode);
int camellia_get_iv_length(const char* mode);

#endif /* CAMELLIA_COMMON_H */ 