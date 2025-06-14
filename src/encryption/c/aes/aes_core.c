#include "aes_core.h"
#include <stdio.h>
#include <stdlib.h>

// Galois field multiplication 
uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    uint8_t high_bit;
    
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            result ^= a;
        }
        high_bit = a & 0x80;
        a <<= 1;
        if (high_bit) {
            a ^= 0x1b; 
        }
        b >>= 1;
    }
    return result;
}

// sub bytes transformation
void sub_bytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = aes_sbox[state[i]];
    }
}

// inverse sub bytes transformation
void inv_sub_bytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = aes_inv_sbox[state[i]];
    }
}

// shift rows transformation
void shift_rows(uint8_t* state) {
    uint8_t temp;
    
    // row 1 shift left by 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    // row 2 shift left by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // row 3 shift left by 3 (or right by 1)
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

// inverse shift rows transformation
void inv_shift_rows(uint8_t* state) {
    uint8_t temp;
    
    // row 1 shift right by 1
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    
    // row 2 shift right by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // row 3 shift right by 3 (or left by 1)
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

// mix columns transformation
void mix_columns(uint8_t* state) {
    uint8_t temp[4];
    
    for (int col = 0; col < 4; col++) {
        temp[0] = gf_mul(0x02, state[col * 4 + 0]) ^ gf_mul(0x03, state[col * 4 + 1]) ^ 
                  state[col * 4 + 2] ^ state[col * 4 + 3];
        temp[1] = state[col * 4 + 0] ^ gf_mul(0x02, state[col * 4 + 1]) ^ 
                  gf_mul(0x03, state[col * 4 + 2]) ^ state[col * 4 + 3];
        temp[2] = state[col * 4 + 0] ^ state[col * 4 + 1] ^ 
                  gf_mul(0x02, state[col * 4 + 2]) ^ gf_mul(0x03, state[col * 4 + 3]);
        temp[3] = gf_mul(0x03, state[col * 4 + 0]) ^ state[col * 4 + 1] ^ 
                  state[col * 4 + 2] ^ gf_mul(0x02, state[col * 4 + 3]);
        
        for (int i = 0; i < 4; i++) {
            state[col * 4 + i] = temp[i];
        }
    }
}

// inverse mix columns transformation
void inv_mix_columns(uint8_t* state) {
    uint8_t temp[4];
    
    for (int col = 0; col < 4; col++) {
        temp[0] = gf_mul(0x0e, state[col * 4 + 0]) ^ gf_mul(0x0b, state[col * 4 + 1]) ^ 
                  gf_mul(0x0d, state[col * 4 + 2]) ^ gf_mul(0x09, state[col * 4 + 3]);
        temp[1] = gf_mul(0x09, state[col * 4 + 0]) ^ gf_mul(0x0e, state[col * 4 + 1]) ^ 
                  gf_mul(0x0b, state[col * 4 + 2]) ^ gf_mul(0x0d, state[col * 4 + 3]);
        temp[2] = gf_mul(0x0d, state[col * 4 + 0]) ^ gf_mul(0x09, state[col * 4 + 1]) ^ 
                  gf_mul(0x0e, state[col * 4 + 2]) ^ gf_mul(0x0b, state[col * 4 + 3]);
        temp[3] = gf_mul(0x0b, state[col * 4 + 0]) ^ gf_mul(0x0d, state[col * 4 + 1]) ^ 
                  gf_mul(0x09, state[col * 4 + 2]) ^ gf_mul(0x0e, state[col * 4 + 3]);
        
        for (int i = 0; i < 4; i++) {
            state[col * 4 + i] = temp[i];
        }
    }
}

// add round key transformation
void add_round_key(uint8_t* state, const uint8_t* round_key) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

// key expansion algorithm
void aes_key_expansion(const uint8_t* key, int key_size, aes_core_context_t* ctx) {
    int nk, nr;
    
    // set number of rounds based on key size
    switch (key_size) {
        case AES_128_KEY_SIZE:
            nk = 4;
            nr = AES_128_ROUNDS;
            break;
        case AES_192_KEY_SIZE:
            nk = 6;
            nr = AES_192_ROUNDS;
            break;
        case AES_256_KEY_SIZE:
            nk = 8;
            nr = AES_256_ROUNDS;
            break;
        default:
            fprintf(stderr, "Error: Invalid AES key size: %d\n", key_size);
            return;
    }
    
    ctx->num_rounds = nr;
    ctx->key_size = key_size;
    
    // create expanded key array
    uint8_t expanded_key[240]; 
    
    // copy the original key
    memcpy(expanded_key, key, key_size);
    
    // Generate round keys
    uint8_t temp[4];
    int i = nk;
    
    while (i < 4 * (nr + 1)) {
        // copy previous word
        for (int j = 0; j < 4; j++) {
            temp[j] = expanded_key[(i - 1) * 4 + j];
        }
        
        if (i % nk == 0) {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            
            // SubWord
            for (int j = 0; j < 4; j++) {
                temp[j] = aes_sbox[temp[j]];
            }
            
            // XOR with rcon
            temp[0] ^= rcon[i / nk];
        } else if (nk > 6 && i % nk == 4) {
            // sub word 
            for (int j = 0; j < 4; j++) {
                temp[j] = aes_sbox[temp[j]];
            }
        }
        
        // XOR with word nk positions back
        for (int j = 0; j < 4; j++) {
            expanded_key[i * 4 + j] = expanded_key[(i - nk) * 4 + j] ^ temp[j];
        }
        
        i++;
    }
    
    // organize round keys into separate arrays
    for (int round = 0; round <= nr; round++) {
        for (int j = 0; j < 16; j++) {
            ctx->round_keys[round][j] = expanded_key[round * 16 + j];
        }
    }
}

// block encryption
void aes_encrypt_block(const uint8_t* plaintext, uint8_t* ciphertext, const aes_core_context_t* ctx) {
    uint8_t state[16];
    
    // copy plaintext to state
    memcpy(state, plaintext, 16);
    
    // initial round key addition
    add_round_key(state, ctx->round_keys[0]);
    
    // main rounds
    for (int round = 1; round < ctx->num_rounds; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, ctx->round_keys[round]);
    }
    
    // final round (no mix columns)
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, ctx->round_keys[ctx->num_rounds]);
    
    // copy state to ciphertext
    memcpy(ciphertext, state, 16);
}

// block decryption
void aes_decrypt_block(const uint8_t* ciphertext, uint8_t* plaintext, const aes_core_context_t* ctx) {
    uint8_t state[16];
    
    // copy ciphertext to state
    memcpy(state, ciphertext, 16);
    
    // initial round key addition
    add_round_key(state, ctx->round_keys[ctx->num_rounds]);
    
    // main rounds (in reverse)
    for (int round = ctx->num_rounds - 1; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, ctx->round_keys[round]);
        inv_mix_columns(state);
    }
    
    // final round (no inv mix columns)
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, ctx->round_keys[0]);
    
    // copy state to plaintext
    memcpy(plaintext, state, 16);
} 