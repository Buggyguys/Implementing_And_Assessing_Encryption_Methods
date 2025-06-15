#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "implementation.h"
#include "camellia_common.h"

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

// s-box from RFC 3713
static const uint8_t camellia_sbox1[256] = {
    112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
     35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
    134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
    166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
    139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
    223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
     20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
    254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
    170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
     16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
    135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
     82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
    233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
    120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
    114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
     64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158
};

// sigma constants from RFC 3713
static const uint64_t sigma[6] = {
    0xA09E667F3BCC908BULL,
    0xB67AE8584CAA73B2ULL,
    0xC6EF372FE94F82BEULL,
    0x54FF53A5F1D36F1CULL,
    0x10E527FADE682D1DULL,
    0xB05688C2B3E6C1FDULL
};

// bit operation macros
#define MASK8   0xFFULL
#define MASK32  0xFFFFFFFFULL
#define MASK64  0xFFFFFFFFFFFFFFFFULL
#define MASK128 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFULL

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROL64(x, n) (((x) << ((n) % 64)) | ((x) >> (64 - ((n) % 64))))
#define ROL128(x, n) (((x) << (n)) | ((x) >> (128 - (n))))

// f-function according to RFC 3713
static uint64_t camellia_f_function(uint64_t input, uint64_t subkey) {
    uint64_t x = input ^ subkey;
    
    // extract 8 bytes
    uint8_t t[8];
    t[0] = (x >> 56) & MASK8;
    t[1] = (x >> 48) & MASK8;
    t[2] = (x >> 40) & MASK8;
    t[3] = (x >> 32) & MASK8;
    t[4] = (x >> 24) & MASK8;
    t[5] = (x >> 16) & MASK8;
    t[6] = (x >> 8) & MASK8;
    t[7] = x & MASK8;
    
    // s-box substitution (sbox2, sbox3, sbox4 are rotated versions of sbox1)
    uint8_t s[8];
    s[0] = camellia_sbox1[t[0]];
    s[1] = ROL32(camellia_sbox1[t[1]], 1) & MASK8;
    s[2] = ROL32(camellia_sbox1[t[2]], 7) & MASK8;
    s[3] = camellia_sbox1[ROL32(t[3], 1) & MASK8];
    s[4] = ROL32(camellia_sbox1[t[4]], 1) & MASK8;
    s[5] = ROL32(camellia_sbox1[t[5]], 7) & MASK8;
    s[6] = camellia_sbox1[ROL32(t[6], 1) & MASK8];
    s[7] = camellia_sbox1[t[7]];
    
    // p-function (linear transformation)
    uint8_t y[8];
    y[0] = s[0] ^ s[2] ^ s[3] ^ s[5] ^ s[6] ^ s[7];
    y[1] = s[0] ^ s[1] ^ s[3] ^ s[4] ^ s[6] ^ s[7];
    y[2] = s[0] ^ s[1] ^ s[2] ^ s[4] ^ s[5] ^ s[7];
    y[3] = s[1] ^ s[2] ^ s[3] ^ s[4] ^ s[5] ^ s[6];
    y[4] = s[0] ^ s[1] ^ s[5] ^ s[6] ^ s[7];
    y[5] = s[1] ^ s[2] ^ s[4] ^ s[6] ^ s[7];
    y[6] = s[2] ^ s[3] ^ s[4] ^ s[5] ^ s[7];
    y[7] = s[0] ^ s[3] ^ s[4] ^ s[5] ^ s[6];
    
    // combine result
    return ((uint64_t)y[0] << 56) | ((uint64_t)y[1] << 48) | 
           ((uint64_t)y[2] << 40) | ((uint64_t)y[3] << 32) |
           ((uint64_t)y[4] << 24) | ((uint64_t)y[5] << 16) |
           ((uint64_t)y[6] << 8)  | (uint64_t)y[7];
}

// fl function according to RFC 3713
static uint64_t camellia_fl_function(uint64_t input, uint64_t subkey) {
    uint32_t x1 = (input >> 32) & MASK32;
    uint32_t x2 = input & MASK32;
    uint32_t k1 = (subkey >> 32) & MASK32;
    uint32_t k2 = subkey & MASK32;
    
    x2 = x2 ^ ROL32((x1 & k1), 1);
    x1 = x1 ^ (x2 | k2);
    
    return ((uint64_t)x1 << 32) | x2;
}

// flinv function (inverse of fl) according to RFC 3713
static uint64_t camellia_flinv_function(uint64_t input, uint64_t subkey) {
    uint32_t y1 = (input >> 32) & MASK32;
    uint32_t y2 = input & MASK32;
    uint32_t k1 = (subkey >> 32) & MASK32;
    uint32_t k2 = subkey & MASK32;
    
    y1 = y1 ^ (y2 | k2);
    y2 = y2 ^ ROL32((y1 & k1), 1);
    
    return ((uint64_t)y1 << 32) | y2;
}

// key schedule for 128-bit keys according to RFC 3713
void camellia_key_schedule_128(const uint8_t* key, uint64_t subkeys[26]) {
    // convert key to 128-bit values
    uint64_t KL_high = 0, KL_low = 0;
    for (int i = 0; i < 8; i++) {
        KL_high = (KL_high << 8) | key[i];
        KL_low = (KL_low << 8) | key[i + 8];
    }
    
    // kr = 0 for 128-bit keys
    uint64_t KR_high = 0, KR_low = 0;
    
    // generate ka according to RFC 3713
    uint64_t D1 = KL_high ^ KR_high;
    uint64_t D2 = KL_low ^ KR_low;
    
    D2 = D2 ^ camellia_f_function(D1, sigma[0]);
    D1 = D1 ^ camellia_f_function(D2, sigma[1]);
    D1 = D1 ^ KL_high;
    D2 = D2 ^ KL_low;
    D2 = D2 ^ camellia_f_function(D1, sigma[2]);
    D1 = D1 ^ camellia_f_function(D2, sigma[3]);
    
    uint64_t KA_high = D1;
    uint64_t KA_low = D2;
    
    // generate subkeys according to RFC 3713 table for 128-bit keys
    // prewhitening keys
    subkeys[0] = KL_high;                    // kw1
    subkeys[1] = KL_low;                     // kw2
    
    // round keys k1-k18
    subkeys[2] = KA_high;                    // k1
    subkeys[3] = KA_low;                     // k2
    subkeys[4] = ROL64(KL_high, 15);         // k3
    subkeys[5] = ROL64(KL_low, 15);          // k4
    subkeys[6] = ROL64(KA_high, 15);         // k5
    subkeys[7] = ROL64(KA_low, 15);          // k6
    subkeys[8] = ROL64(KA_high, 30);         // k7
    subkeys[9] = ROL64(KA_low, 30);          // k8
    subkeys[10] = ROL64(KL_high, 45);        // k9
    subkeys[11] = ROL64(KL_low, 45);         // k10
    subkeys[12] = ROL64(KA_high, 45);        // k11
    subkeys[13] = ROL64(KA_low, 45);         // k12
    subkeys[14] = ROL64(KL_high, 60);        // k13
    subkeys[15] = ROL64(KL_low, 60);         // k14
    subkeys[16] = ROL64(KA_high, 60);        // k15
    subkeys[17] = ROL64(KA_low, 60);         // k16
    subkeys[18] = ROL64(KL_high, 77);        // k17
    subkeys[19] = ROL64(KL_low, 77);         // k18
    
    // postwhitening keys
    subkeys[20] = ROL64(KA_high, 77);        // kw3
    subkeys[21] = ROL64(KA_low, 77);         // kw4
    
    // fl/flinv subkeys
    subkeys[22] = ROL64(KA_high, 30);        // ke1
    subkeys[23] = ROL64(KA_low, 30);         // ke2
    subkeys[24] = ROL64(KL_high, 77);        // ke3
    subkeys[25] = ROL64(KL_low, 77);         // ke4
}

// key schedule for 192-bit keys according to RFC 3713
void camellia_key_schedule_192(const uint8_t* key, uint64_t subkeys[34]) {
    // convert key to 192-bit values
    uint64_t KL_high = 0, KL_low = 0;
    uint64_t KR_high = 0, KR_low = 0;
    
    for (int i = 0; i < 8; i++) {
        KL_high = (KL_high << 8) | key[i];
        KL_low = (KL_low << 8) | key[i + 8];
    }
    for (int i = 0; i < 8; i++) {
        KR_high = (KR_high << 8) | key[i + 16];
        if (i < 8) KR_low = (KR_low << 8) | 0xFF;  // pad with 0xFF for 192-bit
    }
    
    // generate ka and kb according to RFC 3713
    uint64_t D1 = KL_high ^ KR_high;
    uint64_t D2 = KL_low ^ KR_low;
    
    D2 = D2 ^ camellia_f_function(D1, sigma[0]);
    D1 = D1 ^ camellia_f_function(D2, sigma[1]);
    D1 = D1 ^ KL_high;
    D2 = D2 ^ KL_low;
    D2 = D2 ^ camellia_f_function(D1, sigma[2]);
    D1 = D1 ^ camellia_f_function(D2, sigma[3]);
    
    uint64_t KA_high = D1;
    uint64_t KA_low = D2;
    
    // generate kb
    D1 = KA_high ^ KR_high;
    D2 = KA_low ^ KR_low;
    D2 = D2 ^ camellia_f_function(D1, sigma[4]);
    D1 = D1 ^ camellia_f_function(D2, sigma[5]);
    
    uint64_t KB_high = D1;
    uint64_t KB_low = D2;
    
    // generate subkeys for 192-bit (24 rounds) - proper RFC 3713 implementation
    subkeys[0] = KL_high;                    // kw1
    subkeys[1] = KL_low;                     // kw2
    subkeys[2] = KB_high;                    // k1
    subkeys[3] = KB_low;                     // k2
    subkeys[4] = ROL64(KR_high, 15);         // k3
    subkeys[5] = ROL64(KR_low, 15);          // k4
    subkeys[6] = ROL64(KA_high, 15);         // k5
    subkeys[7] = ROL64(KA_low, 15);          // k6
    subkeys[8] = ROL64(KR_high, 30);         // k7
    subkeys[9] = ROL64(KR_low, 30);          // k8
    subkeys[10] = ROL64(KB_high, 30);        // k9
    subkeys[11] = ROL64(KB_low, 30);         // k10
    subkeys[12] = ROL64(KL_high, 45);        // k11
    subkeys[13] = ROL64(KL_low, 45);         // k12
    subkeys[14] = ROL64(KA_high, 45);        // k13
    subkeys[15] = ROL64(KA_low, 45);         // k14
    subkeys[16] = ROL64(KR_high, 60);        // k15
    subkeys[17] = ROL64(KR_low, 60);         // k16
    subkeys[18] = ROL64(KB_high, 60);        // k17
    subkeys[19] = ROL64(KB_low, 60);         // k18
    subkeys[20] = ROL64(KL_high, 77);        // k19
    subkeys[21] = ROL64(KL_low, 77);         // k20
    subkeys[22] = ROL64(KA_high, 77);        // k21
    subkeys[23] = ROL64(KA_low, 77);         // k22
    subkeys[24] = ROL64(KR_high, 94);        // k23
    subkeys[25] = ROL64(KR_low, 94);         // k24
    
    // postwhitening keys
    subkeys[26] = ROL64(KB_high, 111);       // kw3
    subkeys[27] = ROL64(KB_low, 111);        // kw4
    
    // fl/flinv subkeys
    subkeys[28] = ROL64(KA_high, 30);        // ke1
    subkeys[29] = ROL64(KA_low, 30);         // ke2
    subkeys[30] = ROL64(KL_high, 60);        // ke3
    subkeys[31] = ROL64(KL_low, 60);         // ke4
    subkeys[32] = ROL64(KB_high, 77);        // ke5
    subkeys[33] = ROL64(KB_low, 77);         // ke6
}

// key schedule for 256-bit keys according to RFC 3713
void camellia_key_schedule_256(const uint8_t* key, uint64_t subkeys[34]) {
    // convert key to 256-bit values
    uint64_t KL_high = 0, KL_low = 0;
    uint64_t KR_high = 0, KR_low = 0;
    
    for (int i = 0; i < 8; i++) {
        KL_high = (KL_high << 8) | key[i];
        KL_low = (KL_low << 8) | key[i + 8];
        KR_high = (KR_high << 8) | key[i + 16];
        KR_low = (KR_low << 8) | key[i + 24];
    }
    
    // generate ka and kb according to RFC 3713
    uint64_t D1 = KL_high ^ KR_high;
    uint64_t D2 = KL_low ^ KR_low;
    
    D2 = D2 ^ camellia_f_function(D1, sigma[0]);
    D1 = D1 ^ camellia_f_function(D2, sigma[1]);
    D1 = D1 ^ KL_high;
    D2 = D2 ^ KL_low;
    D2 = D2 ^ camellia_f_function(D1, sigma[2]);
    D1 = D1 ^ camellia_f_function(D2, sigma[3]);
    
    uint64_t KA_high = D1;
    uint64_t KA_low = D2;
    
    // generate kb
    D1 = KA_high ^ KR_high;
    D2 = KA_low ^ KR_low;
    D2 = D2 ^ camellia_f_function(D1, sigma[4]);
    D1 = D1 ^ camellia_f_function(D2, sigma[5]);
    
    uint64_t KB_high = D1;
    uint64_t KB_low = D2;
    
    // generate subkeys for 256-bit (24 rounds) - proper implementation
    subkeys[0] = KL_high;                    // kw1
    subkeys[1] = KL_low;                     // kw2
    subkeys[2] = KB_high;                    // k1
    subkeys[3] = KB_low;                     // k2
    subkeys[4] = ROL64(KR_high, 15);         // k3
    subkeys[5] = ROL64(KR_low, 15);          // k4
    subkeys[6] = ROL64(KA_high, 15);         // k5
    subkeys[7] = ROL64(KA_low, 15);          // k6
    subkeys[8] = ROL64(KR_high, 30);         // k7
    subkeys[9] = ROL64(KR_low, 30);          // k8
    subkeys[10] = ROL64(KB_high, 30);        // k9
    subkeys[11] = ROL64(KB_low, 30);         // k10
    subkeys[12] = ROL64(KL_high, 45);        // k11
    subkeys[13] = ROL64(KL_low, 45);         // k12
    subkeys[14] = ROL64(KA_high, 45);        // k13
    subkeys[15] = ROL64(KA_low, 45);         // k14
    subkeys[16] = ROL64(KR_high, 60);        // k15
    subkeys[17] = ROL64(KR_low, 60);         // k16
    subkeys[18] = ROL64(KB_high, 60);        // k17
    subkeys[19] = ROL64(KB_low, 60);         // k18
    subkeys[20] = ROL64(KL_high, 77);        // k19
    subkeys[21] = ROL64(KL_low, 77);         // k20
    subkeys[22] = ROL64(KA_high, 77);        // k21
    subkeys[23] = ROL64(KA_low, 77);         // k22
    subkeys[24] = ROL64(KR_high, 94);        // k23
    subkeys[25] = ROL64(KR_low, 94);         // k24
    
    // postwhitening keys
    subkeys[26] = ROL64(KB_high, 111);       // kw3
    subkeys[27] = ROL64(KB_low, 111);        // kw4
    
    // fl/flinv subkeys
    subkeys[28] = ROL64(KA_high, 30);        // ke1
    subkeys[29] = ROL64(KA_low, 30);         // ke2
    subkeys[30] = ROL64(KL_high, 60);        // ke3
    subkeys[31] = ROL64(KL_low, 60);         // ke4
    subkeys[32] = ROL64(KB_high, 77);        // ke5
    subkeys[33] = ROL64(KB_low, 77);         // ke6
}

// encryption (128-bit keys, 18 rounds)
void camellia_encrypt_128(const uint8_t* input, uint8_t* output, const uint64_t subkeys[26]) {
    // Convert input to 64-bit halves
    uint64_t D1 = 0, D2 = 0;
    for (int i = 0; i < 8; i++) {
        D1 = (D1 << 8) | input[i];
        D2 = (D2 << 8) | input[i + 8];
    }
    
    // prewhitening
    D1 = D1 ^ subkeys[0];  // kw1
    D2 = D2 ^ subkeys[1];  // kw2
    
    // 18 rounds with FL/FLINV every 6 rounds
    for (int round = 0; round < 18; round++) {
        if (round == 6) {
            // FL and FLINV after round 6
            D1 = camellia_fl_function(D1, subkeys[22]);     // ke1
            D2 = camellia_flinv_function(D2, subkeys[23]);  // ke2
        } else if (round == 12) {
            // FL and FLINV after round 12
            D1 = camellia_fl_function(D1, subkeys[24]);     // ke3
            D2 = camellia_flinv_function(D2, subkeys[25]);  // ke4
        }
        
        // Feistel round
        if (round % 2 == 0) {
            D2 = D2 ^ camellia_f_function(D1, subkeys[2 + round]);
        } else {
            D1 = D1 ^ camellia_f_function(D2, subkeys[2 + round]);
        }
    }
    
    // postwhitening (swap and XOR)
    D2 = D2 ^ subkeys[20];  // kw3 (approximation)
    D1 = D1 ^ subkeys[21];  // kw4 (approximation)
    
    // convert to bytes (swap D1 and D2)
    for (int i = 0; i < 8; i++) {
        output[i] = (D2 >> (56 - i * 8)) & 0xFF;
        output[i + 8] = (D1 >> (56 - i * 8)) & 0xFF;
    }
}

// decryption
void camellia_decrypt_128(const uint8_t* input, uint8_t* output, const uint64_t subkeys[26]) {
    // convert input to 64-bit halves
    uint64_t D2 = 0, D1 = 0;  // swapped for decryption
    for (int i = 0; i < 8; i++) {
        D2 = (D2 << 8) | input[i];
        D1 = (D1 << 8) | input[i + 8];
    }
    
    // reverse postwhitening
    D2 = D2 ^ subkeys[20];  // kw3
    D1 = D1 ^ subkeys[21];  // kw4
    
    // 18 rounds in reverse
    for (int round = 17; round >= 0; round--) {
        // reverse feistel round
        if (round % 2 == 0) {
            D2 = D2 ^ camellia_f_function(D1, subkeys[2 + round]);
        } else {
            D1 = D1 ^ camellia_f_function(D2, subkeys[2 + round]);
        }
        
        if (round == 12) {
            // reverse FL and FLINV after round 12
            D1 = camellia_flinv_function(D1, subkeys[24]);   // ke3
            D2 = camellia_fl_function(D2, subkeys[25]);      // ke4
        } else if (round == 6) {
            // reverse FL and FLINV after round 6
            D1 = camellia_flinv_function(D1, subkeys[22]);   // ke1
            D2 = camellia_fl_function(D2, subkeys[23]);      // ke2
        }
    }
    
    // reverse prewhitening
    D1 = D1 ^ subkeys[0];  // kw1
    D2 = D2 ^ subkeys[1];  // kw2
    
    // convert to bytes
    for (int i = 0; i < 8; i++) {
        output[i] = (D1 >> (56 - i * 8)) & 0xFF;
        output[i + 8] = (D2 >> (56 - i * 8)) & 0xFF;
    }
}

// encryption (192/256-bit keys, 24 rounds)
void camellia_encrypt_192_256(const uint8_t* input, uint8_t* output, const uint64_t subkeys[34]) {
    // convert input to 64-bit halves
    uint64_t D1 = 0, D2 = 0;
    for (int i = 0; i < 8; i++) {
        D1 = (D1 << 8) | input[i];
        D2 = (D2 << 8) | input[i + 8];
    }
    
    // prewhitening
    D1 = D1 ^ subkeys[0];  // kw1
    D2 = D2 ^ subkeys[1];  // kw2
    
    // 24 rounds with FL/FLINV every 6 rounds
    for (int round = 0; round < 24; round++) {
        if (round == 6) {
            // FL and FLINV after round 6
            D1 = camellia_fl_function(D1, subkeys[28]);     // ke1
            D2 = camellia_flinv_function(D2, subkeys[29]);  // ke2
        } else if (round == 12) {
            // FL and FLINV after round 12
            D1 = camellia_fl_function(D1, subkeys[30]);     // ke3
            D2 = camellia_flinv_function(D2, subkeys[31]);  // ke4
        } else if (round == 18) {
            // FL and FLINV after round 18
            D1 = camellia_fl_function(D1, subkeys[32]);     // ke5
            D2 = camellia_flinv_function(D2, subkeys[33]);  // ke6
        }
        
        // Feistel round
        if (round % 2 == 0) {
            D2 = D2 ^ camellia_f_function(D1, subkeys[2 + round]);
        } else {
            D1 = D1 ^ camellia_f_function(D2, subkeys[2 + round]);
        }
    }
    
    // postwhitening 
    D2 = D2 ^ subkeys[26];  // kw3
    D1 = D1 ^ subkeys[27];  // kw4
    
    // convert to bytes (swap D1 and D2)
    for (int i = 0; i < 8; i++) {
        output[i] = (D2 >> (56 - i * 8)) & 0xFF;
        output[i + 8] = (D1 >> (56 - i * 8)) & 0xFF;
    }
}

// decryption (192/256-bit keys, 24 rounds)
void camellia_decrypt_192_256(const uint8_t* input, uint8_t* output, const uint64_t subkeys[34]) {
    // convert input to 64-bit halves
    uint64_t D2 = 0, D1 = 0;  // swapped for decryption
    for (int i = 0; i < 8; i++) {
        D2 = (D2 << 8) | input[i];
        D1 = (D1 << 8) | input[i + 8];
    }
    
    // reverse postwhitening
    D2 = D2 ^ subkeys[26];  // kw3
    D1 = D1 ^ subkeys[27];  // kw4
    
    // 24 rounds in reverse
    for (int round = 23; round >= 0; round--) {
        // reverse Feistel round
        if (round % 2 == 0) {
            D2 = D2 ^ camellia_f_function(D1, subkeys[2 + round]);
        } else {
            D1 = D1 ^ camellia_f_function(D2, subkeys[2 + round]);
        }
        
        if (round == 18) {
            // reverse FL and FLINV after round 18
            D1 = camellia_flinv_function(D1, subkeys[32]);   // ke5
            D2 = camellia_fl_function(D2, subkeys[33]);      // ke6
        } else if (round == 12) {
            // reverse FL and FLINV after round 12
            D1 = camellia_flinv_function(D1, subkeys[30]);   // ke3
            D2 = camellia_fl_function(D2, subkeys[31]);      // ke4
        } else if (round == 6) {
            // reverse FL and FLINV after round 6
            D1 = camellia_flinv_function(D1, subkeys[28]);   // ke1
            D2 = camellia_fl_function(D2, subkeys[29]);      // ke2
        }
    }
    
    // reverse prewhitening
    D1 = D1 ^ subkeys[0];  // kw1
    D2 = D2 ^ subkeys[1];  // kw2
    
    // convert to bytes
    for (int i = 0; i < 8; i++) {
        output[i] = (D1 >> (56 - i * 8)) & 0xFF;
        output[i + 8] = (D2 >> (56 - i * 8)) & 0xFF;
    }
}

// standard implementation using OpenSSL
void* camellia_init(void) {
    camellia_context_t* context = (camellia_context_t*)malloc(sizeof(camellia_context_t));
    if (!context) return NULL;
    
    memset(context, 0, sizeof(camellia_context_t));
    
    // read configuration from environment variables
    char* key_size_str = getenv("CAMELLIA_KEY_SIZE");
    char* mode_str = getenv("CAMELLIA_MODE");
    
    // set key size from environment or default to 256
    context->key_size = key_size_str ? atoi(key_size_str) : 256;
    
    // validate key size
    if (context->key_size != 128 && context->key_size != 192 && context->key_size != 256) {
        fprintf(stderr, "Warning: Invalid Camellia key size %d, defaulting to 256\n", context->key_size);
        context->key_size = 256;
    }
    
    // set mode from environment or default to CBC
    if (mode_str) {
        strncpy(context->mode, mode_str, sizeof(context->mode) - 1);
    } else {
        strcpy(context->mode, "CBC");
    }
    
    // validate mode
    if (strcmp(context->mode, "ECB") != 0 && strcmp(context->mode, "CBC") != 0 && 
        strcmp(context->mode, "CFB") != 0 && strcmp(context->mode, "OFB") != 0) {
        fprintf(stderr, "Warning: Invalid Camellia mode %s, defaulting to CBC\n", context->mode);
        strcpy(context->mode, "CBC");
    }
    
    context->is_custom = 0;
    
    // generate IV for modes that need it
    if (strcmp(context->mode, "ECB") != 0) {
        context->iv_length = 16; // block size
        context->iv = (unsigned char*)malloc(context->iv_length);
        if (context->iv) {
            // generate random IV
            FILE* urandom = fopen("/dev/urandom", "rb");
            if (urandom) {
                fread(context->iv, 1, context->iv_length, urandom);
                fclose(urandom);
            } else {
                for (int i = 0; i < context->iv_length; i++) {
                    context->iv[i] = rand() & 0xFF;
                }
            }
        }
    }
    
    return context;
}

void camellia_cleanup(void* context) {
    if (!context) return;
    
    camellia_context_t* ctx = (camellia_context_t*)context;
    if (ctx->key) {
        memset(ctx->key, 0, ctx->key_length);
        free(ctx->key);
    }
    if (ctx->iv) {
        memset(ctx->iv, 0, ctx->iv_length);
        free(ctx->iv);
    }
    
    memset(ctx, 0, sizeof(camellia_context_t));
    free(ctx);
}

unsigned char* camellia_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length) {
    if (!context || !data || !key || data_length == 0) return NULL;
    
    camellia_context_t* ctx = (camellia_context_t*)context;
    
#ifdef USE_OPENSSL
    // standard implementation using OpenSSL
    EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
    if (!evp_ctx) return NULL;
    
    const EVP_CIPHER* cipher = NULL;
    if (ctx->key_size == 128) {
        if (strcmp(ctx->mode, "CBC") == 0) cipher = EVP_camellia_128_cbc();
        else if (strcmp(ctx->mode, "CFB") == 0) cipher = EVP_camellia_128_cfb();
        else if (strcmp(ctx->mode, "OFB") == 0) cipher = EVP_camellia_128_ofb();
        else if (strcmp(ctx->mode, "ECB") == 0) cipher = EVP_camellia_128_ecb();
    } else if (ctx->key_size == 192) {
        if (strcmp(ctx->mode, "CBC") == 0) cipher = EVP_camellia_192_cbc();
        else if (strcmp(ctx->mode, "CFB") == 0) cipher = EVP_camellia_192_cfb();
        else if (strcmp(ctx->mode, "OFB") == 0) cipher = EVP_camellia_192_ofb();
        else if (strcmp(ctx->mode, "ECB") == 0) cipher = EVP_camellia_192_ecb();
    } else {
        if (strcmp(ctx->mode, "CBC") == 0) cipher = EVP_camellia_256_cbc();
        else if (strcmp(ctx->mode, "CFB") == 0) cipher = EVP_camellia_256_cfb();
        else if (strcmp(ctx->mode, "OFB") == 0) cipher = EVP_camellia_256_ofb();
        else if (strcmp(ctx->mode, "ECB") == 0) cipher = EVP_camellia_256_ecb();
    }
    
    if (!cipher) {
        EVP_CIPHER_CTX_free(evp_ctx);
        return NULL;
    }
    
    if (EVP_EncryptInit_ex(evp_ctx, cipher, NULL, key, ctx->iv) != 1) {
        EVP_CIPHER_CTX_free(evp_ctx);
        return NULL;
    }
    
    size_t max_output_len = data_length + CAMELLIA_BLOCK_SIZE + ctx->iv_length;
    unsigned char* output = (unsigned char*)malloc(max_output_len);
    if (!output) {
        EVP_CIPHER_CTX_free(evp_ctx);
        return NULL;
    }
    
    size_t current_pos = 0;
    
    // Prepend IV for non-ECB modes
    if (strcmp(ctx->mode, "ECB") != 0 && ctx->iv) {
        memcpy(output, ctx->iv, ctx->iv_length);
        current_pos = ctx->iv_length;
    }
    
    int len;
    if (EVP_EncryptUpdate(evp_ctx, output + current_pos, &len, data, (int)data_length) != 1) {
        free(output);
        EVP_CIPHER_CTX_free(evp_ctx);
            return NULL;
        }
    current_pos += len;
    
    if (EVP_EncryptFinal_ex(evp_ctx, output + current_pos, &len) != 1) {
        free(output);
        EVP_CIPHER_CTX_free(evp_ctx);
        return NULL;
    }
    current_pos += len;
    
    EVP_CIPHER_CTX_free(evp_ctx);
    *output_length = current_pos;
    return output;
#else
        return NULL;
#endif
}

unsigned char* camellia_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length) {
    if (!context || !data || !key || data_length == 0) return NULL;
    
    camellia_context_t* ctx = (camellia_context_t*)context;
    
        #ifdef USE_OPENSSL
    // standard implementation using OpenSSL
    EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
    if (!evp_ctx) return NULL;
    
    const EVP_CIPHER* cipher = NULL;
    if (ctx->key_size == 128) {
        if (strcmp(ctx->mode, "CBC") == 0) cipher = EVP_camellia_128_cbc();
        else if (strcmp(ctx->mode, "CFB") == 0) cipher = EVP_camellia_128_cfb();
        else if (strcmp(ctx->mode, "OFB") == 0) cipher = EVP_camellia_128_ofb();
        else if (strcmp(ctx->mode, "ECB") == 0) cipher = EVP_camellia_128_ecb();
    } else if (ctx->key_size == 192) {
        if (strcmp(ctx->mode, "CBC") == 0) cipher = EVP_camellia_192_cbc();
        else if (strcmp(ctx->mode, "CFB") == 0) cipher = EVP_camellia_192_cfb();
        else if (strcmp(ctx->mode, "OFB") == 0) cipher = EVP_camellia_192_ofb();
        else if (strcmp(ctx->mode, "ECB") == 0) cipher = EVP_camellia_192_ecb();
    } else {
        if (strcmp(ctx->mode, "CBC") == 0) cipher = EVP_camellia_256_cbc();
        else if (strcmp(ctx->mode, "CFB") == 0) cipher = EVP_camellia_256_cfb();
        else if (strcmp(ctx->mode, "OFB") == 0) cipher = EVP_camellia_256_ofb();
        else if (strcmp(ctx->mode, "ECB") == 0) cipher = EVP_camellia_256_ecb();
    }
    
    if (!cipher) {
        EVP_CIPHER_CTX_free(evp_ctx);
        return NULL;
    }
    
    size_t iv_offset = 0;
    unsigned char* iv_ptr = NULL;
    
    // handle IV 
    if (strcmp(ctx->mode, "ECB") != 0) {
        iv_offset = 16; // Camellia block size
        if (data_length < iv_offset) {
            EVP_CIPHER_CTX_free(evp_ctx);
            return NULL;
        }
        iv_ptr = (unsigned char*)data; 
    }
    
    if (EVP_DecryptInit_ex(evp_ctx, cipher, NULL, key, iv_ptr) != 1) {
        EVP_CIPHER_CTX_free(evp_ctx);
        return NULL;
    }
    
    size_t ciphertext_len = data_length - iv_offset;
    unsigned char* output = (unsigned char*)malloc(ciphertext_len);
    if (!output) {
        EVP_CIPHER_CTX_free(evp_ctx);
            return NULL;
        }
        
    int len;
    if (EVP_DecryptUpdate(evp_ctx, output, &len, data + iv_offset, (int)ciphertext_len) != 1) {
        free(output);
        EVP_CIPHER_CTX_free(evp_ctx);
        return NULL;
    }
    
    int final_len;
    if (EVP_DecryptFinal_ex(evp_ctx, output + len, &final_len) != 1) {
        free(output);
        EVP_CIPHER_CTX_free(evp_ctx);
        return NULL;
    }
    
    EVP_CIPHER_CTX_free(evp_ctx);
    *output_length = len + final_len;
    return output;
        #else
        return NULL;
#endif
}

// custom implementation context
void* camellia_custom_init(void) {
    camellia_context_t* context = (camellia_context_t*)malloc(sizeof(camellia_context_t));
    if (!context) return NULL;
    
    memset(context, 0, sizeof(camellia_context_t));
    
    // read configuration from environment variables
    char* key_size_str = getenv("CAMELLIA_KEY_SIZE");
    char* mode_str = getenv("CAMELLIA_MODE");
    
    // set key size from environment or default to 256
    context->key_size = key_size_str ? atoi(key_size_str) : 256;
    
    // validate key size
    if (context->key_size != 128 && context->key_size != 192 && context->key_size != 256) {
        fprintf(stderr, "Warning: Invalid Camellia key size %d, defaulting to 256\n", context->key_size);
        context->key_size = 256;
    }
    
    // set mode from environment or default to CBC
    if (mode_str) {
        strncpy(context->mode, mode_str, sizeof(context->mode) - 1);
    } else {
        strcpy(context->mode, "CBC");
    }
    
    // validate mode
    if (strcmp(context->mode, "ECB") != 0 && strcmp(context->mode, "CBC") != 0 && 
        strcmp(context->mode, "CFB") != 0 && strcmp(context->mode, "OFB") != 0) {
        fprintf(stderr, "Warning: Invalid Camellia mode %s, defaulting to CBC\n", context->mode);
        strcpy(context->mode, "CBC");
    }
    
    context->is_custom = 1;
    
    // generate IV for modes that need it
    if (strcmp(context->mode, "ECB") != 0) {
        context->iv_length = 16; // Camellia block size
        context->iv = (unsigned char*)malloc(context->iv_length);
        if (context->iv) {
            // generate random IV
            FILE* urandom = fopen("/dev/urandom", "rb");
            if (urandom) {
                fread(context->iv, 1, context->iv_length, urandom);
                fclose(urandom);
            } else {
                for (int i = 0; i < context->iv_length; i++) {
                    context->iv[i] = rand() & 0xFF;
                }
            }
        }
    }
    
    return context;
}

void camellia_custom_cleanup(void* context) {
    camellia_cleanup(context);
}

// forward declarations for mode-specific functions
// 128-bit key functions (26 subkeys)
static unsigned char* camellia_custom_encrypt_ecb_128(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[26], size_t* output_length);
static unsigned char* camellia_custom_decrypt_ecb_128(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[26], size_t* output_length);
static unsigned char* camellia_custom_encrypt_cbc_128(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[26], size_t* output_length);
static unsigned char* camellia_custom_decrypt_cbc_128(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[26], size_t* output_length);
static unsigned char* camellia_custom_encrypt_cfb_128(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[26], size_t* output_length);
static unsigned char* camellia_custom_decrypt_cfb_128(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[26], size_t* output_length);
static unsigned char* camellia_custom_encrypt_ofb_128(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[26], size_t* output_length);
static unsigned char* camellia_custom_decrypt_ofb_128(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[26], size_t* output_length);

// 192/256-bit key functions (34 subkeys)
static unsigned char* camellia_custom_encrypt_ecb_192_256(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[34], size_t* output_length);
static unsigned char* camellia_custom_decrypt_ecb_192_256(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[34], size_t* output_length);
static unsigned char* camellia_custom_encrypt_cbc_192_256(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[34], size_t* output_length);
static unsigned char* camellia_custom_decrypt_cbc_192_256(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[34], size_t* output_length);
static unsigned char* camellia_custom_encrypt_cfb_192_256(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[34], size_t* output_length);
static unsigned char* camellia_custom_decrypt_cfb_192_256(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[34], size_t* output_length);
static unsigned char* camellia_custom_encrypt_ofb_192_256(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[34], size_t* output_length);
static unsigned char* camellia_custom_decrypt_ofb_192_256(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[34], size_t* output_length);

// cryptographically secure random number generation
static int secure_random_bytes(unsigned char* buffer, size_t length) {
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        size_t bytes_read = fread(buffer, 1, length, urandom);
        fclose(urandom);
        
        if (bytes_read == length) {
            return 1; // Success
        }
    }
    
    // fallback to enhanced entropy if /dev/urandom fails
    fprintf(stderr, "Warning: Using fallback random generation (not cryptographically secure)\n");
    for (size_t i = 0; i < length; i++) {
        buffer[i] = (rand() ^ (i * 17) ^ (rand() >> 8)) & 0xFF;
    }
    
    return 0; 
}

unsigned char* camellia_custom_encrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length) {
    if (!context || !data || !key || data_length == 0) return NULL;
    
    camellia_context_t* ctx = (camellia_context_t*)context;
    
    // support key sizes: 128, 192, 256 bits
    if (ctx->key_size == 128) {
        // generate subkeys for 128-bit
        uint64_t subkeys[26];
        camellia_key_schedule_128(key, subkeys);
        
        // handle different modes
        if (strcmp(ctx->mode, "ECB") == 0) {
            return camellia_custom_encrypt_ecb_128(ctx, data, data_length, subkeys, output_length);
        } else if (strcmp(ctx->mode, "CBC") == 0) {
            return camellia_custom_encrypt_cbc_128(ctx, data, data_length, subkeys, output_length);
        } else if (strcmp(ctx->mode, "CFB") == 0) {
            return camellia_custom_encrypt_cfb_128(ctx, data, data_length, subkeys, output_length);
        } else if (strcmp(ctx->mode, "OFB") == 0) {
            return camellia_custom_encrypt_ofb_128(ctx, data, data_length, subkeys, output_length);
        } else {
            fprintf(stderr, "Custom Camellia: Unsupported mode %s\n", ctx->mode);
        return NULL;
    }
    } else if (ctx->key_size == 192 || ctx->key_size == 256) {
        // Generate subkeys for 192/256-bit
        uint64_t subkeys[34];
        if (ctx->key_size == 192) {
            camellia_key_schedule_192(key, subkeys);
        } else {
            camellia_key_schedule_256(key, subkeys);
        }
        
        // Handle different modes
        if (strcmp(ctx->mode, "ECB") == 0) {
            return camellia_custom_encrypt_ecb_192_256(ctx, data, data_length, subkeys, output_length);
        } else if (strcmp(ctx->mode, "CBC") == 0) {
            return camellia_custom_encrypt_cbc_192_256(ctx, data, data_length, subkeys, output_length);
        } else if (strcmp(ctx->mode, "CFB") == 0) {
            return camellia_custom_encrypt_cfb_192_256(ctx, data, data_length, subkeys, output_length);
        } else if (strcmp(ctx->mode, "OFB") == 0) {
            return camellia_custom_encrypt_ofb_192_256(ctx, data, data_length, subkeys, output_length);
    } else {
            fprintf(stderr, "Custom Camellia: Unsupported mode %s\n", ctx->mode);
            return NULL;
        }
    } else {
        fprintf(stderr, "Custom Camellia: Unsupported key size %d\n", ctx->key_size);
        return NULL;
    }
}

unsigned char* camellia_custom_decrypt(void* context, const unsigned char* data, size_t data_length, const unsigned char* key, size_t* output_length) {
    if (!context || !data || !key || data_length == 0) return NULL;
    
    camellia_context_t* ctx = (camellia_context_t*)context;
    
    // support key sizes: 128, 192, 256 bits
    if (ctx->key_size == 128) {
        // generate subkeys for 128-bit
        uint64_t subkeys[26];
        camellia_key_schedule_128(key, subkeys);
        
        // handle different modes
        if (strcmp(ctx->mode, "ECB") == 0) {
            return camellia_custom_decrypt_ecb_128(ctx, data, data_length, subkeys, output_length);
        } else if (strcmp(ctx->mode, "CBC") == 0) {
            return camellia_custom_decrypt_cbc_128(ctx, data, data_length, subkeys, output_length);
        } else if (strcmp(ctx->mode, "CFB") == 0) {
            return camellia_custom_decrypt_cfb_128(ctx, data, data_length, subkeys, output_length);
        } else if (strcmp(ctx->mode, "OFB") == 0) {
            return camellia_custom_decrypt_ofb_128(ctx, data, data_length, subkeys, output_length);
        } else {
            fprintf(stderr, "Custom Camellia: Unsupported mode %s\n", ctx->mode);
            return NULL;
        }
    } else if (ctx->key_size == 192 || ctx->key_size == 256) {
        // generate subkeys for 192/256-bit
        uint64_t subkeys[34];
        if (ctx->key_size == 192) {
            camellia_key_schedule_192(key, subkeys);
        } else {
            camellia_key_schedule_256(key, subkeys);
        }
        
        // handle different modes
        if (strcmp(ctx->mode, "ECB") == 0) {
            return camellia_custom_decrypt_ecb_192_256(ctx, data, data_length, subkeys, output_length);
        } else if (strcmp(ctx->mode, "CBC") == 0) {
            return camellia_custom_decrypt_cbc_192_256(ctx, data, data_length, subkeys, output_length);
        } else if (strcmp(ctx->mode, "CFB") == 0) {
            return camellia_custom_decrypt_cfb_192_256(ctx, data, data_length, subkeys, output_length);
        } else if (strcmp(ctx->mode, "OFB") == 0) {
            return camellia_custom_decrypt_ofb_192_256(ctx, data, data_length, subkeys, output_length);
        } else {
            fprintf(stderr, "Custom Camellia: Unsupported mode %s\n", ctx->mode);
            return NULL;
        }
    } else {
        fprintf(stderr, "Custom Camellia: Unsupported key size %d\n", ctx->key_size);
        return NULL;
    }
}

// ECB mode implementation
static unsigned char* camellia_custom_encrypt_ecb_128(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[26], size_t* output_length) {
    // calculate output size (padded to 16-byte blocks)
    size_t padded_length = ((data_length + 15) / 16) * 16;
    unsigned char* output = (unsigned char*)malloc(padded_length);
    if (!output) return NULL;
    
    // encrypt block by block
    for (size_t i = 0; i < data_length; i += 16) {
        uint8_t block[16];
        memset(block, 0, 16);
        
        size_t copy_len = (data_length - i < 16) ? data_length - i : 16;
        memcpy(block, data + i, copy_len);
        
        // PKCS#7 padding for last block
        if (copy_len < 16) {
            uint8_t pad_value = 16 - copy_len;
            for (size_t j = copy_len; j < 16; j++) {
                block[j] = pad_value;
            }
        }
        
        camellia_encrypt_128(block, output + i, subkeys);
    }
    
    *output_length = padded_length;
    return output;
}

static unsigned char* camellia_custom_decrypt_ecb_128(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[26], size_t* output_length) {
    if (data_length % 16 != 0) return NULL;
    
    unsigned char* output = (unsigned char*)malloc(data_length);
    if (!output) return NULL;
    
    // decrypt block by block
    for (size_t i = 0; i < data_length; i += 16) {
        camellia_decrypt_128(data + i, output + i, subkeys);
    }
    
    // remove PKCS#7 padding
    if (data_length > 0) {
        uint8_t pad_value = output[data_length - 1];
        if (pad_value <= 16) {
            *output_length = data_length - pad_value;
    } else {
            *output_length = data_length;
        }
    } else {
        *output_length = 0;
    }
    
    return output;
}

// CBC mode implementation
static unsigned char* camellia_custom_encrypt_cbc_128(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[26], size_t* output_length) {
    // generate IV if not present
    if (!ctx->iv) {
        ctx->iv_length = 16;
        ctx->iv = (unsigned char*)malloc(16);
        if (!ctx->iv) return NULL;
        
        // generate random IV
        secure_random_bytes(ctx->iv, 16);
    }
    
    // calculate output size (IV + padded data)
    size_t padded_length = ((data_length + 15) / 16) * 16;
    size_t total_length = 16 + padded_length;
    unsigned char* output = (unsigned char*)malloc(total_length);
    if (!output) return NULL;
    
    // copy IV to output
    memcpy(output, ctx->iv, 16);
    
    // previous block starts with IV
    uint8_t prev_block[16];
    memcpy(prev_block, ctx->iv, 16);
    
    // encrypt block by block
    for (size_t i = 0; i < data_length; i += 16) {
        uint8_t block[16];
        memset(block, 0, 16);
        
        size_t copy_len = (data_length - i < 16) ? data_length - i : 16;
        memcpy(block, data + i, copy_len);
        
        // PKCS#7 padding for last block
        if (copy_len < 16) {
            uint8_t pad_value = 16 - copy_len;
            for (size_t j = copy_len; j < 16; j++) {
                block[j] = pad_value;
            }
        }
        
        // XOR with previous block (CBC mode)
        for (int j = 0; j < 16; j++) {
            block[j] ^= prev_block[j];
        }
        
        // encrypt the XORed block
        camellia_encrypt_128(block, output + 16 + i, subkeys);
        
        // update previous block
        memcpy(prev_block, output + 16 + i, 16);
    }
    
    *output_length = total_length;
    return output;
}

static unsigned char* camellia_custom_decrypt_cbc_128(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[26], size_t* output_length) {
    if (data_length < 32 || (data_length - 16) % 16 != 0) return NULL;
    
    // extract IV
    uint8_t iv[16];
    memcpy(iv, data, 16);
    
    size_t ciphertext_length = data_length - 16;
    unsigned char* output = (unsigned char*)malloc(ciphertext_length);
    if (!output) return NULL;
    
    // previous block starts with IV
    uint8_t prev_block[16];
    memcpy(prev_block, iv, 16);
    
    // decrypt block by block
    for (size_t i = 0; i < ciphertext_length; i += 16) {
        uint8_t decrypted_block[16];
        
        // decrypt the block
        camellia_decrypt_128(data + 16 + i, decrypted_block, subkeys);
        
        // XOR with previous block (CBC mode)
        for (int j = 0; j < 16; j++) {
            output[i + j] = decrypted_block[j] ^ prev_block[j];
        }
        
        // update previous block
        memcpy(prev_block, data + 16 + i, 16);
    }
    
    // remove PKCS#7 padding
    if (ciphertext_length > 0) {
        uint8_t pad_value = output[ciphertext_length - 1];
        if (pad_value <= 16) {
            *output_length = ciphertext_length - pad_value;
        } else {
            *output_length = ciphertext_length;
        }
    } else {
        *output_length = 0;
    }
    
    return output;
}

// CFB mode implementation
static unsigned char* camellia_custom_encrypt_cfb_128(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[26], size_t* output_length) {
    // generate IV if not present
    if (!ctx->iv) {
        ctx->iv_length = 16;
        ctx->iv = (unsigned char*)malloc(16);
        if (!ctx->iv) return NULL;
        
        // generate random IV
        secure_random_bytes(ctx->iv, 16);
    }
    
    size_t total_length = 16 + data_length;
    unsigned char* output = (unsigned char*)malloc(total_length);
    if (!output) return NULL;
    
    // copy IV to output
    memcpy(output, ctx->iv, 16);
    
    // feedback register starts with IV
    uint8_t feedback[16];
    memcpy(feedback, ctx->iv, 16);
    
    // encrypt byte by byte (CFB mode)
    for (size_t i = 0; i < data_length; i++) {
        // encrypt feedback to create keystream
        uint8_t keystream[16];
        camellia_encrypt_128(feedback, keystream, subkeys);
        
        // XOR plaintext with keystream
        uint8_t ciphertext_byte = data[i] ^ keystream[0];
        output[16 + i] = ciphertext_byte;
        
        // shift feedback and add new ciphertext byte
        memmove(feedback, feedback + 1, 15);
        feedback[15] = ciphertext_byte;
    }
    
    *output_length = total_length;
    return output;
}

static unsigned char* camellia_custom_decrypt_cfb_128(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[26], size_t* output_length) {
    if (data_length < 16) return NULL;
    
    // extract IV
    uint8_t iv[16];
    memcpy(iv, data, 16);
    
    size_t ciphertext_length = data_length - 16;
    unsigned char* output = (unsigned char*)malloc(ciphertext_length);
    if (!output) return NULL;
    
    // feedback register starts with IV
    uint8_t feedback[16];
    memcpy(feedback, iv, 16);
    
    // decrypt byte by byte (CFB mode)
    for (size_t i = 0; i < ciphertext_length; i++) {
        // encrypt feedback to create keystream
        uint8_t keystream[16];
        camellia_encrypt_128(feedback, keystream, subkeys);
        
        // XOR ciphertext with keystream
        uint8_t ciphertext_byte = data[16 + i];
        output[i] = ciphertext_byte ^ keystream[0];
        
        // shift feedback and add ciphertext byte
        memmove(feedback, feedback + 1, 15);
        feedback[15] = ciphertext_byte;
    }
    
    *output_length = ciphertext_length;
    return output;
}

// OFB mode implementation
static unsigned char* camellia_custom_encrypt_ofb_128(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[26], size_t* output_length) {
    // generate IV if not present
    if (!ctx->iv) {
        ctx->iv_length = 16;
        ctx->iv = (unsigned char*)malloc(16);
        if (!ctx->iv) return NULL;
        
        // generate random IV
        secure_random_bytes(ctx->iv, 16);
    }
    
    size_t total_length = 16 + data_length;
    unsigned char* output = (unsigned char*)malloc(total_length);
    if (!output) return NULL;
    
    // copy IV to output
    memcpy(output, ctx->iv, 16);
    
    // feedback register starts with IV
    uint8_t feedback[16];
    memcpy(feedback, ctx->iv, 16);
    
    // encrypt byte by byte (OFB mode)
    for (size_t i = 0; i < data_length; i++) {
        // encrypt feedback to create keystream
        uint8_t keystream[16];
        camellia_encrypt_128(feedback, keystream, subkeys);
        
        // XOR plaintext with keystream
        output[16 + i] = data[i] ^ keystream[0];
        
        // update feedback with encrypted feedback 
        memmove(feedback, feedback + 1, 15);
        feedback[15] = keystream[0];
    }
    
    *output_length = total_length;
    return output;
}

static unsigned char* camellia_custom_decrypt_ofb_128(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[26], size_t* output_length) {
    if (data_length < 16) return NULL;
    
    // extract IV
    uint8_t iv[16];
    memcpy(iv, data, 16);
    
    size_t ciphertext_length = data_length - 16;
    unsigned char* output = (unsigned char*)malloc(ciphertext_length);
    if (!output) return NULL;
    
    // feedback register starts with IV
    uint8_t feedback[16];
    memcpy(feedback, iv, 16);
    
    // decrypt byte by byte (OFB mode - same as encryption)
    for (size_t i = 0; i < ciphertext_length; i++) {
        // encrypt feedback to create keystream
        uint8_t keystream[16];
        camellia_encrypt_128(feedback, keystream, subkeys);
        
        // XOR ciphertext with keystream
        output[i] = data[16 + i] ^ keystream[0];
        
        // update feedback with encrypted feedback 
        memmove(feedback, feedback + 1, 15);
        feedback[15] = keystream[0];
    }
    
    *output_length = ciphertext_length;
    return output;
}

// ECB mode implementation
static unsigned char* camellia_custom_encrypt_ecb_192_256(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[34], size_t* output_length) {
    // calculate output size (padded to 16-byte blocks)
    size_t padded_length = ((data_length + 15) / 16) * 16;
    unsigned char* output = (unsigned char*)malloc(padded_length);
    if (!output) return NULL;
    
    // Encrypt block by block
    for (size_t i = 0; i < data_length; i += 16) {
        uint8_t block[16];
        memset(block, 0, 16);
        
        size_t copy_len = (data_length - i < 16) ? data_length - i : 16;
        memcpy(block, data + i, copy_len);
        
        // PKCS#7 padding for last block
        if (copy_len < 16) {
            uint8_t pad_value = 16 - copy_len;
            for (size_t j = copy_len; j < 16; j++) {
                block[j] = pad_value;
            }
        }
        
        camellia_encrypt_192_256(block, output + i, subkeys);
    }
    
    *output_length = padded_length;
    return output;
}

static unsigned char* camellia_custom_decrypt_ecb_192_256(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[34], size_t* output_length) {
    if (data_length % 16 != 0) return NULL;
    
    unsigned char* output = (unsigned char*)malloc(data_length);
    if (!output) return NULL;
    
    // Decrypt block by block
    for (size_t i = 0; i < data_length; i += 16) {
        camellia_decrypt_192_256(data + i, output + i, subkeys);
    }
    
    // Remove PKCS#7 padding
    if (data_length > 0) {
        uint8_t pad_value = output[data_length - 1];
        if (pad_value <= 16) {
            *output_length = data_length - pad_value;
        } else {
            *output_length = data_length;
        }
    } else {
        *output_length = 0;
    }
    
    return output;
}

// CBC Mode Implementation
static unsigned char* camellia_custom_encrypt_cbc_192_256(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[34], size_t* output_length) {
    // Generate IV if not present
    if (!ctx->iv) {
        ctx->iv_length = 16;
        ctx->iv = (unsigned char*)malloc(16);
        if (!ctx->iv) return NULL;
        
        // Generate cryptographically secure random IV
        secure_random_bytes(ctx->iv, 16);
    }
    
    // Calculate output size (IV + padded data)
    size_t padded_length = ((data_length + 15) / 16) * 16;
    size_t total_length = 16 + padded_length;
    unsigned char* output = (unsigned char*)malloc(total_length);
    if (!output) return NULL;
    
    // Copy IV to output
    memcpy(output, ctx->iv, 16);
    
    // Previous block starts with IV
    uint8_t prev_block[16];
    memcpy(prev_block, ctx->iv, 16);
    
    // Encrypt block by block
    for (size_t i = 0; i < data_length; i += 16) {
        uint8_t block[16];
        memset(block, 0, 16);
        
        size_t copy_len = (data_length - i < 16) ? data_length - i : 16;
        memcpy(block, data + i, copy_len);
        
        // PKCS#7 padding for last block
        if (copy_len < 16) {
            uint8_t pad_value = 16 - copy_len;
            for (size_t j = copy_len; j < 16; j++) {
                block[j] = pad_value;
            }
        }
        
        // XOR with previous block (CBC mode)
        for (int j = 0; j < 16; j++) {
            block[j] ^= prev_block[j];
        }
        
        // Encrypt the XORed block
        camellia_encrypt_192_256(block, output + 16 + i, subkeys);
        
        // Update previous block
        memcpy(prev_block, output + 16 + i, 16);
    }
    
    *output_length = total_length;
    return output;
}

static unsigned char* camellia_custom_decrypt_cbc_192_256(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[34], size_t* output_length) {
    if (data_length < 32 || (data_length - 16) % 16 != 0) return NULL;
    
    // Extract IV
    uint8_t iv[16];
    memcpy(iv, data, 16);
    
    size_t ciphertext_length = data_length - 16;
    unsigned char* output = (unsigned char*)malloc(ciphertext_length);
    if (!output) return NULL;
    
    // Previous block starts with IV
    uint8_t prev_block[16];
    memcpy(prev_block, iv, 16);
    
    // Decrypt block by block
    for (size_t i = 0; i < ciphertext_length; i += 16) {
        uint8_t decrypted_block[16];
        
        // Decrypt the block
        camellia_decrypt_192_256(data + 16 + i, decrypted_block, subkeys);
        
        // XOR with previous block (CBC mode)
        for (int j = 0; j < 16; j++) {
            output[i + j] = decrypted_block[j] ^ prev_block[j];
        }
        
        // Update previous block
        memcpy(prev_block, data + 16 + i, 16);
    }
    
    // Remove PKCS#7 padding
    if (ciphertext_length > 0) {
        uint8_t pad_value = output[ciphertext_length - 1];
        if (pad_value <= 16) {
            *output_length = ciphertext_length - pad_value;
        } else {
            *output_length = ciphertext_length;
        }
    } else {
        *output_length = 0;
    }
    
    return output;
}

// CFB Mode Implementation
static unsigned char* camellia_custom_encrypt_cfb_192_256(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[34], size_t* output_length) {
    // Generate IV if not present
    if (!ctx->iv) {
        ctx->iv_length = 16;
        ctx->iv = (unsigned char*)malloc(16);
        if (!ctx->iv) return NULL;
        
        // Generate cryptographically secure random IV
        secure_random_bytes(ctx->iv, 16);
    }
    
    size_t total_length = 16 + data_length;
    unsigned char* output = (unsigned char*)malloc(total_length);
    if (!output) return NULL;
    
    // Copy IV to output
    memcpy(output, ctx->iv, 16);
    
    // Feedback register starts with IV
    uint8_t feedback[16];
    memcpy(feedback, ctx->iv, 16);
    
    // Encrypt byte by byte (CFB mode)
    for (size_t i = 0; i < data_length; i++) {
        // Encrypt feedback to create keystream
        uint8_t keystream[16];
        camellia_encrypt_192_256(feedback, keystream, subkeys);
        
        // XOR plaintext with keystream
        uint8_t ciphertext_byte = data[i] ^ keystream[0];
        output[16 + i] = ciphertext_byte;
        
        // Shift feedback and add new ciphertext byte
        memmove(feedback, feedback + 1, 15);
        feedback[15] = ciphertext_byte;
    }
    
    *output_length = total_length;
    return output;
}

static unsigned char* camellia_custom_decrypt_cfb_192_256(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[34], size_t* output_length) {
    if (data_length < 16) return NULL;
    
    // Extract IV
    uint8_t iv[16];
    memcpy(iv, data, 16);
    
    size_t ciphertext_length = data_length - 16;
    unsigned char* output = (unsigned char*)malloc(ciphertext_length);
    if (!output) return NULL;
    
    // Feedback register starts with IV
    uint8_t feedback[16];
    memcpy(feedback, iv, 16);
    
    // Decrypt byte by byte (CFB mode)
    for (size_t i = 0; i < ciphertext_length; i++) {
        // Encrypt feedback to create keystream
        uint8_t keystream[16];
        camellia_encrypt_192_256(feedback, keystream, subkeys);
        
        // XOR ciphertext with keystream
        uint8_t ciphertext_byte = data[16 + i];
        output[i] = ciphertext_byte ^ keystream[0];
        
        // Shift feedback and add ciphertext byte
        memmove(feedback, feedback + 1, 15);
        feedback[15] = ciphertext_byte;
    }
    
    *output_length = ciphertext_length;
    return output;
}

// OFB Mode Implementation
static unsigned char* camellia_custom_encrypt_ofb_192_256(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[34], size_t* output_length) {
    // Generate IV if not present
    if (!ctx->iv) {
        ctx->iv_length = 16;
        ctx->iv = (unsigned char*)malloc(16);
        if (!ctx->iv) return NULL;
        
        // Generate cryptographically secure random IV
        secure_random_bytes(ctx->iv, 16);
    }
    
    size_t total_length = 16 + data_length;
    unsigned char* output = (unsigned char*)malloc(total_length);
    if (!output) return NULL;
    
    // Copy IV to output
    memcpy(output, ctx->iv, 16);
    
    // Feedback register starts with IV
    uint8_t feedback[16];
    memcpy(feedback, ctx->iv, 16);
    
    // Encrypt byte by byte (OFB mode)
    for (size_t i = 0; i < data_length; i++) {
        // Encrypt feedback to create keystream
        uint8_t keystream[16];
        camellia_encrypt_192_256(feedback, keystream, subkeys);
        
        // XOR plaintext with keystream
        output[16 + i] = data[i] ^ keystream[0];
        
        // Update feedback with encrypted feedback (OFB characteristic)
        memmove(feedback, feedback + 1, 15);
        feedback[15] = keystream[0];
    }
    
    *output_length = total_length;
    return output;
}

static unsigned char* camellia_custom_decrypt_ofb_192_256(camellia_context_t* ctx, const unsigned char* data, size_t data_length, const uint64_t subkeys[34], size_t* output_length) {
    if (data_length < 16) return NULL;
    
    // Extract IV
    uint8_t iv[16];
    memcpy(iv, data, 16);
    
    size_t ciphertext_length = data_length - 16;
    unsigned char* output = (unsigned char*)malloc(ciphertext_length);
    if (!output) return NULL;
    
    // Feedback register starts with IV
    uint8_t feedback[16];
    memcpy(feedback, iv, 16);
    
    // Decrypt byte by byte (OFB mode - same as encryption)
    for (size_t i = 0; i < ciphertext_length; i++) {
        // Encrypt feedback to create keystream
        uint8_t keystream[16];
        camellia_encrypt_192_256(feedback, keystream, subkeys);
        
        // XOR ciphertext with keystream
        output[i] = data[16 + i] ^ keystream[0];
        
        // Update feedback with encrypted feedback (OFB characteristic)
        memmove(feedback, feedback + 1, 15);
        feedback[15] = keystream[0];
    }
    
    *output_length = ciphertext_length;
    return output;
}

// Stream mode functions
unsigned char* camellia_encrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    if (!context || !data || !key || data_length <= 0) return NULL;
    
    camellia_context_t* ctx = (camellia_context_t*)context;
    size_t out_len;
    unsigned char* result;
    
    if (ctx->is_custom) {
        result = camellia_custom_encrypt(context, data, (size_t)data_length, key, &out_len);
    } else {
        result = camellia_encrypt(context, data, (size_t)data_length, key, &out_len);
    }
    
    *output_length = (int)out_len;
    return result;
}

unsigned char* camellia_decrypt_stream(void* context, const unsigned char* data, int data_length, const unsigned char* key, int chunk_index, int* output_length) {
    if (!context || !data || !key || data_length <= 0) return NULL;
    
    camellia_context_t* ctx = (camellia_context_t*)context;
    size_t out_len;
    unsigned char* result;
    
    if (ctx->is_custom) {
        result = camellia_custom_decrypt(context, data, (size_t)data_length, key, &out_len);
    } else {
        result = camellia_decrypt(context, data, (size_t)data_length, key, &out_len);
    }
    
    *output_length = (int)out_len;
    return result;
}

// Key generation functions
unsigned char* camellia_generate_key(void* context, int* key_length) {
    if (!context || !key_length) return NULL;
    
    camellia_context_t* ctx = (camellia_context_t*)context;
    *key_length = ctx->key_size / 8;
    
    unsigned char* key = (unsigned char*)malloc(*key_length);
    if (!key) return NULL;
    
#ifdef USE_OPENSSL
    if (RAND_bytes(key, *key_length) != 1) {
        free(key);
        return NULL;
    }
#else
    // Simple random key generation (not cryptographically secure)
    for (int i = 0; i < *key_length; i++) {
        key[i] = rand() & 0xFF;
    }
#endif
    
    return key;
}

unsigned char* camellia_custom_generate_key(void* context, int* key_length) {
    if (!context || !key_length) return NULL;
    
    camellia_context_t* ctx = (camellia_context_t*)context;
    *key_length = ctx->key_size / 8;
    
    unsigned char* key = (unsigned char*)malloc(*key_length);
    if (!key) return NULL;
    
    // Cryptographically secure key generation using /dev/urandom
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        size_t bytes_read = fread(key, 1, *key_length, urandom);
        fclose(urandom);
        
        if (bytes_read == *key_length) {
            return key;
        }
    }
    
    // Fallback to enhanced entropy if /dev/urandom fails
    fprintf(stderr, "Warning: Using fallback key generation (not cryptographically secure)\n");
    for (int i = 0; i < *key_length; i++) {
        key[i] = (rand() ^ (i * 17) ^ (rand() >> 8)) & 0xFF;
    }
    
    return key;
}

// Registration function
void register_camellia_implementations(implementation_registry_t* registry) {
    if (!registry) return;
    
    int index = registry->count;
    int implementations_before = registry->count;
    
    // Get the configuration to determine Camellia parameters
    char* key_size_str = getenv("CAMELLIA_KEY_SIZE");
    char* mode_str = getenv("CAMELLIA_MODE");
    char* use_stdlib_str = getenv("USE_STDLIB");
    char* use_custom_str = getenv("USE_CUSTOM");
    char* camellia_enabled_str = getenv("CAMELLIA_ENABLED");
    
    // Default values if environment variables are not set
    int key_size = key_size_str ? atoi(key_size_str) : 256;  // default to 256
    char mode[16] = "CBC";  // default to CBC
    int use_stdlib = use_stdlib_str ? atoi(use_stdlib_str) : 1;  // default to true
    int use_custom = use_custom_str ? atoi(use_custom_str) : 0;  // default to false
    int camellia_enabled = camellia_enabled_str ? atoi(camellia_enabled_str) : 1;  // Default to enabled
    
    // Check if Camellia is enabled in the configuration
    if (!camellia_enabled) {
        printf("Camellia implementations disabled in configuration\n");
        return;
    }
    
    if (mode_str) {
        strncpy(mode, mode_str, sizeof(mode) - 1);
    }
    
    // Validate key size
    if (key_size != 128 && key_size != 192 && key_size != 256) {
        fprintf(stderr, "Warning: Invalid Camellia key size %d, defaulting to 256\n", key_size);
        key_size = 256;
    }
    
    // Validate mode
    if (strcmp(mode, "ECB") != 0 && strcmp(mode, "CBC") != 0 && 
        strcmp(mode, "CFB") != 0 && strcmp(mode, "OFB") != 0) {
        fprintf(stderr, "Warning: Invalid Camellia mode %s, defaulting to CBC\n", mode);
        strcpy(mode, "CBC");
    }
    
    // Register standard Camellia implementation if enabled
    if (use_stdlib) {
        strcpy(registry->implementations[index].name, "camellia");
        registry->implementations[index].algo_type = ALGO_CAMELLIA;
        registry->implementations[index].is_custom = 0;
        registry->implementations[index].key_size = key_size;  // Use configured key size
        strcpy(registry->implementations[index].mode, mode);  // Use configured mode
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
        registry->implementations[index].key_size = key_size;  // Use configured key size
        strcpy(registry->implementations[index].mode, mode);  // Use configured mode
        registry->implementations[index].init = camellia_custom_init;
        registry->implementations[index].cleanup = camellia_custom_cleanup;
        registry->implementations[index].generate_key = camellia_custom_generate_key;
        registry->implementations[index].encrypt = camellia_custom_encrypt;
        registry->implementations[index].decrypt = camellia_custom_decrypt;
        registry->implementations[index].encrypt_stream = camellia_encrypt_stream;
        registry->implementations[index].decrypt_stream = camellia_decrypt_stream;
        registry->count++;
    }
    
    printf("Registered %d Camellia implementations (Key: %d-bit, Mode: %s)\n", 
           registry->count - implementations_before, key_size, mode);
} 