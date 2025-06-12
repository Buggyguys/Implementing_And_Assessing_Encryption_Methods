#!/usr/bin/env python3
"""
Camellia Constants
Contains S-boxes, constants, and utility functions for Camellia encryption.
Based on RFC 3713.
"""

# Camellia S-box 1 (SBOX1) from RFC 3713
SBOX1 = [
    112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
     35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
    134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
    166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
    139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
    223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
     20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
    254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
    170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210,
     16, 196, 0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148,
     135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246, 243, 157, 127, 191, 226,
     82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111, 75, 19, 190, 99, 46,
    233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180, 89,
    120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250,
    114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164,
     64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199, 128, 158
]

# Camellia S-box 2 (SBOX2) - derived from SBOX1
SBOX2 = [SBOX1[(i << 1) & 0xFF] for i in range(256)]

# Camellia S-box 3 (SBOX3) - derived from SBOX1  
SBOX3 = [SBOX1[(i << 7) & 0xFF] for i in range(256)]

# Camellia S-box 4 (SBOX4) - derived from SBOX1
SBOX4 = [SBOX1[((i << 1) ^ (i >> 7)) & 0xFF] for i in range(256)]

# Sigma constants for key schedule
SIGMA = [
    0xA09E667F3BCC908B, 0xB67AE8584CAA73B2, 0xC6EF372FE94F82BE, 0x54FF53A5F1D36F1C,
    0x10E527FADE682D1D, 0xB05688C2B3E6C1FD
]

def f_function(x, ke):
    """
    Camellia F-function.
    
    Args:
        x: 64-bit input
        ke: 64-bit subkey
        
    Returns:
        int: 64-bit output
    """
    # XOR with subkey
    x ^= ke
    
    # Extract bytes
    t = [0] * 8
    for i in range(8):
        t[i] = (x >> (8 * (7 - i))) & 0xFF
    
    # Apply S-boxes
    t[0] = SBOX1[t[0]]
    t[1] = SBOX2[t[1]]
    t[2] = SBOX3[t[2]]
    t[3] = SBOX4[t[3]]
    t[4] = SBOX2[t[4]]
    t[5] = SBOX3[t[5]]
    t[6] = SBOX4[t[6]]
    t[7] = SBOX1[t[7]]
    
    # Apply P-layer (linear transformation)
    y = [0] * 8
    y[0] = t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7]
    y[1] = t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7]
    y[2] = t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7]
    y[3] = t[1] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7]
    y[4] = t[0] ^ t[1] ^ t[5] ^ t[6]
    y[5] = t[1] ^ t[2] ^ t[6] ^ t[7]
    y[6] = t[2] ^ t[3] ^ t[0] ^ t[7]
    y[7] = t[3] ^ t[4] ^ t[0] ^ t[1]
    
    # Combine bytes back to 64-bit value
    result = 0
    for i in range(8):
        result |= (y[i] << (8 * (7 - i)))
    
    return result

def fl_function(x, ke):
    """
    Camellia FL-function.
    
    Args:
        x: 64-bit input
        ke: 64-bit subkey
        
    Returns:
        int: 64-bit output
    """
    xl = (x >> 32) & 0xFFFFFFFF
    xr = x & 0xFFFFFFFF
    kel = (ke >> 32) & 0xFFFFFFFF
    ker = ke & 0xFFFFFFFF
    
    yr = xr ^ ((xl & kel) << 1 | (xl & kel) >> 31) & 0xFFFFFFFF
    yl = xl ^ (yr | ker)
    
    return ((yl & 0xFFFFFFFF) << 32) | (yr & 0xFFFFFFFF)

def flinv_function(y, ke):
    """
    Camellia FL^-1 function (inverse of FL).
    
    Args:
        y: 64-bit input
        ke: 64-bit subkey
        
    Returns:
        int: 64-bit output
    """
    yl = (y >> 32) & 0xFFFFFFFF
    yr = y & 0xFFFFFFFF
    kel = (ke >> 32) & 0xFFFFFFFF
    ker = ke & 0xFFFFFFFF
    
    xl = yl ^ (yr | ker)
    xr = yr ^ ((xl & kel) << 1 | (xl & kel) >> 31) & 0xFFFFFFFF
    
    return ((xl & 0xFFFFFFFF) << 32) | (xr & 0xFFFFFFFF)

def rotl(value, amount, width=64):
    """Rotate left."""
    amount %= width
    return ((value << amount) | (value >> (width - amount))) & ((1 << width) - 1)

def rotr(value, amount, width=64):
    """Rotate right."""
    amount %= width
    return ((value >> amount) | (value << (width - amount))) & ((1 << width) - 1) 