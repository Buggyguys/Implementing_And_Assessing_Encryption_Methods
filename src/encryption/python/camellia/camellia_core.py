import struct

# S-box from RFC 3713 (SBOX1)
SBOX = [
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
]

# rotate left 32-bit value
def rotl32(value, amount):
    return ((value << amount) | (value >> (32 - amount))) & 0xFFFFFFFF

def f_function(x, subkey):
    # XOR with subkey
    x ^= subkey
    
    # pply S-box to each byte (substitution layer)
    result = 0
    for i in range(8):
        byte_val = (x >> (8 * i)) & 0xFF
        s_val = SBOX[byte_val]
        result |= s_val << (8 * i)
    
    # split into 32-bit halves for mixing
    left = (result >> 32) & 0xFFFFFFFF
    right = result & 0xFFFFFFFF
    
    # diffusion through rotation and XOR
    left = rotl32(left, 1) ^ right
    right = rotl32(right, 8) ^ left
    
    return ((left & 0xFFFFFFFF) << 32) | (right & 0xFFFFFFFF)

class CamelliaCore:

    def __init__(self, key):
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes (128, 192, or 256 bits)")
        
        self.key_size = len(key) * 8
        self.master_key = key
        self.subkeys = self._generate_subkeys()
    
    def _generate_subkeys(self):
        subkeys = []
        
        # convert master key to 64-bit words
        if len(self.master_key) == 16:  # 128-bit
            k1 = struct.unpack('>Q', self.master_key[:8])[0]
            k2 = struct.unpack('>Q', self.master_key[8:16])[0]
            k3 = k4 = 0
        elif len(self.master_key) == 24:  # 192-bit
            k1 = struct.unpack('>Q', self.master_key[:8])[0]
            k2 = struct.unpack('>Q', self.master_key[8:16])[0]
            k3 = struct.unpack('>Q', self.master_key[16:24])[0]
            k4 = 0
        else:  # 256-bit
            k1 = struct.unpack('>Q', self.master_key[:8])[0]
            k2 = struct.unpack('>Q', self.master_key[8:16])[0]
            k3 = struct.unpack('>Q', self.master_key[16:24])[0]
            k4 = struct.unpack('>Q', self.master_key[24:32])[0]
        
        # create base key array (only non-zero keys)
        base_keys = [k for k in [k1, k2, k3, k4] if k != 0]
        
        # 128-bit: 18 rounds + 4 whitening = 22 subkeys minimum
        # 192/256-bit: 24 rounds + 4 whitening = 28 subkeys minimum
        # we generate 30 to have some extra for safety
        num_subkeys = 30
        
        for i in range(num_subkeys):
            # select base key in round-robin fashion
            key_idx = i % len(base_keys)
            base_key = base_keys[key_idx]
            
            # apply rotation for key diffusion
            # use modulo to prevent negative shifts
            shift_amount = (i * 7) % 64
            rotated = ((base_key << shift_amount) | (base_key >> (64 - shift_amount))) & 0xFFFFFFFFFFFFFFFF
            
            # mix with round constant to make it random
            mixed = rotated ^ (i * 0x0123456789ABCDEF)
            
            subkeys.append(mixed)
        
        return subkeys
    
    def encrypt_block(self, plaintext_block):
        if len(plaintext_block) != 16:
            raise ValueError("Block must be exactly 16 bytes")
        
        # conversion to two 64-bit halves (big-endian)
        left = struct.unpack('>Q', plaintext_block[:8])[0]
        right = struct.unpack('>Q', plaintext_block[8:])[0]
        
        # determine number of rounds 
        if self.key_size == 128:
            rounds = 18  # standard for Camellia-128
        else:
            rounds = 24  # standard for Camellia-192/256
        
        # initial whitening (pre-whitening)
        left ^= self.subkeys[0]
        right ^= self.subkeys[1]
        
        # main Feistel rounds
        for i in range(rounds):
            # standard Feistel round
            f_result = f_function(right, self.subkeys[i + 2])
            new_left = right
            new_right = left ^ f_result
            left, right = new_left, new_right
        
        # final whitening (post-whitening)
        left ^= self.subkeys[rounds + 2]
        right ^= self.subkeys[rounds + 3]
        
        # convert back to bytes (big-endian)
        return struct.pack('>QQ', left, right)
    
    def decrypt_block(self, ciphertext_block):
        if len(ciphertext_block) != 16:
            raise ValueError("Block must be exactly 16 bytes")
        
        # convert into 2 64-bit halves
        left = struct.unpack('>Q', ciphertext_block[:8])[0]
        right = struct.unpack('>Q', ciphertext_block[8:])[0]
        
        # number of rounds 
        if self.key_size == 128:
            rounds = 18
        else:
            rounds = 24
        
        # Initial whitening (reverse)
        left ^= self.subkeys[rounds + 2]
        right ^= self.subkeys[rounds + 3]
        
        # main Feistel rounds (reverse)
        for i in range(rounds - 1, -1, -1):
            # reverse Feistel round
            f_result = f_function(left, self.subkeys[i + 2])
            new_right = left
            new_left = right ^ f_result
            left, right = new_left, new_right
        
        # final whitening (reverse)
        left ^= self.subkeys[0]
        right ^= self.subkeys[1]
        
        # convert to bytes 
        return struct.pack('>QQ', left, right)

SimpleCamelliaCore = CamelliaCore 
