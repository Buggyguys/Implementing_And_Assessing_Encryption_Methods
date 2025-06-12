#!/usr/bin/env python3
"""
Camellia Key Schedule Implementation
Based on RFC 3713 - A Description of the Camellia Encryption Algorithm
"""

import struct
try:
    from .camellia_constants import SIGMA, s_layer, p_layer, rotl64
except ImportError:
    # Fallback for direct execution
    from camellia_constants import SIGMA, s_layer, p_layer, rotl64

class CamelliaKeySchedule:
    """Handles Camellia key schedule generation."""
    
    def __init__(self, master_key):
        """
        Initialize key schedule with master key.
        
        Args:
            master_key: bytes, 16, 24, or 32 bytes long
        """
        self.key_size = len(master_key) * 8
        if self.key_size not in [128, 192, 256]:
            raise ValueError("Key size must be 128, 192, or 256 bits")
        
        self.master_key = master_key
        self.subkeys = self._generate_subkeys()
    
    def _bytes_to_u64_pairs(self, data):
        """Convert bytes to pairs of 64-bit integers."""
        # Pad to 32 bytes if necessary
        padded_data = data + b'\x00' * (32 - len(data))
        return struct.unpack('>QQQQ', padded_data)
    
    def _u64_pairs_to_bytes(self, *values):
        """Convert 64-bit integers to bytes."""
        return struct.pack('>QQQQ', *values)
    
    def _f_function(self, fin, ke):
        """F-function used in key schedule."""
        x = fin ^ ke
        # Apply S-layer
        t = s_layer(x)
        # Apply P-layer
        return p_layer(t)
    
    def _generate_subkeys(self):
        """Generate all subkeys according to RFC 3713."""
        # Convert master key to 64-bit values
        if self.key_size == 128:
            return self._generate_128_bit_subkeys()
        elif self.key_size == 192:
            return self._generate_192_bit_subkeys()
        else:  # 256-bit
            return self._generate_256_bit_subkeys()
    
    def _generate_128_bit_subkeys(self):
        """Generate subkeys for 128-bit master key."""
        # Step 1: Generate KL and KR
        KL = self._bytes_to_u64_pairs(self.master_key)
        KR = (0, 0, 0, 0)  # KR is zero for 128-bit keys
        
        # Step 2: Generate intermediate values
        KA = self._generate_ka(KL, KR)
        
        # Step 3: Generate round keys for 128-bit (18 rounds + FL keys)
        subkeys = []
        
        # Pre-whitening (kw1, kw2) - indexes 0-1
        subkeys.extend([KL[0], KL[1]])
        
        # Rounds 1-6 (k1-k6) - indexes 2-7
        subkeys.extend([
            rotl64(KA[0], 0), rotl64(KA[1], 0),  # k1, k2
            rotl64(KL[0], 15), rotl64(KL[1], 15),  # k3, k4
            rotl64(KA[0], 15), rotl64(KA[1], 15),  # k5, k6
        ])
        
        # FL/FL^-1 keys (kl1, kr1) - indexes 8-9
        subkeys.extend([rotl64(KL[0], 45), rotl64(KA[0], 30)])
        
        # Rounds 7-12 (k7-k12) - indexes 10-15
        subkeys.extend([
            rotl64(KL[0], 60), rotl64(KA[1], 30),  # k7, k8
            rotl64(KA[0], 60), rotl64(KL[1], 45),  # k9, k10
            rotl64(KL[0], 77), rotl64(KL[1], 60),  # k11, k12
        ])
        
        # FL/FL^-1 keys (kl2, kr2) - indexes 16-17
        subkeys.extend([rotl64(KA[0], 77), rotl64(KL[0], 94)])
        
        # Rounds 13-18 (k13-k18) - indexes 18-23
        subkeys.extend([
            rotl64(KA[0], 94), rotl64(KA[1], 77),  # k13, k14
            rotl64(KL[0], 111), rotl64(KA[1], 94),  # k15, k16
            rotl64(KL[1], 94), rotl64(KA[0], 111),  # k17, k18
        ])
        
        # Post-whitening (kw3, kw4) - indexes 24-25 (accessed as -2, -1)
        subkeys.extend([rotl64(KL[1], 111), rotl64(KA[1], 111)])
        
        return subkeys  # 24 subkeys total for 128-bit
    
    def _generate_192_bit_subkeys(self):
        """Generate subkeys for 192-bit master key."""
        # Pad 192-bit key to 256-bit
        padded_key = self.master_key + b'\x00' * 8
        return self._generate_256_bit_subkeys_internal(padded_key)
    
    def _generate_256_bit_subkeys(self):
        """Generate subkeys for 256-bit master key."""
        return self._generate_256_bit_subkeys_internal(self.master_key)
    
    def _generate_256_bit_subkeys_internal(self, master_key):
        """Internal method for 256-bit subkey generation."""
        # Step 1: Generate KL and KR
        key_parts = self._bytes_to_u64_pairs(master_key)
        KL = (key_parts[0], key_parts[1], 0, 0)
        KR = (key_parts[2], key_parts[3], 0, 0)
        
        # Step 2: Generate intermediate values
        KA = self._generate_ka(KL, KR)
        KB = self._generate_kb(KL, KR, KA)
        
        # Step 3: Generate round keys for 256-bit (24 rounds + FL keys)
        subkeys = []
        
        # Pre-whitening (kw1, kw2)
        subkeys.extend([KL[0], KL[1]])
        
        # Rounds 1-6 (k1-k6)
        subkeys.extend([
            rotl64(KA[0], 0), rotl64(KA[1], 0),  # k1, k2
            rotl64(KL[0], 15), rotl64(KL[1], 15),  # k3, k4
            rotl64(KA[0], 15), rotl64(KA[1], 15),  # k5, k6
        ])
        
        # FL/FL^-1 keys (kl1, kr1)
        subkeys.extend([rotl64(KL[0], 45), rotl64(KA[0], 30)])
        
        # Rounds 7-12 (k7-k12)
        subkeys.extend([
            rotl64(KL[0], 60), rotl64(KA[1], 30),  # k7, k8
            rotl64(KA[0], 60), rotl64(KL[1], 45),  # k9, k10
            rotl64(KL[0], 77), rotl64(KL[1], 60),  # k11, k12
        ])
        
        # FL/FL^-1 keys (kl2, kr2)
        subkeys.extend([rotl64(KA[0], 77), rotl64(KL[0], 94)])
        
        # Rounds 13-18 (k13-k18)
        subkeys.extend([
            rotl64(KA[0], 94), rotl64(KA[1], 77),  # k13, k14
            rotl64(KL[0], 111), rotl64(KA[1], 94),  # k15, k16
            rotl64(KL[1], 94), rotl64(KA[0], 111),  # k17, k18
        ])
        
        # FL/FL^-1 keys (kl3, kr3)
        subkeys.extend([rotl64(KL[1], 111), rotl64(KA[1], 111)])
        
        # Rounds 19-24 (k19-k24)
        subkeys.extend([
            rotl64(KB[0], 0), rotl64(KB[1], 0),    # k19, k20
            rotl64(KR[0], 15), rotl64(KR[1], 15),  # k21, k22
            rotl64(KB[0], 15), rotl64(KB[1], 15),  # k23, k24
        ])
        
        # Post-whitening (kw3, kw4)
        subkeys.extend([rotl64(KR[0], 30), rotl64(KR[1], 30)])
        
        return subkeys  # 34 subkeys total for 256-bit
    
    def _generate_ka(self, KL, KR):
        """Generate KA intermediate value."""
        # D1 = (KL ^ KR)
        D1 = (KL[0] ^ KR[0], KL[1] ^ KR[1])
        
        # Apply F-function with SIGMA constants
        D2_0 = D1[0] ^ self._f_function(D1[1], SIGMA[0])
        D2_1 = D1[1] ^ self._f_function(D2_0, SIGMA[1])
        
        # XOR with KL
        D2 = (D2_0 ^ KL[0], D2_1 ^ KL[1])
        
        # Apply F-function again
        KA_0 = D2[0] ^ self._f_function(D2[1], SIGMA[2])
        KA_1 = D2[1] ^ self._f_function(KA_0, SIGMA[3])
        
        return (KA_0, KA_1, 0, 0)
    
    def _generate_kb(self, KL, KR, KA):
        """Generate KB intermediate value (used for 256-bit keys)."""
        # D1 = (KA ^ KR)
        D1 = (KA[0] ^ KR[0], KA[1] ^ KR[1])
        
        # Apply F-function with SIGMA constants
        KB_0 = D1[0] ^ self._f_function(D1[1], SIGMA[4])
        KB_1 = D1[1] ^ self._f_function(KB_0, SIGMA[5])
        
        return (KB_0, KB_1, 0, 0)
    
    def get_round_key(self, round_num):
        """Get the key for a specific round."""
        if round_num < 0 or round_num >= len(self.subkeys):
            raise ValueError(f"Invalid round number: {round_num}")
        return self.subkeys[round_num]
    
    def get_all_subkeys(self):
        """Get all generated subkeys."""
        return self.subkeys.copy()
    
    def get_num_rounds(self):
        """Get the number of rounds for this key size."""
        if self.key_size == 128:
            return 18
        else:  # 192 or 256
            return 24 