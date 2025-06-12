#!/usr/bin/env python3
"""
Camellia Key Schedule
Implements the key schedule algorithm for Camellia encryption.
Based on RFC 3713.
"""

from .camellia_constants import f_function, SIGMA, rotl

class CamelliaKeySchedule:
    """Camellia key schedule implementation."""
    
    def __init__(self, key):
        """
        Initialize key schedule with master key.
        
        Args:
            key: Master key (16, 24, or 32 bytes)
        """
        self.key_size = len(key) * 8
        if self.key_size not in [128, 192, 256]:
            raise ValueError(f"Invalid key size: {self.key_size} bits. Must be 128, 192, or 256.")
        
        self.master_key = key
        self.subkeys = self._generate_subkeys()
    
    def _generate_subkeys(self):
        """
        Generate all subkeys according to RFC 3713.
        
        Returns:
            dict: Dictionary containing all subkeys
        """
        # Convert master key to 128-bit or 256-bit format
        if self.key_size == 128:
            kl = int.from_bytes(self.master_key, 'big')
            kr = 0
        elif self.key_size == 192:
            # For 192-bit keys, pad to 256 bits
            padded_key = self.master_key + b'\x00' * 8
            kl = int.from_bytes(padded_key[:16], 'big')
            kr = int.from_bytes(padded_key[16:32], 'big')
        else:  # 256-bit
            kl = int.from_bytes(self.master_key[:16], 'big')
            kr = int.from_bytes(self.master_key[16:32], 'big')
        
        # Generate intermediate keys
        if self.key_size == 128:
            ka, kb = self._generate_ka_kb_128(kl)
        else:
            ka, kb = self._generate_ka_kb_256(kl, kr)
        
        # Generate all subkeys
        subkeys = {}
        
        if self.key_size == 128:
            # 128-bit key schedule
            subkeys.update(self._generate_128_bit_subkeys(kl, ka))
        else:
            # 192/256-bit key schedule  
            subkeys.update(self._generate_256_bit_subkeys(kl, kr, ka, kb))
        
        return subkeys
    
    def _generate_ka_kb_128(self, kl):
        """Generate KA for 128-bit keys."""
        # D1 = (KL ^ SIGMA1)
        d1 = kl ^ (SIGMA[0] << 64 | SIGMA[1])
        
        # D2 = F(D1_left, D1_right) ^ D1_right || D1_left ^ F(D1_left, D1_right)
        d1_left = (d1 >> 64) & 0xFFFFFFFFFFFFFFFF
        d1_right = d1 & 0xFFFFFFFFFFFFFFFF
        
        f_result = f_function(d1_left, d1_right)
        d2_left = f_result ^ d1_right
        d2_right = d1_left ^ f_result
        d2 = (d2_left << 64) | d2_right
        
        # KA = D2 ^ KL
        ka = d2 ^ kl
        
        return ka, 0  # KB is 0 for 128-bit keys
    
    def _generate_ka_kb_256(self, kl, kr):
        """Generate KA and KB for 192/256-bit keys."""
        # D1 = (KL ^ SIGMA1) || (KR ^ SIGMA2)
        d1 = ((kl ^ SIGMA[0]) << 64) | (kr ^ SIGMA[1])
        
        # D2 = F(D1_left, D1_right) ^ D1_right || D1_left ^ F(D1_left, D1_right)
        d1_left = (d1 >> 64) & 0xFFFFFFFFFFFFFFFF
        d1_right = d1 & 0xFFFFFFFFFFFFFFFF
        
        f_result = f_function(d1_left, d1_right)
        d2_left = f_result ^ d1_right
        d2_right = d1_left ^ f_result
        d2 = (d2_left << 64) | d2_right
        
        # D3 = D2 ^ KR || KL
        kr_kl = (kr << 64) | kl
        d3 = d2 ^ kr_kl
        
        # D4 = F(D3_left, D3_right) ^ D3_right || D3_left ^ F(D3_left, D3_right)
        d3_left = (d3 >> 64) & 0xFFFFFFFFFFFFFFFF
        d3_right = d3 & 0xFFFFFFFFFFFFFFFF
        
        f_result2 = f_function(d3_left, d3_right)
        d4_left = f_result2 ^ d3_right
        d4_right = d3_left ^ f_result2
        d4 = (d4_left << 64) | d4_right
        
        # KA = D2 ^ KL || KR
        kl_kr = (kl << 64) | kr
        ka = d2 ^ kl_kr
        
        # KB = D4 ^ KA
        kb = d4 ^ ka
        
        return ka, kb
    
    def _generate_128_bit_subkeys(self, kl, ka):
        """Generate subkeys for 128-bit keys."""
        subkeys = {}
        
        # Round keys (kw, k, kl, kr)
        subkeys['kw1'] = (kl >> 64) & 0xFFFFFFFFFFFFFFFF
        subkeys['kw2'] = kl & 0xFFFFFFFFFFFFFFFF
        
        # Generate k1-k18
        ka_rotated = ka
        for i in range(1, 19):
            if i % 2 == 1:
                subkeys[f'k{i}'] = (ka_rotated >> 64) & 0xFFFFFFFFFFFFFFFF
            else:
                subkeys[f'k{i}'] = ka_rotated & 0xFFFFFFFFFFFFFFFF
                if i < 18:
                    ka_rotated = rotl(ka_rotated, 15, 128)
        
        # FL/FLINV keys
        subkeys['kl1'] = rotl(kl, 45, 128) >> 64
        subkeys['kr1'] = rotl(kl, 45, 128) & 0xFFFFFFFFFFFFFFFF
        subkeys['kl2'] = rotl(ka, 30, 128) >> 64
        subkeys['kr2'] = rotl(ka, 30, 128) & 0xFFFFFFFFFFFFFFFF
        
        # Final whitening keys
        subkeys['kw3'] = rotl(ka, 111, 128) >> 64
        subkeys['kw4'] = rotl(ka, 111, 128) & 0xFFFFFFFFFFFFFFFF
        
        return subkeys
    
    def _generate_256_bit_subkeys(self, kl, kr, ka, kb):
        """Generate subkeys for 192/256-bit keys."""
        subkeys = {}
        
        # Round keys - more complex for 256-bit
        subkeys['kw1'] = (kl >> 64) & 0xFFFFFFFFFFFFFFFF
        subkeys['kw2'] = kl & 0xFFFFFFFFFFFFFFFF
        
        # Generate k1-k24 for 256-bit keys
        keys = [kl, kr, ka, kb]
        rotations = [0, 45, 15, 17, 34, 15, 17, 34, 15, 17, 34, 15]
        
        key_idx = 0
        rotation_idx = 0
        
        for i in range(1, 25):
            current_key = rotl(keys[key_idx % 4], rotations[rotation_idx % len(rotations)], 128)
            
            if i % 2 == 1:
                subkeys[f'k{i}'] = (current_key >> 64) & 0xFFFFFFFFFFFFFFFF
            else:
                subkeys[f'k{i}'] = current_key & 0xFFFFFFFFFFFFFFFF
                key_idx += 1
                rotation_idx += 1
        
        # FL/FLINV keys for 256-bit
        subkeys['kl1'] = rotl(ka, 45, 128) >> 64
        subkeys['kr1'] = rotl(ka, 45, 128) & 0xFFFFFFFFFFFFFFFF
        subkeys['kl2'] = rotl(kb, 30, 128) >> 64
        subkeys['kr2'] = rotl(kb, 30, 128) & 0xFFFFFFFFFFFFFFFF
        subkeys['kl3'] = rotl(kl, 77, 128) >> 64
        subkeys['kr3'] = rotl(kl, 77, 128) & 0xFFFFFFFFFFFFFFFF
        
        # Final whitening keys
        subkeys['kw3'] = rotl(kr, 111, 128) >> 64
        subkeys['kw4'] = rotl(kr, 111, 128) & 0xFFFFFFFFFFFFFFFF
        
        return subkeys
    
    def get_encryption_subkeys(self):
        """Get subkeys in encryption order."""
        return self.subkeys
    
    def get_decryption_subkeys(self):
        """Get subkeys in decryption order (reversed)."""
        dec_subkeys = {}
        
        # Reverse the round keys
        if self.key_size == 128:
            rounds = 18
        else:
            rounds = 24
        
        # Swap whitening keys
        dec_subkeys['kw1'] = self.subkeys['kw3']
        dec_subkeys['kw2'] = self.subkeys['kw4']
        dec_subkeys['kw3'] = self.subkeys['kw1']
        dec_subkeys['kw4'] = self.subkeys['kw2']
        
        # Reverse round keys
        for i in range(1, rounds + 1):
            dec_subkeys[f'k{i}'] = self.subkeys[f'k{rounds + 1 - i}']
        
        # FL/FLINV keys need special handling
        for key in self.subkeys:
            if key.startswith('kl') or key.startswith('kr'):
                dec_subkeys[key] = self.subkeys[key]
        
        return dec_subkeys 