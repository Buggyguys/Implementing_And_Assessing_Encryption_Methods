#!/usr/bin/env python3
"""
Camellia Core Cipher Implementation
Based on RFC 3713 - A Description of the Camellia Encryption Algorithm
"""

import struct
try:
    from .camellia_constants import s_layer, s_layer_inv, p_layer, FL_MASK1, FL_MASK2
    from .camellia_key_schedule import CamelliaKeySchedule
except ImportError:
    # Fallback for direct execution
    from camellia_constants import s_layer, s_layer_inv, p_layer, FL_MASK1, FL_MASK2
    from camellia_key_schedule import CamelliaKeySchedule

class CamelliaCore:
    """Core Camellia cipher implementation."""
    
    def __init__(self, master_key):
        """
        Initialize Camellia cipher.
        
        Args:
            master_key: bytes, 16, 24, or 32 bytes long
        """
        self.key_schedule = CamelliaKeySchedule(master_key)
        self.num_rounds = self.key_schedule.get_num_rounds()
        self.subkeys = self.key_schedule.get_all_subkeys()
    
    def _f_function(self, fin, ke):
        """
        F-function used in Feistel rounds.
        
        Args:
            fin: 64-bit input
            ke: 64-bit round key
            
        Returns:
            64-bit output
        """
        # XOR with round key
        x = fin ^ ke
        
        # Apply S-layer (substitution)
        t = s_layer(x)
        
        # Apply P-layer (linear transformation)
        return p_layer(t)
    
    def _fl_function(self, flin, ke):
        """
        FL function used in key-dependent layer.
        
        Args:
            flin: 64-bit input
            ke: 64-bit key (split into kl1 and kl2)
            
        Returns:
            64-bit output
        """
        # Split input into left and right halves
        left = (flin & FL_MASK1) >> 32
        right = flin & FL_MASK2
        
        # Split key into two halves
        kl1 = (ke & FL_MASK1) >> 32
        kl2 = ke & FL_MASK2
        
        # FL function operations
        right = right ^ ((left & kl1) << 1 | (left & kl1) >> 31) & FL_MASK2
        left = left ^ (right | kl2)
        
        # Combine halves
        return (left << 32) | (right & FL_MASK2)
    
    def _flinv_function(self, flin, ke):
        """
        FL^(-1) (inverse FL) function used in key-dependent layer.
        
        Args:
            flin: 64-bit input
            ke: 64-bit key (split into kr1 and kr2)
            
        Returns:
            64-bit output
        """
        # Split input into left and right halves
        left = (flin & FL_MASK1) >> 32
        right = flin & FL_MASK2
        
        # Split key into two halves
        kr1 = (ke & FL_MASK1) >> 32
        kr2 = ke & FL_MASK2
        
        # FL^(-1) function operations (reverse of FL)
        left = left ^ (right | kr2)
        right = right ^ ((left & kr1) << 1 | (left & kr1) >> 31) & FL_MASK2
        
        # Combine halves
        return (left << 32) | (right & FL_MASK2)
    
    def _feistel_round(self, left, right, round_key):
        """
        Perform one Feistel round.
        
        Args:
            left: 64-bit left half
            right: 64-bit right half
            round_key: 64-bit round key
            
        Returns:
            tuple: (new_left, new_right)
        """
        # Standard Feistel structure: L' = R, R' = L ⊕ F(R, K)
        new_left = right
        new_right = left ^ self._f_function(right, round_key)
        return new_left, new_right
    
    def _apply_fl_layer(self, left, right, kl_key, kr_key):
        """
        Apply FL/FL^(-1) layer.
        
        Args:
            left: 64-bit left half
            right: 64-bit right half
            kl_key: Key for FL function
            kr_key: Key for FL^(-1) function
            
        Returns:
            tuple: (new_left, new_right)
        """
        new_left = self._fl_function(left, kl_key)
        new_right = self._flinv_function(right, kr_key)
        return new_left, new_right
    
    def _apply_flinv_layer(self, left, right, kl_key, kr_key):
        """
        Apply FL^(-1)/FL layer (for decryption).
        
        Args:
            left: 64-bit left half
            right: 64-bit right half
            kl_key: Key for FL^(-1) function
            kr_key: Key for FL function
            
        Returns:
            tuple: (new_left, new_right)
        """
        new_left = self._flinv_function(left, kl_key)
        new_right = self._fl_function(right, kr_key)
        return new_left, new_right
    
    def encrypt_block(self, plaintext_block):
        """
        Encrypt a single 16-byte block.
        
        Args:
            plaintext_block: bytes, exactly 16 bytes
            
        Returns:
            bytes: 16-byte encrypted block
        """
        if len(plaintext_block) != 16:
            raise ValueError("Block must be exactly 16 bytes")
        
        # Convert to two 64-bit values
        left, right = struct.unpack('>QQ', plaintext_block)
        
        # Pre-whitening
        left ^= self.subkeys[0]
        right ^= self.subkeys[1]
        
        # Main rounds
        subkey_idx = 2
        
        if self.num_rounds == 18:  # 128-bit key
            # Rounds 1-6
            for _ in range(6):
                left, right = self._feistel_round(left, right, self.subkeys[subkey_idx])
                subkey_idx += 1
            
            # FL/FL^(-1) layer
            left, right = self._apply_fl_layer(left, right, self.subkeys[subkey_idx], self.subkeys[subkey_idx + 1])
            subkey_idx += 2
            
            # Rounds 7-12
            for _ in range(6):
                left, right = self._feistel_round(left, right, self.subkeys[subkey_idx])
                subkey_idx += 1
            
            # FL/FL^(-1) layer
            left, right = self._apply_fl_layer(left, right, self.subkeys[subkey_idx], self.subkeys[subkey_idx + 1])
            subkey_idx += 2
            
            # Rounds 13-18
            for _ in range(6):
                left, right = self._feistel_round(left, right, self.subkeys[subkey_idx])
                subkey_idx += 1
        
        else:  # 24 rounds for 192/256-bit keys
            # Rounds 1-6
            for _ in range(6):
                left, right = self._feistel_round(left, right, self.subkeys[subkey_idx])
                subkey_idx += 1
            
            # FL/FL^(-1) layer
            left, right = self._apply_fl_layer(left, right, self.subkeys[subkey_idx], self.subkeys[subkey_idx + 1])
            subkey_idx += 2
            
            # Rounds 7-12
            for _ in range(6):
                left, right = self._feistel_round(left, right, self.subkeys[subkey_idx])
                subkey_idx += 1
            
            # FL/FL^(-1) layer
            left, right = self._apply_fl_layer(left, right, self.subkeys[subkey_idx], self.subkeys[subkey_idx + 1])
            subkey_idx += 2
            
            # Rounds 13-18
            for _ in range(6):
                left, right = self._feistel_round(left, right, self.subkeys[subkey_idx])
                subkey_idx += 1
            
            # FL/FL^(-1) layer
            left, right = self._apply_fl_layer(left, right, self.subkeys[subkey_idx], self.subkeys[subkey_idx + 1])
            subkey_idx += 2
            
            # Rounds 19-24
            for _ in range(6):
                left, right = self._feistel_round(left, right, self.subkeys[subkey_idx])
                subkey_idx += 1
        
        # Post-whitening
        right ^= self.subkeys[-2]
        left ^= self.subkeys[-1]
        
        # Convert back to bytes (note: left and right are swapped in final output)
        return struct.pack('>QQ', right, left)
    
    def decrypt_block(self, ciphertext_block):
        """
        Decrypt a single 16-byte block.
        
        Args:
            ciphertext_block: bytes, exactly 16 bytes
            
        Returns:
            bytes: 16-byte decrypted block
        """
        if len(ciphertext_block) != 16:
            raise ValueError("Block must be exactly 16 bytes")
        
        # Convert to two 64-bit values (note: swapped due to encryption)
        right, left = struct.unpack('>QQ', ciphertext_block)
        
        # Reverse post-whitening
        left ^= self.subkeys[-1]
        right ^= self.subkeys[-2]
        
        # Reverse main rounds
        if self.num_rounds == 18:  # 128-bit key
            subkey_idx = len(self.subkeys) - 3  # Start from last round key
            
            # Reverse rounds 13-18
            for _ in range(6):
                right, left = self._feistel_round(right, left, self.subkeys[subkey_idx])
                subkey_idx -= 1
            
            # Reverse FL/FL^(-1) layer
            right, left = self._apply_flinv_layer(right, left, self.subkeys[subkey_idx], self.subkeys[subkey_idx - 1])
            subkey_idx -= 2
            
            # Reverse rounds 7-12
            for _ in range(6):
                right, left = self._feistel_round(right, left, self.subkeys[subkey_idx])
                subkey_idx -= 1
            
            # Reverse FL/FL^(-1) layer
            right, left = self._apply_flinv_layer(right, left, self.subkeys[subkey_idx], self.subkeys[subkey_idx - 1])
            subkey_idx -= 2
            
            # Reverse rounds 1-6
            for _ in range(6):
                right, left = self._feistel_round(right, left, self.subkeys[subkey_idx])
                subkey_idx -= 1
        
        else:  # 24 rounds for 192/256-bit keys
            subkey_idx = len(self.subkeys) - 3  # Start from last round key
            
            # Reverse rounds 19-24
            for _ in range(6):
                right, left = self._feistel_round(right, left, self.subkeys[subkey_idx])
                subkey_idx -= 1
            
            # Reverse FL/FL^(-1) layer
            right, left = self._apply_flinv_layer(right, left, self.subkeys[subkey_idx], self.subkeys[subkey_idx - 1])
            subkey_idx -= 2
            
            # Reverse rounds 13-18
            for _ in range(6):
                right, left = self._feistel_round(right, left, self.subkeys[subkey_idx])
                subkey_idx -= 1
            
            # Reverse FL/FL^(-1) layer
            right, left = self._apply_flinv_layer(right, left, self.subkeys[subkey_idx], self.subkeys[subkey_idx - 1])
            subkey_idx -= 2
            
            # Reverse rounds 7-12
            for _ in range(6):
                right, left = self._feistel_round(right, left, self.subkeys[subkey_idx])
                subkey_idx -= 1
            
            # Reverse FL/FL^(-1) layer
            right, left = self._apply_flinv_layer(right, left, self.subkeys[subkey_idx], self.subkeys[subkey_idx - 1])
            subkey_idx -= 2
            
            # Reverse rounds 1-6
            for _ in range(6):
                right, left = self._feistel_round(right, left, self.subkeys[subkey_idx])
                subkey_idx -= 1
        
        # Reverse pre-whitening
        right ^= self.subkeys[1]
        left ^= self.subkeys[0]
        
        # Convert back to bytes
        return struct.pack('>QQ', left, right) 