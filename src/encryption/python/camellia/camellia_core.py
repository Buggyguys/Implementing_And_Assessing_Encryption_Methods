#!/usr/bin/env python3
"""
Camellia Core Implementation
The main Camellia block cipher implementation.
Based on RFC 3713.
"""

import struct
from .camellia_constants import f_function, fl_function, flinv_function
from .camellia_key_schedule import CamelliaKeySchedule

class CamelliaCore:
    """Core Camellia cipher implementation."""
    
    def __init__(self, key):
        """
        Initialize Camellia cipher with key.
        
        Args:
            key: Master key (16, 24, or 32 bytes)
        """
        self.key_schedule = CamelliaKeySchedule(key)
        self.key_size = self.key_schedule.key_size
        self.enc_subkeys = self.key_schedule.get_encryption_subkeys()
        self.dec_subkeys = self.key_schedule.get_decryption_subkeys()
    
    def encrypt_block(self, plaintext_block):
        """
        Encrypt a single 16-byte block.
        
        Args:
            plaintext_block: 16-byte plaintext block
            
        Returns:
            bytes: 16-byte ciphertext block
        """
        if len(plaintext_block) != 16:
            raise ValueError("Block must be exactly 16 bytes")
        
        # Convert to two 64-bit values
        left = struct.unpack('>Q', plaintext_block[:8])[0]
        right = struct.unpack('>Q', plaintext_block[8:])[0]
        
        # Pre-whitening
        left ^= self.enc_subkeys['kw1']
        right ^= self.enc_subkeys['kw2']
        
        # Main rounds
        if self.key_size == 128:
            left, right = self._encrypt_rounds_128(left, right)
        else:
            left, right = self._encrypt_rounds_256(left, right)
        
        # Post-whitening
        left ^= self.enc_subkeys['kw3']
        right ^= self.enc_subkeys['kw4']
        
        # Convert back to bytes
        return struct.pack('>QQ', left, right)
    
    def decrypt_block(self, ciphertext_block):
        """
        Decrypt a single 16-byte block.
        
        Args:
            ciphertext_block: 16-byte ciphertext block
            
        Returns:
            bytes: 16-byte plaintext block
        """
        if len(ciphertext_block) != 16:
            raise ValueError("Block must be exactly 16 bytes")
        
        # Convert to two 64-bit values
        left = struct.unpack('>Q', ciphertext_block[:8])[0]
        right = struct.unpack('>Q', ciphertext_block[8:])[0]
        
        # Pre-whitening (with decryption subkeys)
        left ^= self.dec_subkeys['kw1']
        right ^= self.dec_subkeys['kw2']
        
        # Main rounds (reversed)
        if self.key_size == 128:
            left, right = self._decrypt_rounds_128(left, right)
        else:
            left, right = self._decrypt_rounds_256(left, right)
        
        # Post-whitening
        left ^= self.dec_subkeys['kw3']
        right ^= self.dec_subkeys['kw4']
        
        # Convert back to bytes
        return struct.pack('>QQ', left, right)
    
    def _encrypt_rounds_128(self, left, right):
        """Perform encryption rounds for 128-bit keys."""
        # Rounds 1-6
        for i in range(1, 7):
            left, right = self._feistel_round(left, right, self.enc_subkeys[f'k{i}'])
        
        # FL/FLINV after round 6
        left = fl_function(left, self.enc_subkeys['kl1'])
        right = flinv_function(right, self.enc_subkeys['kr1'])
        
        # Rounds 7-12
        for i in range(7, 13):
            left, right = self._feistel_round(left, right, self.enc_subkeys[f'k{i}'])
        
        # FL/FLINV after round 12
        left = fl_function(left, self.enc_subkeys['kl2'])
        right = flinv_function(right, self.enc_subkeys['kr2'])
        
        # Rounds 13-18
        for i in range(13, 19):
            left, right = self._feistel_round(left, right, self.enc_subkeys[f'k{i}'])
        
        return left, right
    
    def _encrypt_rounds_256(self, left, right):
        """Perform encryption rounds for 192/256-bit keys."""
        # Rounds 1-6
        for i in range(1, 7):
            left, right = self._feistel_round(left, right, self.enc_subkeys[f'k{i}'])
        
        # FL/FLINV after round 6
        left = fl_function(left, self.enc_subkeys['kl1'])
        right = flinv_function(right, self.enc_subkeys['kr1'])
        
        # Rounds 7-12
        for i in range(7, 13):
            left, right = self._feistel_round(left, right, self.enc_subkeys[f'k{i}'])
        
        # FL/FLINV after round 12
        left = fl_function(left, self.enc_subkeys['kl2'])
        right = flinv_function(right, self.enc_subkeys['kr2'])
        
        # Rounds 13-18
        for i in range(13, 19):
            left, right = self._feistel_round(left, right, self.enc_subkeys[f'k{i}'])
        
        # FL/FLINV after round 18
        left = fl_function(left, self.enc_subkeys['kl3'])
        right = flinv_function(right, self.enc_subkeys['kr3'])
        
        # Rounds 19-24
        for i in range(19, 25):
            left, right = self._feistel_round(left, right, self.enc_subkeys[f'k{i}'])
        
        return left, right
    
    def _decrypt_rounds_128(self, left, right):
        """Perform decryption rounds for 128-bit keys."""
        # Rounds 18-13 (reversed)
        for i in range(18, 12, -1):
            left, right = self._feistel_round(left, right, self.dec_subkeys[f'k{i}'])
        
        # FL/FLINV after round 12 (reversed)
        left = fl_function(left, self.dec_subkeys['kl2'])
        right = flinv_function(right, self.dec_subkeys['kr2'])
        
        # Rounds 12-7 (reversed)
        for i in range(12, 6, -1):
            left, right = self._feistel_round(left, right, self.dec_subkeys[f'k{i}'])
        
        # FL/FLINV after round 6 (reversed)
        left = fl_function(left, self.dec_subkeys['kl1'])
        right = flinv_function(right, self.dec_subkeys['kr1'])
        
        # Rounds 6-1 (reversed)
        for i in range(6, 0, -1):
            left, right = self._feistel_round(left, right, self.dec_subkeys[f'k{i}'])
        
        return left, right
    
    def _decrypt_rounds_256(self, left, right):
        """Perform decryption rounds for 192/256-bit keys."""
        # Rounds 24-19 (reversed)
        for i in range(24, 18, -1):
            left, right = self._feistel_round(left, right, self.dec_subkeys[f'k{i}'])
        
        # FL/FLINV after round 18 (reversed)
        left = fl_function(left, self.dec_subkeys['kl3'])
        right = flinv_function(right, self.dec_subkeys['kr3'])
        
        # Rounds 18-13 (reversed)
        for i in range(18, 12, -1):
            left, right = self._feistel_round(left, right, self.dec_subkeys[f'k{i}'])
        
        # FL/FLINV after round 12 (reversed)
        left = fl_function(left, self.dec_subkeys['kl2'])
        right = flinv_function(right, self.dec_subkeys['kr2'])
        
        # Rounds 12-7 (reversed)
        for i in range(12, 6, -1):
            left, right = self._feistel_round(left, right, self.dec_subkeys[f'k{i}'])
        
        # FL/FLINV after round 6 (reversed)
        left = fl_function(left, self.dec_subkeys['kl1'])
        right = flinv_function(right, self.dec_subkeys['kr1'])
        
        # Rounds 6-1 (reversed)
        for i in range(6, 0, -1):
            left, right = self._feistel_round(left, right, self.dec_subkeys[f'k{i}'])
        
        return left, right
    
    def _feistel_round(self, left, right, subkey):
        """
        Perform one Feistel round.
        
        Args:
            left: Left 64-bit half
            right: Right 64-bit half
            subkey: Round subkey
            
        Returns:
            tuple: (new_left, new_right)
        """
        # F-function on right half with subkey
        f_result = f_function(right, subkey)
        
        # XOR with left half and swap
        new_right = left ^ f_result
        new_left = right
        
        return new_left, new_right 