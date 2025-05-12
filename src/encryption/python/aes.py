"""
Handmade AES Implementation

This module implements AES encryption/decryption from scratch, including key expansion,
substitution-permutation network operations, and GCM mode.
"""

import os
import struct
from typing import List, Tuple, Dict, Union, Optional

class AESHandmade:
    """
    A handmade implementation of AES encryption and decryption with GCM mode.
    """
    
    # AES S-box
    SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    
    # AES Inverse S-box
    INV_SBOX = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]
    
    # Round constants
    RCON = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A
    ]
    
    def __init__(self, key_size: str = "128"):
        """
        Initialize the AES cipher with the specified key size.
        
        Args:
            key_size: Key size in bits ("128", "192", or "256")
        """
        self.key_size = key_size
        self.key_bytes = int(key_size) // 8
        
        # Set number of rounds based on key size
        if key_size == "128":
            self.rounds = 10
            self.key_words = 4
        elif key_size == "192":
            self.rounds = 12
            self.key_words = 6
        elif key_size == "256":
            self.rounds = 14
            self.key_words = 8
        else:
            raise ValueError("Key size must be 128, 192, or 256 bits")
    
    def generate_key(self) -> bytes:
        """
        Generate a random AES key of the specified size.
        
        Returns:
            bytes: The generated key
        """
        return os.urandom(self.key_bytes)
    
    def key_expansion(self, key: bytes) -> List[List[int]]:
        """
        Expand the key into the key schedule for all rounds.
        
        Args:
            key: The encryption key
            
        Returns:
            List[List[int]]: The expanded key schedule
        """
        if len(key) != self.key_bytes:
            raise ValueError(f"Key must be {self.key_bytes} bytes for AES-{self.key_size}")
        
        # Convert key to words (4 bytes each)
        key_words = [list(key[i:i+4]) for i in range(0, len(key), 4)]
        
        # Expand key
        expanded_key = []
        expanded_key.extend(key_words)
        
        for i in range(self.key_words, 4 * (self.rounds + 1)):
            temp = expanded_key[i-1].copy()
            
            if i % self.key_words == 0:
                # RotWord
                temp = temp[1:] + temp[:1]
                # SubWord
                temp = [self.SBOX[b] for b in temp]
                # XOR with round constant
                temp[0] ^= self.RCON[i // self.key_words]
            elif self.key_words > 6 and i % self.key_words == 4:
                # Only for AES-256
                temp = [self.SBOX[b] for b in temp]
            
            expanded_key.append([
                expanded_key[i-self.key_words][0] ^ temp[0],
                expanded_key[i-self.key_words][1] ^ temp[1],
                expanded_key[i-self.key_words][2] ^ temp[2],
                expanded_key[i-self.key_words][3] ^ temp[3]
            ])
        
        # Group into round keys (4 words per round key)
        round_keys = []
        for i in range(0, len(expanded_key), 4):
            round_key = []
            for j in range(4):
                if i + j < len(expanded_key):
                    round_key.extend(expanded_key[i + j])
            round_keys.append(round_key)
        
        return round_keys
    
    def sub_bytes(self, state: List[List[int]]) -> List[List[int]]:
        """Apply SubBytes transformation using S-box."""
        return [[self.SBOX[byte] for byte in row] for row in state]
    
    def inv_sub_bytes(self, state: List[List[int]]) -> List[List[int]]:
        """Apply inverse SubBytes transformation using inverse S-box."""
        return [[self.INV_SBOX[byte] for byte in row] for row in state]
    
    def shift_rows(self, state: List[List[int]]) -> List[List[int]]:
        """Apply ShiftRows transformation."""
        return [
            state[0],
            state[1][1:] + state[1][:1],
            state[2][2:] + state[2][:2],
            state[3][3:] + state[3][:3]
        ]
    
    def inv_shift_rows(self, state: List[List[int]]) -> List[List[int]]:
        """Apply inverse ShiftRows transformation."""
        return [
            state[0],
            state[1][-1:] + state[1][:-1],
            state[2][-2:] + state[2][:-2],
            state[3][-3:] + state[3][:-3]
        ]
    
    def mix_columns(self, state: List[List[int]]) -> List[List[int]]:
        """Apply MixColumns transformation."""
        def galois_mult(a: int, b: int) -> int:
            """Galois Field (2^8) multiplication."""
            p = 0
            for i in range(8):
                if b & 1:
                    p ^= a
                hi_bit_set = a & 0x80
                a <<= 1
                if hi_bit_set:
                    a ^= 0x1B  # x^8 + x^4 + x^3 + x + 1
                b >>= 1
            return p & 0xFF
        
        result = [[], [], [], []]
        for i in range(4):
            col = [state[j][i] for j in range(4)]
            result[0].append(galois_mult(0x02, col[0]) ^ galois_mult(0x03, col[1]) ^ col[2] ^ col[3])
            result[1].append(col[0] ^ galois_mult(0x02, col[1]) ^ galois_mult(0x03, col[2]) ^ col[3])
            result[2].append(col[0] ^ col[1] ^ galois_mult(0x02, col[2]) ^ galois_mult(0x03, col[3]))
            result[3].append(galois_mult(0x03, col[0]) ^ col[1] ^ col[2] ^ galois_mult(0x02, col[3]))
        
        return result
    
    def inv_mix_columns(self, state: List[List[int]]) -> List[List[int]]:
        """Apply inverse MixColumns transformation."""
        def galois_mult(a: int, b: int) -> int:
            """Galois Field (2^8) multiplication."""
            p = 0
            for i in range(8):
                if b & 1:
                    p ^= a
                hi_bit_set = a & 0x80
                a <<= 1
                if hi_bit_set:
                    a ^= 0x1B  # x^8 + x^4 + x^3 + x + 1
                b >>= 1
            return p & 0xFF
        
        result = [[], [], [], []]
        for i in range(4):
            col = [state[j][i] for j in range(4)]
            result[0].append(galois_mult(0x0E, col[0]) ^ galois_mult(0x0B, col[1]) ^ 
                             galois_mult(0x0D, col[2]) ^ galois_mult(0x09, col[3]))
            result[1].append(galois_mult(0x09, col[0]) ^ galois_mult(0x0E, col[1]) ^ 
                             galois_mult(0x0B, col[2]) ^ galois_mult(0x0D, col[3]))
            result[2].append(galois_mult(0x0D, col[0]) ^ galois_mult(0x09, col[1]) ^ 
                             galois_mult(0x0E, col[2]) ^ galois_mult(0x0B, col[3]))
            result[3].append(galois_mult(0x0B, col[0]) ^ galois_mult(0x0D, col[1]) ^ 
                             galois_mult(0x09, col[2]) ^ galois_mult(0x0E, col[3]))
        
        return result
    
    def add_round_key(self, state: List[List[int]], round_key: List[int]) -> List[List[int]]:
        """Apply AddRoundKey transformation."""
        result = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                result[i].append(state[i][j] ^ round_key[i + 4 * j])
        return result
    
    def bytes_to_state(self, data: bytes) -> List[List[int]]:
        """Convert a 16-byte block to a state matrix."""
        state = [[], [], [], []]
        for i in range(16):
            state[i % 4].append(data[i])
        return state
    
    def state_to_bytes(self, state: List[List[int]]) -> bytes:
        """Convert a state matrix to bytes."""
        result = bytearray(16)
        for i in range(4):
            for j in range(4):
                result[i + 4 * j] = state[i][j]
        return bytes(result)
    
    def encrypt_block(self, plaintext_block: bytes, key: bytes) -> bytes:
        """
        Encrypt a single 16-byte block using AES.
        
        Args:
            plaintext_block: 16-byte block to encrypt
            key: Encryption key
            
        Returns:
            bytes: Encrypted 16-byte block
        """
        if len(plaintext_block) != 16:
            raise ValueError("Plaintext block must be 16 bytes")
        
        # Expand key
        round_keys = self.key_expansion(key)
        
        # Convert plaintext to state matrix
        state = self.bytes_to_state(plaintext_block)
        
        # Initial AddRoundKey
        state = self.add_round_key(state, round_keys[0])
        
        # Main rounds
        for round_num in range(1, self.rounds):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, round_keys[round_num])
        
        # Final round (no MixColumns)
        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, round_keys[self.rounds])
        
        # Convert state back to bytes
        return self.state_to_bytes(state)
    
    def decrypt_block(self, ciphertext_block: bytes, key: bytes) -> bytes:
        """
        Decrypt a single 16-byte block using AES.
        
        Args:
            ciphertext_block: 16-byte block to decrypt
            key: Encryption key
            
        Returns:
            bytes: Decrypted 16-byte block
        """
        if len(ciphertext_block) != 16:
            raise ValueError("Ciphertext block must be 16 bytes")
        
        # Expand key
        round_keys = self.key_expansion(key)
        
        # Convert ciphertext to state matrix
        state = self.bytes_to_state(ciphertext_block)
        
        # Initial AddRoundKey (with last round key)
        state = self.add_round_key(state, round_keys[self.rounds])
        
        # Main rounds (in reverse)
        for round_num in range(self.rounds - 1, 0, -1):
            state = self.inv_shift_rows(state)
            state = self.inv_sub_bytes(state)
            state = self.add_round_key(state, round_keys[round_num])
            state = self.inv_mix_columns(state)
        
        # Final round (no InvMixColumns)
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, round_keys[0])
        
        # Convert state back to bytes
        return self.state_to_bytes(state)
    
    def ghash(self, h: bytes, data: bytes) -> bytes:
        """
        Implement GHASH function for GCM mode.
        
        Args:
            h: Hash subkey (usually encrypted zero block)
            data: Data to hash
            
        Returns:
            bytes: Authentication tag
        """
        def gf_multiply(x: int, y: int) -> int:
            """Multiply two numbers in the GF(2^128) field."""
            z = 0
            v = y
            R = 0xE1000000000000000000000000000000  # x^128 + x^7 + x^2 + x + 1
            
            for i in range(128):
                if (x >> i) & 1:
                    z ^= v
                if v & 1:
                    v = (v >> 1) ^ R
                else:
                    v >>= 1
            
            return z
        
        # Convert bytes to int for GF multiplication
        h_int = int.from_bytes(h, byteorder='big')
        
        # Pad data to 16-byte blocks
        padded_data = data
        if len(padded_data) % 16 != 0:
            padded_data += b'\x00' * (16 - (len(padded_data) % 16))
        
        # Initialize y
        y = 0
        
        # Process each block
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            block_int = int.from_bytes(block, byteorder='big')
            y ^= block_int
            y = gf_multiply(y, h_int)
        
        # Convert result back to bytes
        return y.to_bytes(16, byteorder='big')
    
    def gcm_encrypt(self, plaintext: bytes, key: bytes, nonce: bytes, auth_data: bytes = b'') -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-GCM mode.
        
        Args:
            plaintext: Data to encrypt
            key: Encryption key
            nonce: Nonce (usually 12 bytes)
            auth_data: Additional authenticated data
            
        Returns:
            Tuple[bytes, bytes]: (ciphertext, authentication tag)
        """
        # Generate counter blocks
        def inc_ctr(ctr: bytes) -> bytes:
            """Increment the last 4 bytes of counter block."""
            ctr_int = int.from_bytes(ctr, byteorder='big')
            ctr_int = (ctr_int + 1) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            return ctr_int.to_bytes(16, byteorder='big')
        
        # Generate initial counter
        if len(nonce) == 12:
            j0 = nonce + b'\x00\x00\x00\x01'
        else:
            # For nonce lengths not equal to 12 bytes (96 bits)
            s = 16 * ((len(nonce) + 15) // 16)
            padded_nonce = nonce + b'\x00' * (s - len(nonce))
            padded_nonce += (8 * len(nonce)).to_bytes(8, byteorder='big')
            j0 = self.ghash(self.encrypt_block(b'\x00' * 16, key), padded_nonce)
        
        # Generate hash subkey
        h = self.encrypt_block(b'\x00' * 16, key)
        
        # Encrypt plaintext
        ctr = inc_ctr(j0)
        ciphertext = b''
        
        for i in range(0, len(plaintext), 16):
            plaintext_block = plaintext[i:i+16]
            if len(plaintext_block) < 16:
                # Pad last block
                plaintext_block = plaintext_block.ljust(16, b'\x00')
                encrypted_block = self.encrypt_block(ctr, key)
                ciphertext += bytes(a ^ b for a, b in zip(plaintext_block, encrypted_block))[:len(plaintext_block)]
            else:
                encrypted_block = self.encrypt_block(ctr, key)
                ciphertext += bytes(a ^ b for a, b in zip(plaintext_block, encrypted_block))
            ctr = inc_ctr(ctr)
        
        # Calculate authentication tag
        len_a = len(auth_data)
        len_c = len(ciphertext)
        
        s = auth_data
        if len(s) % 16 != 0:
            s += b'\x00' * (16 - (len(s) % 16))
        
        s += ciphertext
        if len(s) % 16 != 0:
            s += b'\x00' * (16 - (len(s) % 16))
        
        s += (len_a * 8).to_bytes(8, byteorder='big')
        s += (len_c * 8).to_bytes(8, byteorder='big')
        
        t = self.ghash(h, s)
        tag = bytes(a ^ b for a, b in zip(t, self.encrypt_block(j0, key)))
        
        return ciphertext, tag
    
    def gcm_decrypt(self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, auth_data: bytes = b'') -> bytes:
        """
        Decrypt data using AES-GCM mode.
        
        Args:
            ciphertext: Data to decrypt
            key: Encryption key
            nonce: Nonce (usually 12 bytes)
            tag: Authentication tag
            auth_data: Additional authenticated data
            
        Returns:
            bytes: Decrypted data
        """
        # Generate counter blocks
        def inc_ctr(ctr: bytes) -> bytes:
            """Increment the last 4 bytes of counter block."""
            ctr_int = int.from_bytes(ctr, byteorder='big')
            ctr_int = (ctr_int + 1) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            return ctr_int.to_bytes(16, byteorder='big')
        
        # Generate initial counter
        if len(nonce) == 12:
            j0 = nonce + b'\x00\x00\x00\x01'
        else:
            # For nonce lengths not equal to 12 bytes (96 bits)
            s = 16 * ((len(nonce) + 15) // 16)
            padded_nonce = nonce + b'\x00' * (s - len(nonce))
            padded_nonce += (8 * len(nonce)).to_bytes(8, byteorder='big')
            j0 = self.ghash(self.encrypt_block(b'\x00' * 16, key), padded_nonce)
        
        # Generate hash subkey
        h = self.encrypt_block(b'\x00' * 16, key)
        
        # Verify tag
        len_a = len(auth_data)
        len_c = len(ciphertext)
        
        s = auth_data
        if len(s) % 16 != 0:
            s += b'\x00' * (16 - (len(s) % 16))
        
        s += ciphertext
        if len(s) % 16 != 0:
            s += b'\x00' * (16 - (len(s) % 16))
        
        s += (len_a * 8).to_bytes(8, byteorder='big')
        s += (len_c * 8).to_bytes(8, byteorder='big')
        
        t = self.ghash(h, s)
        expected_tag = bytes(a ^ b for a, b in zip(t, self.encrypt_block(j0, key)))
        
        if tag != expected_tag:
            raise ValueError("Authentication failed")
        
        # Decrypt ciphertext
        ctr = inc_ctr(j0)
        plaintext = b''
        
        for i in range(0, len(ciphertext), 16):
            ciphertext_block = ciphertext[i:i+16]
            if len(ciphertext_block) < 16:
                # Handle last block
                encrypted_block = self.encrypt_block(ctr, key)
                plaintext += bytes(a ^ b for a, b in zip(ciphertext_block, encrypted_block))
            else:
                encrypted_block = self.encrypt_block(ctr, key)
                plaintext += bytes(a ^ b for a, b in zip(ciphertext_block, encrypted_block))
            ctr = inc_ctr(ctr)
        
        return plaintext
    
    def encrypt(self, plaintext: bytes, key: bytes = None) -> bytes:
        """
        Encrypt data using AES-GCM.
        
        Args:
            plaintext: Data to encrypt
            key: Encryption key (optional, will use instance key if available)
            
        Returns:
            bytes: Encrypted data (nonce + ciphertext + tag)
        """
        # Use provided key or instance key
        if key is None:
            if not hasattr(self, 'key') or self.key is None:
                self.key = self.generate_key()
            key = self.key
        else:
            # Store key for future use
            self.key = key
        
        # Generate a random 12-byte nonce
        nonce = os.urandom(12)
        
        # Encrypt using GCM mode
        ciphertext, tag = self.gcm_encrypt(plaintext, key, nonce)
        
        # Return nonce + ciphertext + tag
        return nonce + ciphertext + tag
    
    def decrypt(self, ciphertext: bytes, key: bytes = None) -> bytes:
        """
        Decrypt data using AES-GCM.
        
        Args:
            ciphertext: Data to decrypt (nonce + ciphertext + tag)
            key: Encryption key (optional, will use instance key if available)
            
        Returns:
            bytes: Decrypted data
        """
        # Use provided key or instance key
        if key is None:
            if not hasattr(self, 'key') or self.key is None:
                raise ValueError("No key provided for decryption")
            key = self.key
        else:
            # Store key for future use
            self.key = key
        
        # Extract nonce, ciphertext, and tag
        nonce = ciphertext[:12]
        tag = ciphertext[-16:]
        actual_ciphertext = ciphertext[12:-16]
        
        # Decrypt using GCM mode
        return self.gcm_decrypt(actual_ciphertext, key, nonce, tag) 