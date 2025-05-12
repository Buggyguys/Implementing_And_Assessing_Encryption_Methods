"""
Handmade ChaCha20 Implementation

This module implements ChaCha20 stream cipher with Poly1305 authentication
from scratch, following RFC 8439.
"""

import os
import struct
from typing import Tuple, List, Union

class ChaCha20Handmade:
    """
    A handmade implementation of the ChaCha20 stream cipher with Poly1305 authentication.
    """
    
    def __init__(self):
        """Initialize the ChaCha20 cipher."""
        pass
    
    def generate_key(self) -> bytes:
        """
        Generate a random 32-byte key for ChaCha20.
        
        Returns:
            bytes: The generated key
        """
        return os.urandom(32)
    
    def _quarter_round(self, state: List[int], a: int, b: int, c: int, d: int) -> None:
        """
        Perform a ChaCha20 quarter round on the state.
        
        Args:
            state: The ChaCha20 state
            a, b, c, d: Indices for the quarter round operation
        """
        # a += b; d ^= a; d <<<= 16;
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = ((state[d] << 16) | (state[d] >> 16)) & 0xFFFFFFFF
        
        # c += d; b ^= c; b <<<= 12;
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = ((state[b] << 12) | (state[b] >> 20)) & 0xFFFFFFFF
        
        # a += b; d ^= a; d <<<= 8;
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = ((state[d] << 8) | (state[d] >> 24)) & 0xFFFFFFFF
        
        # c += d; b ^= c; b <<<= 7;
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = ((state[b] << 7) | (state[b] >> 25)) & 0xFFFFFFFF
    
    def _chacha20_block(self, key: bytes, counter: int, nonce: bytes) -> bytes:
        """
        Generate a ChaCha20 keystream block.
        
        Args:
            key: 32-byte key
            counter: Block counter
            nonce: 12-byte nonce
            
        Returns:
            bytes: 64-byte keystream block
        """
        # Set up the state
        state = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,  # "expand 32-byte k"
            # Key (8 words)
            *struct.unpack("<IIIIIIII", key),
            # Counter and nonce (4 words)
            counter,
            *struct.unpack("<III", nonce)
        ]
        
        # Copy the state for later XOR
        working_state = state.copy()
        
        # Apply 10 double rounds (20 rounds total)
        for _ in range(10):
            # Column rounds
            self._quarter_round(working_state, 0, 4, 8, 12)
            self._quarter_round(working_state, 1, 5, 9, 13)
            self._quarter_round(working_state, 2, 6, 10, 14)
            self._quarter_round(working_state, 3, 7, 11, 15)
            
            # Diagonal rounds
            self._quarter_round(working_state, 0, 5, 10, 15)
            self._quarter_round(working_state, 1, 6, 11, 12)
            self._quarter_round(working_state, 2, 7, 8, 13)
            self._quarter_round(working_state, 3, 4, 9, 14)
        
        # Add the working state to the initial state
        for i in range(16):
            working_state[i] = (working_state[i] + state[i]) & 0xFFFFFFFF
        
        # Convert to bytes
        result = bytearray(64)
        for i in range(16):
            struct.pack_into("<I", result, i * 4, working_state[i])
        
        return bytes(result)
    
    def _poly1305_keygen(self, key: bytes, nonce: bytes) -> bytes:
        """
        Generate a Poly1305 one-time key.
        
        Args:
            key: 32-byte key
            nonce: 12-byte nonce
            
        Returns:
            bytes: 32-byte one-time key for Poly1305
        """
        # Generate a ChaCha20 block with counter = 0
        block = self._chacha20_block(key, 0, nonce)
        
        # Return the first 32 bytes as the Poly1305 key
        return block[:32]
    
    def _poly1305_mac(self, msg: bytes, key: bytes) -> bytes:
        """
        Compute a Poly1305 message authentication code.
        
        Args:
            msg: Message to authenticate
            key: 32-byte one-time key
            
        Returns:
            bytes: 16-byte authentication tag
        """
        # Extract r and s from the key
        r = int.from_bytes(key[:16], byteorder='little')
        s = int.from_bytes(key[16:], byteorder='little')
        
        # Clamp r
        r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
        
        # Initialize accumulator
        acc = 0
        
        # Prime number for Poly1305
        p = 0x3fffffffffffffffffffffffffffffffb  # 2^130 - 5
        
        # Process message in 16-byte blocks
        for i in range(0, len(msg), 16):
            block = msg[i:i+16]
            
            # Add padding bit and convert to number
            if len(block) < 16:
                block = block + b'\x01' + b'\x00' * (15 - len(block))
            else:
                block = block + b'\x01'
            
            # Convert block to integer (little-endian)
            n = int.from_bytes(block[:16], byteorder='little')
            
            # Update accumulator: acc = (acc + n) * r % p
            acc = (acc + n) % p
            acc = (acc * r) % p
        
        # Complete the MAC: acc + s
        acc = (acc + s) % (1 << 128)
        
        # Convert to bytes (16 bytes, little-endian)
        return acc.to_bytes(16, byteorder='little')
    
    def chacha20_encrypt(self, plaintext: bytes, key: bytes, nonce: bytes, counter: int = 1) -> bytes:
        """
        Encrypt data using ChaCha20.
        
        Args:
            plaintext: Data to encrypt
            key: 32-byte encryption key
            nonce: 12-byte nonce
            counter: Initial counter value (default: 1)
            
        Returns:
            bytes: Encrypted data
        """
        ciphertext = bytearray(len(plaintext))
        
        # Process plaintext in 64-byte blocks (size of ChaCha20 keystream block)
        for i in range(0, len(plaintext), 64):
            # Generate keystream block
            keystream = self._chacha20_block(key, counter, nonce)
            
            # XOR plaintext with keystream
            block_size = min(64, len(plaintext) - i)
            for j in range(block_size):
                ciphertext[i + j] = plaintext[i + j] ^ keystream[j]
            
            # Increment counter
            counter += 1
        
        return bytes(ciphertext)
    
    def chacha20_decrypt(self, ciphertext: bytes, key: bytes, nonce: bytes, counter: int = 1) -> bytes:
        """
        Decrypt data using ChaCha20.
        
        Args:
            ciphertext: Data to decrypt
            key: 32-byte encryption key
            nonce: 12-byte nonce
            counter: Initial counter value (default: 1)
            
        Returns:
            bytes: Decrypted data
        """
        # ChaCha20 encryption and decryption are the same operation
        return self.chacha20_encrypt(ciphertext, key, nonce, counter)
    
    def chacha20_poly1305_encrypt(self, plaintext: bytes, key: bytes, nonce: bytes, aad: bytes = b'') -> Tuple[bytes, bytes]:
        """
        Encrypt and authenticate data using ChaCha20-Poly1305.
        
        Args:
            plaintext: Data to encrypt
            key: 32-byte encryption key
            nonce: 12-byte nonce
            aad: Additional authenticated data
            
        Returns:
            Tuple[bytes, bytes]: (ciphertext, tag)
        """
        # Generate Poly1305 one-time key
        poly_key = self._poly1305_keygen(key, nonce)
        
        # Encrypt plaintext
        ciphertext = self.chacha20_encrypt(plaintext, key, nonce, 1)
        
        # Compute Poly1305 tag over AAD and ciphertext
        mac_data = aad
        # Pad AAD to multiple of 16 bytes
        if len(aad) % 16:
            mac_data += b'\x00' * (16 - (len(aad) % 16))
        
        # Append ciphertext
        mac_data += ciphertext
        
        # Pad ciphertext to multiple of 16 bytes
        if len(ciphertext) % 16:
            mac_data += b'\x00' * (16 - (len(ciphertext) % 16))
        
        # Append lengths of AAD and ciphertext
        mac_data += len(aad).to_bytes(8, byteorder='little')
        mac_data += len(ciphertext).to_bytes(8, byteorder='little')
        
        # Compute tag
        tag = self._poly1305_mac(mac_data, poly_key)
        
        return ciphertext, tag
    
    def chacha20_poly1305_decrypt(self, ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes, aad: bytes = b'') -> bytes:
        """
        Decrypt and verify data using ChaCha20-Poly1305.
        
        Args:
            ciphertext: Data to decrypt
            tag: Authentication tag
            key: 32-byte encryption key
            nonce: 12-byte nonce
            aad: Additional authenticated data
            
        Returns:
            bytes: Decrypted data if authentication succeeds
            
        Raises:
            ValueError: If authentication fails
        """
        # Generate Poly1305 one-time key
        poly_key = self._poly1305_keygen(key, nonce)
        
        # Compute expected tag
        mac_data = aad
        # Pad AAD to multiple of 16 bytes
        if len(aad) % 16:
            mac_data += b'\x00' * (16 - (len(aad) % 16))
        
        # Append ciphertext
        mac_data += ciphertext
        
        # Pad ciphertext to multiple of 16 bytes
        if len(ciphertext) % 16:
            mac_data += b'\x00' * (16 - (len(ciphertext) % 16))
        
        # Append lengths of AAD and ciphertext
        mac_data += len(aad).to_bytes(8, byteorder='little')
        mac_data += len(ciphertext).to_bytes(8, byteorder='little')
        
        # Compute expected tag
        expected_tag = self._poly1305_mac(mac_data, poly_key)
        
        # Verify tag
        if not self._constant_time_compare(tag, expected_tag):
            raise ValueError("Authentication failed")
        
        # Decrypt ciphertext
        return self.chacha20_decrypt(ciphertext, key, nonce, 1)
    
    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """
        Compare two byte strings in constant time.
        
        Args:
            a, b: Byte strings to compare
            
        Returns:
            bool: True if equal, False otherwise
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        
        return result == 0
    
    def encrypt(self, plaintext: bytes, key: bytes = None) -> bytes:
        """
        Encrypt data using ChaCha20-Poly1305.
        
        Args:
            plaintext: Data to encrypt
            key: 32-byte encryption key (optional, will use instance key if available)
            
        Returns:
            bytes: Encrypted data (nonce + ciphertext + tag)
        """
        # Use provided key or generate a new one
        if key is None:
            if not hasattr(self, 'key') or self.key is None:
                self.key = self.generate_key()
            key = self.key
        else:
            # Store key for future use
            self.key = key
        
        # Generate a random 12-byte nonce
        nonce = os.urandom(12)
        
        # Encrypt and authenticate
        ciphertext, tag = self.chacha20_poly1305_encrypt(plaintext, key, nonce)
        
        # Return nonce + ciphertext + tag
        return nonce + ciphertext + tag
    
    def decrypt(self, ciphertext: bytes, key: bytes = None) -> bytes:
        """
        Decrypt data using ChaCha20-Poly1305.
        
        Args:
            ciphertext: Data to decrypt (nonce + ciphertext + tag)
            key: 32-byte encryption key (optional, will use instance key if available)
            
        Returns:
            bytes: Decrypted data
            
        Raises:
            ValueError: If authentication fails
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
        
        # Decrypt and verify
        return self.chacha20_poly1305_decrypt(actual_ciphertext, tag, key, nonce) 