#!/usr/bin/env python3
"""
CryptoBench Pro - Custom ChaCha20 Implementation
Provides a custom implementation of the ChaCha20 cipher without external dependencies.
"""

import struct
import hashlib
import binascii
import os
from typing import List, Tuple, Optional

# ChaCha20 block function constants
CHACHA_CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]  # "expand 32-byte k"


def _rotate_left(value: int, shift: int) -> int:
    """Rotate a 32-bit integer left by shift bits."""
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def _quarter_round(state: List[int], a: int, b: int, c: int, d: int) -> None:
    """Perform a ChaCha20 quarter round on 4 state elements."""
    # a += b; d ^= a; d <<<= 16;
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotate_left(state[d], 16)
    
    # c += d; b ^= c; b <<<= 12;
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotate_left(state[b], 12)
    
    # a += b; d ^= a; d <<<= 8;
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotate_left(state[d], 8)
    
    # c += d; b ^= c; b <<<= 7;
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotate_left(state[b], 7)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Generate a ChaCha20 block."""
    # Initialize state
    state = CHACHA_CONSTANTS.copy()
    
    # Add key (8 words = 32 bytes)
    for i in range(8):
        state.append(struct.unpack("<I", key[i*4:i*4+4])[0])
    
    # Add counter (1 word = 4 bytes)
    state.append(counter)
    
    # Add nonce (3 words = 12 bytes)
    for i in range(3):
        state.append(struct.unpack("<I", nonce[i*4:i*4+4])[0])
    
    # Copy the initial state
    working_state = state.copy()
    
    # Perform 20 rounds (10 double rounds)
    for _ in range(10):
        # Column rounds
        _quarter_round(working_state, 0, 4, 8, 12)
        _quarter_round(working_state, 1, 5, 9, 13)
        _quarter_round(working_state, 2, 6, 10, 14)
        _quarter_round(working_state, 3, 7, 11, 15)
        
        # Diagonal rounds
        _quarter_round(working_state, 0, 5, 10, 15)
        _quarter_round(working_state, 1, 6, 11, 12)
        _quarter_round(working_state, 2, 7, 8, 13)
        _quarter_round(working_state, 3, 4, 9, 14)
    
    # Add initial state to the final state
    for i in range(16):
        working_state[i] = (working_state[i] + state[i]) & 0xFFFFFFFF
    
    # Convert state to bytes
    output = bytearray(64)
    for i in range(16):
        struct.pack_into("<I", output, i * 4, working_state[i])
    
    return bytes(output)


def chacha20_encrypt(plaintext: bytes, key: bytes, nonce: bytes, initial_counter: int = 0) -> bytes:
    """Encrypt plaintext using ChaCha20."""
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes")
    
    ciphertext = bytearray(len(plaintext))
    counter = initial_counter
    
    for i in range(0, len(plaintext), 64):
        block = _chacha20_block(key, counter, nonce)
        counter += 1
        
        # XOR block with plaintext
        j = 0
        while j < 64 and i + j < len(plaintext):
            ciphertext[i + j] = plaintext[i + j] ^ block[j]
            j += 1
    
    return bytes(ciphertext)


def chacha20_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, initial_counter: int = 0) -> bytes:
    """Decrypt ciphertext using ChaCha20 (same as encryption)."""
    return chacha20_encrypt(ciphertext, key, nonce, initial_counter)


def poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    """Generate a Poly1305 one-time key from the ChaCha20 key and nonce."""
    # Use counter 0 to generate the Poly1305 key
    poly_key = _chacha20_block(key, 0, nonce)
    # Return the first 32 bytes as the Poly1305 key
    return poly_key[:32]


def _le_bytes_to_num(data: bytes) -> int:
    """Convert little-endian bytes to an integer."""
    return int.from_bytes(data, byteorder='little')


def _num_to_le_bytes(num: int, length: int) -> bytes:
    """Convert an integer to little-endian bytes of specified length."""
    return num.to_bytes(length, byteorder='little')


def _clamp(r: bytes) -> bytes:
    """Clamp the Poly1305 'r' value according to the spec."""
    r_clamped = bytearray(r)
    r_clamped[3] &= 15  # Clear high 4 bits
    r_clamped[7] &= 15
    r_clamped[11] &= 15
    r_clamped[15] &= 15
    r_clamped[4] &= 252  # Clear low 2 bits
    r_clamped[8] &= 252
    r_clamped[12] &= 252
    return bytes(r_clamped)


def poly1305_mac(msg: bytes, key: bytes) -> bytes:
    """Compute a Poly1305 MAC for the given message and key."""
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")
    
    # Split the key into r and s parts
    r = _clamp(key[:16])
    s = key[16:32]
    
    # Convert to integers
    r_int = _le_bytes_to_num(r)
    s_int = _le_bytes_to_num(s)
    
    # Poly1305 prime: 2^130 - 5
    p = (1 << 130) - 5
    
    # Initialize accumulator
    acc = 0
    
    # Process message in 16-byte blocks
    for i in range(0, len(msg), 16):
        block = msg[i:i+16]
        
        # Convert block to number and add the 1 bit at the end
        if len(block) == 16:
            block_int = _le_bytes_to_num(block) + (1 << 128)
        else:
            # Padding for the last partial block
            block_padded = bytearray(block)
            block_padded.append(1)  # Add the 1 bit
            block_padded.extend(b'\x00' * (16 - len(block) - 1))  # Zero pad to 16 bytes
            block_int = _le_bytes_to_num(bytes(block_padded))
        
        # Update accumulator: acc = (acc + block) * r % p
        acc = (acc + block_int) % p
        acc = (acc * r_int) % p
    
    # Finalize: acc = acc + s
    acc = (acc + s_int) % (1 << 128)
    
    # Convert back to bytes
    return _num_to_le_bytes(acc, 16)


def chacha20_poly1305_encrypt(plaintext: bytes, key: bytes, nonce: bytes, aad: bytes = b'') -> Tuple[bytes, bytes]:
    """Encrypt plaintext using ChaCha20-Poly1305."""
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes")
    
    # Generate Poly1305 key
    poly_key = poly1305_key_gen(key, nonce)
    
    # Encrypt plaintext with ChaCha20 using counter 1
    ciphertext = chacha20_encrypt(plaintext, key, nonce, 1)
    
    # Prepare data for Poly1305 MAC
    mac_data = bytearray()
    mac_data.extend(aad)
    # Pad AAD to multiple of 16
    if len(aad) % 16 != 0:
        mac_data.extend(b'\x00' * (16 - (len(aad) % 16)))
    
    mac_data.extend(ciphertext)
    # Pad ciphertext to multiple of 16
    if len(ciphertext) % 16 != 0:
        mac_data.extend(b'\x00' * (16 - (len(ciphertext) % 16)))
    
    # Append lengths
    mac_data.extend(_num_to_le_bytes(len(aad), 8))
    mac_data.extend(_num_to_le_bytes(len(ciphertext), 8))
    
    # Compute MAC
    tag = poly1305_mac(mac_data, poly_key)
    
    return ciphertext, tag


def chacha20_poly1305_decrypt(ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes, aad: bytes = b'') -> Optional[bytes]:
    """Decrypt ciphertext using ChaCha20-Poly1305."""
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")
    
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes")
    
    if len(tag) != 16:
        raise ValueError("Poly1305 tag must be 16 bytes")
    
    # Generate Poly1305 key
    poly_key = poly1305_key_gen(key, nonce)
    
    # Prepare data for Poly1305 MAC
    mac_data = bytearray()
    mac_data.extend(aad)
    # Pad AAD to multiple of 16
    if len(aad) % 16 != 0:
        mac_data.extend(b'\x00' * (16 - (len(aad) % 16)))
    
    mac_data.extend(ciphertext)
    # Pad ciphertext to multiple of 16
    if len(ciphertext) % 16 != 0:
        mac_data.extend(b'\x00' * (16 - (len(ciphertext) % 16)))
    
    # Append lengths
    mac_data.extend(_num_to_le_bytes(len(aad), 8))
    mac_data.extend(_num_to_le_bytes(len(ciphertext), 8))
    
    # Compute and verify MAC
    expected_tag = poly1305_mac(mac_data, poly_key)
    if not bytes_equal(expected_tag, tag):
        return None  # Authentication failed
    
    # Decrypt ciphertext with ChaCha20 using counter 1
    plaintext = chacha20_decrypt(ciphertext, key, nonce, 1)
    
    return plaintext


def bytes_equal(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time."""
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0


class CustomChaCha20:
    """Custom implementation of ChaCha20 algorithm."""
    
    def __init__(self):
        """Initialize the implementation."""
        self.nonce = None
    
    def encrypt(self, plaintext: bytes, key: bytes, nonce: Optional[bytes] = None, aad: bytes = b'') -> Tuple[bytes, Optional[bytes]]:
        """Encrypt plaintext using ChaCha20, returning encrypted data and None for tag."""
        if not nonce:
            nonce = os.urandom(12)
        
        # Store nonce for reference
        self.nonce = nonce
        
        # Encrypt the plaintext
        ciphertext = chacha20_encrypt(plaintext, key, nonce)
        
        # Return tuple of (nonce + ciphertext, None)
        return nonce + ciphertext, None
    
    def decrypt(self, ciphertext: bytes, key: bytes, tag: Optional[bytes] = None, aad: bytes = b'') -> Optional[bytes]:
        """Decrypt ciphertext using ChaCha20."""
        # Extract nonce from ciphertext
        nonce = ciphertext[:12]
        actual_ciphertext = ciphertext[12:]
        
        # Decrypt the ciphertext
        return chacha20_decrypt(actual_ciphertext, key, nonce) 