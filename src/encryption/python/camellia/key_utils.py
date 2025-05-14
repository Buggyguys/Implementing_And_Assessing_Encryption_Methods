#!/usr/bin/env python3
"""
CryptoBench Pro - Camellia Key Utilities
Provides key generation and management functions for Camellia.
"""

import os
import hashlib
import hmac
import secrets

def generate_key(key_size=256):
    """
    Generate a random key of the specified size.
    
    Args:
        key_size: Key size in bits (128, 192, or 256)
        
    Returns:
        bytes: Random key
    """
    if key_size not in [128, 192, 256]:
        raise ValueError(f"Invalid key size: {key_size}. Must be 128, 192, or 256 bits.")
    
    # Generate random bytes for the key
    key_bytes = key_size // 8
    return os.urandom(key_bytes)

def derive_key(master_key, salt=None, key_size=256, info=b''):
    """
    Derive a key using HKDF-like construction.
    
    Args:
        master_key: Master key to derive from
        salt: Optional salt
        key_size: Size of derived key in bits
        info: Optional context/application specific information
        
    Returns:
        bytes: Derived key
    """
    if key_size not in [128, 192, 256]:
        raise ValueError(f"Invalid key size: {key_size}. Must be 128, 192, or 256 bits.")
    
    # Use a salt if provided, otherwise use a zero-filled byte string
    if salt is None:
        salt = b'\x00' * 32
    
    # Extract phase - create a pseudorandom key using the master key and salt
    prk = hmac.new(salt, master_key, hashlib.sha256).digest()
    
    # Expand phase - expand the pseudorandom key to desired length
    key_bytes = key_size // 8
    derived_key = b''
    output = b''
    i = 1
    
    while len(derived_key) < key_bytes:
        output = hmac.new(prk, output + info + bytes([i]), hashlib.sha256).digest()
        derived_key += output
        i += 1
    
    return derived_key[:key_bytes]

def pad_data(data, block_size=16):
    """
    Pad data using PKCS#7 padding.
    
    Args:
        data: Data to pad
        block_size: Block size in bytes
        
    Returns:
        bytes: Padded data
    """
    pad_length = block_size - (len(data) % block_size)
    padding = bytes([pad_length]) * pad_length
    return data + padding

def unpad_data(data, block_size=16):
    """
    Remove PKCS#7 padding from data.
    
    Args:
        data: Padded data
        block_size: Block size in bytes
        
    Returns:
        bytes: Unpadded data
    """
    if not data:
        return data
    
    # Get the padding length from the last byte
    pad_length = data[-1]
    
    # Validate the padding
    if pad_length > block_size or pad_length == 0:
        raise ValueError("Invalid padding")
    
    # Check that all padding bytes are correct
    if data[-pad_length:] != bytes([pad_length]) * pad_length:
        raise ValueError("Invalid padding")
    
    return data[:-pad_length]

def add_chunk_delimiter(chunk_data, chunk_index=0):
    """
    Add a delimiter to a chunk for stream mode processing.
    Format: 4 bytes for chunk index + 4 bytes for chunk length
    
    Args:
        chunk_data: Data chunk to delimit
        chunk_index: Index of this chunk in the sequence
        
    Returns:
        bytes: Delimited chunk data
    """
    chunk_header = chunk_index.to_bytes(4, byteorder='big') + len(chunk_data).to_bytes(4, byteorder='big')
    return chunk_header + chunk_data

def split_delimited_chunks(combined_data):
    """
    Split combined data back into original chunks based on delimiters.
    
    Args:
        combined_data: Combined data with delimiters
        
    Returns:
        list: List of (chunk_index, chunk_data) tuples
    """
    chunks = []
    offset = 0
    
    while offset + 8 <= len(combined_data):
        chunk_index = int.from_bytes(combined_data[offset:offset+4], byteorder='big')
        chunk_length = int.from_bytes(combined_data[offset+4:offset+8], byteorder='big')
        
        if offset + 8 + chunk_length > len(combined_data):
            break  # Incomplete chunk
            
        chunk_data = combined_data[offset+8:offset+8+chunk_length]
        chunks.append((chunk_index, chunk_data))
        
        offset += 8 + chunk_length
    
    return chunks 