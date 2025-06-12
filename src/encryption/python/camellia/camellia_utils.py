#!/usr/bin/env python3
"""
Camellia Utilities
Utility functions for padding, key generation, and other helpers.
"""

import os
import secrets

def pad_data(data, block_size):
    """
    Apply PKCS#7 padding to data.
    
    Args:
        data: Data to pad
        block_size: Block size in bytes
        
    Returns:
        bytes: Padded data
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data must be bytes or bytearray")
    
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad_data(padded_data, block_size):
    """
    Remove PKCS#7 padding from data.
    
    Args:
        padded_data: Padded data
        block_size: Block size in bytes
        
    Returns:
        bytes: Unpadded data
        
    Raises:
        ValueError: If padding is invalid
    """
    if not isinstance(padded_data, (bytes, bytearray)):
        raise TypeError("Data must be bytes or bytearray")
    
    if len(padded_data) == 0:
        raise ValueError("Cannot unpad empty data")
    
    if len(padded_data) % block_size != 0:
        raise ValueError("Padded data length must be multiple of block size")
    
    padding_length = padded_data[-1]
    
    if padding_length == 0 or padding_length > block_size:
        raise ValueError("Invalid padding length")
    
    if len(padded_data) < padding_length:
        raise ValueError("Invalid padding length")
    
    # Check that all padding bytes are correct
    for i in range(padding_length):
        if padded_data[-(i + 1)] != padding_length:
            raise ValueError("Invalid padding")
    
    return padded_data[:-padding_length]

def generate_key(key_size_bits):
    """
    Generate a random key of specified size.
    
    Args:
        key_size_bits: Key size in bits (128, 192, or 256)
        
    Returns:
        bytes: Random key
        
    Raises:
        ValueError: If key size is invalid
    """
    if key_size_bits not in [128, 192, 256]:
        raise ValueError(f"Invalid key size: {key_size_bits} bits. Must be 128, 192, or 256.")
    
    key_size_bytes = key_size_bits // 8
    return secrets.token_bytes(key_size_bytes)

def generate_iv():
    """
    Generate a random 16-byte initialization vector.
    
    Returns:
        bytes: Random IV
    """
    return secrets.token_bytes(16)

def bytes_to_int(data):
    """
    Convert bytes to integer (big-endian).
    
    Args:
        data: Bytes to convert
        
    Returns:
        int: Integer value
    """
    return int.from_bytes(data, 'big')

def int_to_bytes(value, length):
    """
    Convert integer to bytes (big-endian).
    
    Args:
        value: Integer value
        length: Number of bytes
        
    Returns:
        bytes: Byte representation
    """
    return value.to_bytes(length, 'big')

def xor_bytes(a, b):
    """
    XOR two byte strings.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        bytes: XOR result
        
    Raises:
        ValueError: If lengths don't match
    """
    if len(a) != len(b):
        raise ValueError("Byte strings must have same length")
    
    return bytes(x ^ y for x, y in zip(a, b))

def validate_key_size(key):
    """
    Validate that key size is supported.
    
    Args:
        key: Key bytes
        
    Raises:
        ValueError: If key size is invalid
    """
    key_size_bits = len(key) * 8
    if key_size_bits not in [128, 192, 256]:
        raise ValueError(f"Invalid key size: {key_size_bits} bits. Must be 128, 192, or 256.")

def validate_iv(iv):
    """
    Validate that IV is correct size.
    
    Args:
        iv: Initialization vector
        
    Raises:
        ValueError: If IV size is invalid
    """
    if len(iv) != 16:
        raise ValueError("IV must be exactly 16 bytes")

def validate_block_size(data, block_size=16):
    """
    Validate that data is correct block size.
    
    Args:
        data: Data to validate
        block_size: Expected block size
        
    Raises:
        ValueError: If data size is invalid
    """
    if len(data) % block_size != 0:
        raise ValueError(f"Data length must be multiple of {block_size} bytes") 