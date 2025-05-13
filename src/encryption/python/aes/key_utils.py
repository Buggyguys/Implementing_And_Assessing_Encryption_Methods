#!/usr/bin/env python3
"""
CryptoBench Pro - AES Key Utilities
Provides key generation and management functions for AES implementations.
"""

import os
import hashlib
import secrets

def format_key_size(size_bits):
    """Convert key size in bits to bytes."""
    return size_bits // 8

def generate_key(key_size=256, use_kdf=False):
    """
    Generate a random key of the specified size using standard library methods.
    
    Args:
        key_size: Key size in bits (128, 192, or 256)
        use_kdf: Whether to apply a key derivation function
        
    Returns:
        bytes: The generated key
    """
    key_bytes = format_key_size(key_size)
    
    # Validate key size
    if key_bytes not in (16, 24, 32):  # 128, 192, or 256 bits
        raise ValueError(f"Invalid key size: {key_size} bits. Must be 128, 192, or 256 bits.")
    
    # Generate a high-quality random key
    key = os.urandom(key_bytes)
    
    # Key derivation (optional, for benchmarking purpose)
    if use_kdf:
        salt = os.urandom(16)
        key_material = hashlib.pbkdf2_hmac('sha256', key, salt, 10000, dklen=key_bytes)
        key = key_material
        
    return key

def generate_custom_key(key_size=256, use_kdf=False):
    """
    Generate a random key of the specified size using our custom implementation.
    This is a simplified version for demonstration purposes.
    
    Args:
        key_size: Key size in bits (128, 192, or 256)
        use_kdf: Whether to apply a key derivation function
        
    Returns:
        bytes: The generated key
    """
    key_bytes = format_key_size(key_size)
    
    # Validate key size
    if key_bytes not in (16, 24, 32):  # 128, 192, or 256 bits
        raise ValueError(f"Invalid key size: {key_size} bits. Must be 128, 192, or 256 bits.")
    
    # Custom random key generation
    # In a real custom implementation, you might use a different source of randomness
    # or implement your own PRNG algorithm. For this example, we're still using
    # a cryptographically secure method from the standard library.
    key = bytes(secrets.randbits(8) for _ in range(key_bytes))
    
    # Custom key derivation (optional)
    if use_kdf:
        # Simple custom KDF implementation
        # In a real scenario, you would implement a more secure custom KDF
        derived_key = bytearray(key_bytes)
        salt = bytes(secrets.randbits(8) for _ in range(16))
        
        # A basic key stretching technique (not recommended for production)
        for i in range(1000):
            temp = salt + key + i.to_bytes(4, 'big')
            hash_result = hashlib.sha256(temp).digest()
            for j in range(key_bytes):
                derived_key[j] ^= hash_result[j % 32]
        
        key = bytes(derived_key)
        
    return key

def get_iv(mode, custom=False):
    """
    Generate an appropriate initialization vector based on the AES mode.
    
    Args:
        mode: AES mode of operation (CBC, CTR, GCM, ECB)
        custom: Whether to use the custom IV generation (default: False)
        
    Returns:
        bytes: The generated IV/nonce
    """
    if custom:
        return get_custom_iv(mode)
    else:
        return get_stdlib_iv(mode)

def get_stdlib_iv(mode):
    """
    Generate an initialization vector using standard library methods.
    
    Args:
        mode: AES mode of operation (CBC, CTR, GCM, ECB)
        
    Returns:
        bytes: The generated IV/nonce
    """
    # Generate a standard 16-byte IV
    iv = os.urandom(16)
    
    # Return appropriate length based on mode
    if mode == "GCM":
        return iv[:12]  # 12 bytes for GCM
    elif mode == "CTR":
        return iv       # 16 bytes, but only first 8 used as nonce
    else:
        return iv       # 16 bytes for CBC/ECB

def get_custom_iv(mode):
    """
    Generate an initialization vector using custom methods.
    
    Args:
        mode: AES mode of operation (CBC, CTR, GCM, ECB)
        
    Returns:
        bytes: The generated IV/nonce
    """
    # Generate a 16-byte IV using our custom random generation
    iv = bytes(secrets.randbits(8) for _ in range(16))
    
    # Return appropriate length based on mode
    if mode == "GCM":
        return iv[:12]  # 12 bytes for GCM
    elif mode == "CTR":
        return iv       # 16 bytes, but only first 8 used as nonce
    else:
        return iv       # 16 bytes for CBC/ECB 