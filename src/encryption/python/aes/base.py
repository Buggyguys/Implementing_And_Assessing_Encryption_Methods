#!/usr/bin/env python3
"""
CryptoBench Pro - AES Base Implementation
Provides the base class for AES implementations and common utilities.
"""

import os
import hashlib

# Maximum input size for AES (increased for better memory efficiency)
MAX_INPUT_SIZE = 16 * 1024 * 1024  # 16MB chunks for processing larger data

class AESImplementationBase:
    """Base class for AES implementations."""
    
    def __init__(self, key_size="256", mode="GCM", **kwargs):
        """Initialize with key size and mode of operation."""
        self.key_size = int(key_size)
        self.mode = mode
        self.name = "AES"
        self.description = f"AES-{key_size} in {mode} mode"
        self.key = None
        self.iv = None
        self.tag = None
    
    def _format_key_size(self, size_bits):
        """Convert key size in bits to bytes."""
        return size_bits // 8
    
    def generate_key(self):
        """Generate a random key of the specified size."""
        key_bytes = self._format_key_size(self.key_size)
        
        # Validate key size
        if key_bytes not in (16, 24, 32):  # 128, 192, or 256 bits
            raise ValueError(f"Invalid key size: {self.key_size} bits. Must be 128, 192, or 256 bits.")
        
        # Generate a high-quality random key
        self.key = os.urandom(key_bytes)
        
        # Key derivation (optional, for benchmarking purpose)
        # In a real implementation, you might want to use a secure KDF
        # This simple demonstration uses a single-pass hash
        if hasattr(self, 'use_kdf') and self.use_kdf:
            salt = os.urandom(16)
            key_material = hashlib.pbkdf2_hmac('sha256', self.key, salt, 10000, dklen=key_bytes)
            self.key = key_material
            
        return self.key
    
    def encrypt(self, data, key):
        """Encrypt data using the specified key. Should be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement this method")
    
    def decrypt(self, ciphertext, key):
        """Decrypt data using the specified key. Should be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement this method") 