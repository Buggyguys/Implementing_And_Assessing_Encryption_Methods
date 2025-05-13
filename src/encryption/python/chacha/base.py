#!/usr/bin/env python3
"""
CryptoBench Pro - ChaCha20 Base Implementation
Provides the base class for ChaCha20 implementations and common utilities.
"""

import os
import hashlib

# Maximum input size for ChaCha20 (for efficient memory usage)
MAX_INPUT_SIZE = 16 * 1024 * 1024  # 16MB chunks for processing larger data

class ChaCha20ImplementationBase:
    """Base class for ChaCha20 implementations."""
    
    def __init__(self, key_size="256", **kwargs):
        """Initialize with key size."""
        self.key_size = int(key_size)
        self.name = "ChaCha20"
        self.description = f"ChaCha20 with {key_size}-bit key"
        self.key = None
        self.nonce = None
    
    def _format_key_size(self, size_bits):
        """Convert key size in bits to bytes."""
        return size_bits // 8
    
    def generate_key(self):
        """Generate a random key of the specified size."""
        # ChaCha20 uses 256-bit (32-byte) keys, but we'll support different sizes for KDF
        key_bytes = self._format_key_size(self.key_size)
        
        # Validate key size
        if key_bytes not in (16, 24, 32):  # 128, 192, or 256 bits
            # Standard is 256 bits, but we'll allow other sizes for benchmarking
            key_bytes = 32  # Default to 256 bits if invalid size
        
        # Generate a high-quality random key
        self.key = os.urandom(key_bytes)
        
        # Key derivation (optional, for benchmarking purpose)
        # In a real implementation, you might want to use a secure KDF
        if hasattr(self, 'use_kdf') and self.use_kdf:
            salt = os.urandom(16)
            key_material = hashlib.pbkdf2_hmac('sha256', self.key, salt, 10000, dklen=32)  # Always 32 bytes for ChaCha20
            self.key = key_material
            
        return self.key
    
    def encrypt(self, data, key):
        """Encrypt data using the specified key. Should be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement this method")
    
    def decrypt(self, ciphertext, key):
        """Decrypt data using the specified key. Should be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement this method") 