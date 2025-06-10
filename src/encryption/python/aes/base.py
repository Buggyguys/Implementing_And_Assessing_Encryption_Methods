#!/usr/bin/env python3
"""
CryptoBench Pro - AES Base Implementation
Provides the base class for AES implementations and common utilities.
"""

from .key_utils import generate_key, generate_custom_key

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
        self.use_kdf = kwargs.get('use_kdf', False)
        self.is_custom = kwargs.get('is_custom', False)
    
    def generate_key(self):
        """Generate a random key of the specified size."""
        # Delegate key generation to the appropriate utility function
        if self.is_custom:
            self.key = generate_custom_key(self.key_size, self.use_kdf)
        else:
            self.key = generate_key(self.key_size, self.use_kdf)
        return self.key
    
    def encrypt(self, data, key):
        """Encrypt data using the specified key. Should be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement this method")
    
    def decrypt(self, ciphertext, key):
        """Decrypt data using the specified key. Should be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement this method") 