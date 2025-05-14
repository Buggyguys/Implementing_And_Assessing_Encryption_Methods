#!/usr/bin/env python3
"""
CryptoBench Pro - Camellia Base Implementation
Provides the base class for Camellia implementations.
"""

from abc import ABC, abstractmethod

class CamelliaImplementationBase(ABC):
    """Base class for Camellia implementations."""
    
    def __init__(self, key_size=256, mode="GCM", is_custom=False):
        """
        Initialize the base class with key size and mode.
        
        Args:
            key_size: Key size in bits (128, 192, or 256)
            mode: Mode of operation (CBC, CTR, GCM, ECB)
            is_custom: Whether to use custom implementation
        """
        self.key_size = int(key_size)
        self.mode = mode.upper()
        self.is_custom = is_custom
        
        # Initialize keys
        self.encryption_key = None
        self.public_key = None
        self.private_key = None
    
    @abstractmethod
    def generate_key(self):
        """Generate a key for encryption/decryption."""
        pass
    
    @abstractmethod
    def encrypt(self, data, key=None):
        """
        Encrypt data using Camellia.
        
        Args:
            data: Data to encrypt
            key: Key to use for encryption, or None to use the instance's key
            
        Returns:
            bytes: Encrypted data
        """
        pass
    
    @abstractmethod
    def decrypt(self, data, key=None):
        """
        Decrypt data using Camellia.
        
        Args:
            data: Data to decrypt
            key: Key to use for decryption, or None to use the instance's key
            
        Returns:
            bytes: Decrypted data
        """
        pass 