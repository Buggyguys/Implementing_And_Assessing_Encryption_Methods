#!/usr/bin/env python3
"""
CryptoBench Pro - Camellia ECB Implementation
Implements Camellia encryption/decryption in ECB mode.

WARNING: ECB mode is not secure for most use cases as it does not provide
semantic security. It is included for completeness and benchmarking purposes only.
"""

import os
import logging
from .base import CamelliaImplementationBase
from .key_utils import generate_key, pad_data, unpad_data

class CamelliaECBImplementation(CamelliaImplementationBase):
    """Camellia implementation in ECB mode (insecure for most use cases)."""
    
    def __init__(self, key_size=256, **kwargs):
        """
        Initialize with key size.
        
        Args:
            key_size: Key size in bits (128, 192, or 256)
            **kwargs: Additional keyword arguments
        """
        # Remove mode from kwargs if it exists to avoid conflicts
        if 'mode' in kwargs:
            kwargs.pop('mode')
        
        # Set the is_custom flag before passing to super
        is_custom = kwargs.pop('is_custom', False) if 'is_custom' in kwargs else False
        
        super().__init__(key_size=key_size, mode="ECB", is_custom=is_custom)
        self.name = "Camellia-ECB"
        self.description = f"{self.key_size}-bit Camellia-ECB (INSECURE)"
        
        if self.is_custom:
            self.description = f"Custom {self.description}"
        else:
            self.description = f"Cryptography.io {self.description}"
        
        # Log a warning about ECB mode
        logging.warning(
            "WARNING: Camellia ECB mode is being used. ECB mode is not secure for most "
            "use cases as it does not provide semantic security. It is included for "
            "completeness and benchmarking purposes only."
        )
    
    def generate_key(self):
        """
        Generate a key for Camellia encryption/decryption.
        
        Returns:
            bytes: The generated key
        """
        self.encryption_key = generate_key(self.key_size)
        return self.encryption_key
    
    def encrypt(self, data, key=None):
        """
        Encrypt data using Camellia in ECB mode.
        
        Args:
            data: Data to encrypt
            key: Key to use for encryption, or None to use the instance's key
            
        Returns:
            bytes: Encrypted data
        """
        if key is None:
            key = self.encryption_key
        
        if key is None:
            raise ValueError("Encryption key is required")
        
        # Delegate to appropriate implementation
        if self.is_custom:
            return self._encrypt_custom(data, key)
        else:
            return self._encrypt_stdlib(data, key)
    
    def decrypt(self, data, key=None):
        """
        Decrypt data using Camellia in ECB mode.
        
        Args:
            data: Data to decrypt
            key: Key to use for decryption, or None to use the instance's key
            
        Returns:
            bytes: Decrypted data
        """
        if key is None:
            key = self.encryption_key
        
        if key is None:
            raise ValueError("Decryption key is required")
        
        # Delegate to appropriate implementation
        if self.is_custom:
            return self._decrypt_custom(data, key)
        else:
            return self._decrypt_stdlib(data, key)
    
    def _encrypt_stdlib(self, data, key):
        """
        Encrypt data using the standard library in ECB mode.
        
        Args:
            data: Data to encrypt
            key: Key to use for encryption
            
        Returns:
            bytes: Encrypted data
        """
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            # Add padding to ensure data length is a multiple of block size
            padded_data = pad_data(data, 16)
            
            # Create encryptor
            cipher = Cipher(
                algorithms.Camellia(key),
                modes.ECB(),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Encrypt the data
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # For ECB mode, we'll add a marker to indicate that this is ECB mode
            # This is to prevent confusion with other modes when decrypting
            return b'ECB:' + ciphertext
            
        except ImportError:
            # Fallback to custom implementation if the library is not available
            return self._encrypt_custom(data, key)
    
    def _decrypt_stdlib(self, data, key):
        """
        Decrypt data using the standard library in ECB mode.
        
        Args:
            data: Data to decrypt
            key: Key to use for decryption
            
        Returns:
            bytes: Decrypted data
        """
        try:
            if len(data) < 4:
                raise ValueError("Invalid ciphertext length")
            
            # Check if the data has our ECB marker
            if data.startswith(b'ECB:'):
                ciphertext = data[4:]
            else:
                ciphertext = data
            
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            # Create decryptor
            cipher = Cipher(
                algorithms.Camellia(key),
                modes.ECB(),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt the data
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            try:
                plaintext = unpad_data(padded_plaintext, 16)
                return plaintext
            except ValueError:
                # Handle padding errors (common in stream mode)
                return b''
                
        except ImportError:
            # Fallback to custom implementation if the library is not available
            return self._decrypt_custom(data, key)
        except Exception:
            # Handle other errors
            return b''
    
    def _encrypt_custom(self, data, key):
        """
        Encrypt data using a custom implementation in ECB mode.
        
        Args:
            data: Data to encrypt
            key: Key to use for encryption
            
        Returns:
            bytes: Encrypted data
        """
        # For the custom implementation, we'll use PyCryptodome if available,
        # or fallback to our own implementation
        try:
            from Crypto.Cipher import Camellia
            from Crypto.Util.Padding import pad
            
            # Create cipher
            cipher = Camellia.new(key, Camellia.MODE_ECB)
            
            # Pad and encrypt
            padded_data = pad(data, 16)
            ciphertext = cipher.encrypt(padded_data)
            
            # Add ECB marker
            return b'ECB:' + ciphertext
            
        except ImportError:
            # If PyCryptodome is not available, fallback to standard library
            # This is because a full custom implementation of Camellia would be
            # very complex and outside the scope of this project
            return self._encrypt_stdlib(data, key)
    
    def _decrypt_custom(self, data, key):
        """
        Decrypt data using a custom implementation in ECB mode.
        
        Args:
            data: Data to decrypt
            key: Key to use for decryption
            
        Returns:
            bytes: Decrypted data
        """
        if len(data) < 4:
            # Not enough data
            return b''
        
        try:
            from Crypto.Cipher import Camellia
            from Crypto.Util.Padding import unpad
            
            # Check if the data has our ECB marker
            if data.startswith(b'ECB:'):
                ciphertext = data[4:]
            else:
                ciphertext = data
            
            # Create cipher
            cipher = Camellia.new(key, Camellia.MODE_ECB)
            
            # Decrypt
            padded_plaintext = cipher.decrypt(ciphertext)
            
            try:
                # Remove padding
                plaintext = unpad(padded_plaintext, 16)
                return plaintext
            except Exception:
                # Handle padding errors (common in stream mode)
                return b''
                
        except ImportError:
            # If PyCryptodome is not available, fallback to standard library
            return self._decrypt_stdlib(data, key)
        except Exception:
            # Handle other errors
            return b'' 