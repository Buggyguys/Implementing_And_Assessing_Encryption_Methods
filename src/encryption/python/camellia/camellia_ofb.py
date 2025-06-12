#!/usr/bin/env python3
"""
CryptoBench Pro - Camellia OFB Implementation
Implements Camellia encryption/decryption in OFB mode.
"""

import os
from .base import CamelliaImplementationBase
from .key_utils import generate_key
import logging

class CamelliaOFBImplementation(CamelliaImplementationBase):
    """Camellia implementation in OFB mode."""
    
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
        
        super().__init__(key_size=key_size, mode="OFB", is_custom=is_custom)
        self.name = "Camellia-OFB"
        self.description = f"{self.key_size}-bit Camellia-OFB"
        
        if self.is_custom:
            self.description = f"Custom {self.description}"
        else:
            self.description = f"Cryptography.io {self.description}"
    
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
        Encrypt data using Camellia in OFB mode.
        
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
        Decrypt data using Camellia in OFB mode.
        
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
        Encrypt data using the standard library in OFB mode.
        
        Args:
            data: Data to encrypt
            key: Key to use for encryption
            
        Returns:
            bytes: Encrypted data
        """
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            # Generate a random IV
            iv = os.urandom(16)
            
            # Create cipher
            cipher = Cipher(
                algorithms.Camellia(key),
                modes.OFB(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Encrypt the data
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            # Return the IV + ciphertext
            return iv + ciphertext
            
        except ImportError:
            logging.error("cryptography.io library not available for Camellia OFB")
            raise NotImplementedError("Camellia OFB mode requires cryptography.io library")
        except Exception as e:
            logging.error(f"Error in OFB encrypt: {str(e)}")
            return b''
    
    def _decrypt_stdlib(self, data, key):
        """
        Decrypt data using the standard library in OFB mode.
        
        Args:
            data: Data to decrypt
            key: Key to use for decryption
            
        Returns:
            bytes: Decrypted data
        """
        if len(data) < 16:
            return b''  # Not enough data for IV
        
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            # Extract IV and ciphertext
            iv = data[:16]
            ciphertext = data[16:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.Camellia(key),
                modes.OFB(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt the data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext
            
        except ImportError:
            logging.error("cryptography.io library not available for Camellia OFB")
            raise NotImplementedError("Camellia OFB mode requires cryptography.io library")
        except Exception as e:
            logging.error(f"Error in OFB decrypt: {str(e)}")
            return b''
    
    def _encrypt_custom(self, data, key):
        """
        Encrypt data using custom Camellia implementation in OFB mode.
        
        Args:
            data: Data to encrypt
            key: Key to use for encryption
            
        Returns:
            bytes: Encrypted data
        """
        try:
            from .custom_camellia import camellia_encrypt_ofb
            
            # Generate a random IV
            iv = os.urandom(16)
            
            # Encrypt using custom implementation
            ciphertext = camellia_encrypt_ofb(data, key, iv)
            
            # Return the IV + ciphertext
            return iv + ciphertext
            
        except ImportError as e:
            logging.error(f"Custom Camellia implementation not available: {str(e)}")
            # Fallback to standard library
            return self._encrypt_stdlib(data, key)
        except Exception as e:
            logging.error(f"Error in custom OFB encrypt: {str(e)}")
            return b''
    
    def _decrypt_custom(self, data, key):
        """
        Decrypt data using custom Camellia implementation in OFB mode.
        
        Args:
            data: Data to decrypt
            key: Key to use for decryption
            
        Returns:
            bytes: Decrypted data
        """
        if len(data) < 16:
            return b''  # Not enough data for IV
        
        try:
            from .custom_camellia import camellia_decrypt_ofb
            
            # Extract IV and ciphertext
            iv = data[:16]
            ciphertext = data[16:]
            
            # Decrypt using custom implementation
            plaintext = camellia_decrypt_ofb(ciphertext, key, iv)
            
            return plaintext
            
        except ImportError as e:
            logging.error(f"Custom Camellia implementation not available: {str(e)}")
            # Fallback to standard library
            return self._decrypt_stdlib(data, key)
        except Exception as e:
            logging.error(f"Error in custom OFB decrypt: {str(e)}")
            return b'' 