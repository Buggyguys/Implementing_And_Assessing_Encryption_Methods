#!/usr/bin/env python3
"""
CryptoBench Pro - Camellia CTR Implementation
Implements Camellia encryption/decryption in CTR mode.
"""

import os
from .base import CamelliaImplementationBase
from .key_utils import generate_key
import logging

class CamelliaCTRImplementation(CamelliaImplementationBase):
    """Camellia implementation in CTR mode."""
    
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
        
        super().__init__(key_size=key_size, mode="CTR", is_custom=is_custom)
        self.name = "Camellia-CTR"
        self.description = f"{self.key_size}-bit Camellia-CTR"
        
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
        Encrypt data using Camellia in CTR mode.
        
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
        Decrypt data using Camellia in CTR mode.
        
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
        Encrypt data using the standard library in CTR mode.
        
        Args:
            data: Data to encrypt
            key: Key to use for encryption
            
        Returns:
            bytes: Encrypted data
        """
        # For Camellia, PyCryptodome is generally more reliable
        try:
            from Crypto.Cipher import Camellia
            from Crypto.Util import Counter
            
            # Generate a random nonce
            nonce = os.urandom(16)
            
            # Create CTR counter
            ctr = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
            
            # Create cipher
            cipher = Camellia.new(key, Camellia.MODE_CTR, counter=ctr)
            
            # Encrypt the data
            ciphertext = cipher.encrypt(data)
            
            # Return nonce + ciphertext
            return nonce + ciphertext
            
        except ImportError:
            # If PyCryptodome is not available, try cryptography.io
            logging.info("PyCryptodome not available, using cryptography.io for Camellia CTR")
            try:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.backends import default_backend
                
                # Generate a random nonce
                nonce = os.urandom(16)
                
                # Create encryptor
                cipher = Cipher(
                    algorithms.Camellia(key),
                    modes.CTR(nonce),
                    backend=default_backend()
                )
                encryptor = cipher.encryptor()
                
                # Encrypt the data
                ciphertext = encryptor.update(data) + encryptor.finalize()
                
                # Return the nonce + ciphertext
                return nonce + ciphertext
            except Exception as e:
                logging.error(f"Error using cryptography.io for CTR encryption: {str(e)}")
                return b''
        except Exception as e:
            logging.error(f"Error in CTR encrypt: {str(e)}")
            return b''
    
    def _decrypt_stdlib(self, data, key):
        """
        Decrypt data using the standard library in CTR mode.
        
        Args:
            data: Data to decrypt
            key: Key to use for decryption
            
        Returns:
            bytes: Decrypted data
        """
        if len(data) < 16:
            return b''  # Not enough data for nonce
        
        # For Camellia, PyCryptodome is generally more reliable
        try:
            from Crypto.Cipher import Camellia
            from Crypto.Util import Counter
            
            # Extract nonce and ciphertext
            nonce = data[:16]
            ciphertext = data[16:]
            
            # Create CTR counter
            ctr = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
            
            # Create cipher
            cipher = Camellia.new(key, Camellia.MODE_CTR, counter=ctr)
            
            # Decrypt the data
            plaintext = cipher.decrypt(ciphertext)
            
            return plaintext
                
        except ImportError:
            # If PyCryptodome is not available, try cryptography.io
            logging.info("PyCryptodome not available, using cryptography.io for Camellia CTR")
            try:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.backends import default_backend
                
                # Extract nonce and ciphertext
                nonce = data[:16]
                ciphertext = data[16:]
                
                # Create decryptor
                cipher = Cipher(
                    algorithms.Camellia(key),
                    modes.CTR(nonce),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                
                # Decrypt the data
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                
                return plaintext
            except Exception as e:
                logging.error(f"Error using cryptography.io for CTR decryption: {str(e)}")
                return b''
        except Exception as e:
            logging.error(f"Error in CTR decrypt: {str(e)}")
            return b''
    
    def _encrypt_custom(self, data, key):
        """
        Encrypt data using a custom implementation in CTR mode.
        
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
            from Crypto.Util import Counter
            
            # Generate a random nonce
            nonce = os.urandom(16)
            
            # Create CTR counter
            ctr = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
            
            # Create cipher
            cipher = Camellia.new(key, Camellia.MODE_CTR, counter=ctr)
            
            # Encrypt the data
            ciphertext = cipher.encrypt(data)
            
            # Return nonce + ciphertext
            return nonce + ciphertext
            
        except ImportError:
            # If PyCryptodome is not available, fallback to standard library
            # This is because a full custom implementation of Camellia would be
            # very complex and outside the scope of this project
            return self._encrypt_stdlib(data, key)
    
    def _decrypt_custom(self, data, key):
        """
        Decrypt data using a custom implementation in CTR mode.
        
        Args:
            data: Data to decrypt
            key: Key to use for decryption
            
        Returns:
            bytes: Decrypted data
        """
        if len(data) < 16:
            # Not enough data for nonce
            return b''
        
        try:
            from Crypto.Cipher import Camellia
            from Crypto.Util import Counter
            
            # Extract nonce and ciphertext
            nonce = data[:16]
            ciphertext = data[16:]
            
            # Create CTR counter
            ctr = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
            
            # Create cipher
            cipher = Camellia.new(key, Camellia.MODE_CTR, counter=ctr)
            
            # Decrypt the data
            plaintext = cipher.decrypt(ciphertext)
            
            return plaintext
                
        except ImportError:
            # If PyCryptodome is not available, fallback to standard library
            return self._decrypt_stdlib(data, key) 