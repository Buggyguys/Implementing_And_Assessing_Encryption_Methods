#!/usr/bin/env python3
"""
CryptoBench Pro - Camellia CBC Implementation
Implements Camellia encryption/decryption in CBC mode.
"""

import os
from .base import CamelliaImplementationBase
from .key_utils import generate_key, pad_data, unpad_data
import logging

class CamelliaCBCImplementation(CamelliaImplementationBase):
    """Camellia implementation in CBC mode."""
    
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
        
        super().__init__(key_size=key_size, mode="CBC", is_custom=is_custom)
        self.name = "Camellia-CBC"
        self.description = f"{self.key_size}-bit Camellia-CBC"
        
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
        Encrypt data using Camellia in CBC mode.
        
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
        Decrypt data using Camellia in CBC mode.
        
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
        Encrypt data using the standard library in CBC mode.
        
        Args:
            data: Data to encrypt
            key: Key to use for encryption
            
        Returns:
            bytes: Encrypted data
        """
        # For Camellia, PyCryptodome is generally more reliable
        try:
            from Crypto.Cipher import Camellia
            from Crypto.Util.Padding import pad
            
            # Generate a random IV
            iv = os.urandom(16)
            
            # Create cipher
            cipher = Camellia.new(key, Camellia.MODE_CBC, iv)
            
            # Pad and encrypt
            padded_data = pad(data, 16)
            ciphertext = cipher.encrypt(padded_data)
            
            # Return IV + ciphertext
            return iv + ciphertext
            
        except ImportError:
            # If PyCryptodome is not available, try cryptography.io
            logging.info("PyCryptodome not available, using cryptography.io for Camellia CBC")
            try:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.backends import default_backend
                
                # Generate a random IV
                iv = os.urandom(16)
                
                # Pad the data to the block size
                padded_data = pad_data(data, 16)
                
                # Create encryptor
                cipher = Cipher(
                    algorithms.Camellia(key),
                    modes.CBC(iv),
                    backend=default_backend()
                )
                encryptor = cipher.encryptor()
                
                # Encrypt the data
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
                
                # Return the IV + ciphertext
                return iv + ciphertext
            except Exception as e:
                logging.error(f"Error using cryptography.io for CBC encryption: {str(e)}")
                return b''
        except Exception as e:
            logging.error(f"Error in CBC encrypt: {str(e)}")
            return b''
    
    def _decrypt_stdlib(self, data, key):
        """
        Decrypt data using the standard library in CBC mode.
        
        Args:
            data: Data to decrypt
            key: Key to use for decryption
            
        Returns:
            bytes: Decrypted data
        """
        if len(data) < 16:
            return b''  # Not enough data for IV
        
        # For Camellia, PyCryptodome is generally more reliable
        try:
            from Crypto.Cipher import Camellia
            from Crypto.Util.Padding import unpad
            
            # Extract IV and ciphertext
            iv = data[:16]
            ciphertext = data[16:]
            
            # Create cipher
            cipher = Camellia.new(key, Camellia.MODE_CBC, iv)
            
            # Decrypt
            padded_plaintext = cipher.decrypt(ciphertext)
            
            try:
                # Remove padding
                plaintext = unpad(padded_plaintext, 16)
                return plaintext
            except Exception:
                # Handle padding errors (common in stream mode)
                logging.warning("CBC padding error in PyCryptodome")
                return b''
                
        except ImportError:
            # If PyCryptodome is not available, try cryptography.io
            logging.info("PyCryptodome not available, using cryptography.io for Camellia CBC")
            try:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.backends import default_backend
                
                # Extract IV and ciphertext
                iv = data[:16]
                ciphertext = data[16:]
                
                # Create decryptor
                cipher = Cipher(
                    algorithms.Camellia(key),
                    modes.CBC(iv),
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
                    logging.warning("CBC padding error in cryptography.io")
                    return b''
            except Exception as e:
                logging.error(f"Error using cryptography.io for CBC decryption: {str(e)}")
                return b''
        except Exception as e:
            logging.error(f"Error in CBC decrypt: {str(e)}")
            return b''
    
    def _encrypt_custom(self, data, key):
        """
        Encrypt data using custom Camellia implementation in CBC mode.
        
        Args:
            data: Data to encrypt
            key: Key to use for encryption
            
        Returns:
            bytes: Encrypted data
        """
        try:
            from .custom_camellia import camellia_encrypt_cbc
            
            # Generate a random IV
            iv = os.urandom(16)
            
            # Encrypt using our custom implementation
            ciphertext = camellia_encrypt_cbc(data, key, iv)
            
            # Return IV + ciphertext
            return iv + ciphertext
            
        except ImportError as e:
            logging.error(f"Custom Camellia implementation not available: {str(e)}")
            # Fallback to standard library
            return self._encrypt_stdlib(data, key)
        except Exception as e:
            logging.error(f"Error in custom CBC encrypt: {str(e)}")
            return b''
    
    def _decrypt_custom(self, data, key):
        """
        Decrypt data using custom Camellia implementation in CBC mode.
        
        Args:
            data: Data to decrypt
            key: Key to use for decryption
            
        Returns:
            bytes: Decrypted data
        """
        if len(data) < 16:
            return b''  # Not enough data for IV
        
        try:
            from .custom_camellia import camellia_decrypt_cbc
            
            # Extract IV and ciphertext
            iv = data[:16]
            ciphertext = data[16:]
            
            # Decrypt using our custom implementation
            plaintext = camellia_decrypt_cbc(ciphertext, key, iv)
            
            return plaintext
            
        except ImportError as e:
            logging.error(f"Custom Camellia implementation not available: {str(e)}")
            # Fallback to standard library
            return self._decrypt_stdlib(data, key)
        except Exception as e:
            logging.error(f"Error in custom CBC decrypt: {str(e)}")
                return b''