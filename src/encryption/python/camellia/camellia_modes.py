#!/usr/bin/env python3
"""
Camellia Mode Implementations
Implements ECB, CBC, CFB, and OFB modes for Camellia encryption.
"""

from .camellia_core_simple import SimpleCamelliaCore as CamelliaCore
from .camellia_utils import pad_data, unpad_data, generate_iv, validate_iv, xor_bytes

class CamelliaModes:
    """Camellia mode implementations."""
    
    def __init__(self, key):
        """
        Initialize with key.
        
        Args:
            key: Master key (16, 24, or 32 bytes)
        """
        self.cipher = CamelliaCore(key)
    
    # ECB Mode
    def encrypt_ecb(self, plaintext):
        """
        Encrypt data using ECB mode.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            bytes: Encrypted data
        """
        # Pad the plaintext
        padded_plaintext = pad_data(plaintext, 16)
        
        ciphertext = b''
        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i:i+16]
            encrypted_block = self.cipher.encrypt_block(block)
            ciphertext += encrypted_block
        
        return ciphertext
    
    def decrypt_ecb(self, ciphertext):
        """
        Decrypt data using ECB mode.
        
        Args:
            ciphertext: Data to decrypt
            
        Returns:
            bytes: Decrypted data
        """
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")
        
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_block = self.cipher.decrypt_block(block)
            plaintext += decrypted_block
        
        # Remove padding
        return unpad_data(plaintext, 16)
    
    # CBC Mode
    def encrypt_cbc(self, plaintext, iv=None):
        """
        Encrypt data using CBC mode.
        
        Args:
            plaintext: Data to encrypt
            iv: Initialization vector (16 bytes), or None to generate
            
        Returns:
            bytes: IV + encrypted data
        """
        if iv is None:
            iv = generate_iv()
        else:
            validate_iv(iv)
        
        # Pad the plaintext
        padded_plaintext = pad_data(plaintext, 16)
        
        ciphertext = b''
        previous_block = iv
        
        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i:i+16]
            # XOR with previous ciphertext block (or IV)
            xored_block = xor_bytes(block, previous_block)
            # Encrypt the XORed block
            encrypted_block = self.cipher.encrypt_block(xored_block)
            ciphertext += encrypted_block
            previous_block = encrypted_block
        
        return iv + ciphertext
    
    def decrypt_cbc(self, data):
        """
        Decrypt data using CBC mode.
        
        Args:
            data: IV + ciphertext to decrypt
            
        Returns:
            bytes: Decrypted data
        """
        if len(data) < 32:  # At least IV + one block
            raise ValueError("Data too short for CBC mode")
        
        # Extract IV and ciphertext
        iv = data[:16]
        ciphertext = data[16:]
        
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")
        
        plaintext = b''
        previous_block = iv
        
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            # Decrypt the block
            decrypted_block = self.cipher.decrypt_block(block)
            # XOR with previous ciphertext block (or IV)
            xored_block = xor_bytes(decrypted_block, previous_block)
            plaintext += xored_block
            previous_block = block
        
        # Remove padding
        return unpad_data(plaintext, 16)
    
    # CFB Mode
    def encrypt_cfb(self, plaintext, iv=None):
        """
        Encrypt data using CFB mode.
        
        Args:
            plaintext: Data to encrypt
            iv: Initialization vector (16 bytes), or None to generate
            
        Returns:
            bytes: IV + encrypted data
        """
        if iv is None:
            iv = generate_iv()
        else:
            validate_iv(iv)
        
        ciphertext = b''
        feedback = iv
        
        for i in range(0, len(plaintext), 16):
            # Encrypt the feedback to create keystream
            keystream = self.cipher.encrypt_block(feedback)
            
            # XOR plaintext with keystream
            block = plaintext[i:i+16]
            encrypted_block = xor_bytes(block, keystream[:len(block)])
            ciphertext += encrypted_block
            
            # Update feedback for next iteration
            if len(encrypted_block) == 16:
                feedback = encrypted_block
            else:
                # For partial blocks, shift feedback and add new ciphertext
                feedback = feedback[len(encrypted_block):] + encrypted_block
        
        return iv + ciphertext
    
    def decrypt_cfb(self, data):
        """
        Decrypt data using CFB mode.
        
        Args:
            data: IV + ciphertext to decrypt
            
        Returns:
            bytes: Decrypted data
        """
        if len(data) < 16:
            raise ValueError("Data too short for CFB mode")
        
        # Extract IV and ciphertext
        iv = data[:16]
        ciphertext = data[16:]
        
        plaintext = b''
        feedback = iv
        
        for i in range(0, len(ciphertext), 16):
            # Encrypt the feedback to create keystream
            keystream = self.cipher.encrypt_block(feedback)
            
            # XOR ciphertext with keystream
            block = ciphertext[i:i+16]
            decrypted_block = xor_bytes(block, keystream[:len(block)])
            plaintext += decrypted_block
            
            # Update feedback for next iteration (use ciphertext block)
            if len(block) == 16:
                feedback = block
            else:
                # For partial blocks, shift feedback and add new ciphertext
                feedback = feedback[len(block):] + block
        
        return plaintext
    
    # OFB Mode
    def encrypt_ofb(self, plaintext, iv=None):
        """
        Encrypt data using OFB mode.
        
        Args:
            plaintext: Data to encrypt
            iv: Initialization vector (16 bytes), or None to generate
            
        Returns:
            bytes: IV + encrypted data
        """
        if iv is None:
            iv = generate_iv()
        else:
            validate_iv(iv)
        
        ciphertext = b''
        feedback = iv
        
        for i in range(0, len(plaintext), 16):
            # Encrypt the feedback to create keystream
            feedback = self.cipher.encrypt_block(feedback)
            
            # XOR plaintext with keystream
            block = plaintext[i:i+16]
            encrypted_block = xor_bytes(block, feedback[:len(block)])
            ciphertext += encrypted_block
        
        return iv + ciphertext
    
    def decrypt_ofb(self, data):
        """
        Decrypt data using OFB mode.
        
        Args:
            data: IV + ciphertext to decrypt
            
        Returns:
            bytes: Decrypted data
        """
        if len(data) < 16:
            raise ValueError("Data too short for OFB mode")
        
        # Extract IV and ciphertext
        iv = data[:16]
        ciphertext = data[16:]
        
        plaintext = b''
        feedback = iv
        
        for i in range(0, len(ciphertext), 16):
            # Encrypt the feedback to create keystream
            feedback = self.cipher.encrypt_block(feedback)
            
            # XOR ciphertext with keystream
            block = ciphertext[i:i+16]
            decrypted_block = xor_bytes(block, feedback[:len(block)])
            plaintext += decrypted_block
        
        return plaintext 