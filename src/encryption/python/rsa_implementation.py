#!/usr/bin/env python3
"""
CryptoBench Pro - RSA Implementation
Python implementation of RSA encryption for benchmarking.
"""

import os
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

# Use absolute import path
from src.encryption.python.python_core import register_implementation

@register_implementation("rsa")
class RSAImplementation:
    """RSA encryption implementation for benchmarking."""
    
    def __init__(self, key_size="2048", **kwargs):
        """Initialize with key size."""
        self.key_size = int(key_size)
        self.chunk_size = self.key_size // 16  # Maximum bytes to encrypt at once (considering PKCS1_OAEP padding)
    
    def generate_key(self):
        """Generate RSA key pair."""
        key = RSA.generate(self.key_size)
        private_key = key
        public_key = key.publickey()
        
        # Store some key components for metrics
        key_components = {
            "n_size_bits": key.n.bit_length(),
            "e": key.e,
        }
        
        return {
            "private_key": private_key,
            "public_key": public_key,
            "components": key_components
        }
    
    def encrypt(self, plaintext, key):
        """Encrypt plaintext using RSA-OAEP."""
        if not isinstance(plaintext, bytes):
            plaintext = plaintext.encode('utf-8')
        
        # Get public key
        public_key = key["public_key"]
        
        # Create cipher
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        
        # Calculate maximum chunk size (accounting for OAEP padding)
        max_chunk_size = (self.key_size // 8) - 2 - 2 * SHA256.digest_size
        
        # Process data in chunks
        chunks = [plaintext[i:i+max_chunk_size] for i in range(0, len(plaintext), max_chunk_size)]
        
        # Encrypt each chunk
        encrypted_chunks = []
        for chunk in chunks:
            encrypted_chunk = cipher.encrypt(chunk)
            encrypted_chunks.append(encrypted_chunk)
        
        # Combine all encrypted chunks with size markers
        result = b''
        for chunk in encrypted_chunks:
            # Store chunk length as 4 bytes
            chunk_len = len(chunk).to_bytes(4, byteorder='big')
            result += chunk_len + chunk
        
        return result
    
    def decrypt(self, ciphertext, key, **kwargs):
        """Decrypt ciphertext using RSA-OAEP."""
        # Get private key
        private_key = key["private_key"]
        
        # Create cipher
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        
        # Process data in chunks
        decrypted_data = b''
        
        # Read chunks
        offset = 0
        while offset < len(ciphertext):
            # Read chunk length (first 4 bytes of each chunk)
            chunk_len = int.from_bytes(ciphertext[offset:offset+4], byteorder='big')
            offset += 4
            
            # Extract the chunk
            chunk = ciphertext[offset:offset+chunk_len]
            offset += chunk_len
            
            # Decrypt chunk
            try:
                decrypted_chunk = cipher.decrypt(chunk)
                decrypted_data += decrypted_chunk
            except Exception as e:
                # Handle decryption errors
                return None
        
        return decrypted_data

# Standard library RSA implementation
@register_implementation("rsa_stdlib")
class RSAStdlibImplementation:
    """RSA implementation using standard libraries (PyCryptodome)."""
    
    def __init__(self, key_size="2048", **kwargs):
        """Initialize with key size."""
        self.key_size = int(key_size)
    
    def generate_key(self):
        """Generate RSA key pair using standard library."""
        key = RSA.generate(self.key_size)
        private_key = key
        public_key = key.publickey()
        
        return {
            "private_key": private_key,
            "public_key": public_key
        }
    
    def encrypt(self, plaintext, key):
        """Encrypt plaintext using RSA-OAEP with standard library."""
        if not isinstance(plaintext, bytes):
            plaintext = plaintext.encode('utf-8')
        
        # Get public key
        public_key = key["public_key"]
        
        # Create cipher
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        
        # Calculate maximum chunk size (accounting for OAEP padding)
        max_chunk_size = (self.key_size // 8) - 2 - 2 * SHA256.digest_size
        
        # Process data in chunks
        chunks = [plaintext[i:i+max_chunk_size] for i in range(0, len(plaintext), max_chunk_size)]
        
        # Encrypt each chunk
        encrypted_chunks = []
        for chunk in chunks:
            encrypted_chunk = cipher.encrypt(chunk)
            encrypted_chunks.append(encrypted_chunk)
        
        # Combine all encrypted chunks with size markers
        result = b''
        for chunk in encrypted_chunks:
            # Store chunk length as 4 bytes
            chunk_len = len(chunk).to_bytes(4, byteorder='big')
            result += chunk_len + chunk
        
        return result
    
    def decrypt(self, ciphertext, key, **kwargs):
        """Decrypt ciphertext using RSA-OAEP with standard library."""
        # Get private key
        private_key = key["private_key"]
        
        # Create cipher
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        
        # Process data in chunks
        decrypted_data = b''
        
        # Read chunks
        offset = 0
        while offset < len(ciphertext):
            # Read chunk length (first 4 bytes of each chunk)
            chunk_len = int.from_bytes(ciphertext[offset:offset+4], byteorder='big')
            offset += 4
            
            # Extract the chunk
            chunk = ciphertext[offset:offset+chunk_len]
            offset += chunk_len
            
            # Decrypt chunk
            try:
                decrypted_chunk = cipher.decrypt(chunk)
                decrypted_data += decrypted_chunk
            except Exception as e:
                # Handle decryption errors
                return None
        
        return decrypted_data 