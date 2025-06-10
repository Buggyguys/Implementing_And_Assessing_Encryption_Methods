#!/usr/bin/env python3
"""
CryptoBench Pro - RSA Base Implementation
Provides the base class for RSA implementations and common utilities.
"""

from .key_utils import generate_key_pair, generate_custom_key_pair

class RSAImplementationBase:
    """Base class for RSA implementations."""
    
    def __init__(self, key_size="2048", **kwargs):
        """Initialize with key size."""
        self.key_size = int(key_size)
        self.name = "RSA"
        self.description = f"RSA-{key_size}"
        self.public_key = None
        self.private_key = None
        self.is_custom = kwargs.get('is_custom', False)
        self.use_oaep = kwargs.get('use_oaep', True)
        self.padding_scheme = "OAEP" if self.use_oaep else "PKCS#1 v1.5"
        
        # For a full description including padding scheme
        if self.use_oaep:
            self.description += " with OAEP padding"
        else:
            self.description += " with PKCS#1 v1.5 padding"
    
    def generate_key_pair(self):
        """Generate a key pair of the specified size."""
        # Delegate key generation to the appropriate utility function
        if self.is_custom:
            self.public_key, self.private_key = generate_custom_key_pair(self.key_size)
        else:
            self.public_key, self.private_key = generate_key_pair(self.key_size)
        return self.public_key, self.private_key
    
    def generate_key(self):
        """
        Generate a key pair and return it as a single object for benchmark compatibility.
        This method provides compatibility with the benchmark system which expects a single key object.
        """
        # Call generate_key_pair and return the key pair as a tuple
        self.public_key, self.private_key = self.generate_key_pair()
        return (self.public_key, self.private_key)
    
    def encrypt(self, data, public_key):
        """Encrypt data using the public key. Should be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement this method")
    
    def decrypt(self, ciphertext, private_key):
        """Decrypt data using the private key. Should be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement this method")
    
    def sign(self, data, private_key):
        """Sign data using the private key. Should be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement this method")
    
    def verify(self, data, signature, public_key):
        """Verify signature using the public key. Should be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement this method") 