#!/usr/bin/env python3
"""
CryptoBench Pro - ECC Base Implementation
Provides the base class for ECC implementations and common utilities.
"""

from .key_utils import generate_key_pair, generate_custom_key_pair

class ECCImplementationBase:
    """Base class for ECC implementations."""
    
    def __init__(self, curve="P-256", **kwargs):
        """Initialize with curve name."""
        self.curve = curve
        self.name = "ECC"
        self.description = f"ECC-{curve}"
        self.public_key = None
        self.private_key = None
        self.is_custom = kwargs.get('is_custom', False)
        
        # Set appropriate description
        if self.is_custom:
            self.description = f"Custom {self.description}"
        else:
            self.description = f"Cryptography.io {self.description}"
    
    def generate_key_pair(self):
        """Generate a key pair of the specified curve."""
        # Delegate key generation to the appropriate utility function
        if self.is_custom:
            self.public_key, self.private_key = generate_custom_key_pair(self.curve)
        else:
            self.public_key, self.private_key = generate_key_pair(self.curve)
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
        """
        Encrypt data using ECIES (Elliptic Curve Integrated Encryption Scheme).
        Should be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method")
    
    def decrypt(self, ciphertext, private_key):
        """
        Decrypt data using ECIES (Elliptic Curve Integrated Encryption Scheme).
        Should be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method")
    
    def sign(self, data, private_key):
        """
        Sign data using ECDSA (Elliptic Curve Digital Signature Algorithm).
        Should be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method")
    
    def verify(self, data, signature, public_key):
        """
        Verify signature using ECDSA (Elliptic Curve Digital Signature Algorithm).
        Should be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method") 