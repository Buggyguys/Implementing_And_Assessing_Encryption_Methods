#!/usr/bin/env python3
from .key_utils import generate_key_pair, generate_custom_key_pair

class RSAImplementationBase:
    # base class for RSA implementations
    
    def __init__(self, key_size="2048", **kwargs):
        self.key_size = int(key_size)
        self.name = "RSA"
        self.description = f"RSA-{key_size}"
        self.public_key = None
        self.private_key = None
        self.is_custom = kwargs.get('is_custom', False)
        self.use_oaep = kwargs.get('use_oaep', True)
        self.padding_scheme = "OAEP" if self.use_oaep else "PKCS#1 v1.5"
        
        if self.use_oaep:
            self.description += " with OAEP padding"
        else:
            self.description += " with PKCS#1 v1.5 padding"
    
    def generate_key_pair(self):
        # generate a key pair of the specified size
        if self.is_custom:
            self.public_key, self.private_key = generate_custom_key_pair(self.key_size)
        else:
            self.public_key, self.private_key = generate_key_pair(self.key_size)
        return self.public_key, self.private_key
    
    def generate_key(self):
        # generate a key pair and return it as a single object for benchmark compatibility
        self.public_key, self.private_key = self.generate_key_pair()
        return (self.public_key, self.private_key)
    
    def encrypt(self, data, public_key):
        # encrypt data using the public key
        raise NotImplementedError("Subclasses must implement this method")
    
    def decrypt(self, ciphertext, private_key):
        # decrypt data using the private key
        raise NotImplementedError("Subclasses must implement this method")
    
    def sign(self, data, private_key):
        # sign data using the private key
        raise NotImplementedError("Subclasses must implement this method")
    
    def verify(self, data, signature, public_key):
        # verify signature using the public key
        raise NotImplementedError("Subclasses must implement this method") 