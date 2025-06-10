#!/usr/bin/env python3
"""
CryptoBench Pro - RSA Implementation
Implements RSA encryption/decryption, signing, and verification with different key sizes.
"""

import os
import hashlib
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Signature
from Crypto.Hash import SHA256
from .base import RSAImplementationBase
from .key_utils import extract_key_components

# Dictionary to track implementations
RSA_IMPLEMENTATIONS = {}

# Local implementation of register_implementation to avoid circular imports
def register_rsa_variant(name):
    """Register an RSA implementation variant."""
    def decorator(impl_class):
        RSA_IMPLEMENTATIONS[name] = impl_class
        return impl_class
    return decorator

@register_rsa_variant("rsa")
class RSAImplementation(RSAImplementationBase):
    """RSA implementation using both standard library and custom approaches."""
    
    def __init__(self, key_size="2048", **kwargs):
        """Initialize with key size."""
        super().__init__(key_size, **kwargs)
        
        # Set appropriate description
        if self.is_custom:
            self.description = f"Custom {self.description}"
        else:
            self.description = f"PyCryptodome {self.description}"
    
    def encrypt(self, data, public_key=None):
        """
        Encrypt data using RSA.
        
        Args:
            data: Data to encrypt
            public_key: Public key to use. If None, use the instance's public key.
                        Can also be a tuple (public_key, private_key) returned by generate_key.
                        
        Returns:
            bytes: Encrypted data
        """
        if public_key is None:
            public_key = self.public_key
        elif hasattr(public_key, '__rotating_keys__'):
            # This is a RotatingKeySet - get the next key
            key_pair = public_key.get_next_key()
            # If a key pair tuple is passed, use the first element (public key)
            public_key = key_pair[0]
        elif isinstance(public_key, tuple):
            # If a key pair tuple is passed, use the first element (public key)
            public_key = public_key[0]
        
        if not public_key:
            raise ValueError("Public key is required for encryption")
        
        if self.is_custom:
            return self._encrypt_custom(data, public_key)
        else:
            return self._encrypt_stdlib(data, public_key)
    
    def decrypt(self, ciphertext, private_key=None):
        """
        Decrypt ciphertext using RSA.
        
        Args:
            ciphertext: Data to decrypt
            private_key: Private key to use. If None, use the instance's private key.
                         Can also be a tuple (public_key, private_key) returned by generate_key.
                         
        Returns:
            bytes: Decrypted data
        """
        if private_key is None:
            private_key = self.private_key
        elif hasattr(private_key, '__rotating_keys__'):
            # This is a RotatingKeySet - get the next key
            key_pair = private_key.get_next_key()
            # If a key pair tuple is passed, use the second element (private key)
            private_key = key_pair[1]
        elif isinstance(private_key, tuple):
            # If a key pair tuple is passed, use the second element (private key)
            private_key = private_key[1]
        
        if not private_key:
            raise ValueError("Private key is required for decryption")
        
        if self.is_custom:
            return self._decrypt_custom(ciphertext, private_key)
        else:
            return self._decrypt_stdlib(ciphertext, private_key)
    
    def sign(self, data, private_key=None):
        """
        Sign data using RSA.
        
        Args:
            data: Data to sign
            private_key: Private key to use. If None, use the instance's private key.
                         Can also be a tuple (public_key, private_key) returned by generate_key.
            
        Returns:
            bytes: Signature
        """
        if private_key is None:
            private_key = self.private_key
        elif isinstance(private_key, tuple):
            # If a key pair tuple is passed, use the second element (private key)
            private_key = private_key[1]
        
        if not private_key:
            raise ValueError("Private key is required for signing")
        
        if self.is_custom:
            return self._sign_custom(data, private_key)
        else:
            return self._sign_stdlib(data, private_key)
    
    def verify(self, data, signature, public_key=None):
        """
        Verify signature using RSA.
        
        Args:
            data: Data that was signed
            signature: Signature to verify
            public_key: Public key to use. If None, use the instance's public key.
                        Can also be a tuple (public_key, private_key) returned by generate_key.
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        if public_key is None:
            public_key = self.public_key
        elif isinstance(public_key, tuple):
            # If a key pair tuple is passed, use the first element (public key)
            public_key = public_key[0]
        
        if not public_key:
            raise ValueError("Public key is required for verification")
        
        if self.is_custom:
            return self._verify_custom(data, signature, public_key)
        else:
            return self._verify_stdlib(data, signature, public_key)
    
    def _encrypt_stdlib(self, data, public_key):
        """Encrypt data using the standard library."""
        if self.use_oaep:
            cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        else:
            cipher = PKCS1_v1_5_Cipher.new(public_key)
        
        # Calculate the maximum data size that can be encrypted
        key_size_bytes = public_key.size_in_bytes()
        
        # OAEP overhead: 2 * hash_size + 2
        # PKCS#1 v1.5 overhead: 11 bytes
        max_data_size = key_size_bytes - (2 * SHA256.digest_size + 2) if self.use_oaep else key_size_bytes - 11
        
        if len(data) > max_data_size:
            # For simplicity in this demo, we'll just encrypt the first max_data_size bytes
            # In a real implementation, you would use hybrid encryption for larger data
            data = data[:max_data_size]
        
        return cipher.encrypt(data)
    
    def _decrypt_stdlib(self, ciphertext, private_key):
        """Decrypt ciphertext using the standard library."""
        if self.use_oaep:
            cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
            try:
                return cipher.decrypt(ciphertext)
            except ValueError:
                # Decryption failed
                return b''
        else:
            cipher = PKCS1_v1_5_Cipher.new(private_key)
            sentinel = b''  # Return this if decryption fails
            return cipher.decrypt(ciphertext, sentinel)
    
    def _sign_stdlib(self, data, private_key):
        """Sign data using the standard library."""
        # Create a hash of the data
        h = SHA256.new(data)
        
        # Sign the hash with the private key
        signer = PKCS1_v1_5_Signature.new(private_key)
        signature = signer.sign(h)
        
        return signature
    
    def _verify_stdlib(self, data, signature, public_key):
        """Verify signature using the standard library."""
        # Create a hash of the data
        h = SHA256.new(data)
        
        # Verify the signature
        verifier = PKCS1_v1_5_Signature.new(public_key)
        
        try:
            return verifier.verify(h, signature)
        except:
            return False
    
    def _encrypt_custom(self, data, public_key):
        """
        Encrypt data using a custom RSA implementation.
        This is a simplified version for demonstration purposes.
        """
        # Extract key components
        n = public_key['n']
        e = public_key['e']
        
        # Calculate the maximum data size that can be encrypted
        key_size_bytes = (n.bit_length() + 7) // 8
        
        # For simplicity, we'll implement PKCS#1 v1.5 padding
        # In a real implementation, you would implement OAEP as well
        max_data_size = key_size_bytes - 11
        
        if len(data) > max_data_size:
            # For simplicity, we'll just encrypt the first max_data_size bytes
            data = data[:max_data_size]
        
        # PKCS#1 v1.5 padding
        padded_data = b'\x00\x02' + os.urandom(key_size_bytes - len(data) - 3) + b'\x00' + data
        
        # Convert to integer
        m = int.from_bytes(padded_data, byteorder='big')
        
        # RSA encryption: ciphertext = message^e mod n
        c = pow(m, e, n)
        
        # Convert back to bytes
        return c.to_bytes(key_size_bytes, byteorder='big')
    
    def _decrypt_custom(self, ciphertext, private_key):
        """
        Decrypt ciphertext using a custom RSA implementation.
        This is a simplified version for demonstration purposes.
        """
        # Extract key components
        n = private_key['n']
        d = private_key['d']
        
        # Convert ciphertext to integer
        c = int.from_bytes(ciphertext, byteorder='big')
        
        # RSA decryption: message = ciphertext^d mod n
        m = pow(c, d, n)
        
        # Chinese Remainder Theorem for optimization (optional)
        if 'p' in private_key and 'q' in private_key:
            p = private_key['p']
            q = private_key['q']
            
            # Compute message mod p
            dp = d % (p - 1)
            mp = pow(c % p, dp, p)
            
            # Compute message mod q
            dq = d % (q - 1)
            mq = pow(c % q, dq, q)
            
            # Combine results using CRT
            inv_q = pow(q, p - 2, p)  # q^-1 mod p
            m = (mq + q * (inv_q * (mp - mq) % p)) % (p * q)
        
        # Convert back to bytes
        key_size_bytes = (n.bit_length() + 7) // 8
        padded_message = m.to_bytes(key_size_bytes, byteorder='big')
        
        # Remove PKCS#1 v1.5 padding
        if padded_message[0:2] != b'\x00\x02':
            return b''  # Invalid padding
        
        # Find the first zero byte after the padding
        i = 2
        while i < len(padded_message) and padded_message[i] != 0:
            i += 1
        
        # Return the message after the padding
        if i < len(padded_message):
            return padded_message[i+1:]
        else:
            return b''  # No zero byte found, invalid padding
    
    def _sign_custom(self, data, private_key):
        """
        Sign data using a custom RSA implementation.
        This is a simplified version for demonstration purposes.
        """
        # Extract key components
        n = private_key['n']
        d = private_key['d']
        
        # Hash the data
        hash_obj = hashlib.sha256(data)
        digest = hash_obj.digest()
        
        # PKCS#1 v1.5 DigestInfo encoding
        # This is a simplification - a full implementation would include the ASN.1 structure
        key_size_bytes = (n.bit_length() + 7) // 8
        padded_digest = b'\x00\x01' + b'\xff' * (key_size_bytes - len(digest) - 3) + b'\x00' + digest
        
        # Convert to integer
        m = int.from_bytes(padded_digest, byteorder='big')
        
        # RSA signing: signature = digest^d mod n
        s = pow(m, d, n)
        
        # Convert back to bytes
        return s.to_bytes(key_size_bytes, byteorder='big')
    
    def _verify_custom(self, data, signature, public_key):
        """
        Verify signature using a custom RSA implementation.
        This is a simplified version for demonstration purposes.
        """
        # Extract key components
        n = public_key['n']
        e = public_key['e']
        
        # Convert signature to integer
        s = int.from_bytes(signature, byteorder='big')
        
        # RSA verification: message = signature^e mod n
        m = pow(s, e, n)
        
        # Convert back to bytes
        key_size_bytes = (n.bit_length() + 7) // 8
        padded_digest = m.to_bytes(key_size_bytes, byteorder='big')
        
        # Check PKCS#1 v1.5 padding
        if padded_digest[0:2] != b'\x00\x01':
            return False
        
        # Find the first zero byte after the padding
        i = 2
        while i < len(padded_digest) and padded_digest[i] == 0xff:
            i += 1
        
        # Check that the next byte is zero
        if i < len(padded_digest) and padded_digest[i] == 0:
            # Extract the digest
            extracted_digest = padded_digest[i+1:]
            
            # Hash the data
            hash_obj = hashlib.sha256(data)
            digest = hash_obj.digest()
            
            # Compare the digests
            return extracted_digest == digest
        else:
            return False

def create_custom_rsa_implementation(key_size, use_oaep=True):
    """Create a custom RSA implementation with the specified key size."""
    return RSAImplementation(key_size=key_size, is_custom=True, use_oaep=use_oaep)

def create_stdlib_rsa_implementation(key_size, use_oaep=True):
    """Create a standard library RSA implementation with the specified key size."""
    return RSAImplementation(key_size=key_size, is_custom=False, use_oaep=use_oaep)

def register_all_rsa_variants():
    """Register all RSA variants."""
    # Different key sizes and padding schemes
    for key_size in ["1024", "2048", "3072", "4096"]:
        for padding in [True, False]:  # True for OAEP, False for PKCS#1 v1.5
            padding_name = "oaep" if padding else "pkcs1"
            variant_name = f"rsa{key_size}_{padding_name}"
            RSA_IMPLEMENTATIONS[variant_name] = lambda ks=key_size, p=padding, **kwargs: RSAImplementation(
                key_size=ks, use_oaep=p, **kwargs
            ) 