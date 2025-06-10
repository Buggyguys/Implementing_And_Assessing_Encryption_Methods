#!/usr/bin/env python3
"""
CryptoBench Pro - AES Implementation
Implements AES encryption/decryption with different key sizes and modes using a modular approach.
"""

from .base import AESImplementationBase
from . import aes_gcm, aes_cbc, aes_ctr, aes_ecb

# Dictionary to track implementations
AES_IMPLEMENTATIONS = {}

# Local implementation of register_implementation to avoid circular imports
def register_aes_variant(name):
    """Register an AES implementation variant."""
    def decorator(impl_class):
        AES_IMPLEMENTATIONS[name] = impl_class
        return impl_class
    return decorator

@register_aes_variant("aes")
class AESImplementation(AESImplementationBase):
    """AES implementation using a modular approach for different modes."""
    
    def __init__(self, key_size="256", mode="GCM", **kwargs):
        """Initialize with key size and mode of operation."""
        super().__init__(key_size, mode, **kwargs)
        
        # Set appropriate description
        if self.is_custom:
            self.description = f"Custom AES-{key_size} in {mode} mode"
        else:
            self.description = f"PyCryptodome AES-{key_size} in {mode} mode"
    
    def encrypt(self, data, key):
        """Encrypt data using AES with the specified mode."""
        # Delegate to the appropriate mode implementation
        if self.mode == "GCM":
            return aes_gcm.encrypt(data, key, None, self.is_custom)
        elif self.mode == "CBC":
            return aes_cbc.encrypt(data, key, None, self.is_custom)
        elif self.mode == "CTR":
            return aes_ctr.encrypt(data, key, None, self.is_custom)
        elif self.mode == "ECB":
            return aes_ecb.encrypt(data, key, None, self.is_custom)
        else:
            raise ValueError(f"Unsupported AES mode: {self.mode}")
    
    def decrypt(self, ciphertext, key):
        """Decrypt ciphertext using AES with the specified mode."""
        # Delegate to the appropriate mode implementation
        if self.mode == "GCM":
            return aes_gcm.decrypt(ciphertext, key, self.is_custom)
        elif self.mode == "CBC":
            return aes_cbc.decrypt(ciphertext, key, self.is_custom)
        elif self.mode == "CTR":
            return aes_ctr.decrypt(ciphertext, key, self.is_custom)
        elif self.mode == "ECB":
            return aes_ecb.decrypt(ciphertext, key, self.is_custom)
        else:
            raise ValueError(f"Unsupported AES mode: {self.mode}")

def create_custom_aes_implementation(key_size, mode):
    """Create a custom AES implementation with the specified key size and mode."""
    return AESImplementation(key_size=key_size, mode=mode, is_custom=True)

def create_stdlib_aes_implementation(key_size, mode):
    """Create a standard library AES implementation with the specified key size and mode."""
    return AESImplementation(key_size=key_size, mode=mode, is_custom=False)

def register_all_aes_variants():
    """Register all AES variants."""
    # Different key sizes and modes
    for key_size in ["128", "192", "256"]:
        for mode in ["GCM", "CBC", "CTR", "ECB"]:
            variant_name = f"aes{key_size}_{mode.lower()}"
            AES_IMPLEMENTATIONS[variant_name] = lambda ks=key_size, m=mode, **kwargs: AESImplementation(
                key_size=ks, mode=m, **kwargs
            ) 