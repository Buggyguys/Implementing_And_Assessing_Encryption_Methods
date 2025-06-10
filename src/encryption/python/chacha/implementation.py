#!/usr/bin/env python3
"""
CryptoBench Pro - ChaCha20 Implementation
Implements ChaCha20 encryption/decryption with both standard and custom implementations.
"""

import gc
import os
import time
import struct
import hashlib
try:
    from Crypto.Cipher import ChaCha20 as CryptoChaCha20
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Remove circular import
from .base import ChaCha20ImplementationBase, MAX_INPUT_SIZE
from .custom_chacha20 import CustomChaCha20

# Dictionary to track implementations
CHACHA_IMPLEMENTATIONS = {}

# Local implementation of register_implementation to avoid circular imports
def register_chacha_variant(name):
    """Register a ChaCha20 implementation variant."""
    def decorator(impl_class):
        CHACHA_IMPLEMENTATIONS[name] = impl_class
        return impl_class
    return decorator

@register_chacha_variant("chacha20")
class ChaCha20Implementation(ChaCha20ImplementationBase):
    """ChaCha20 implementation with both standard and custom options."""
    
    def __init__(self, key_size="256", **kwargs):
        """Initialize with key size."""
        super().__init__(key_size=key_size, **kwargs)
        self.is_custom = kwargs.get("is_custom", False)
        if self.is_custom:
            self.description = f"Custom ChaCha20 Implementation ({key_size}-bit key)"
        else:
            self.description = f"PyCryptodome ChaCha20 Implementation ({key_size}-bit key)"
        
        # Set up the specific implementation to use
        if self.is_custom:
            self.impl = CustomChaCha20()
    
    def encrypt(self, data, key):
        """Encrypt data using ChaCha20."""
        if self.is_custom:
            return self._custom_encrypt(data, key)
        else:
            return self._lib_encrypt(data, key)
    
    def decrypt(self, ciphertext, key):
        """Decrypt ciphertext using ChaCha20."""
        if self.is_custom:
            return self._custom_decrypt(ciphertext, key)
        else:
            return self._lib_decrypt(ciphertext, key)
    
    def _lib_encrypt(self, data, key):
        """Encrypt data using PyCryptodome ChaCha20 implementation."""
        if not CRYPTO_AVAILABLE:
            raise ImportError("PyCryptodome is not available. Install it with 'pip install pycryptodome'")
        
        # Generate a random nonce
        nonce = os.urandom(8)  # 8 bytes (64 bits) for ChaCha20
        
        # Store for potential debugging/verification
        self.nonce = nonce
        
        # Process in chunks if data exceeds MAX_INPUT_SIZE
        if len(data) > MAX_INPUT_SIZE:
            # Use a generator approach to avoid creating too many chunks in memory at once
            result = bytearray()
            
            # Prepend nonce
            result.extend(nonce)
            
            # Process chunks
            for i in range(0, len(data), MAX_INPUT_SIZE):
                chunk = data[i:i+MAX_INPUT_SIZE]
                
                # Each chunk needs a new cipher with the same nonce but different counter
                counter = 1 + (i // MAX_INPUT_SIZE)  # Start counter at 1
                cipher = CryptoChaCha20.new(key=key, nonce=nonce)
                # Skip to the appropriate counter position
                if counter > 1:
                    # Skip ahead in the keystream
                    skip_size = (counter - 1) * MAX_INPUT_SIZE
                    cipher.seek(skip_size)
                
                # Encrypt this chunk
                result.extend(cipher.encrypt(chunk))
                
                # Force memory cleanup for processed chunks
                del chunk, cipher
                if i % (5 * MAX_INPUT_SIZE) == 0:  # Every 5 chunks
                    gc.collect()  # Help clean up memory
            
            # Convert bytearray to bytes for return
            return bytes(result)
        
        # Single chunk processing
        cipher = CryptoChaCha20.new(key=key, nonce=nonce)
        return nonce + cipher.encrypt(data)
    
    def _lib_decrypt(self, ciphertext, key):
        """Decrypt ciphertext using PyCryptodome ChaCha20 implementation."""
        if not CRYPTO_AVAILABLE:
            raise ImportError("PyCryptodome is not available. Install it with 'pip install pycryptodome'")
        
        # Extract nonce (8 bytes) from ciphertext
        nonce = ciphertext[:8]
        actual_ciphertext = ciphertext[8:]
        
        # For very large ciphertext, use chunk-based processing
        if len(actual_ciphertext) > MAX_INPUT_SIZE:
            result = bytearray()
            
            # Process chunks
            for i in range(0, len(actual_ciphertext), MAX_INPUT_SIZE):
                chunk = actual_ciphertext[i:i+MAX_INPUT_SIZE]
                
                # Each chunk needs a new cipher with the same nonce but different counter
                counter = 1 + (i // MAX_INPUT_SIZE)  # Start counter at 1
                cipher = CryptoChaCha20.new(key=key, nonce=nonce)
                # Skip to the appropriate counter position
                if counter > 1:
                    # Skip ahead in the keystream
                    skip_size = (counter - 1) * MAX_INPUT_SIZE
                    cipher.seek(skip_size)
                
                # Decrypt this chunk
                result.extend(cipher.decrypt(chunk))
                
                # Force memory cleanup
                del chunk, cipher
                if i % (5 * MAX_INPUT_SIZE) == 0:  # Every 5 chunks
                    gc.collect()
            
            return bytes(result)
        else:
            # Simple case: just decrypt the whole thing
            cipher = CryptoChaCha20.new(key=key, nonce=nonce)
            return cipher.decrypt(actual_ciphertext)
    
    def _custom_encrypt(self, data, key):
        """Encrypt data using custom ChaCha20 implementation."""
        encrypted, _ = self.impl.encrypt(data, key)
        return encrypted
    
    def _custom_decrypt(self, ciphertext, key):
        """Decrypt data using custom ChaCha20 implementation."""
        # Plain decryption
        return self.impl.decrypt(ciphertext, key)


def create_custom_chacha20_implementation(key_size="256"):
    """Create a custom ChaCha20 implementation."""
    return ChaCha20Implementation(key_size=key_size, is_custom=True)


def create_stdlib_chacha20_implementation(key_size="256"):
    """Create a standard library ChaCha20 implementation."""
    return ChaCha20Implementation(key_size=key_size, is_custom=False)


def register_all_chacha20_variants():
    """Register all ChaCha20 variants."""
    # Register ChaCha20 (standard and custom)
    CHACHA_IMPLEMENTATIONS["chacha20_std"] = lambda **kwargs: create_stdlib_chacha20_implementation(
        key_size=kwargs.get("key_size", "256")
    )
    
    CHACHA_IMPLEMENTATIONS["chacha20_custom"] = lambda **kwargs: create_custom_chacha20_implementation(
        key_size=kwargs.get("key_size", "256")
    ) 