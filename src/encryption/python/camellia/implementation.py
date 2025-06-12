#!/usr/bin/env python3
"""
CryptoBench Pro - Camellia Implementation
Implements Camellia encryption/decryption with different modes.
"""

import os
import logging

# Setup logger
logger = logging.getLogger("PythonCore")

from .base import CamelliaImplementationBase
from .key_utils import generate_key

# Dictionary to track implementations
CAMELLIA_IMPLEMENTATIONS = {}

# Local implementation of register_implementation to avoid circular imports
def register_camellia_variant(name):
    """Register a Camellia implementation variant."""
    def decorator(impl_class):
        CAMELLIA_IMPLEMENTATIONS[name] = impl_class
        return impl_class
    return decorator

@register_camellia_variant("camellia")
class CamelliaImplementation(CamelliaImplementationBase):
    """Camellia implementation using both standard library and custom approaches."""
    
    def __init__(self, key_size=256, mode="CBC", **kwargs):
        """
        Initialize with key size and mode.
        
        Args:
            key_size: Key size in bits (128, 192, or 256)
            mode: Mode of operation (CBC, ECB, CFB, OFB)
            **kwargs: Additional keyword arguments
        """
        # Remove is_custom from kwargs if it exists to avoid conflicts
        is_custom = kwargs.pop('is_custom', False) if 'is_custom' in kwargs else False
        
        super().__init__(key_size=key_size, mode=mode, is_custom=is_custom)
        self.name = "Camellia"
        
        # Try to import the PyCryptodome library first
        self.pycrypto_available = False
        self.cryptography_available = False
        
        try:
            from Crypto.Cipher import Camellia
            self.pycrypto_available = True
            logger.debug("Using PyCryptodome for Camellia encryption")
        except ImportError:
            logger.debug("PyCryptodome library not available for Camellia.")
            
            # Try to import the cryptography library next
            try:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                self.cryptography_available = True
                logger.debug("Using cryptography.io for Camellia encryption")
            except ImportError:
                logger.debug("Cryptography library not available for Camellia.")
                if not self.is_custom:
                    logger.debug("Falling back to custom implementation.")
                    self.is_custom = True
    
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
        Encrypt data using Camellia.
        
        Args:
            data: Data to encrypt
            key: Key to use for encryption, or None to use the instance's key
            
        Returns:
            bytes: Encrypted data
        """
        # Import specific Camellia implementation module based on mode
        mode_lower = self.mode.lower()
        
        if mode_lower == "cbc":
            from .camellia_cbc import CamelliaCBCImplementation
            impl = CamelliaCBCImplementation(key_size=self.key_size, is_custom=self.is_custom)
        elif mode_lower == "ecb":
            from .camellia_ecb import CamelliaECBImplementation
            impl = CamelliaECBImplementation(key_size=self.key_size, is_custom=self.is_custom)
        elif mode_lower == "cfb":
            from .camellia_cfb import CamelliaCFBImplementation
            impl = CamelliaCFBImplementation(key_size=self.key_size, is_custom=self.is_custom)
        elif mode_lower == "ofb":
            from .camellia_ofb import CamelliaOFBImplementation
            impl = CamelliaOFBImplementation(key_size=self.key_size, is_custom=self.is_custom)
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")
        
        if key is None:
            key = self.encryption_key
        
        if key is None:
            raise ValueError("Encryption key is required")
        
        return impl.encrypt(data, key)
    
    def decrypt(self, data, key=None):
        """
        Decrypt data using Camellia.
        
        Args:
            data: Data to decrypt
            key: Key to use for decryption, or None to use the instance's key
            
        Returns:
            bytes: Decrypted data
        """
        # Import specific Camellia implementation module based on mode
        mode_lower = self.mode.lower()
        
        if mode_lower == "cbc":
            from .camellia_cbc import CamelliaCBCImplementation
            impl = CamelliaCBCImplementation(key_size=self.key_size, is_custom=self.is_custom)
        elif mode_lower == "ecb":
            from .camellia_ecb import CamelliaECBImplementation
            impl = CamelliaECBImplementation(key_size=self.key_size, is_custom=self.is_custom)
        elif mode_lower == "cfb":
            from .camellia_cfb import CamelliaCFBImplementation
            impl = CamelliaCFBImplementation(key_size=self.key_size, is_custom=self.is_custom)
        elif mode_lower == "ofb":
            from .camellia_ofb import CamelliaOFBImplementation
            impl = CamelliaOFBImplementation(key_size=self.key_size, is_custom=self.is_custom)
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")
        
        if key is None:
            key = self.encryption_key
        
        if key is None:
            raise ValueError("Decryption key is required")
        
        return impl.decrypt(data, key)


def create_stdlib_camellia_implementation(key_size=256, mode="CBC", **kwargs):
    """
    Create a standard library Camellia implementation.
    
    Args:
        key_size: Key size in bits (128, 192, or 256)
        mode: Mode of operation (CBC, ECB, CFB, OFB)
        **kwargs: Additional keyword arguments
        
    Returns:
        CamelliaImplementation: Standard library implementation
    """
    # Clean kwargs to avoid conflicts
    kwargs = {k: v for k, v in kwargs.items() if k != 'is_custom'}
    
    logger.info(f"Creating standard library Camellia implementation with key size {key_size} and mode {mode}")
    
    # Create specialized implementation based on mode
    if mode == "CBC":
        from .camellia_cbc import CamelliaCBCImplementation
        return CamelliaCBCImplementation(key_size=key_size, is_custom=False, **kwargs)
    elif mode == "ECB":
        from .camellia_ecb import CamelliaECBImplementation
        return CamelliaECBImplementation(key_size=key_size, is_custom=False, **kwargs)
    elif mode == "CFB":
        from .camellia_cfb import CamelliaCFBImplementation
        return CamelliaCFBImplementation(key_size=key_size, is_custom=False, **kwargs)
    elif mode == "OFB":
        from .camellia_ofb import CamelliaOFBImplementation
        return CamelliaOFBImplementation(key_size=key_size, is_custom=False, **kwargs)
    else:
        # Fallback to generic implementation
        logger.debug(f"Unsupported mode '{mode}' for Camellia. Using generic implementation.")
        return CamelliaImplementation(key_size=key_size, mode=mode, is_custom=False, **kwargs)


def create_custom_camellia_implementation(key_size=256, mode="CBC", **kwargs):
    """
    Create a custom Camellia implementation.
    
    Args:
        key_size: Key size in bits (128, 192, or 256)
        mode: Mode of operation (CBC, ECB, CFB, OFB)
        **kwargs: Additional keyword arguments
        
    Returns:
        CamelliaImplementation: Custom implementation
    """
    # Clean kwargs to avoid conflicts
    kwargs = {k: v for k, v in kwargs.items() if k != 'is_custom'}
    
    logger.info(f"Creating custom Camellia implementation with key size {key_size} and mode {mode}")
    
    # Create specialized implementation based on mode
    if mode == "CBC":
        from .camellia_cbc import CamelliaCBCImplementation
        return CamelliaCBCImplementation(key_size=key_size, is_custom=True, **kwargs)
    elif mode == "ECB":
        from .camellia_ecb import CamelliaECBImplementation
        return CamelliaECBImplementation(key_size=key_size, is_custom=True, **kwargs)
    elif mode == "CFB":
        from .camellia_cfb import CamelliaCFBImplementation
        return CamelliaCFBImplementation(key_size=key_size, is_custom=True, **kwargs)
    elif mode == "OFB":
        from .camellia_ofb import CamelliaOFBImplementation
        return CamelliaOFBImplementation(key_size=key_size, is_custom=True, **kwargs)
    else:
        # Fallback to generic implementation
        logger.debug(f"Unsupported mode '{mode}' for Camellia. Using generic implementation.")
        return CamelliaImplementation(key_size=key_size, mode=mode, is_custom=True, **kwargs)


def register_all_camellia_variants():
    """Register all Camellia variants."""
    # Register different key sizes with different modes
    for key_size in [128, 192, 256]:
        key_size_str = str(key_size)
        
        # Register standard library implementations
        for mode in ["CBC", "ECB", "CFB", "OFB"]:
            mode_lower = mode.lower()
            variant_name = f"camellia{key_size_str}_{mode_lower}"
            
            # Create a closure to capture parameters correctly
            def make_std_factory(ks=key_size, m=mode):
                return lambda **kwargs: create_stdlib_camellia_implementation(
                    key_size=ks,
                    mode=m,
                    **{k: v for k, v in kwargs.items() if k not in ['key_size', 'mode', 'is_custom']}
                )
            
            CAMELLIA_IMPLEMENTATIONS[variant_name] = make_std_factory()
        
        # Register custom implementations
        for mode in ["CBC", "ECB", "CFB", "OFB"]:
            mode_lower = mode.lower()
            variant_name = f"camellia{key_size_str}_{mode_lower}_custom"
            
            # Create a closure to capture parameters correctly
            def make_custom_factory(ks=key_size, m=mode):
                return lambda **kwargs: create_custom_camellia_implementation(
                    key_size=ks,
                    mode=m,
                    **{k: v for k, v in kwargs.items() if k not in ['key_size', 'mode', 'is_custom']}
                )
            
            CAMELLIA_IMPLEMENTATIONS[variant_name] = make_custom_factory()
    
    # Register general custom implementation
    CAMELLIA_IMPLEMENTATIONS["camellia_custom"] = lambda **kwargs: create_custom_camellia_implementation(
        key_size=int(kwargs.pop("key_size", 256)),
        mode=kwargs.pop("mode", "CBC"),
        **kwargs
    ) 