#!/usr/bin/env python3
"""
CryptoBench Pro - AES Implementation Package
Provides AES encryption/decryption with different key sizes and modes.
"""

from .base import AESImplementationBase, MAX_INPUT_SIZE
from .implementation import (
    AESImplementation, 
    create_custom_aes_implementation, 
    create_stdlib_aes_implementation, 
    register_all_aes_variants,
    AES_IMPLEMENTATIONS,
    register_aes_variant
)
from .custom_aes import CustomAES

# Ensure all variants are registered
register_all_aes_variants() 