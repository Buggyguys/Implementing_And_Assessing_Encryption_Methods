#!/usr/bin/env python3
"""
CryptoBench Pro - ChaCha20 Implementation Package
Provides ChaCha20 and ChaCha20-Poly1305 encryption/decryption.
"""

from .base import ChaCha20ImplementationBase, MAX_INPUT_SIZE
from .implementation import (
    ChaCha20Implementation, 
    create_custom_chacha20_implementation, 
    create_stdlib_chacha20_implementation, 
    register_all_chacha20_variants,
    CHACHA_IMPLEMENTATIONS,
    register_chacha_variant
)

# Ensure all variants are registered
register_all_chacha20_variants() 