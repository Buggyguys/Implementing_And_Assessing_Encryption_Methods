#!/usr/bin/env python3
"""
CryptoBench Pro - Camellia Encryption Package
A complete RFC 3713-compliant Camellia implementation with multiple modes.
"""

from .implementation import CamelliaImplementation, create_custom_camellia_implementation, create_stdlib_camellia_implementation
from .custom_camellia import (
    camellia_encrypt_ecb, camellia_decrypt_ecb,
    camellia_encrypt_cbc, camellia_decrypt_cbc,
    camellia_encrypt_cfb, camellia_decrypt_cfb,
    camellia_encrypt_ofb, camellia_decrypt_ofb,
    CamelliaKey, CustomCamellia
)
from .camellia_core import CamelliaCore
from .key_utils import generate_key, derive_key, pad_data, unpad_data

__all__ = [
    'CamelliaImplementation',
    'create_custom_camellia_implementation', 
    'create_stdlib_camellia_implementation',
    'camellia_encrypt_ecb', 'camellia_decrypt_ecb',
    'camellia_encrypt_cbc', 'camellia_decrypt_cbc', 
    'camellia_encrypt_cfb', 'camellia_decrypt_cfb',
    'camellia_encrypt_ofb', 'camellia_decrypt_ofb',
    'CamelliaCore', 'CamelliaKey', 'CustomCamellia',
    'generate_key', 'derive_key', 'pad_data', 'unpad_data'
] 