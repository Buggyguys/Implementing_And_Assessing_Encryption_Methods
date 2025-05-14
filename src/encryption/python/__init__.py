#!/usr/bin/env python3
"""
CryptoBench Pro - Python Encryption Implementations
Implements encryption methods in Python.
"""

# Import core modules
from src.encryption.python.core.registry import register_all_implementations, list_implementations, get_implementation

# Import AES implementations
from src.encryption.python.aes.implementation import AESImplementation, create_custom_aes_implementation

# Import ChaCha20 implementations
from src.encryption.python.chacha.implementation import ChaCha20Implementation

# Import RSA implementations
from src.encryption.python.rsa.implementation import RSAImplementation, create_custom_rsa_implementation

# Import ECC implementations
from src.encryption.python.ecc.implementation import ECCImplementation, create_custom_ecc_implementation

# Import Camellia implementations
from src.encryption.python.camellia.implementation import CamelliaImplementation, create_custom_camellia_implementation

__all__ = [
    'register_all_implementations',
    'list_implementations',
    'get_implementation',
    'AESImplementation',
    'create_custom_aes_implementation',
    'ChaCha20Implementation',
    'RSAImplementation',
    'create_custom_rsa_implementation',
    'ECCImplementation',
    'create_custom_ecc_implementation',
    'CamelliaImplementation',
    'create_custom_camellia_implementation'
]

# We'll let python_core import and register the implementations
# to avoid circular imports
# from src.encryption.python.python_core import register_implementation
# from src.encryption.python.aes import AESImplementation

# Other imports can be added as needed
# from src.encryption.python.rsa_implementation import RSAImplementation
# from src.encryption.python.chacha20_implementation import ChaCha20Implementation
# from src.encryption.python.ecc_implementation import ECCImplementation
# from src.encryption.python.twofish_implementation import TwofishImplementation

# Add more implementations as they are developed
# from src.encryption.python.ecc_implementation import ECCImplementation
# from src.encryption.python.mlkem_implementation import MLKEMImplementation 