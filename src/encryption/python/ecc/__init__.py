#!/usr/bin/env python3
"""
CryptoBench Pro - ECC Module
Exports implementation classes and creation functions.
"""

from .implementation import (
    ECCImplementation,
    create_custom_ecc_implementation,
    create_stdlib_ecc_implementation,
    register_all_ecc_variants,
    ECC_IMPLEMENTATIONS
)

from .ecc_p256 import ECCP256Implementation
from .ecc_p384 import ECCP384Implementation
from .ecc_p521 import ECCP521Implementation

# Register all variants on import
register_all_ecc_variants()

# Export supported curves
SUPPORTED_CURVES = ["P-256", "P-384", "P-521"]
CUSTOM_SUPPORTED_CURVES = ["P-256", "P-384", "P-521"]  # All curves now supported for custom implementation

__all__ = [
    'ECCImplementation',
    'ECCP256Implementation',
    'ECCP384Implementation',
    'ECCP521Implementation',
    'create_custom_ecc_implementation',
    'create_stdlib_ecc_implementation',
    'ECC_IMPLEMENTATIONS',
    'SUPPORTED_CURVES',
    'CUSTOM_SUPPORTED_CURVES',
    'register_all_ecc_variants'
] 