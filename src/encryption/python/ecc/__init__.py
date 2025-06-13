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

register_all_ecc_variants()

SUPPORTED_CURVES = ["P-256", "P-384", "P-521"]
CUSTOM_SUPPORTED_CURVES = ["P-256", "P-384", "P-521"]  

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