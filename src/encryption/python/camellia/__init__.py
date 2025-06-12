#!/usr/bin/env python3
"""
Camellia Encryption Implementation
A complete implementation of the Camellia block cipher supporting all key sizes and modes.
"""

from .camellia_implementation import CamelliaImplementation

# Export the main implementation
__all__ = ['CamelliaImplementation', 'get_camellia_implementation', 'register_camellia_implementations']

def get_camellia_implementation(key_size=256, mode="CBC", is_custom=False, **kwargs):
    """
    Get a Camellia implementation with specified parameters.
    
    Args:
        key_size: Key size in bits (128, 192, or 256)
        mode: Mode of operation (CBC, ECB, CFB, OFB)
        is_custom: Whether to use custom implementation (True) or standard library (False)
        **kwargs: Additional arguments
        
    Returns:
        CamelliaImplementation: Configured Camellia implementation
    """
    return CamelliaImplementation(
        key_size=key_size,
        mode=mode,
        is_custom=is_custom,
        **kwargs
    )

def register_camellia_implementations():
    """
    Register all Camellia implementations with the benchmarking system.
    This function should be called by the main Python encryption module.
    """
    implementations = {}
    
    # Register all combinations of key sizes and modes
    for key_size in [128, 192, 256]:
        for mode in ["CBC", "ECB", "CFB", "OFB"]:
            # Standard library implementation
            std_name = f"camellia{key_size}_{mode.lower()}"
            implementations[std_name] = lambda ks=key_size, m=mode, **kwargs: CamelliaImplementation(
                key_size=ks,
                mode=m,
                is_custom=False,
                **{k: v for k, v in kwargs.items() if k not in ['key_size', 'mode', 'is_custom']}
            )
            
            # Custom implementation
            custom_name = f"camellia{key_size}_{mode.lower()}_custom"
            implementations[custom_name] = lambda ks=key_size, m=mode, **kwargs: CamelliaImplementation(
                key_size=ks,
                mode=m,
                is_custom=True,
                **{k: v for k, v in kwargs.items() if k not in ['key_size', 'mode', 'is_custom']}
            )
    
    # Also register generic implementations for backward compatibility
    implementations["camellia"] = lambda **kwargs: CamelliaImplementation(
        is_custom=False, 
        **{k: v for k, v in kwargs.items() if k != 'is_custom'}
    )
    implementations["camellia_custom"] = lambda **kwargs: CamelliaImplementation(
        is_custom=True, 
        **{k: v for k, v in kwargs.items() if k != 'is_custom'}
    )
    
    return implementations

# For backward compatibility and easy access
def create_camellia_cbc_128(**kwargs):
    """Create Camellia CBC 128-bit implementation."""
    return CamelliaImplementation(key_size=128, mode="CBC", **kwargs)

def create_camellia_cbc_192(**kwargs):
    """Create Camellia CBC 192-bit implementation."""
    return CamelliaImplementation(key_size=192, mode="CBC", **kwargs)

def create_camellia_cbc_256(**kwargs):
    """Create Camellia CBC 256-bit implementation."""
    return CamelliaImplementation(key_size=256, mode="CBC", **kwargs)

def create_camellia_ecb_128(**kwargs):
    """Create Camellia ECB 128-bit implementation."""
    return CamelliaImplementation(key_size=128, mode="ECB", **kwargs)

def create_camellia_ecb_192(**kwargs):
    """Create Camellia ECB 192-bit implementation."""
    return CamelliaImplementation(key_size=192, mode="ECB", **kwargs)

def create_camellia_ecb_256(**kwargs):
    """Create Camellia ECB 256-bit implementation."""
    return CamelliaImplementation(key_size=256, mode="ECB", **kwargs)

def create_camellia_cfb_128(**kwargs):
    """Create Camellia CFB 128-bit implementation."""
    return CamelliaImplementation(key_size=128, mode="CFB", **kwargs)

def create_camellia_cfb_192(**kwargs):
    """Create Camellia CFB 192-bit implementation."""
    return CamelliaImplementation(key_size=192, mode="CFB", **kwargs)

def create_camellia_cfb_256(**kwargs):
    """Create Camellia CFB 256-bit implementation."""
    return CamelliaImplementation(key_size=256, mode="CFB", **kwargs)

def create_camellia_ofb_128(**kwargs):
    """Create Camellia OFB 128-bit implementation."""
    return CamelliaImplementation(key_size=128, mode="OFB", **kwargs)

def create_camellia_ofb_192(**kwargs):
    """Create Camellia OFB 192-bit implementation."""
    return CamelliaImplementation(key_size=192, mode="OFB", **kwargs)

def create_camellia_ofb_256(**kwargs):
    """Create Camellia OFB 256-bit implementation."""
    return CamelliaImplementation(key_size=256, mode="OFB", **kwargs) 