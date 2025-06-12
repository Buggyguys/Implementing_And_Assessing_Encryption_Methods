#!/usr/bin/env python3
"""
CryptoBench Pro - Implementation Registry Module
Provides functionality for registering and retrieving encryption implementations.
"""

import logging

# Setup logging
logger = logging.getLogger("PythonCore")

# Dictionary to store implementations
ENCRYPTION_IMPLEMENTATIONS = {}

def register_implementation(name):
    """
    Register an encryption implementation.
    
    Args:
        name: Name of the implementation
        
    Returns:
        Decorator function
    """
    def decorator(impl_class):
        ENCRYPTION_IMPLEMENTATIONS[name] = impl_class
        return impl_class
    return decorator

def get_implementation(name):
    """
    Get an implementation by name.
    
    Args:
        name: Name of the implementation
        
    Returns:
        The implementation class or None if not found
    """
    return ENCRYPTION_IMPLEMENTATIONS.get(name)

def list_implementations():
    """
    List all registered implementations.
    
    Returns:
        List of implementation names
    """
    return list(ENCRYPTION_IMPLEMENTATIONS.keys())

def register_all_implementations():
    """Register all available implementations in the system."""
    # Import here to avoid circular imports
    try:
        # Import AES implementations
        from src.encryption.python.aes.implementation import (
            AES_IMPLEMENTATIONS, 
            AESImplementation,
            create_custom_aes_implementation,
            create_stdlib_aes_implementation
        )
        
        # Register AES implementation directly
        ENCRYPTION_IMPLEMENTATIONS["aes"] = AESImplementation
        
        # Register custom AES implementation
        ENCRYPTION_IMPLEMENTATIONS["aes_custom"] = lambda **kwargs: create_custom_aes_implementation(
            kwargs.get("key_size", "256"), 
            kwargs.get("mode", "GCM")
        )
        
        # Register all AES variants
        for name, impl in AES_IMPLEMENTATIONS.items():
            if name not in ["aes", "aes_custom"]:  # We already registered these implementations
                ENCRYPTION_IMPLEMENTATIONS[name] = impl
                
        logger.info(f"Registered AES implementations: {', '.join(AES_IMPLEMENTATIONS.keys())}")
    except ImportError as e:
        logger.warning(f"Could not import AES implementations: {str(e)}")
    except Exception as e:
        logger.warning(f"Error registering AES implementations: {str(e)}")

    try:
        # Import Camellia implementations
        from src.encryption.python.camellia import (
            CamelliaImplementation,
            register_camellia_implementations
        )
        
        # Get all Camellia implementations
        camellia_implementations = register_camellia_implementations()
        
        # Register all Camellia implementations
        for name, impl in camellia_implementations.items():
            ENCRYPTION_IMPLEMENTATIONS[name] = impl
                
        logger.info(f"Registered Camellia implementations: {', '.join(camellia_implementations.keys())}")
    except ImportError as e:
        logger.warning(f"Could not import Camellia implementations: {str(e)}")
    except Exception as e:
        logger.warning(f"Error registering Camellia implementations: {str(e)}")

    try:
        # Import ChaCha20 implementations
        from src.encryption.python.chacha.implementation import (
            CHACHA_IMPLEMENTATIONS,
            ChaCha20Implementation,
            create_custom_chacha20_implementation,
            create_stdlib_chacha20_implementation
        )
        
        # Register ChaCha20 implementation directly
        ENCRYPTION_IMPLEMENTATIONS["chacha20"] = ChaCha20Implementation
        
        # Register ChaCha20 variants (both with and without Poly1305)
        for name, impl in CHACHA_IMPLEMENTATIONS.items():
            if name not in ["chacha20"]:  # We already registered this implementation
                ENCRYPTION_IMPLEMENTATIONS[name] = impl
                
        logger.info(f"Registered ChaCha20 implementations: {', '.join(CHACHA_IMPLEMENTATIONS.keys())}")
    except ImportError as e:
        logger.warning(f"Could not import ChaCha20 implementations: {str(e)}")
    except Exception as e:
        logger.warning(f"Error registering ChaCha20 implementations: {str(e)}")

    try:
        # Import RSA implementations
        from src.encryption.python.rsa.implementation import (
            RSA_IMPLEMENTATIONS,
            RSAImplementation,
            create_custom_rsa_implementation, 
            create_stdlib_rsa_implementation
        )
        
        # Register RSA implementation directly
        ENCRYPTION_IMPLEMENTATIONS["rsa"] = RSAImplementation
        
        # Register custom RSA implementation
        ENCRYPTION_IMPLEMENTATIONS["rsa_custom"] = lambda **kwargs: create_custom_rsa_implementation(
            kwargs.get("key_size", "2048"),
            kwargs.get("padding", "OAEP") == "OAEP"  # Convert padding string to boolean use_oaep
        )
        
        # Register all RSA variants
        for name, impl in RSA_IMPLEMENTATIONS.items():
            if name not in ["rsa", "rsa_custom"]:  # We already registered these implementations
                ENCRYPTION_IMPLEMENTATIONS[name] = impl
                
        logger.info(f"Registered RSA implementations: {', '.join(RSA_IMPLEMENTATIONS.keys())}")
    except ImportError as e:
        logger.warning(f"Could not import RSA implementations: {str(e)}")
    except Exception as e:
        logger.warning(f"Error registering RSA implementations: {str(e)}")

    try:
        # Import ECC implementations
        from src.encryption.python.ecc.implementation import (
            ECC_IMPLEMENTATIONS,
            ECCImplementation,
            create_custom_ecc_implementation,
            create_stdlib_ecc_implementation
        )
        
        # Import specialized curve implementations
        from src.encryption.python.ecc.ecc_p256 import ECCP256Implementation
        from src.encryption.python.ecc.ecc_p384 import ECCP384Implementation
        from src.encryption.python.ecc.ecc_p521 import ECCP521Implementation
        
        # Register ECC implementation directly
        ENCRYPTION_IMPLEMENTATIONS["ecc"] = ECCImplementation
        
        # Register specialized curve implementations
        ENCRYPTION_IMPLEMENTATIONS["ecc_p256"] = ECCP256Implementation
        ENCRYPTION_IMPLEMENTATIONS["ecc_p384"] = ECCP384Implementation
        ENCRYPTION_IMPLEMENTATIONS["ecc_p521"] = ECCP521Implementation
        
        # Use a lambda to filter out unwanted parameters and respect curve parameter
        ENCRYPTION_IMPLEMENTATIONS["ecc_custom"] = lambda **kwargs: create_custom_ecc_implementation(
            curve=kwargs.get("curve", "P-256")
        )
        
        # Register all ECC variants
        for name, impl in ECC_IMPLEMENTATIONS.items():
            if name not in ["ecc", "ecc_custom", "ecc_p256", "ecc_p384", "ecc_p521"]:  # Skip already registered implementations
                ENCRYPTION_IMPLEMENTATIONS[name] = impl
                
        logger.info(f"Registered ECC implementations: {', '.join(ECC_IMPLEMENTATIONS.keys())}")
    except ImportError as e:
        logger.warning(f"Could not import ECC implementations: {str(e)}")
    except Exception as e:
        logger.warning(f"Error registering ECC implementations: {str(e)}")
        
    # Log all registered implementations
    logger.info(f"Total registered implementations: {len(ENCRYPTION_IMPLEMENTATIONS)}")
    return ENCRYPTION_IMPLEMENTATIONS 