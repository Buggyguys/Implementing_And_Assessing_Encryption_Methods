import logging

# setup logging
logger = logging.getLogger("PythonCore")

# dictionary to store implementations
ENCRYPTION_IMPLEMENTATIONS = {}

def register_implementation(name):
    # register an encryption implementation
    def decorator(impl_class):
        ENCRYPTION_IMPLEMENTATIONS[name] = impl_class
        return impl_class
    return decorator

def get_implementation(name):
    # get an implementation by name
    return ENCRYPTION_IMPLEMENTATIONS.get(name)

def list_implementations():
    # list all registered implementations
    return list(ENCRYPTION_IMPLEMENTATIONS.keys())

def register_all_implementations():
    # import here to avoid circular imports
    try:
        # import AES implementations
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
        
        # register all AES variants 
        for name, impl in AES_IMPLEMENTATIONS.items():
            if name not in ["aes", "aes_custom"]:  # we already registered these implementations
                ENCRYPTION_IMPLEMENTATIONS[name] = impl
                
        logger.info(f"Registered AES implementations: {', '.join(AES_IMPLEMENTATIONS.keys())}")
    except ImportError as e:
        logger.warning(f"Could not import AES implementations: {str(e)}")
    except Exception as e:
        logger.warning(f"Error registering AES implementations: {str(e)}")

    try:
        # import Camellia implementations
        from src.encryption.python.camellia import (
            CamelliaImplementation,
            register_camellia_implementations
        )
        
        # get all Camellia implementations
        camellia_implementations = register_camellia_implementations()
        
        # register all Camellia implementations
        for name, impl in camellia_implementations.items():
            ENCRYPTION_IMPLEMENTATIONS[name] = impl
                
        logger.info(f"Registered Camellia implementations: {', '.join(camellia_implementations.keys())}")
    except ImportError as e:
        logger.warning(f"Could not import Camellia implementations: {str(e)}")
    except Exception as e:
        logger.warning(f"Error registering Camellia implementations: {str(e)}")

    try:
        # import ChaCha20 implementations
        from src.encryption.python.chacha.implementation import (
            CHACHA_IMPLEMENTATIONS,
            ChaCha20Implementation,
            create_custom_chacha20_implementation,
            create_stdlib_chacha20_implementation
        )
        
        # register ChaCha20 implementation directly
        ENCRYPTION_IMPLEMENTATIONS["chacha20"] = ChaCha20Implementation
        
        # register ChaCha20 variants (both with and without Poly1305)
        for name, impl in CHACHA_IMPLEMENTATIONS.items():
            if name not in ["chacha20"]:  # we already registered this implementation
                ENCRYPTION_IMPLEMENTATIONS[name] = impl
                
        logger.info(f"Registered ChaCha20 implementations: {', '.join(CHACHA_IMPLEMENTATIONS.keys())}")
    except ImportError as e:
        logger.warning(f"Could not import ChaCha20 implementations: {str(e)}")
    except Exception as e:
        logger.warning(f"Error registering ChaCha20 implementations: {str(e)}")

    try:
        # import RSA implementations
        from src.encryption.python.rsa.implementation import (
            RSA_IMPLEMENTATIONS,
            RSAImplementation,
            create_custom_rsa_implementation, 
            create_stdlib_rsa_implementation
        )
        
        # register RSA implementation directly
        ENCRYPTION_IMPLEMENTATIONS["rsa"] = RSAImplementation
        
        # register custom RSA implementation
        ENCRYPTION_IMPLEMENTATIONS["rsa_custom"] = lambda **kwargs: create_custom_rsa_implementation(
            kwargs.get("key_size", "2048"),
            kwargs.get("padding", "OAEP") == "OAEP"  # convert padding string to boolean use_oaep
        )
        
        # register all RSA variants
        for name, impl in RSA_IMPLEMENTATIONS.items():
            if name not in ["rsa", "rsa_custom"]:  # we already registered these implementations
                ENCRYPTION_IMPLEMENTATIONS[name] = impl
                
        logger.info(f"Registered RSA implementations: {', '.join(RSA_IMPLEMENTATIONS.keys())}")
    except ImportError as e:
        logger.warning(f"Could not import RSA implementations: {str(e)}")
    except Exception as e:
        logger.warning(f"Error registering RSA implementations: {str(e)}")

    try:
        # import ECC implementations
        from src.encryption.python.ecc.implementation import (
            ECC_IMPLEMENTATIONS,
            ECCImplementation,
            create_custom_ecc_implementation,
            create_stdlib_ecc_implementation
        )
        
        # import specialized curve implementations
        from src.encryption.python.ecc.ecc_p256 import ECCP256Implementation
        from src.encryption.python.ecc.ecc_p384 import ECCP384Implementation
        from src.encryption.python.ecc.ecc_p521 import ECCP521Implementation
        
        # register ECC implementation directly
        ENCRYPTION_IMPLEMENTATIONS["ecc"] = ECCImplementation
        
        # register specialized curve implementations
        ENCRYPTION_IMPLEMENTATIONS["ecc_p256"] = ECCP256Implementation
        ENCRYPTION_IMPLEMENTATIONS["ecc_p384"] = ECCP384Implementation
        ENCRYPTION_IMPLEMENTATIONS["ecc_p521"] = ECCP521Implementation
        
        # use a lambda to filter out unwanted parameters and respect curve parameter
        ENCRYPTION_IMPLEMENTATIONS["ecc_custom"] = lambda **kwargs: create_custom_ecc_implementation(
            curve=kwargs.get("curve", "P-256")
        )
        
        # register all ECC variants
        for name, impl in ECC_IMPLEMENTATIONS.items():
            if name not in ["ecc", "ecc_custom", "ecc_p256", "ecc_p384", "ecc_p521"]:  # skip already registered implementations
                ENCRYPTION_IMPLEMENTATIONS[name] = impl
                
        logger.info(f"Registered ECC implementations: {', '.join(ECC_IMPLEMENTATIONS.keys())}")
    except ImportError as e:
        logger.warning(f"Could not import ECC implementations: {str(e)}")
    except Exception as e:
        logger.warning(f"Error registering ECC implementations: {str(e)}")
        
    # log all registered implementations
    logger.info(f"Total registered implementations: {len(ENCRYPTION_IMPLEMENTATIONS)}")
    return ENCRYPTION_IMPLEMENTATIONS 