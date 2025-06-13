import os
import hashlib
import hmac
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from .base import ECCImplementationBase
from .key_utils import extract_key_components, CURVE_PARAMS
import logging

# dictionary to track implementations
ECC_IMPLEMENTATIONS = {}

# local implementation of register_implementation to avoid circular imports
def register_ecc_variant(name):
    def decorator(impl_class):
        ECC_IMPLEMENTATIONS[name] = impl_class
        return impl_class
    return decorator

@register_ecc_variant("ecc")
class ECCImplementation(ECCImplementationBase):
    
    def __init__(self, curve="P-256", **kwargs):
        super().__init__(curve, **kwargs)
        # set a name attribute to help with special Stream mode handling
        self.name = "ECC"
    
    def encrypt(self, data, public_key=None):
        # encrypt data using pure ECC with chunking for large data
        if public_key is None:
            public_key = self.public_key
        elif hasattr(public_key, '__rotating_keys__'):
            # this is a RotatingKeySet - get the next key
            key_pair = public_key.get_next_key()
            # if a key pair tuple is passed, use the first element (public key)
            public_key = key_pair[0]
        elif isinstance(public_key, tuple):
            # if a key pair tuple is passed, use the first element (public key)
            public_key = public_key[0]
        
        if not public_key:
            raise ValueError("Public key is required for encryption")
        
        # calculate maximum chunk size based on curve
        max_chunk_size = self._get_max_chunk_size()
        
        # if data fits in one chunk, encrypt directly
        if len(data) <= max_chunk_size:
            return self._encrypt_single_chunk(data, public_key)
        
        # for larger data, encrypt in chunks with separators
        result = b""
        chunk_count = 0
        
        for i in range(0, len(data), max_chunk_size):
            chunk = data[i:i + max_chunk_size]
            encrypted_chunk = self._encrypt_single_chunk(chunk, public_key)
            
            # add chunk metadata: [chunk_number:4][encrypted_size:4][encrypted_chunk]
            chunk_header = chunk_count.to_bytes(4, byteorder='big') + len(encrypted_chunk).to_bytes(4, byteorder='big')
            result += chunk_header + encrypted_chunk
            chunk_count += 1
        
        return result
    
    def _get_max_chunk_size(self):
        if self.is_custom:
            # custom implementation uses discrete log solving, so keep data small
            return 2  # very small for brute force discrete log
        else:
            # standard library can handle slightly larger due to optimizations
            return 4  # still small but manageable
    
    def _encrypt_single_chunk(self, data, public_key):
        # encrypt a single chunk of data
        if self.is_custom:
            # delegate to the appropriate curve-specific implementation
            from .ecc_p256 import ECCP256Implementation
            from .ecc_p384 import ECCP384Implementation
            from .ecc_p521 import ECCP521Implementation
            
            if self.curve == "P-256":
                impl = ECCP256Implementation(is_custom=True)
                return impl._encrypt_custom(data, public_key)
            elif self.curve == "P-384":
                impl = ECCP384Implementation(is_custom=True)
                return impl._encrypt_custom(data, public_key)
            elif self.curve == "P-521":
                impl = ECCP521Implementation(is_custom=True)
                return impl._encrypt_custom(data, public_key)
            else:
                raise ValueError(f"Unsupported curve for custom implementation: {self.curve}")
        else:
            return self._encrypt_stdlib_single(data, public_key)
    
    def _encrypt_stdlib_single(self, data, public_key):
        # encrypt a single chunk using standard library
        # get the curve
        curve_map = {
            "P-256": ec.SECP256R1(),
            "P-384": ec.SECP384R1(),
            "P-521": ec.SECP521R1()
        }
        curve = curve_map.get(self.curve)
        if not curve:
            raise ValueError(f"Unsupported curve: {self.curve}")
        
        # generate an ephemeral key pair for this chunk
        ephemeral_private = ec.generate_private_key(curve)
        ephemeral_public = ephemeral_private.public_key()
        
        # perform key agreement to get a shared secret
        shared_secret = ephemeral_private.exchange(
            ec.ECDH(),
            public_key
        )
        
        shared_secret_bytes = shared_secret[:len(data)]  # take only needed bytes
        if len(shared_secret_bytes) < len(data):
            # extend shared secret if needed using hash expansion
            import hashlib
            extended_secret = shared_secret
            while len(extended_secret) < len(data):
                extended_secret += hashlib.sha256(extended_secret).digest()
            shared_secret_bytes = extended_secret[:len(data)]
        
        # XOR encryption (one-time pad)
        ciphertext = bytes(a ^ b for a, b in zip(data, shared_secret_bytes))
        
        # serialize the ephemeral public key (compressed format)
        ephemeral_public_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        
        # return: curve_id + ephemeral_public_key + ciphertext
        curve_id = self.curve.encode('ascii')
        header = len(curve_id).to_bytes(1, 'big') + curve_id
        return header + len(ephemeral_public_bytes).to_bytes(2, 'big') + ephemeral_public_bytes + ciphertext
    
    def decrypt(self, ciphertext, private_key=None):
        # decrypt data using pure ECC with chunk processing
        if private_key is None:
            private_key = self.private_key
        elif hasattr(private_key, '__rotating_keys__'):
            # this is a RotatingKeySet - get the next key
            key_pair = private_key.get_next_key()
            # if a key pair tuple is passed, use the second element (private key)
            private_key = key_pair[1]
        elif isinstance(private_key, tuple):
            # if a key pair tuple is passed, use the second element (private key)
            private_key = private_key[1]
        
        if not private_key:
            raise ValueError("Private key is required for decryption")
        
        # check if this is chunked data (has chunk headers)
        if len(ciphertext) < 8:  # too small to have chunk headers
            # try direct decryption
            return self._decrypt_single_chunk(ciphertext, private_key)
        
        # check if it looks like chunked data
        try:
            first_chunk_num = int.from_bytes(ciphertext[:4], byteorder='big')
            first_chunk_size = int.from_bytes(ciphertext[4:8], byteorder='big')
            
            # if chunk number is 0 and chunk size seems reasonable, assume chunked format
            if first_chunk_num == 0 and 0 < first_chunk_size <= 2048:  # reasonable size limit
                return self._decrypt_chunked_data(ciphertext, private_key)
            else:
                # try direct decryption
                return self._decrypt_single_chunk(ciphertext, private_key)
        except:
            # if parsing headers fails, try direct decryption
            return self._decrypt_single_chunk(ciphertext, private_key)
    
    def _decrypt_chunked_data(self, ciphertext, private_key):

        result = b""
        offset = 0
        expected_chunk_num = 0
        
        while offset < len(ciphertext):
            # read chunk header (8 bytes)
            if offset + 8 > len(ciphertext):
                break
            
            chunk_num = int.from_bytes(ciphertext[offset:offset+4], byteorder='big')
            encrypted_size = int.from_bytes(ciphertext[offset+4:offset+8], byteorder='big')
            offset += 8
            
            # verify chunk ordering
            if chunk_num != expected_chunk_num:
                return b''  # chunks out of order
            
            # read encrypted chunk
            if offset + encrypted_size > len(ciphertext):
                break
            
            encrypted_chunk = ciphertext[offset:offset+encrypted_size]
            offset += encrypted_size
            expected_chunk_num += 1
            
            # decrypt chunk
            try:
                decrypted_chunk = self._decrypt_single_chunk(encrypted_chunk, private_key)
                result += decrypted_chunk
            except:
                return b''  # Decryption failed
        
        return result
    
    def _decrypt_single_chunk(self, ciphertext, private_key):
        if self.is_custom:
            # delegate to the appropriate curve-specific implementation
            from .ecc_p256 import ECCP256Implementation
            from .ecc_p384 import ECCP384Implementation
            from .ecc_p521 import ECCP521Implementation
            
            if self.curve == "P-256":
                impl = ECCP256Implementation(is_custom=True)
                return impl._decrypt_custom(ciphertext, private_key)
            elif self.curve == "P-384":
                impl = ECCP384Implementation(is_custom=True)
                return impl._decrypt_custom(ciphertext, private_key)
            elif self.curve == "P-521":
                impl = ECCP521Implementation(is_custom=True)
                return impl._decrypt_custom(ciphertext, private_key)
            else:
                raise ValueError(f"Unsupported curve for custom implementation: {self.curve}")
        else:
            return self._decrypt_stdlib_single(ciphertext, private_key)
    
    def _decrypt_stdlib_single(self, ciphertext, private_key):
       
        try:
            # parse the header to get curve ID
            if len(ciphertext) < 1:
                return b''
            
            curve_id_len = ciphertext[0]
            if len(ciphertext) < 1 + curve_id_len + 2:  # header + curve_id + ephemeral_key_len
                return b''
            
            curve_id = ciphertext[1:1+curve_id_len].decode('ascii')
            if curve_id != self.curve:
                return b''  # wrong curve
            
            # extract ephemeral public key length
            offset = 1 + curve_id_len
            ephemeral_key_len = int.from_bytes(ciphertext[offset:offset+2], 'big')
            offset += 2
            
            # ensure we have enough data
            if len(ciphertext) < offset + ephemeral_key_len:  # key + ciphertext
                return b''
            
            # extract ephemeral public key
            ephemeral_public_bytes = ciphertext[offset:offset+ephemeral_key_len]
            offset += ephemeral_key_len
            
            # extract actual ciphertext
            actual_ciphertext = ciphertext[offset:]
            
            # load the ephemeral public key
            ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
                {
                    "P-256": ec.SECP256R1(),
                    "P-384": ec.SECP384R1(),
                    "P-521": ec.SECP521R1()
                }[curve_id],
                ephemeral_public_bytes
            )
            
            # perform key agreement to get the shared secret
            shared_secret = private_key.exchange(
                ec.ECDH(),
                ephemeral_public
            )
            
            shared_secret_bytes = shared_secret[:len(actual_ciphertext)]  # take only needed bytes
            if len(shared_secret_bytes) < len(actual_ciphertext):
                # extend shared secret if needed using hash expansion
                import hashlib
                extended_secret = shared_secret
                while len(extended_secret) < len(actual_ciphertext):
                    extended_secret += hashlib.sha256(extended_secret).digest()
                shared_secret_bytes = extended_secret[:len(actual_ciphertext)]
            
            # XOR decryption (one-time pad)
            plaintext = bytes(a ^ b for a, b in zip(actual_ciphertext, shared_secret_bytes))
            return plaintext
            
        except Exception:
            # handle errors gracefully for chunk processing
            return b''
    
    def sign(self, data, private_key=None):
        
        if private_key is None:
            private_key = self.private_key
        elif isinstance(private_key, tuple):
            # if a key pair tuple is passed, use the second element (private key)
            private_key = private_key[1]
        
        if not private_key:
            raise ValueError("Private key is required for signing")
        
        if self.is_custom:
            # delegate to the appropriate curve-specific implementation
            from .ecc_p256 import ECCP256Implementation
            from .ecc_p384 import ECCP384Implementation
            from .ecc_p521 import ECCP521Implementation
            
            if self.curve == "P-256":
                impl = ECCP256Implementation(is_custom=True)
                return impl._sign_custom(data, private_key)
            elif self.curve == "P-384":
                impl = ECCP384Implementation(is_custom=True)
                return impl._sign_custom(data, private_key)
            elif self.curve == "P-521":
                impl = ECCP521Implementation(is_custom=True)
                return impl._sign_custom(data, private_key)
            else:
                raise ValueError(f"Unsupported curve for custom implementation: {self.curve}")
        else:
            # choose the appropriate hash algorithm based on curve size
            hash_algo = {
                "P-256": hashes.SHA256(),
                "P-384": hashes.SHA384(),
                "P-521": hashes.SHA512()
            }.get(self.curve, hashes.SHA256())
            
            # hash the data first
            data_hash = hashlib.new(hash_algo.name, data).digest()
            
            # sign the hash
            signature = private_key.sign(
                data_hash,
                ec.ECDSA(hash_algo)
            )
            
            return signature
    
    def verify(self, data, signature, public_key=None):
        
        if public_key is None:
            public_key = self.public_key
        elif isinstance(public_key, tuple):
            # if a key pair tuple is passed, use the first element (public key)
            public_key = public_key[0]
        
        if not public_key:
            raise ValueError("Public key is required for verification")
        
        if self.is_custom:
            # delegate to the appropriate curve-specific implementation
            from .ecc_p256 import ECCP256Implementation
            from .ecc_p384 import ECCP384Implementation
            from .ecc_p521 import ECCP521Implementation
            
            if self.curve == "P-256":
                impl = ECCP256Implementation(is_custom=True)
                return impl._verify_custom(data, signature, public_key)
            elif self.curve == "P-384":
                impl = ECCP384Implementation(is_custom=True)
                return impl._verify_custom(data, signature, public_key)
            elif self.curve == "P-521":
                impl = ECCP521Implementation(is_custom=True)
                return impl._verify_custom(data, signature, public_key)
            else:
                raise ValueError(f"Unsupported curve for custom implementation: {self.curve}")
        else:
            # choose the appropriate hash algorithm based on curve size
            hash_algo = {
                "P-256": hashes.SHA256(),
                "P-384": hashes.SHA384(),
                "P-521": hashes.SHA512()
            }.get(self.curve, hashes.SHA256())
            
            # hash the data first
            data_hash = hashlib.new(hash_algo.name, data).digest()
            
            # verify the signature
            try:
                public_key.verify(
                    signature,
                    data_hash,
                    ec.ECDSA(hash_algo)
                )
                return True
            except InvalidSignature:
                return False
            except Exception:
                return False
    
    def encrypt_stream(self, data, key, chunk_size=8192):
       
        if isinstance(key, tuple):
            public_key = key[0]
        else:
            public_key = key
        
        return self.encrypt(data, public_key)
    
    def decrypt_stream(self, data, key, chunk_size=8192):
        
        # extract private key if a key pair is provided
        if isinstance(key, tuple):
            private_key = key[1]
        else:
            private_key = key
        
        return self.decrypt(data, private_key)


def create_stdlib_ecc_implementation(curve="P-256", **kwargs):
    
    from .ecc_p256 import ECCP256Implementation
    from .ecc_p384 import ECCP384Implementation
    from .ecc_p521 import ECCP521Implementation
    
    logger = logging.getLogger("PythonCore")
    logger.info(f"Creating standard library ECC implementation with curve {curve}")
    
    # remove curve from kwargs if it exists
    if 'curve' in kwargs:
        kwargs.pop('curve')
    
    # set is_custom to False, removing any existing value
    kwargs = {k: v for k, v in kwargs.items() if k != 'is_custom'}
    
    if curve == "P-256":
        logger.info(f"Using specialized P-256 ECC implementation")
        return ECCP256Implementation(is_custom=False, **kwargs)
    elif curve == "P-384":
        logger.info(f"Using specialized P-384 ECC implementation")
        return ECCP384Implementation(is_custom=False, **kwargs)
    elif curve == "P-521":
        logger.info(f"Using specialized P-521 ECC implementation")
        return ECCP521Implementation(is_custom=False, **kwargs)
    else:
        logger.info(f"Using generic ECC implementation for curve {curve}")
        return ECCImplementation(curve=curve, is_custom=False, **kwargs)


def create_custom_ecc_implementation(curve="P-256", **kwargs):
    
    from .ecc_p256 import ECCP256Implementation
    from .ecc_p384 import ECCP384Implementation
    from .ecc_p521 import ECCP521Implementation
    
    logger = logging.getLogger("PythonCore")
    logger.info(f"Creating custom ECC implementation with curve {curve}")
    
    # remove curve from kwargs if it exists
    if 'curve' in kwargs:
        kwargs.pop('curve')
    
    # set is_custom to True, removing any existing value
    kwargs = {k: v for k, v in kwargs.items() if k != 'is_custom'}
    
    if curve == "P-256":
        logger.info(f"Using specialized custom P-256 ECC implementation")
        return ECCP256Implementation(is_custom=True, **kwargs)
    elif curve == "P-384":
        logger.info(f"Using specialized custom P-384 ECC implementation")
        return ECCP384Implementation(is_custom=True, **kwargs)
    elif curve == "P-521":
        logger.info(f"Using specialized custom P-521 ECC implementation")
        return ECCP521Implementation(is_custom=True, **kwargs)
    else:
        logger.info(f"Using generic custom ECC implementation for curve {curve}")
        return ECCImplementation(curve=curve, is_custom=True, **kwargs)


def register_all_ecc_variants():
    
    # different curves with specialized implementations
    from .ecc_p256 import ECCP256Implementation
    from .ecc_p384 import ECCP384Implementation
    from .ecc_p521 import ECCP521Implementation
    
    # define curves and their mappings
    curves = [
        ("P-256", "p256", ECCP256Implementation),
        ("P-384", "p384", ECCP384Implementation), 
        ("P-521", "p521", ECCP521Implementation)
    ]
    
    # register all combinations: ecc{curve}_{standard/custom}
    for curve_name, safe_name, impl_class in curves:
        # standard library implementations
        variant_name = f"ecc{safe_name}_standard"
        ECC_IMPLEMENTATIONS[variant_name] = lambda impl=impl_class, **kwargs: impl(**{k: v for k, v in kwargs.items() if k != 'is_custom'}, is_custom=False)
        
        # custom implementations  
        variant_name = f"ecc{safe_name}_custom"
        ECC_IMPLEMENTATIONS[variant_name] = lambda impl=impl_class, **kwargs: impl(**{k: v for k, v in kwargs.items() if k != 'is_custom'}, is_custom=True)
    
    # legacy compatibility variants
    ECC_IMPLEMENTATIONS["ecc_p256"] = lambda **kwargs: ECCP256Implementation(**{k: v for k, v in kwargs.items() if k != 'is_custom'}, is_custom=False)
    ECC_IMPLEMENTATIONS["ecc_p384"] = lambda **kwargs: ECCP384Implementation(**{k: v for k, v in kwargs.items() if k != 'is_custom'}, is_custom=False)
    ECC_IMPLEMENTATIONS["ecc_p521"] = lambda **kwargs: ECCP521Implementation(**{k: v for k, v in kwargs.items() if k != 'is_custom'}, is_custom=False)
    
    ECC_IMPLEMENTATIONS["ecc_p256_custom"] = lambda **kwargs: ECCP256Implementation(**{k: v for k, v in kwargs.items() if k != 'is_custom'}, is_custom=True)
    ECC_IMPLEMENTATIONS["ecc_p384_custom"] = lambda **kwargs: ECCP384Implementation(**{k: v for k, v in kwargs.items() if k != 'is_custom'}, is_custom=True)
    ECC_IMPLEMENTATIONS["ecc_p521_custom"] = lambda **kwargs: ECCP521Implementation(**{k: v for k, v in kwargs.items() if k != 'is_custom'}, is_custom=True)
    
    # default variants
    ECC_IMPLEMENTATIONS["ecc_custom"] = lambda **kwargs: create_custom_ecc_implementation(curve=kwargs.pop("curve", "P-256"), **kwargs) 