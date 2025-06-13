import gc
import os
import time
import struct
import hashlib
try:
    from Crypto.Cipher import ChaCha20 as CryptoChaCha20
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# remove circular import
from .base import ChaCha20ImplementationBase, MAX_INPUT_SIZE
from .custom_chacha20 import CustomChaCha20

# dictionary to track implementations
CHACHA_IMPLEMENTATIONS = {}

# local implementation of register_implementation to avoid circular imports
def register_chacha_variant(name):
    # register a chacha20 implementation variant
    def decorator(impl_class):
        CHACHA_IMPLEMENTATIONS[name] = impl_class
        return impl_class
    return decorator

@register_chacha_variant("chacha20")
class ChaCha20Implementation(ChaCha20ImplementationBase):
    # chacha20 implementation with both standard and custom options
    
    def __init__(self, key_size="256", **kwargs):
        # initialize with key size
        super().__init__(key_size=key_size, **kwargs)
        self.is_custom = kwargs.get("is_custom", False)
        if self.is_custom:
            self.description = f"Custom ChaCha20 Implementation ({key_size}-bit key)"
        else:
            self.description = f"PyCryptodome ChaCha20 Implementation ({key_size}-bit key)"
        
        # set specific implementation to use
        if self.is_custom:
            self.impl = CustomChaCha20()
    
    def encrypt(self, data, key):
        # encrypt data using chacha20
        if self.is_custom:
            return self._custom_encrypt(data, key)
        else:
            return self._lib_encrypt(data, key)
    
    def decrypt(self, ciphertext, key):
        # decrypt ciphertext using chacha20
        if self.is_custom:
            return self._custom_decrypt(ciphertext, key)
        else:
            return self._lib_decrypt(ciphertext, key)
    
    def _lib_encrypt(self, data, key):
        # encrypt using pycryptodome chacha20 implementation
        if not CRYPTO_AVAILABLE:
            raise ImportError("PyCryptodome is not available. Install it with 'pip install pycryptodome'")
        
        # generate a random nonce
        nonce = os.urandom(8)  # 8 bytes (64 bits) for ChaCha20
        
        # store for potential debugging/verification
        self.nonce = nonce
        
        # process in chunks if data exceeds max
        if len(data) > MAX_INPUT_SIZE:
            result = bytearray()
            
            # prepend nonce
            result.extend(nonce)
            
            # process chunks
            for i in range(0, len(data), MAX_INPUT_SIZE):
                chunk = data[i:i+MAX_INPUT_SIZE]
                
                # each chunk needs a new cipher with the same nonce but different counter
                counter = 1 + (i // MAX_INPUT_SIZE)  # start counter at 1
                cipher = CryptoChaCha20.new(key=key, nonce=nonce)
                # skip to the appropriate counter position
                if counter > 1:
                    # skip ahead in the keystream
                    skip_size = (counter - 1) * MAX_INPUT_SIZE
                    cipher.seek(skip_size)
                
                # encrypt this chunk
                result.extend(cipher.encrypt(chunk))
                
                # force memory cleanup for processed chunks
                del chunk, cipher
                if i % (5 * MAX_INPUT_SIZE) == 0:  # every 5 chunks
                    gc.collect()  # help clean up memory
            
            # convert bytearray to bytes for return
            return bytes(result)
        
        # single chunk processing
        cipher = CryptoChaCha20.new(key=key, nonce=nonce)
        return nonce + cipher.encrypt(data)
    
    def _lib_decrypt(self, ciphertext, key):
        # decrypt ciphertext using pycryptodome chacha20 implementation
        if not CRYPTO_AVAILABLE:
            raise ImportError("PyCryptodome is not available. Install it with 'pip install pycryptodome'")
        
        # extract nonce (8 bytes) from ciphertext
        nonce = ciphertext[:8]
        actual_ciphertext = ciphertext[8:]
        
        # for very large ciphertext, use chunk-based processing
        if len(actual_ciphertext) > MAX_INPUT_SIZE:
            result = bytearray()
            
            # process chunks
            for i in range(0, len(actual_ciphertext), MAX_INPUT_SIZE):
                chunk = actual_ciphertext[i:i+MAX_INPUT_SIZE]
                
                # each chunk needs a new cipher with the same nonce but different counter
                counter = 1 + (i // MAX_INPUT_SIZE)  # start counter at 1
                cipher = CryptoChaCha20.new(key=key, nonce=nonce)
                # skip to the appropriate counter position
                if counter > 1:
                    # skip ahead in the keystream
                    skip_size = (counter - 1) * MAX_INPUT_SIZE
                    cipher.seek(skip_size)
                
                # decrypt this chunk
                result.extend(cipher.decrypt(chunk))
                
                # memory cleanup
                del chunk, cipher
                if i % (5 * MAX_INPUT_SIZE) == 0:  # every 5 chunks
                    gc.collect()
            
            return bytes(result)
        else:
            # just decrypt the whole thing
            cipher = CryptoChaCha20.new(key=key, nonce=nonce)
            return cipher.decrypt(actual_ciphertext)
    
    def _custom_encrypt(self, data, key):
        # encrypt using custom chacha20 implementation
        encrypted, _ = self.impl.encrypt(data, key)
        return encrypted
    
    def _custom_decrypt(self, ciphertext, key):
        # decrypt using custom chacha20 implementation
        return self.impl.decrypt(ciphertext, key)
    
    def encrypt_stream(self, data, key, chunk_size=8192):
        # encrypt using chacha20 in stream mode with specified chunk size
        result = b""
        
        # process data in chunks
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            
            # Encrypt the chunk using regular encrypt method
            encrypted_chunk = self.encrypt(chunk, key)
            
            # add chunk boundary marker
            chunk_header = len(encrypted_chunk).to_bytes(4, byteorder='big')
            result += chunk_header + encrypted_chunk
        
        return result
    
    def decrypt_stream(self, data, key, chunk_size=8192):
        # decrypt using chacha20 in stream mode with specified chunk size
        result = b""
        offset = 0
        
        # process concatenated encrypted chunks
        while offset < len(data):
            # read chunk size (4 bytes)
            if offset + 4 > len(data):
                break
            
            encrypted_chunk_size = int.from_bytes(data[offset:offset+4], byteorder='big')
            offset += 4
            
            # read encrypted chunk
            if offset + encrypted_chunk_size > len(data):
                break
            
            encrypted_chunk = data[offset:offset+encrypted_chunk_size]
            offset += encrypted_chunk_size
            
            # decrypt chunk using regular decrypt method
            decrypted_chunk = self.decrypt(encrypted_chunk, key)
            result += decrypted_chunk
        
        return result


def create_custom_chacha20_implementation(key_size="256"):
    # create a custom chacha20 implementation
    return ChaCha20Implementation(key_size=key_size, is_custom=True)


def create_stdlib_chacha20_implementation(key_size="256"):
    # create a standard library chacha20 implementation
    return ChaCha20Implementation(key_size=key_size, is_custom=False)


def register_all_chacha20_variants():
    # register all chacha20 variants
    # register chacha20 (standard and custom)
    CHACHA_IMPLEMENTATIONS["chacha20_std"] = lambda **kwargs: create_stdlib_chacha20_implementation(
        key_size=kwargs.get("key_size", "256")
    )
    
    CHACHA_IMPLEMENTATIONS["chacha20_custom"] = lambda **kwargs: create_custom_chacha20_implementation(
        key_size=kwargs.get("key_size", "256")
    ) 