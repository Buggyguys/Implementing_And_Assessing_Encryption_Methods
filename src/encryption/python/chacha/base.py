import os
import hashlib

# max input size
MAX_INPUT_SIZE = 16 * 1024 * 1024  # 16MB 

class ChaCha20ImplementationBase:
    # base class for chacha20
    
    def __init__(self, key_size="256", **kwargs):
        self.key_size = int(key_size)
        self.name = "ChaCha20"
        self.description = f"ChaCha20 with {key_size}-bit key"
        self.key = None
        self.nonce = None
    
    def _format_key_size(self, size_bits):
        # convert key size in bits to bytes
        return size_bits // 8
    
    def generate_key(self):

        # generate a random key of the specified size
        key_bytes = self._format_key_size(self.key_size)
        
        # validate key size
        if key_bytes not in (16, 24, 32):  
            key_bytes = 32  # default to 256 bits if invalid size
        
        # generate a high-quality random key
        self.key = os.urandom(key_bytes)
        
        # key derivation (for benchmarking)
        if hasattr(self, 'use_kdf') and self.use_kdf:
            salt = os.urandom(16)
            key_material = hashlib.pbkdf2_hmac('sha256', self.key, salt, 10000, dklen=32)  # Always 32 bytes for ChaCha20
            self.key = key_material
            
        return self.key

    def encrypt(self, data, key):
        # encrypt data using the specified key
        raise NotImplementedError("Subclasses must implement this method")
    
    def decrypt(self, ciphertext, key):
        # decrypt data using the specified key
        raise NotImplementedError("Subclasses must implement this method") 