from .key_utils import generate_key, generate_custom_key

MAX_INPUT_SIZE = 16 * 1024 * 1024

class AESImplementationBase:
    
    def __init__(self, key_size="256", mode="GCM", **kwargs):
        self.key_size = int(key_size)
        self.mode = mode
        self.name = "AES"
        self.description = f"AES-{key_size} in {mode} mode"
        self.key = None
        self.iv = None
        self.tag = None
        self.use_kdf = kwargs.get('use_kdf', False)
        self.is_custom = kwargs.get('is_custom', False)
    
    def generate_key(self):
        # Delegate key generation to the appropriate utility function
        if self.is_custom:
            self.key = generate_custom_key(self.key_size, self.use_kdf)
        else:
            self.key = generate_key(self.key_size, self.use_kdf)
        return self.key
    
    def encrypt(self, data, key):
        raise NotImplementedError("Subclasses must implement this method")
    
    def decrypt(self, ciphertext, key):
        raise NotImplementedError("Subclasses must implement this method") 
