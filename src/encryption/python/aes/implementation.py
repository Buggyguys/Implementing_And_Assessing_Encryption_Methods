from .base import AESImplementationBase
from . import aes_gcm, aes_cbc, aes_cfb, aes_ofb

# dictionary to track implementations
AES_IMPLEMENTATIONS = {}

# local implementation of register_implementation to avoid circular imports
def register_aes_variant(name):

    def decorator(impl_class):
        AES_IMPLEMENTATIONS[name] = impl_class
        return impl_class
    return decorator

@register_aes_variant("aes")
class AESImplementation(AESImplementationBase):
    # implementaaion using modular approach for different modes
    
    def __init__(self, key_size="256", mode="GCM", **kwargs):

        # initialize key with size and mode
        super().__init__(key_size, mode, **kwargs)
        
        if self.is_custom:
            self.description = f"Custom AES-{key_size} in {mode} mode"
        else:
            self.description = f"PyCryptodome AES-{key_size} in {mode} mode"
    
    def encrypt(self, data, key):

        # select appropriate mode implementation
        if self.mode == "GCM":
            return aes_gcm.encrypt(data, key, None, self.is_custom)
        elif self.mode == "CBC":
            return aes_cbc.encrypt(data, key, None, self.is_custom)
        elif self.mode == "CFB":
            return aes_cfb.encrypt(data, key, None, self.is_custom)
        elif self.mode == "OFB":
            return aes_ofb.encrypt(data, key, None, self.is_custom)
        else:
            raise ValueError(f"Unsupported AES mode: {self.mode}")
    
    def decrypt(self, ciphertext, key):
        
        # select appropriate mode implementation
        if self.mode == "GCM":
            return aes_gcm.decrypt(ciphertext, key, self.is_custom)
        elif self.mode == "CBC":
            return aes_cbc.decrypt(ciphertext, key, self.is_custom)
        elif self.mode == "CFB":
            return aes_cfb.decrypt(ciphertext, key, self.is_custom)
        elif self.mode == "OFB":
            return aes_ofb.decrypt(ciphertext, key, self.is_custom)
        else:
            raise ValueError(f"Unsupported AES mode: {self.mode}")
    
    def encrypt_stream(self, data, key, chunk_size=8192):

        result = b""
        
        # process data in chunks
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            
            # encrypt the chunk using regular encrypt method
            encrypted_chunk = self.encrypt(chunk, key)
            
            # add chunk boundary marker
            chunk_header = len(encrypted_chunk).to_bytes(4, byteorder='big')
            result += chunk_header + encrypted_chunk
        
        return result
    
    def decrypt_stream(self, data, key, chunk_size=8192):
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

def create_custom_aes_implementation(key_size, mode):

    return AESImplementation(key_size=key_size, mode=mode, is_custom=True)

def create_stdlib_aes_implementation(key_size, mode):

    return AESImplementation(key_size=key_size, mode=mode, is_custom=False)

def register_all_aes_variants():

    # different key sizes and modes
    for key_size in ["128", "192", "256"]:
        for mode in ["GCM", "CBC", "CFB", "OFB"]:
            variant_name = f"aes{key_size}_{mode.lower()}"
            AES_IMPLEMENTATIONS[variant_name] = lambda ks=key_size, m=mode, **kwargs: AESImplementation(
                key_size=ks, mode=m, **kwargs
            ) 
