import os
import hashlib
import secrets

def format_key_size(size_bits):

    # convert key form bits to bytes
    return size_bits // 8

def generate_key(key_size=256, use_kdf=False):

    key_bytes = format_key_size(key_size)
    
    # validate key size
    if key_bytes not in (16, 24, 32):  # 128, 192, or 256 bits
        raise ValueError(f"Invalid key size: {key_size} bits. Must be 128, 192, or 256 bits.")
    
    # generate a random key
    key = os.urandom(key_bytes)
    
    # key derivation (optional, for benchmarking purpose)
    if use_kdf:
        salt = os.urandom(16)
        key_material = hashlib.pbkdf2_hmac('sha256', key, salt, 10000, dklen=key_bytes)
        key = key_material
        
    return key

def generate_custom_key(key_size=256, use_kdf=False):

    key_bytes = format_key_size(key_size)
    
    # validate key size
    if key_bytes not in (16, 24, 32):  # 128, 192, or 256 bits
        raise ValueError(f"Invalid key size: {key_size} bits. Must be 128, 192, or 256 bits.")
    
    key = bytes(secrets.randbits(8) for _ in range(key_bytes))
    
    if use_kdf:

        # simple custom KDF implementation
        derived_key = bytearray(key_bytes)
        salt = bytes(secrets.randbits(8) for _ in range(16))
        
        # key stretching technique (not recommended)
        for i in range(1000):
            temp = salt + key + i.to_bytes(4, 'big')
            hash_result = hashlib.sha256(temp).digest()
            for j in range(key_bytes):
                derived_key[j] ^= hash_result[j % 32]
        
        key = bytes(derived_key)
        
    return key

def get_iv(mode, custom=False):

    if custom:
        return get_custom_iv(mode)
    else:
        return get_stdlib_iv(mode)

def get_stdlib_iv(mode):

    # generate a standard 16-byte IV
    iv = os.urandom(16)
    
    # return appropriate length based on mode
    if mode == "GCM":
        return iv[:12]  # 12 bytes for GCM
    elif mode == "CTR":
        return iv       # 16 bytes, but only first 8 used as nonce
    else:
        return iv       # 16 bytes for CBC/ECB

def get_custom_iv(mode):
    
    # generate a 16-byte IV using our custom random generation
    iv = bytes(secrets.randbits(8) for _ in range(16))
    
    # return appropriate length based on mode
    if mode == "GCM":
        return iv[:12]  # 12 bytes for GCM
    elif mode == "CTR":
        return iv       # 16 bytes, but only first 8 used as nonce
    else:
        return iv       # 16 bytes for CBC/ECB 
