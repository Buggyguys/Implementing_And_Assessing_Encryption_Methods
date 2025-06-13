import os
import secrets

# apply PKCS#7 padding
def pad_data(data, block_size):

    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data must be bytes or bytearray")
    
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

# remove the PKCS#7 padding
def unpad_data(padded_data, block_size):

    if not isinstance(padded_data, (bytes, bytearray)):
        raise TypeError("Data must be bytes or bytearray")
    
    if len(padded_data) == 0:
        raise ValueError("Cannot unpad empty data")
    
    if len(padded_data) % block_size != 0:
        raise ValueError("Padded data length must be multiple of block size")
    
    padding_length = padded_data[-1]
    
    if padding_length == 0 or padding_length > block_size:
        raise ValueError("Invalid padding length")
    
    if len(padded_data) < padding_length:
        raise ValueError("Invalid padding length")
    
    # Check that all padding bytes are correct
    for i in range(padding_length):
        if padded_data[-(i + 1)] != padding_length:
            raise ValueError("Invalid padding")
    
    return padded_data[:-padding_length]

def generate_key(key_size_bits):

    if key_size_bits not in [128, 192, 256]:
        raise ValueError(f"Invalid key size: {key_size_bits} bits. Must be 128, 192, or 256.")
    
    key_size_bytes = key_size_bits // 8
    return secrets.token_bytes(key_size_bytes)

def generate_iv():
    
    return secrets.token_bytes(16)

def bytes_to_int(data):

    return int.from_bytes(data, 'big')

def int_to_bytes(value, length):

    return value.to_bytes(length, 'big')

def xor_bytes(a, b):

    if len(a) != len(b):
        raise ValueError("Byte strings must have same length")
    
    return bytes(x ^ y for x, y in zip(a, b))

def validate_key_size(key):

    key_size_bits = len(key) * 8
    if key_size_bits not in [128, 192, 256]:
        raise ValueError(f"Invalid key size: {key_size_bits} bits. Must be 128, 192, or 256.")

def validate_iv(iv):

    if len(iv) != 16:
        raise ValueError("IV must be equal to 16 bytes")

def validate_block_size(data, block_size=16):
    
    if len(data) % block_size != 0:
        raise ValueError(f"Data length must be multiple of {block_size} bytes") 
