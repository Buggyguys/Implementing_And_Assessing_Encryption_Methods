#!/usr/bin/env python3
"""
CryptoBench Pro - AES-CFB Implementation
Provides AES encryption/decryption in CFB mode.
"""

import gc
from Crypto.Cipher import AES as CryptoAES
from .key_utils import get_iv, format_key_size, get_stdlib_iv, get_custom_iv
from .custom_aes import CustomAES

# Maximum input size for AES (for efficient memory usage)
MAX_INPUT_SIZE = 16 * 1024 * 1024  # 16MB chunks for processing larger data

def encrypt(data, key, iv=None, use_custom=False):
    """
    Encrypt data using AES in CFB mode.
    
    Args:
        data: Data to encrypt
        key: Encryption key
        iv: Initialization vector. If None, a random one will be generated.
        use_custom: Whether to use the custom implementation
        
    Returns:
        bytes: Encrypted data (iv + ciphertext)
    """
    if use_custom:
        return encrypt_custom(data, key, iv)
    else:
        return encrypt_stdlib(data, key, iv)

def decrypt(ciphertext, key, use_custom=False):
    """
    Decrypt data using AES in CFB mode.
    
    Args:
        ciphertext: Data to decrypt (iv + ciphertext)
        key: Decryption key
        use_custom: Whether to use the custom implementation
        
    Returns:
        bytes: Decrypted data
    """
    if use_custom:
        return decrypt_custom(ciphertext, key)
    else:
        return decrypt_stdlib(ciphertext, key)

def encrypt_stdlib(data, key, iv=None):
    """
    Encrypt data using PyCryptodome AES-CFB implementation.
    
    Args:
        data: Data to encrypt
        key: Encryption key
        iv: Initialization vector. If None, a random one will be generated.
        
    Returns:
        bytes: Encrypted data (iv + ciphertext)
    """
    # Generate IV if not provided
    if iv is None:
        iv = get_stdlib_iv("CFB")
    
    # Process in chunks if data exceeds MAX_INPUT_SIZE
    if len(data) > MAX_INPUT_SIZE:
        result = bytearray()
        result.extend(iv)  # Prepend IV
        
        # Process chunks
        for i in range(0, len(data), MAX_INPUT_SIZE):
            chunk = data[i:i+MAX_INPUT_SIZE]
            cipher = CryptoAES.new(key, CryptoAES.MODE_CFB, iv)
            result.extend(cipher.encrypt(chunk))
            
            # Force memory cleanup for processed chunks
            del chunk
            if i % (5 * MAX_INPUT_SIZE) == 0:  # Every 5 chunks
                gc.collect()
        
        return bytes(result)
    else:
        # Single chunk processing
        cipher = CryptoAES.new(key, CryptoAES.MODE_CFB, iv)
        return iv + cipher.encrypt(data)

def decrypt_stdlib(ciphertext, key):
    """
    Decrypt ciphertext using PyCryptodome AES-CFB implementation.
    
    Args:
        ciphertext: Data to decrypt (iv + ciphertext)
        key: Decryption key
        
    Returns:
        bytes: Decrypted data
    """
    # Extract IV from ciphertext
    iv_size = 16
    
    if len(ciphertext) < iv_size:
        raise ValueError("Ciphertext too short")
    
    iv = ciphertext[:iv_size]
    actual_ciphertext = ciphertext[iv_size:]
    
    # Decrypt the data
    cipher = CryptoAES.new(key, CryptoAES.MODE_CFB, iv)
    return cipher.decrypt(actual_ciphertext)

def encrypt_custom(data, key, iv=None):
    """
    Encrypt data using custom AES-CFB implementation.
    
    Args:
        data: Data to encrypt
        key: Encryption key
        iv: Initialization vector. If None, a random one will be generated.
        
    Returns:
        bytes: Encrypted data (iv + ciphertext)
    """
    # Generate IV if not provided
    if iv is None:
        iv = get_custom_iv("CFB")
    
    # Create AES instance
    aes = CustomAES(key)
    
    # Pre-allocate bytearrays for better memory efficiency
    result = bytearray()
    result.extend(iv)  # Add IV to result
    
    # CFB mode: encrypt IV, then XOR with plaintext
    shift_register = bytearray(iv)
    
    # Process data byte by byte (or in chunks for efficiency)
    for i in range(0, len(data)):
        # Encrypt the shift register
        encrypted_sr = aes.encrypt_block(bytes(shift_register))
        
        # XOR first byte of encrypted shift register with plaintext byte
        cipher_byte = data[i] ^ encrypted_sr[0]
        result.append(cipher_byte)
        
        # Update shift register: shift left and add new cipher byte
        shift_register = shift_register[1:] + bytearray([cipher_byte])
    
    return bytes(result)

def decrypt_custom(ciphertext, key):
    """
    Decrypt ciphertext using custom AES-CFB implementation.
    
    Args:
        ciphertext: Data to decrypt (iv + ciphertext)
        key: Decryption key
        
    Returns:
        bytes: Decrypted data
    """
    # Extract IV from ciphertext
    iv_size = 16
    
    if len(ciphertext) < iv_size:
        raise ValueError("Ciphertext too short")
    
    iv = ciphertext[:iv_size]
    actual_ciphertext = ciphertext[iv_size:]
    
    # Create AES instance
    aes = CustomAES(key)
    
    # CFB mode decryption
    result = bytearray()
    shift_register = bytearray(iv)
    
    # Process data byte by byte
    for i in range(len(actual_ciphertext)):
        # Encrypt the shift register
        encrypted_sr = aes.encrypt_block(bytes(shift_register))
        
        # XOR first byte of encrypted shift register with ciphertext byte
        plain_byte = actual_ciphertext[i] ^ encrypted_sr[0]
        result.append(plain_byte)
        
        # Update shift register: shift left and add ciphertext byte
        shift_register = shift_register[1:] + bytearray([actual_ciphertext[i]])
    
    return bytes(result) 