#!/usr/bin/env python3
"""
CryptoBench Pro - AES-CBC Implementation
Provides AES encryption/decryption in CBC mode.
"""

import gc
import struct
from Crypto.Cipher import AES as CryptoAES
from Crypto.Util.Padding import pad, unpad
from .key_utils import get_iv, format_key_size, get_stdlib_iv, get_custom_iv
from .custom_aes import CustomAES

# Maximum input size for AES (for efficient memory usage)
MAX_INPUT_SIZE = 16 * 1024 * 1024  # 16MB chunks for processing larger data

def encrypt(data, key, iv=None, use_custom=False):
    """
    Encrypt data using AES in CBC mode.
    
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
    Decrypt data using AES in CBC mode.
    
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
    Encrypt data using PyCryptodome AES-CBC implementation.
    
    Args:
        data: Data to encrypt
        key: Encryption key
        iv: Initialization vector. If None, a random one will be generated.
        
    Returns:
        bytes: Encrypted data (iv + ciphertext)
    """
    # Generate IV if not provided
    if iv is None:
        iv = get_stdlib_iv("CBC")
    
    # Process in chunks if data exceeds MAX_INPUT_SIZE
    if len(data) > MAX_INPUT_SIZE:
        # Use a generator approach to avoid creating too many chunks in memory at once
        result = bytearray()
        
        cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
        result.extend(iv)  # Prepend IV
        
        # Process chunks
        for i in range(0, len(data), MAX_INPUT_SIZE):
            chunk = data[i:i+MAX_INPUT_SIZE]
            padded_chunk = pad(chunk, CryptoAES.block_size)
            result.extend(cipher.encrypt(padded_chunk))
            
            # Force memory cleanup for processed chunks
            del chunk, padded_chunk
            if i % (5 * MAX_INPUT_SIZE) == 0:  # Every 5 chunks
                gc.collect()  # Help clean up memory
        
        # Convert bytearray to bytes for return
        return bytes(result)
    else:
        # Single chunk processing
        cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
        padded_data = pad(data, CryptoAES.block_size)
        return iv + cipher.encrypt(padded_data)

def decrypt_stdlib(ciphertext, key):
    """
    Decrypt ciphertext using PyCryptodome AES-CBC implementation.
    
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
    cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
    try:
        padded_plaintext = cipher.decrypt(actual_ciphertext)
        return unpad(padded_plaintext, CryptoAES.block_size)
    except ValueError:
        # Handle padding error
        return b''

def encrypt_custom(data, key, iv=None):
    """
    Encrypt data using custom AES-CBC implementation.
    
    Args:
        data: Data to encrypt
        key: Encryption key
        iv: Initialization vector. If None, a random one will be generated.
        
    Returns:
        bytes: Encrypted data (iv + ciphertext)
    """
    # Generate IV if not provided
    if iv is None:
        iv = get_custom_iv("CBC")
    
    # Get appropriate key size in bytes
    key_bytes = len(key)
    
    # Create AES instance
    aes = CustomAES(key)
    
    # Pre-allocate bytearrays for better memory efficiency
    result = bytearray()
    
    # Add IV to result
    result.extend(iv)
    
    # Check data size and choose appropriate processing strategy
    if len(data) > MAX_INPUT_SIZE:
        # Processing large data in chunks
        # CBC requires sequential processing - optimize the block operations
        prev_block = iv
        chunk_size = min(MAX_INPUT_SIZE, 16 * 1024 * 64)  # Process in 64K block chunks
        
        for i in range(0, len(data), chunk_size):
            # Get chunk and pad if it's the last one
            chunk = data[i:i+chunk_size]
            if i + chunk_size >= len(data):
                chunk = pad(chunk, 16)
            
            # Process blocks within the chunk
            for j in range(0, len(chunk), 16):
                block = chunk[j:j+16]
                
                # Skip incomplete blocks (except last one which should be padded)
                if len(block) != 16:
                    continue
                
                # XOR with previous ciphertext block (CBC mode)
                xor_block = bytearray(16)
                for k in range(16):
                    xor_block[k] = block[k] ^ prev_block[k]
                
                # Encrypt the XORed block
                encrypted_block = aes.encrypt_block(bytes(xor_block))
                result.extend(encrypted_block)
                
                # Update previous block
                prev_block = encrypted_block
            
            # Force garbage collection after each chunk
            if i % (chunk_size * 4) == 0 and i > 0:
                gc.collect()
        
        return bytes(result)
    else:
        # Small data processing - optimized implementation
        # Pad data to multiple of 16 bytes
        padded_data = pad(data, 16)
        
        # Process each block
        prev_block = iv
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            
            # XOR operation with bytearray for better performance
            xor_block = bytearray(16)
            for j in range(16):
                xor_block[j] = block[j] ^ prev_block[j]
            
            # Encrypt the XORed block
            encrypted_block = aes.encrypt_block(bytes(xor_block))
            result.extend(encrypted_block)
            
            # Update previous block
            prev_block = encrypted_block
        
        return bytes(result)

def decrypt_custom(ciphertext, key):
    """
    Decrypt ciphertext using custom AES-CBC implementation.
    
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
    
    # Initialize for decryption
    aes = CustomAES(key)
    result = bytearray()
    
    # Handle large data with optimized processing
    if len(actual_ciphertext) > MAX_INPUT_SIZE:
        prev_block = iv
        chunk_size = min(MAX_INPUT_SIZE, 16 * 1024 * 64)  # 64K blocks at a time
        
        for i in range(0, len(actual_ciphertext), chunk_size):
            chunk = actual_ciphertext[i:i+chunk_size]
            
            for j in range(0, len(chunk), 16):
                if j + 16 > len(chunk):
                    break  # Skip incomplete blocks
                
                block = chunk[j:j+16]
                
                # Decrypt the block
                decrypted_block = aes.decrypt_block(block)
                
                # XOR with previous ciphertext block
                xor_result = bytearray(16)
                for k in range(16):
                    xor_result[k] = decrypted_block[k] ^ prev_block[k]
                
                result.extend(xor_result)
                
                # Update previous block
                prev_block = block
            
            # Force garbage collection
            if i % (chunk_size * 4) == 0 and i > 0:
                gc.collect()
        
        # Remove padding
        try:
            return unpad(result, 16)
        except ValueError:
            # Handle padding error
            return b''
    else:
        # Standard decryption for small data
        prev_block = iv
        
        for i in range(0, len(actual_ciphertext), 16):
            if i + 16 > len(actual_ciphertext):
                break
            
            block = actual_ciphertext[i:i+16]
            
            # Decrypt the block
            decrypted_block = aes.decrypt_block(block)
            
            # XOR with previous block
            xor_result = bytearray(16)
            for j in range(16):
                xor_result[j] = decrypted_block[j] ^ prev_block[j]
            
            result.extend(xor_result)
            
            # Update previous block
            prev_block = block
        
        # Remove padding
        try:
            return unpad(result, 16)
        except ValueError:
            # Handle padding error
            return b'' 