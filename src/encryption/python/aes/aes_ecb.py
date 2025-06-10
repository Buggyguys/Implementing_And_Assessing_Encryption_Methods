#!/usr/bin/env python3
"""
CryptoBench Pro - AES-ECB Implementation
Provides AES encryption/decryption in ECB mode.
"""

import gc
from Crypto.Cipher import AES as CryptoAES
from Crypto.Util.Padding import pad, unpad
from .key_utils import get_iv, format_key_size, get_stdlib_iv, get_custom_iv
from .custom_aes import CustomAES

# Maximum input size for AES (for efficient memory usage)
MAX_INPUT_SIZE = 16 * 1024 * 1024  # 16MB chunks for processing larger data

def encrypt(data, key, iv=None, use_custom=False):
    """
    Encrypt data using AES in ECB mode.
    
    Args:
        data: Data to encrypt
        key: Encryption key
        iv: Initialization vector (not used in ECB, but included for API consistency)
        use_custom: Whether to use the custom implementation
        
    Returns:
        bytes: Encrypted data (iv + ciphertext) - IV included for format consistency
    """
    if use_custom:
        return encrypt_custom(data, key, iv)
    else:
        return encrypt_stdlib(data, key, iv)

def decrypt(ciphertext, key, use_custom=False):
    """
    Decrypt data using AES in ECB mode.
    
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
    Encrypt data using PyCryptodome AES-ECB implementation.
    
    Args:
        data: Data to encrypt
        key: Encryption key
        iv: Initialization vector (not used in ECB, but included for API consistency)
        
    Returns:
        bytes: Encrypted data (iv + ciphertext) - IV included for format consistency
    """
    # Generate IV if not provided (not used for encryption, but included for format consistency)
    if iv is None:
        iv = get_stdlib_iv("ECB")
    
    # Process in chunks if data exceeds MAX_INPUT_SIZE
    if len(data) > MAX_INPUT_SIZE:
        # Use a generator approach to avoid creating too many chunks in memory at once
        result = bytearray()
        
        # Prepend IV (not used for encryption but for consistency with other modes)
        result.extend(iv)
        
        # Process chunks
        for i in range(0, len(data), MAX_INPUT_SIZE):
            chunk = data[i:i+MAX_INPUT_SIZE]
            padded_chunk = pad(chunk, CryptoAES.block_size)
            cipher = CryptoAES.new(key, CryptoAES.MODE_ECB)
            result.extend(cipher.encrypt(padded_chunk))
            
            # Force memory cleanup for processed chunks
            del chunk, padded_chunk
            if i % (5 * MAX_INPUT_SIZE) == 0:  # Every 5 chunks
                gc.collect()  # Help clean up memory
        
        # Convert bytearray to bytes for return
        return bytes(result)
    else:
        # Single chunk processing
        cipher = CryptoAES.new(key, CryptoAES.MODE_ECB)
        padded_data = pad(data, CryptoAES.block_size)
        return iv + cipher.encrypt(padded_data)  # IV not used but included for format consistency

def decrypt_stdlib(ciphertext, key):
    """
    Decrypt ciphertext using PyCryptodome AES-ECB implementation.
    
    Args:
        ciphertext: Data to decrypt (iv + ciphertext)
        key: Decryption key
        
    Returns:
        bytes: Decrypted data
    """
    # Extract IV from ciphertext (not used for decryption)
    iv_size = 16
    
    if len(ciphertext) < iv_size:
        raise ValueError("Ciphertext too short")
    
    actual_ciphertext = ciphertext[iv_size:]
    
    # Process in chunks if ciphertext exceeds MAX_INPUT_SIZE
    if len(actual_ciphertext) > MAX_INPUT_SIZE:
        result = bytearray()
        
        # Process chunks
        for i in range(0, len(actual_ciphertext), MAX_INPUT_SIZE):
            chunk = actual_ciphertext[i:i+MAX_INPUT_SIZE]
            cipher = CryptoAES.new(key, CryptoAES.MODE_ECB)
            decrypted_chunk = cipher.decrypt(chunk)
            
            # Only unpad the last chunk
            if i + MAX_INPUT_SIZE >= len(actual_ciphertext):
                try:
                    decrypted_chunk = unpad(decrypted_chunk, CryptoAES.block_size)
                except ValueError:
                    # Handle padding error
                    return b''
            
            result.extend(decrypted_chunk)
            
            # Force memory cleanup
            del chunk, decrypted_chunk
            if i % (5 * MAX_INPUT_SIZE) == 0:  # Every 5 chunks
                gc.collect()
        
        return bytes(result)
    else:
        # Single chunk processing
        cipher = CryptoAES.new(key, CryptoAES.MODE_ECB)
        try:
            padded_plaintext = cipher.decrypt(actual_ciphertext)
            return unpad(padded_plaintext, CryptoAES.block_size)
        except ValueError:
            # Handle padding error
            return b''

def encrypt_custom(data, key, iv=None):
    """
    Encrypt data using custom AES-ECB implementation.
    
    Args:
        data: Data to encrypt
        key: Encryption key
        iv: Initialization vector (not used in ECB, but included for API consistency)
        
    Returns:
        bytes: Encrypted data (iv + ciphertext) - IV included for format consistency
    """
    # Generate IV if not provided (not used for encryption, but included for format consistency)
    if iv is None:
        iv = get_custom_iv("ECB")
    
    # Create AES instance
    aes = CustomAES(key)
    
    # Pre-allocate bytearrays for better memory efficiency
    result = bytearray()
    
    # Add IV to result (not used in ECB but included for format consistency)
    result.extend(iv)
    
    # Check data size and choose appropriate processing strategy
    if len(data) > MAX_INPUT_SIZE:
        # Processing large data in chunks
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
                
                # Encrypt the block directly (no chaining in ECB)
                encrypted_block = aes.encrypt_block(block)
                result.extend(encrypted_block)
            
            # Force garbage collection after each chunk
            if i % (chunk_size * 4) == 0 and i > 0:
                gc.collect()
        
        return bytes(result)
    else:
        # Small data processing - optimized implementation
        # Pad data to multiple of 16 bytes
        padded_data = pad(data, 16)
        
        # Process each block
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            
            # Encrypt the block directly (no chaining in ECB)
            encrypted_block = aes.encrypt_block(block)
            result.extend(encrypted_block)
        
        return bytes(result)

def decrypt_custom(ciphertext, key):
    """
    Decrypt ciphertext using custom AES-ECB implementation.
    
    Args:
        ciphertext: Data to decrypt (iv + ciphertext)
        key: Decryption key
        
    Returns:
        bytes: Decrypted data
    """
    # Extract IV from ciphertext (not used for decryption in ECB)
    iv_size = 16
    
    if len(ciphertext) < iv_size:
        raise ValueError("Ciphertext too short")
    
    actual_ciphertext = ciphertext[iv_size:]
    
    # Initialize for decryption
    aes = CustomAES(key)
    result = bytearray()
    
    # Handle large data with optimized processing
    if len(actual_ciphertext) > MAX_INPUT_SIZE:
        chunk_size = min(MAX_INPUT_SIZE, 16 * 1024 * 64)  # 64K blocks at a time
        total_chunks = (len(actual_ciphertext) + chunk_size - 1) // chunk_size
        
        for i in range(0, len(actual_ciphertext), chunk_size):
            chunk = actual_ciphertext[i:i+chunk_size]
            chunk_result = bytearray()
            
            # Process blocks within the chunk
            for j in range(0, len(chunk), 16):
                if j + 16 > len(chunk):
                    break  # Skip incomplete blocks
                
                block = chunk[j:j+16]
                
                # Decrypt the block directly
                decrypted_block = aes.decrypt_block(block)
                chunk_result.extend(decrypted_block)
            
            # Only unpad the last chunk
            if i + chunk_size >= len(actual_ciphertext):
                try:
                    chunk_result = unpad(chunk_result, 16)
                except ValueError:
                    # Handle padding error
                    return b''
            
            result.extend(chunk_result)
            
            # Force garbage collection
            if i % (chunk_size * 4) == 0 and i > 0:
                gc.collect()
        
        return bytes(result)
    else:
        # Standard decryption for small data
        for i in range(0, len(actual_ciphertext), 16):
            if i + 16 > len(actual_ciphertext):
                break
            
            block = actual_ciphertext[i:i+16]
            
            # Decrypt the block directly
            decrypted_block = aes.decrypt_block(block)
            result.extend(decrypted_block)
        
        # Remove padding
        try:
            return unpad(result, 16)
        except ValueError:
            # Handle padding error
            return b'' 