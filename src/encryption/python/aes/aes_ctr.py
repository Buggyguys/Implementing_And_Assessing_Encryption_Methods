#!/usr/bin/env python3
"""
CryptoBench Pro - AES-CTR Implementation
Provides AES encryption/decryption in CTR mode.
"""

import gc
import struct
from Crypto.Cipher import AES as CryptoAES
from .key_utils import get_iv, format_key_size, get_stdlib_iv, get_custom_iv
from .custom_aes import CustomAES

# Maximum input size for AES (for efficient memory usage)
MAX_INPUT_SIZE = 16 * 1024 * 1024  # 16MB chunks for processing larger data

def encrypt(data, key, iv=None, use_custom=False):
    """
    Encrypt data using AES in CTR mode.
    
    Args:
        data: Data to encrypt
        key: Encryption key
        iv: Initialization vector (nonce). If None, a random one will be generated.
        use_custom: Whether to use the custom implementation
        
    Returns:
        bytes: Encrypted data (nonce + ciphertext)
    """
    if use_custom:
        return encrypt_custom(data, key, iv)
    else:
        return encrypt_stdlib(data, key, iv)

def decrypt(ciphertext, key, use_custom=False):
    """
    Decrypt data using AES in CTR mode.
    
    Args:
        ciphertext: Data to decrypt (nonce + ciphertext)
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
    Encrypt data using PyCryptodome AES-CTR implementation.
    
    Args:
        data: Data to encrypt
        key: Encryption key
        iv: Initialization vector. If None, a random one will be generated.
        
    Returns:
        bytes: Encrypted data (iv + ciphertext)
    """
    # Generate IV if not provided
    if iv is None:
        iv = get_stdlib_iv("CTR")
    
    # Process in chunks if data exceeds MAX_INPUT_SIZE
    if len(data) > MAX_INPUT_SIZE:
        # Use a generator approach to avoid creating too many chunks in memory at once
        result = bytearray()
        
        cipher = CryptoAES.new(key, CryptoAES.MODE_CTR, nonce=iv[:8])
        result.extend(iv)  # Prepend iv
        
        # Process chunks
        for i in range(0, len(data), MAX_INPUT_SIZE):
            chunk = data[i:i+MAX_INPUT_SIZE]
            result.extend(cipher.encrypt(chunk))
            
            # Force memory cleanup for processed chunks
            del chunk
            if i % (5 * MAX_INPUT_SIZE) == 0:  # Every 5 chunks
                gc.collect()  # Help clean up memory
        
        # Convert bytearray to bytes for return
        return bytes(result)
    else:
        # Single chunk processing
        cipher = CryptoAES.new(key, CryptoAES.MODE_CTR, nonce=iv[:8])
        return iv + cipher.encrypt(data)

def decrypt_stdlib(ciphertext, key):
    """
    Decrypt ciphertext using PyCryptodome AES-CTR implementation.
    
    Args:
        ciphertext: Data to decrypt (iv + ciphertext)
        key: Decryption key
        
    Returns:
        bytes: Decrypted data
    """
    # Extract iv from ciphertext
    iv_size = 16
    
    if len(ciphertext) < iv_size:
        raise ValueError("Ciphertext too short")
    
    iv = ciphertext[:iv_size]
    actual_ciphertext = ciphertext[iv_size:]
    
    # Process in chunks if ciphertext exceeds MAX_INPUT_SIZE
    if len(actual_ciphertext) > MAX_INPUT_SIZE:
        result = bytearray()
        
        cipher = CryptoAES.new(key, CryptoAES.MODE_CTR, nonce=iv[:8])
        
        # Process chunks
        for i in range(0, len(actual_ciphertext), MAX_INPUT_SIZE):
            chunk = actual_ciphertext[i:i+MAX_INPUT_SIZE]
            result.extend(cipher.decrypt(chunk))
            
            # Force memory cleanup
            del chunk
            if i % (5 * MAX_INPUT_SIZE) == 0:  # Every 5 chunks
                gc.collect()
        
        return bytes(result)
    else:
        # Single chunk processing
        cipher = CryptoAES.new(key, CryptoAES.MODE_CTR, nonce=iv[:8])
        return cipher.decrypt(actual_ciphertext)

def encrypt_custom(data, key, iv=None):
    """
    Encrypt data using custom AES-CTR implementation.
    
    Args:
        data: Data to encrypt
        key: Encryption key
        iv: Initialization vector. If None, a random one will be generated.
        
    Returns:
        bytes: Encrypted data (iv + ciphertext)
    """
    # Generate IV if not provided
    if iv is None:
        iv = get_custom_iv("CTR")
    
    # Create AES instance
    aes = CustomAES(key)
    
    # Pre-allocate bytearrays for better memory efficiency
    result = bytearray()
    
    # Add IV to result
    result.extend(iv)
    
    # Extract nonce from IV
    nonce = iv[:8]
    
    # Check data size and choose appropriate processing strategy
    if len(data) > MAX_INPUT_SIZE:
        # Processing large data in chunks with a batch approach for better performance
        BATCH_SIZE = 2048  # Encrypt this many blocks at once
        chunk_size = min(MAX_INPUT_SIZE, 16 * BATCH_SIZE)
        counter = 0
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            chunk_blocks = (len(chunk) + 15) // 16  # Ceiling division
            
            # Pre-generate and encrypt all counter blocks for this chunk
            counter_blocks = []
            encrypted_counters = []
            
            for j in range(chunk_blocks):
                counter_block = nonce + struct.pack(">Q", counter + j)
                counter_blocks.append(counter_block)
            
            # Encrypt all counter blocks in one batch
            for counter_block in counter_blocks:
                encrypted_counters.append(aes.encrypt_block(counter_block))
            
            # XOR plaintext with encrypted counters
            for j in range(0, len(chunk), 16):
                block = chunk[j:j+16]
                block_index = j // 16
                
                # Get the right encrypted counter
                encrypted_counter = encrypted_counters[block_index]
                
                # XOR operation - handle partial blocks at the end
                xor_result = bytearray(len(block))
                for k in range(len(block)):
                    xor_result[k] = block[k] ^ encrypted_counter[k % 16]
                
                result.extend(xor_result)
            
            # Update counter for next chunk
            counter += chunk_blocks
            
            # Force garbage collection after each chunk
            if i % (chunk_size * 4) == 0 and i > 0:
                gc.collect()
        
        return bytes(result)
    else:
        # Small data processing - efficient implementation
        # Process all blocks at once for small data
        counter = 0
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            
            # Create counter block
            counter_block = nonce + struct.pack(">Q", counter)
            counter += 1
            
            # Encrypt counter block
            encrypted_counter = aes.encrypt_block(counter_block)
            
            # XOR with plaintext (only up to the length of the actual data)
            xor_result = bytearray(len(block))
            for j in range(len(block)):
                xor_result[j] = block[j] ^ encrypted_counter[j % 16]
            
            result.extend(xor_result)
        
        return bytes(result)

def decrypt_custom(ciphertext, key):
    """
    Decrypt ciphertext using custom AES-CTR implementation.
    
    Args:
        ciphertext: Data to decrypt (iv + ciphertext)
        key: Decryption key
        
    Returns:
        bytes: Decrypted data
    """
    # Extract IV and nonce from ciphertext
    iv_size = 16
    
    if len(ciphertext) < iv_size:
        raise ValueError("Ciphertext too short")
    
    iv = ciphertext[:iv_size]
    nonce = iv[:8]
    actual_ciphertext = ciphertext[iv_size:]
    
    # Initialize AES instance
    aes = CustomAES(key)
    result = bytearray()
    
    # CTR decryption is identical to encryption, just with ciphertext instead of plaintext
    if len(actual_ciphertext) > MAX_INPUT_SIZE:
        # Process in batches for large data
        BATCH_SIZE = 2048  # Process this many blocks at once
        chunk_size = min(MAX_INPUT_SIZE, 16 * BATCH_SIZE)
        counter = 0
        
        for i in range(0, len(actual_ciphertext), chunk_size):
            chunk = actual_ciphertext[i:i+chunk_size]
            chunk_blocks = (len(chunk) + 15) // 16
            
            # Pre-generate and encrypt all counter blocks for this chunk
            counter_blocks = []
            encrypted_counters = []
            
            for j in range(chunk_blocks):
                counter_block = nonce + struct.pack(">Q", counter + j)
                counter_blocks.append(counter_block)
            
            # Encrypt all counter blocks in one batch
            for counter_block in counter_blocks:
                encrypted_counters.append(aes.encrypt_block(counter_block))
            
            # XOR ciphertext with encrypted counters
            for j in range(0, len(chunk), 16):
                block = chunk[j:j+16]
                block_index = j // 16
                
                # Get the right encrypted counter
                encrypted_counter = encrypted_counters[block_index]
                
                # XOR operation - handle partial blocks at the end
                xor_result = bytearray(len(block))
                for k in range(len(block)):
                    xor_result[k] = block[k] ^ encrypted_counter[k % 16]
                
                result.extend(xor_result)
            
            # Update counter for next chunk
            counter += chunk_blocks
            
            # Force garbage collection
            if i % (chunk_size * 4) == 0 and i > 0:
                gc.collect()
    else:
        # Standard processing for small data
        counter = 0
        for i in range(0, len(actual_ciphertext), 16):
            block = actual_ciphertext[i:i+16]
            
            # Create and encrypt counter block
            counter_block = nonce + struct.pack(">Q", counter)
            encrypted_counter = aes.encrypt_block(counter_block)
            counter += 1
            
            # XOR with ciphertext
            xor_result = bytearray(len(block))
            for j in range(len(block)):
                xor_result[j] = block[j] ^ encrypted_counter[j % 16]
            
            result.extend(xor_result)
    
    return bytes(result) 