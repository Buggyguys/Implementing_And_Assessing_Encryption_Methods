#!/usr/bin/env python3
"""
CryptoBench Pro - AES-GCM Implementation
Provides AES encryption/decryption in GCM mode.
"""

import gc
import hashlib
import struct
from Crypto.Cipher import AES as CryptoAES
from .key_utils import get_iv, get_stdlib_iv, get_custom_iv, format_key_size
from .custom_aes import CustomAES

# Maximum input size for AES (for efficient memory usage)
MAX_INPUT_SIZE = 16 * 1024 * 1024  # 16MB chunks for processing larger data

def encrypt(data, key, iv=None, use_custom=False):
    """
    Encrypt data using AES in GCM mode.
    
    Args:
        data: Data to encrypt
        key: Encryption key
        iv: Initialization vector (nonce). If None, a random one will be generated.
        use_custom: Whether to use the custom implementation
        
    Returns:
        bytes: Encrypted data (nonce + ciphertext + tag)
    """
    if use_custom:
        return encrypt_custom(data, key, iv)
    else:
        return encrypt_stdlib(data, key, iv)

def decrypt(ciphertext, key, use_custom=False):
    """
    Decrypt data using AES in GCM mode.
    
    Args:
        ciphertext: Data to decrypt (nonce + ciphertext + tag)
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
    Encrypt data using PyCryptodome AES-GCM implementation.
    
    Args:
        data: Data to encrypt
        key: Encryption key
        iv: Initialization vector (nonce). If None, a random one will be generated.
        
    Returns:
        bytes: Encrypted data (nonce + ciphertext + tag)
    """
    # Generate IV if not provided
    if iv is None:
        iv = get_stdlib_iv("GCM")
    
    # Process in chunks if data exceeds MAX_INPUT_SIZE
    if len(data) > MAX_INPUT_SIZE:
        # Use a generator approach to avoid creating too many chunks in memory at once
        result = bytearray()
        
        cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=iv)
        result.extend(iv)  # Prepend nonce
        
        # Process all chunks except the last one
        total_chunks = (len(data) + MAX_INPUT_SIZE - 1) // MAX_INPUT_SIZE
        for i in range(0, len(data) - MAX_INPUT_SIZE, MAX_INPUT_SIZE):
            chunk = data[i:i+MAX_INPUT_SIZE]
            result.extend(cipher.encrypt(chunk))
            # Force memory cleanup for processed chunks
            del chunk
            if i % (5 * MAX_INPUT_SIZE) == 0:  # Every 5 chunks
                gc.collect()  # Help clean up memory
        
        # Process last chunk
        last_chunk = data[-(len(data) % MAX_INPUT_SIZE or MAX_INPUT_SIZE):]
        ciphertext, tag = cipher.encrypt_and_digest(last_chunk)
        result.extend(ciphertext)
        result.extend(tag)
        
        # Convert bytearray to bytes for return
        return bytes(result)
    else:
        # Single chunk processing
        cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return iv + ciphertext + tag

def decrypt_stdlib(ciphertext, key):
    """
    Decrypt ciphertext using PyCryptodome AES-GCM implementation.
    
    Args:
        ciphertext: Data to decrypt (nonce + ciphertext + tag)
        key: Decryption key
        
    Returns:
        bytes: Decrypted data
    """
    # Extract nonce and tag from ciphertext
    nonce_size = 12
    tag_size = 16
    
    if len(ciphertext) < nonce_size + tag_size:
        raise ValueError("Ciphertext too short")
    
    nonce = ciphertext[:nonce_size]
    tag = ciphertext[-tag_size:]
    actual_ciphertext = ciphertext[nonce_size:-tag_size]
    
    # Decrypt the data
    cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(actual_ciphertext, tag)
    except ValueError:
        # Authentication failed
        return b''

def encrypt_custom(data, key, iv=None):
    """
    Encrypt data using custom AES-GCM implementation.
    
    Args:
        data: Data to encrypt
        key: Encryption key
        iv: Initialization vector (nonce). If None, a random one will be generated.
        
    Returns:
        bytes: Encrypted data (nonce + ciphertext + tag)
    """
    # Generate IV if not provided
    if iv is None:
        iv = get_custom_iv("GCM")
    
    # Create AES instance
    aes = CustomAES(key)
    
    # Pre-allocate bytearrays for better memory efficiency
    result = bytearray()
    
    # Extract nonce
    nonce = iv[:12]
    result.extend(nonce)  # Prepend nonce to result
    
    # Check data size and choose appropriate processing strategy
    if len(data) > MAX_INPUT_SIZE:
        # Processing large data in chunks with a batch approach for better performance
        # Temporary storage for ciphertext
        ciphertext = bytearray()
        
        # GCM counter starts at 1
        counter = 1
        BATCH_SIZE = 2048
        chunk_size = min(MAX_INPUT_SIZE, 16 * BATCH_SIZE)
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            chunk_blocks = (len(chunk) + 15) // 16  # Ceiling division
            
            # Pre-generate and encrypt all counter blocks for this chunk
            counter_blocks = []
            encrypted_counters = []
            
            for j in range(chunk_blocks):
                counter_block = nonce + struct.pack(">I", counter + j)
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
                
                ciphertext.extend(xor_result)
            
            # Update counter for next chunk
            counter += chunk_blocks
            
            # Force garbage collection after each chunk
            if i % (chunk_size * 4) == 0 and i > 0:
                gc.collect()
        
        # Generate authentication tag more efficiently
        auth_data = nonce + struct.pack(">Q", len(ciphertext))
        
        # Use hashlib's incremental update
        hash_obj = hashlib.sha256()
        hash_obj.update(auth_data)
        
        # Update hash in chunks to avoid memory issues
        for i in range(0, len(ciphertext), MAX_INPUT_SIZE):
            hash_obj.update(ciphertext[i:i+MAX_INPUT_SIZE])
        
        tag = hash_obj.digest()[:16]
        
        # Add ciphertext and tag to result
        result.extend(ciphertext)
        result.extend(tag)
        
        return bytes(result)
    else:
        # Small data processing - optimized implementation
        # GCM mode uses a special counter starting with nonce and 1
        counter = 1
        ciphertext = bytearray()
        
        # Process all blocks
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            
            # Create counter block
            counter_block = nonce + struct.pack(">I", counter)
            counter += 1
            
            # Encrypt counter block
            encrypted_counter = aes.encrypt_block(counter_block)
            
            # XOR with plaintext
            xor_result = bytearray(len(block))
            for j in range(len(block)):
                xor_result[j] = block[j] ^ encrypted_counter[j % 16]
            
            ciphertext.extend(xor_result)
        
        # Generate authentication tag
        auth_data = nonce + struct.pack(">Q", len(ciphertext))
        tag = hashlib.sha256(auth_data + bytes(ciphertext)).digest()[:16]
        
        # Add ciphertext and tag to result
        result.extend(ciphertext)
        result.extend(tag)
        
        return bytes(result)

def decrypt_custom(ciphertext, key):
    """
    Decrypt ciphertext using custom AES-GCM implementation.
    
    Args:
        ciphertext: Data to decrypt (nonce + ciphertext + tag)
        key: Decryption key
        
    Returns:
        bytes: Decrypted data
    """
    # Extract nonce and tag from ciphertext
    nonce_size = 12
    tag_size = 16
    
    if len(ciphertext) < nonce_size + tag_size:
        raise ValueError("Ciphertext too short")
    
    nonce = ciphertext[:nonce_size]
    tag = ciphertext[-tag_size:]
    actual_ciphertext = ciphertext[nonce_size:-tag_size]
    
    # Verify authentication tag
    auth_data = nonce + struct.pack(">Q", len(actual_ciphertext))
    
    # For large data, compute the tag incrementally
    if len(actual_ciphertext) > MAX_INPUT_SIZE:
        hash_obj = hashlib.sha256()
        hash_obj.update(auth_data)
        
        # Update hash in chunks
        for i in range(0, len(actual_ciphertext), MAX_INPUT_SIZE):
            hash_obj.update(actual_ciphertext[i:i+MAX_INPUT_SIZE])
        
        computed_tag = hash_obj.digest()[:16]
    else:
        computed_tag = hashlib.sha256(auth_data + actual_ciphertext).digest()[:16]
    
    # Verify the tag - constant time comparison to prevent timing attacks
    if not all(a == b for a, b in zip(computed_tag, tag)):
        # Authentication failed
        return b''
    
    # Initialize for decryption
    aes = CustomAES(key)
    result = bytearray()
    
    # GCM decryption is identical to encryption, just with ciphertext
    if len(actual_ciphertext) > MAX_INPUT_SIZE:
        # Process in batches for large data
        counter = 1  # GCM counter starts at 1
        BATCH_SIZE = 2048
        chunk_size = min(MAX_INPUT_SIZE, 16 * BATCH_SIZE)
        
        for i in range(0, len(actual_ciphertext), chunk_size):
            chunk = actual_ciphertext[i:i+chunk_size]
            chunk_blocks = (len(chunk) + 15) // 16
            
            # Pre-generate and encrypt all counter blocks for this chunk
            counter_blocks = []
            encrypted_counters = []
            
            for j in range(chunk_blocks):
                counter_block = nonce + struct.pack(">I", counter + j)
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
        counter = 1
        for i in range(0, len(actual_ciphertext), 16):
            block = actual_ciphertext[i:i+16]
            
            # Create and encrypt counter block
            counter_block = nonce + struct.pack(">I", counter)
            encrypted_counter = aes.encrypt_block(counter_block)
            counter += 1
            
            # XOR with ciphertext
            xor_result = bytearray(len(block))
            for j in range(len(block)):
                xor_result[j] = block[j] ^ encrypted_counter[j % 16]
            
            result.extend(xor_result)
    
    return bytes(result) 