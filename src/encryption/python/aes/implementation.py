#!/usr/bin/env python3
"""
CryptoBench Pro - AES Implementation
Implements AES encryption/decryption with different key sizes and modes.
"""

import gc
import os
import time
import struct
import hashlib
from Crypto.Cipher import AES as CryptoAES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Remove circular import
# from ..python_core import register_implementation
from .base import AESImplementationBase, MAX_INPUT_SIZE
from .custom_aes import CustomAES

# Dictionary to track implementations
AES_IMPLEMENTATIONS = {}

# Local implementation of register_implementation to avoid circular imports
def register_aes_variant(name):
    """Register an AES implementation variant."""
    def decorator(impl_class):
        AES_IMPLEMENTATIONS[name] = impl_class
        return impl_class
    return decorator

@register_aes_variant("aes")
class AESImplementation(AESImplementationBase):
    """AES implementation using standard library Crypto.Cipher.AES."""
    
    def __init__(self, key_size="256", mode="GCM", **kwargs):
        """Initialize with key size and mode of operation."""
        super().__init__(key_size, mode, **kwargs)
        self.is_custom = kwargs.get("is_custom", False)
        if self.is_custom:
            self.description = f"Custom AES-{key_size} in {mode} mode"
        else:
            self.description = f"PyCryptodome AES-{key_size} in {mode} mode"
    
    def encrypt(self, data, key):
        """Encrypt data using AES."""
        if self.is_custom:
            return self._custom_encrypt(data, key)
        else:
            return self._lib_encrypt(data, key)
    
    def decrypt(self, ciphertext, key):
        """Decrypt ciphertext using AES."""
        if self.is_custom:
            return self._custom_decrypt(ciphertext, key)
        else:
            return self._lib_decrypt(ciphertext, key)
    
    def _lib_encrypt(self, data, key):
        """Encrypt data using PyCryptodome AES implementation."""
        # Process in chunks if data exceeds MAX_INPUT_SIZE
        if len(data) > MAX_INPUT_SIZE:
            # Use a generator approach to avoid creating too many chunks in memory at once
            result = bytearray()
            
            # First chunk initialization
            self.iv = get_random_bytes(16)  # 16 bytes = 128 bits for IV
            
            if self.mode == "CBC":
                cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, self.iv)
                result.extend(self.iv)  # Prepend IV
                
                # Process chunks
                for i in range(0, len(data), MAX_INPUT_SIZE):
                    chunk = data[i:i+MAX_INPUT_SIZE]
                    padded_chunk = pad(chunk, CryptoAES.block_size)
                    result.extend(cipher.encrypt(padded_chunk))
                    # Force memory cleanup for processed chunks
                    del chunk, padded_chunk
                    if i % (5 * MAX_INPUT_SIZE) == 0:  # Every 5 chunks
                        gc.collect()  # Help clean up memory
            
            elif self.mode == "CTR":
                cipher = CryptoAES.new(key, CryptoAES.MODE_CTR, nonce=self.iv[:8])
                result.extend(self.iv)  # Prepend nonce
                
                # Process chunks
                for i in range(0, len(data), MAX_INPUT_SIZE):
                    chunk = data[i:i+MAX_INPUT_SIZE]
                    result.extend(cipher.encrypt(chunk))
                    # Force memory cleanup for processed chunks
                    del chunk
                    if i % (5 * MAX_INPUT_SIZE) == 0:  # Every 5 chunks
                        gc.collect()  # Help clean up memory
            
            elif self.mode == "GCM":
                cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=self.iv[:12])
                result.extend(self.iv[:12])  # Prepend nonce
                
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
                self.tag = tag
            
            elif self.mode == "ECB":
                # ECB doesn't use IV but we'll include it for format consistency
                result.extend(self.iv)
                
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
        
        # Single chunk processing
        self.iv = get_random_bytes(16)  # 16 bytes = 128 bits for IV
        
        if self.mode == "CBC":
            cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, self.iv)
            padded_data = pad(data, CryptoAES.block_size)
            return self.iv + cipher.encrypt(padded_data)
        
        elif self.mode == "CTR":
            cipher = CryptoAES.new(key, CryptoAES.MODE_CTR, nonce=self.iv[:8])
            return self.iv + cipher.encrypt(data)
        
        elif self.mode == "GCM":
            cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=self.iv[:12])
            ciphertext, tag = cipher.encrypt_and_digest(data)
            self.tag = tag
            return self.iv[:12] + ciphertext + tag
        
        elif self.mode == "ECB":
            cipher = CryptoAES.new(key, CryptoAES.MODE_ECB)
            padded_data = pad(data, CryptoAES.block_size)
            return self.iv + cipher.encrypt(padded_data)  # IV not used but included for format consistency
    
    def _lib_decrypt(self, ciphertext, key):
        """Decrypt ciphertext using PyCryptodome AES implementation."""
        # Extract IV from ciphertext
        if self.mode == "GCM":
            iv_size = 12
        else:
            iv_size = 16
        
        iv = ciphertext[:iv_size]
        actual_ciphertext = ciphertext[iv_size:]
        
        # For very large ciphertext, use chunk-based processing
        if len(actual_ciphertext) > MAX_INPUT_SIZE and self.mode in ["CTR", "ECB"]:
            result = bytearray()
            
            if self.mode == "CTR":
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
                
            elif self.mode == "ECB":
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
        
        # Standard (non-chunked) processing for other modes or smaller data
        if self.mode == "CBC":
            cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
            try:
                padded_plaintext = cipher.decrypt(actual_ciphertext)
                return unpad(padded_plaintext, CryptoAES.block_size)
            except ValueError:
                # Handle padding error
                return b''
        
        elif self.mode == "CTR":
            cipher = CryptoAES.new(key, CryptoAES.MODE_CTR, nonce=iv[:8])
            return cipher.decrypt(actual_ciphertext)
        
        elif self.mode == "GCM":
            tag_size = 16
            tag = actual_ciphertext[-tag_size:]
            actual_ciphertext = actual_ciphertext[:-tag_size]
            cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=iv)
            try:
                return cipher.decrypt_and_verify(actual_ciphertext, tag)
            except ValueError:
                # Authentication failed
                return b''
        
        elif self.mode == "ECB":
            cipher = CryptoAES.new(key, CryptoAES.MODE_ECB)
            try:
                padded_plaintext = cipher.decrypt(actual_ciphertext)
                return unpad(padded_plaintext, CryptoAES.block_size)
            except ValueError:
                # Handle padding error
                return b''
    
    def _custom_encrypt(self, data, key):
        """
        Custom AES encryption implementation supporting different key sizes and modes.
        Optimized for performance with large datasets.
        """
        # Create a hash of the key to ensure it's the right size
        key_bytes = self._format_key_size(self.key_size)
        
        # Initialize IV and AES instance with the proper key size
        self.iv = os.urandom(16)
        
        # Pre-allocate bytearrays for better memory efficiency
        result = bytearray()
        
        # Create AES instance just once
        aes = CustomAES(key[:key_bytes])
        
        # Check data size and choose appropriate processing strategy
        if len(data) > MAX_INPUT_SIZE:
            # Processing large data in chunks
            
            if self.mode == "CBC":
                # Add IV to result
                result.extend(self.iv)
                
                # CBC requires sequential processing - optimize the block operations
                prev_block = self.iv
                chunk_size = min(MAX_INPUT_SIZE, 16 * 1024 * 64)  # Process in 64K block chunks
                
                for i in range(0, len(data), chunk_size):
                    # Get chunk and pad if it's the last one
                    chunk = data[i:i+chunk_size]
                    if i + chunk_size >= len(data):
                        chunk = self._pad_data(chunk)
                    
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
            
            elif self.mode == "CTR":
                # Add IV to result
                nonce = self.iv[:8]
                result.extend(self.iv)
                
                # CTR mode - use batched counter encryption for better performance
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
            
            elif self.mode == "GCM":
                # Add nonce to result
                nonce = self.iv[:12]
                result.extend(nonce)
                
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
                self.tag = tag
                
                # Add ciphertext and tag to result
                result.extend(ciphertext)
                result.extend(tag)
            
            elif self.mode == "ECB":
                # Add IV (not used in ECB but included for format consistency)
                result.extend(self.iv)
                
                chunk_size = min(MAX_INPUT_SIZE, 16 * 1024 * 64)  # Process in 64K block chunks
                
                for i in range(0, len(data), chunk_size):
                    # Get chunk and pad if it's the last one
                    chunk = data[i:i+chunk_size]
                    if i + chunk_size >= len(data):
                        chunk = self._pad_data(chunk)
                    
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
            if self.mode == "CBC":
                # Add IV to result
                result.extend(self.iv)
                
                # Pad data to multiple of 16 bytes
                padded_data = self._pad_data(data)
                
                # Process each block
                prev_block = self.iv
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
            
            elif self.mode == "CTR":
                # Add IV to result
                nonce = self.iv[:8]
                result.extend(self.iv)
                
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
            
            elif self.mode == "GCM":
                # Add nonce to result
                nonce = self.iv[:12]
                result.extend(nonce)
                
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
                self.tag = tag
                
                # Add ciphertext and tag to result
                result.extend(ciphertext)
                result.extend(tag)
                
                return bytes(result)
            
            elif self.mode == "ECB":
                # Add IV to result (not used in ECB but included for format consistency)
                result.extend(self.iv)
                
                # Pad data to multiple of 16 bytes
                padded_data = self._pad_data(data)
                
                # Process each block
                for i in range(0, len(padded_data), 16):
                    block = padded_data[i:i+16]
                    
                    # Encrypt the block directly (no chaining in ECB)
                    encrypted_block = aes.encrypt_block(block)
                    result.extend(encrypted_block)
                
                return bytes(result)
    
    def _custom_decrypt(self, ciphertext, key):
        """
        Custom AES decryption implementation supporting different key sizes and modes.
        Optimized for performance with large datasets.
        """
        # Initialize for decryption
        key_bytes = self._format_key_size(self.key_size)
        aes = CustomAES(key[:key_bytes])
        result = bytearray()
        
        # Handle large data with optimized processing
        if len(ciphertext) > MAX_INPUT_SIZE:
            if self.mode == "CBC":
                # Extract IV
                iv = ciphertext[:16]
                actual_ciphertext = ciphertext[16:]
                
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
                result = self._unpad_data(result)
            
            elif self.mode == "CTR":
                # Extract IV
                iv = ciphertext[:16]
                nonce = iv[:8]
                actual_ciphertext = ciphertext[16:]
                
                # CTR decryption is identical to encryption, just with ciphertext
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
            
            elif self.mode == "GCM":
                # Extract components
                nonce = ciphertext[:12]
                tag_size = 16
                tag = ciphertext[-tag_size:]
                actual_ciphertext = ciphertext[12:-tag_size]
                
                # Verify tag incrementally
                auth_data = nonce + struct.pack(">Q", len(actual_ciphertext))
                hash_obj = hashlib.sha256()
                hash_obj.update(auth_data)
                
                # Process ciphertext incrementally for hash
                for i in range(0, len(actual_ciphertext), MAX_INPUT_SIZE):
                    hash_obj.update(actual_ciphertext[i:i+MAX_INPUT_SIZE])
                
                computed_tag = hash_obj.digest()[:16]
                
                # If tags don't match, authentication failed
                if tag != computed_tag:
                    return b''  # Authentication failed
                
                # Decrypt similarly to CTR mode
                BATCH_SIZE = 2048
                chunk_size = min(MAX_INPUT_SIZE, 16 * BATCH_SIZE)
                counter = 1  # GCM starts with 1
                
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
            
            elif self.mode == "ECB":
                # Extract IV (not used in decryption)
                iv_size = 16
                actual_ciphertext = ciphertext[iv_size:]
                
                chunk_size = min(MAX_INPUT_SIZE, 16 * 1024 * 64)
                
                for i in range(0, len(actual_ciphertext), chunk_size):
                    chunk = actual_ciphertext[i:i+chunk_size]
                    
                    for j in range(0, len(chunk), 16):
                        if j + 16 > len(chunk):
                            break  # Skip incomplete blocks
                        
                        block = chunk[j:j+16]
                        
                        # Decrypt the block directly (no chaining in ECB)
                        decrypted_block = aes.decrypt_block(block)
                        result.extend(decrypted_block)
                    
                    # Force garbage collection
                    if i % (chunk_size * 4) == 0 and i > 0:
                        gc.collect()
                
                # Remove padding
                result = self._unpad_data(result)
            
            return bytes(result)
        else:
            # Small data optimized implementation
            if self.mode == "CBC":
                # Extract IV
                iv = ciphertext[:16]
                actual_ciphertext = ciphertext[16:]
                
                prev_block = iv
                
                for i in range(0, len(actual_ciphertext), 16):
                    if i + 16 > len(actual_ciphertext):
                        break  # Skip incomplete blocks
                    
                    block = actual_ciphertext[i:i+16]
                    
                    # Decrypt the block
                    decrypted_block = aes.decrypt_block(block)
                    
                    # XOR with previous ciphertext block
                    xor_result = bytearray(16)
                    for j in range(16):
                        xor_result[j] = decrypted_block[j] ^ prev_block[j]
                    
                    result.extend(xor_result)
                    
                    # Update previous block
                    prev_block = block
                
                # Remove padding
                result = self._unpad_data(result)
                return bytes(result)
            
            elif self.mode == "CTR":
                # Extract IV
                iv = ciphertext[:16]
                nonce = iv[:8]
                actual_ciphertext = ciphertext[16:]
                
                counter = 0
                
                for i in range(0, len(actual_ciphertext), 16):
                    block = actual_ciphertext[i:i+16]
                    
                    # Create counter block
                    counter_block = nonce + struct.pack(">Q", counter)
                    counter += 1
                    
                    # Encrypt counter block
                    encrypted_counter = aes.encrypt_block(counter_block)
                    
                    # XOR with ciphertext
                    xor_result = bytearray(len(block))
                    for j in range(len(block)):
                        xor_result[j] = block[j] ^ encrypted_counter[j % 16]
                    
                    result.extend(xor_result)
                
                return bytes(result)
            
            elif self.mode == "GCM":
                # Extract components
                nonce = ciphertext[:12]
                tag_size = 16
                tag = ciphertext[-tag_size:]
                actual_ciphertext = ciphertext[12:-tag_size]
                
                # Verify tag
                auth_data = nonce + struct.pack(">Q", len(actual_ciphertext))
                computed_tag = hashlib.sha256(auth_data + actual_ciphertext).digest()[:16]
                
                # If tags don't match, authentication failed
                if tag != computed_tag:
                    return b''  # Authentication failed
                
                counter = 1  # GCM starts with 1
                
                for i in range(0, len(actual_ciphertext), 16):
                    block = actual_ciphertext[i:i+16]
                    
                    # Create counter block
                    counter_block = nonce + struct.pack(">I", counter)
                    counter += 1
                    
                    # Encrypt counter block
                    encrypted_counter = aes.encrypt_block(counter_block)
                    
                    # XOR with ciphertext
                    xor_result = bytearray(len(block))
                    for j in range(len(block)):
                        xor_result[j] = block[j] ^ encrypted_counter[j % 16]
                    
                    result.extend(xor_result)
                
                return bytes(result)
            
            elif self.mode == "ECB":
                # Extract IV (not used in decryption)
                iv_size = 16
                actual_ciphertext = ciphertext[iv_size:]
                
                for i in range(0, len(actual_ciphertext), 16):
                    if i + 16 > len(actual_ciphertext):
                        break  # Skip incomplete blocks
                    
                    block = actual_ciphertext[i:i+16]
                    
                    # Decrypt the block directly (no chaining in ECB)
                    decrypted_block = aes.decrypt_block(block)
                    result.extend(decrypted_block)
                
                # Remove padding
                result = self._unpad_data(result)
                return bytes(result)
    
    def _pad_data(self, data):
        """PKCS#7 padding for data."""
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad_data(self, data):
        """Remove PKCS#7 padding from data."""
        padding_length = data[-1]
        if padding_length > 16:
            return data  # Invalid padding, return as is
        
        # Verify all padding bytes are correct
        for i in range(-padding_length, 0):
            if data[i] != padding_length:
                return data  # Invalid padding, return as is
        
        # Return data without padding
        return data[:-padding_length]


# Helper method to create a custom implementation instance
def create_custom_aes_implementation(key_size, mode):
    """Create a custom AES implementation instance."""
    return AESImplementation(key_size=key_size, mode=mode, is_custom=True)


# Helper method to create a standard library implementation instance
def create_stdlib_aes_implementation(key_size, mode):
    """Create a standard library AES implementation instance."""
    return AESImplementation(key_size=key_size, mode=mode, is_custom=False)


# Register all combinations of key sizes and modes
def register_all_aes_variants():
    """
    Register all combinations of AES key sizes and modes of operation.
    This ensures that all variants are available for benchmarking.
    """
    key_sizes = ["128", "192", "256"]
    modes = ["CBC", "CTR", "GCM", "ECB"]
    
    for key_size in key_sizes:
        for mode in modes:
            # Register standard library implementation
            impl_name = f"aes-{key_size}-{mode.lower()}"
            register_aes_variant(impl_name)(
                lambda ks=key_size, m=mode: create_stdlib_aes_implementation(ks, m)
            )
            
            # Register custom implementation
            custom_impl_name = f"custom-aes-{key_size}-{mode.lower()}"
            register_aes_variant(custom_impl_name)(
                lambda ks=key_size, m=mode: create_custom_aes_implementation(ks, m)
            )
    
    return True 