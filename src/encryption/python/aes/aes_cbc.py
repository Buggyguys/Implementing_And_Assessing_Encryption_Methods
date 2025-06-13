import gc
import struct
from Crypto.Cipher import AES as CryptoAES
from Crypto.Util.Padding import pad, unpad
from .key_utils import get_iv, format_key_size, get_stdlib_iv, get_custom_iv
from .custom_aes import CustomAES

# max input size
MAX_INPUT_SIZE = 16 * 1024 * 1024  # 16MB chunks for processing larger data

def encrypt(data, key, iv=None, use_custom=False):

    if use_custom:
        return encrypt_custom(data, key, iv)
    else:
        return encrypt_stdlib(data, key, iv)

def decrypt(ciphertext, key, use_custom=False):

    if use_custom:
        return decrypt_custom(ciphertext, key)
    else:
        return decrypt_stdlib(ciphertext, key)

def encrypt_stdlib(data, key, iv=None):
    
    # generate IV 
    if iv is None:
        iv = get_stdlib_iv("CBC")
    
    # chunks if data exceeds max
    if len(data) > MAX_INPUT_SIZE:
        # use generator to avoid to many chunck in memroy
        result = bytearray()
        
        cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
        result.extend(iv)  # Prepend IV
        
        # process chunks
        for i in range(0, len(data), MAX_INPUT_SIZE):
            chunk = data[i:i+MAX_INPUT_SIZE]
            padded_chunk = pad(chunk, CryptoAES.block_size)
            result.extend(cipher.encrypt(padded_chunk))
            
            # force memory cleanup 
            del chunk, padded_chunk
            if i % (5 * MAX_INPUT_SIZE) == 0:  # every 5 chunks
                gc.collect()  
        
        # convert bytearray to bytes
        return bytes(result)
    else:
        # single chunk processing
        cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
        padded_data = pad(data, CryptoAES.block_size)
        return iv + cipher.encrypt(padded_data)

def decrypt_stdlib(ciphertext, key):

    # extract IV
    iv_size = 16
    
    if len(ciphertext) < iv_size:
        raise ValueError("Ciphertext too short")
    
    iv = ciphertext[:iv_size]
    actual_ciphertext = ciphertext[iv_size:]
    
    # decrypt data
    cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
    try:
        padded_plaintext = cipher.decrypt(actual_ciphertext)
        return unpad(padded_plaintext, CryptoAES.block_size)
    except ValueError:
        return b''

def encrypt_custom(data, key, iv=None):
    
    # generate IV
    if iv is None:
        iv = get_custom_iv("CBC")
    
    # get appropriate key size in bytes
    key_bytes = len(key)
    
    # create AES instance
    aes = CustomAES(key)
    
    # pre-allocate bytearrays 
    result = bytearray()
    
    # add IV to result
    result.extend(iv)
    
    # check data size/processing strategy
    if len(data) > MAX_INPUT_SIZE:

        prev_block = iv
        chunk_size = min(MAX_INPUT_SIZE, 16 * 1024 * 64)  # Process in 64K block chunks
        
        for i in range(0, len(data), chunk_size):
            # get chunk/pad if last
            chunk = data[i:i+chunk_size]
            if i + chunk_size >= len(data):
                chunk = pad(chunk, 16)
            
            # process blocks within chunk
            for j in range(0, len(chunk), 16):
                block = chunk[j:j+16]
                
                if len(block) != 16:
                    continue
                
                # XOR with previous ciphertext block 
                xor_block = bytearray(16)
                for k in range(16):
                    xor_block[k] = block[k] ^ prev_block[k]
                
                # encrypt XORed block
                encrypted_block = aes.encrypt_block(bytes(xor_block))
                result.extend(encrypted_block)
                
                # update previous block
                prev_block = encrypted_block
            
            # garbage collection 
            if i % (chunk_size * 4) == 0 and i > 0:
                gc.collect()
        
        return bytes(result)
    else:
        # pad to multiple of 16 bytes
        padded_data = pad(data, 16)
        
        # process each block
        prev_block = iv
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            
            # XOR operation with bytearray
            xor_block = bytearray(16)
            for j in range(16):
                xor_block[j] = block[j] ^ prev_block[j]
            
            # encrypt the XORed block
            encrypted_block = aes.encrypt_block(bytes(xor_block))
            result.extend(encrypted_block)
            
            # update previous block
            prev_block = encrypted_block
        
        return bytes(result)

def decrypt_custom(ciphertext, key):

    # extract IV from ciphertext
    iv_size = 16
    if len(ciphertext) < iv_size:
        raise ValueError("Ciphertext too short")
    
    iv = ciphertext[:iv_size]
    actual_ciphertext = ciphertext[iv_size:]
    
    # initialize for decryption
    aes = CustomAES(key)
    result = bytearray()
    
    if len(actual_ciphertext) > MAX_INPUT_SIZE:
        prev_block = iv
        chunk_size = min(MAX_INPUT_SIZE, 16 * 1024 * 64)  # 64K blocks at a time
        
        for i in range(0, len(actual_ciphertext), chunk_size):
            chunk = actual_ciphertext[i:i+chunk_size]
            
            for j in range(0, len(chunk), 16):
                if j + 16 > len(chunk):
                    break  
                
                block = chunk[j:j+16]
                
                # decrypt the block
                decrypted_block = aes.decrypt_block(block)
                
                # XOR with previous ciphertext block
                xor_result = bytearray(16)
                for k in range(16):
                    xor_result[k] = decrypted_block[k] ^ prev_block[k]
                
                result.extend(xor_result)
                
                # update previous block
                prev_block = block
            
            if i % (chunk_size * 4) == 0 and i > 0:
                gc.collect()
        
        # remove padding
        try:
            return unpad(result, 16)
        except ValueError:
            # padding error
            return b''
    else:
        # standard decryption for small data
        prev_block = iv
        
        for i in range(0, len(actual_ciphertext), 16):
            if i + 16 > len(actual_ciphertext):
                break
            
            block = actual_ciphertext[i:i+16]
            
            # decrypt
            decrypted_block = aes.decrypt_block(block)
            
            # XOR with previous block
            xor_result = bytearray(16)
            for j in range(16):
                xor_result[j] = decrypted_block[j] ^ prev_block[j]
            
            result.extend(xor_result)
            
            # update previous block
            prev_block = block
        
        # remove padding
        try:
            return unpad(result, 16)
        except ValueError:
            return b'' 
