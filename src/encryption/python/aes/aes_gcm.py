import gc
import hashlib
import struct
from Crypto.Cipher import AES as CryptoAES
from .key_utils import get_iv, get_stdlib_iv, get_custom_iv, format_key_size
from .custom_aes import CustomAES

# max input size
MAX_INPUT_SIZE = 16 * 1024 * 1024  

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
        iv = get_stdlib_iv("GCM")
    
    # process in chunks data > max
    if len(data) > MAX_INPUT_SIZE:
        result = bytearray()
        
        cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=iv)
        result.extend(iv)  # prepend nonce
        
        # process all chunks except the last one
        total_chunks = (len(data) + MAX_INPUT_SIZE - 1) // MAX_INPUT_SIZE
        for i in range(0, len(data) - MAX_INPUT_SIZE, MAX_INPUT_SIZE):
            chunk = data[i:i+MAX_INPUT_SIZE]
            result.extend(cipher.encrypt(chunk))
            del chunk
            if i % (5 * MAX_INPUT_SIZE) == 0:  
                gc.collect()  
        
        # process last chunk
        last_chunk = data[-(len(data) % MAX_INPUT_SIZE or MAX_INPUT_SIZE):]
        ciphertext, tag = cipher.encrypt_and_digest(last_chunk)
        result.extend(ciphertext)
        result.extend(tag)
        
        # convert bytearray to bytes 
        return bytes(result)
    else:
        # single chunk processing
        cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return iv + ciphertext + tag

def decrypt_stdlib(ciphertext, key):

    # extract nonce and tag from ciphertext
    nonce_size = 12
    tag_size = 16
    
    if len(ciphertext) < nonce_size + tag_size:
        raise ValueError("Ciphertext too short")
    
    nonce = ciphertext[:nonce_size]
    tag = ciphertext[-tag_size:]
    actual_ciphertext = ciphertext[nonce_size:-tag_size]
    
    # decrypt data
    cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(actual_ciphertext, tag)
    except ValueError:
        # authentication failed
        return b''

def encrypt_custom(data, key, iv=None):

    # generate IV 
    if iv is None:
        iv = get_custom_iv("GCM")
    
    # create instance
    aes = CustomAES(key)
    
    # pre-allocate bytearrays 
    result = bytearray()
    
    # extract nonce
    nonce = iv[:12]
    result.extend(nonce)  # prepend nonce 
    
    if len(data) > MAX_INPUT_SIZE:
        # temporary storage for ciphertext
        ciphertext = bytearray()
        
        # GCM counter starts at 1
        counter = 1
        BATCH_SIZE = 2048
        chunk_size = min(MAX_INPUT_SIZE, 16 * BATCH_SIZE)
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            chunk_blocks = (len(chunk) + 15) // 16  # Ceiling division
            
            # pre-generate/encrypt all counter blocks for this chunk
            counter_blocks = []
            encrypted_counters = []
            
            for j in range(chunk_blocks):
                counter_block = nonce + struct.pack(">I", counter + j)
                counter_blocks.append(counter_block)
            
            # encrypt 
            for counter_block in counter_blocks:
                encrypted_counters.append(aes.encrypt_block(counter_block))
            
            # XOR plaintext with encrypted counters
            for j in range(0, len(chunk), 16):
                block = chunk[j:j+16]
                block_index = j // 16
                
                # Get right encrypted counter
                encrypted_counter = encrypted_counters[block_index]
                
                # handle partial blocks at the end
                xor_result = bytearray(len(block))
                for k in range(len(block)):
                    xor_result[k] = block[k] ^ encrypted_counter[k % 16]
                
                ciphertext.extend(xor_result)
            
            # update counter for next chunk
            counter += chunk_blocks
            
            if i % (chunk_size * 4) == 0 and i > 0:
                gc.collect()
        
        # generate authentication tag 
        auth_data = nonce + struct.pack(">Q", len(ciphertext))
        
        hash_obj = hashlib.sha256()
        hash_obj.update(auth_data)
        
        # update hash in chunks
        for i in range(0, len(ciphertext), MAX_INPUT_SIZE):
            hash_obj.update(ciphertext[i:i+MAX_INPUT_SIZE])
        
        tag = hash_obj.digest()[:16]
        
        # add ciphertext and tag 
        result.extend(ciphertext)
        result.extend(tag)
        
        return bytes(result)
    else:
        # GCM mode uses a special counter starting with nonce and 1
        counter = 1
        ciphertext = bytearray()
        
        # process all blocks
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            
            # create counter block
            counter_block = nonce + struct.pack(">I", counter)
            counter += 1
            
            # encrypt counter block
            encrypted_counter = aes.encrypt_block(counter_block)
            
            # XOR with plaintext
            xor_result = bytearray(len(block))
            for j in range(len(block)):
                xor_result[j] = block[j] ^ encrypted_counter[j % 16]
            
            ciphertext.extend(xor_result)
        
        # generate authentication tag
        auth_data = nonce + struct.pack(">Q", len(ciphertext))
        tag = hashlib.sha256(auth_data + bytes(ciphertext)).digest()[:16]
        
        # add ciphertext and tag to result
        result.extend(ciphertext)
        result.extend(tag)
        
        return bytes(result)

def decrypt_custom(ciphertext, key):

    # extract nonce and tag from ciphertext
    nonce_size = 12
    tag_size = 16
    
    if len(ciphertext) < nonce_size + tag_size:
        raise ValueError("Ciphertext too short")
    
    nonce = ciphertext[:nonce_size]
    tag = ciphertext[-tag_size:]
    actual_ciphertext = ciphertext[nonce_size:-tag_size]
    
    # verify authentication tag
    auth_data = nonce + struct.pack(">Q", len(actual_ciphertext))
    
    # for large data, compute the tag incrementally
    if len(actual_ciphertext) > MAX_INPUT_SIZE:
        hash_obj = hashlib.sha256()
        hash_obj.update(auth_data)
        
        # update hash in chunks
        for i in range(0, len(actual_ciphertext), MAX_INPUT_SIZE):
            hash_obj.update(actual_ciphertext[i:i+MAX_INPUT_SIZE])
        
        computed_tag = hash_obj.digest()[:16]
    else:
        computed_tag = hashlib.sha256(auth_data + actual_ciphertext).digest()[:16]
    
    # verify tag
    if not all(a == b for a, b in zip(computed_tag, tag)):
        return b''
    
    # initialize for decryption
    aes = CustomAES(key)
    result = bytearray()
    
    # GCM decryption is identical to encryption, just with ciphertext
    if len(actual_ciphertext) > MAX_INPUT_SIZE:
        # batches for large data
        counter = 1  
        BATCH_SIZE = 2048
        chunk_size = min(MAX_INPUT_SIZE, 16 * BATCH_SIZE)
        
        for i in range(0, len(actual_ciphertext), chunk_size):
            chunk = actual_ciphertext[i:i+chunk_size]
            chunk_blocks = (len(chunk) + 15) // 16
            
            # pre-generate/encrypt all counter blocks 
            counter_blocks = []
            encrypted_counters = []
            
            for j in range(chunk_blocks):
                counter_block = nonce + struct.pack(">I", counter + j)
                counter_blocks.append(counter_block)
            
            # encrypt all counter blocks in one batch
            for counter_block in counter_blocks:
                encrypted_counters.append(aes.encrypt_block(counter_block))
            
            # XOR ciphertext with encrypted counters
            for j in range(0, len(chunk), 16):
                block = chunk[j:j+16]
                block_index = j // 16
                
                # get the right encrypted counter
                encrypted_counter = encrypted_counters[block_index]
                
                # handle partial blocks
                xor_result = bytearray(len(block))
                for k in range(len(block)):
                    xor_result[k] = block[k] ^ encrypted_counter[k % 16]
                
                result.extend(xor_result)
            
            # update counter
            counter += chunk_blocks
            
            if i % (chunk_size * 4) == 0 and i > 0:
                gc.collect()
    else:
        # standard processing for small data
        counter = 1
        for i in range(0, len(actual_ciphertext), 16):
            block = actual_ciphertext[i:i+16]
            
            # create and encrypt counter block
            counter_block = nonce + struct.pack(">I", counter)
            encrypted_counter = aes.encrypt_block(counter_block)
            counter += 1
            
            # XOR with ciphertext
            xor_result = bytearray(len(block))
            for j in range(len(block)):
                xor_result[j] = block[j] ^ encrypted_counter[j % 16]
            
            result.extend(xor_result)
    
    return bytes(result) 
