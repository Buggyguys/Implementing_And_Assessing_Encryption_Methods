import gc
from Crypto.Cipher import AES as CryptoAES
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
        iv = get_stdlib_iv("CFB")
    
    # process in chunks if > max
    if len(data) > MAX_INPUT_SIZE:
        result = bytearray()
        result.extend(iv)  # prepend IV
        
        # process chunks
        for i in range(0, len(data), MAX_INPUT_SIZE):
            chunk = data[i:i+MAX_INPUT_SIZE]
            cipher = CryptoAES.new(key, CryptoAES.MODE_CFB, iv)
            result.extend(cipher.encrypt(chunk))
            
            # memory cleanup 
            del chunk
            if i % (5 * MAX_INPUT_SIZE) == 0:  # once every 5 chunks
                gc.collect()
        
        return bytes(result)
    else:
        # single chunk processing
        cipher = CryptoAES.new(key, CryptoAES.MODE_CFB, iv)
        return iv + cipher.encrypt(data)

def decrypt_stdlib(ciphertext, key):

    # extract IV 
    iv_size = 16
    
    if len(ciphertext) < iv_size:
        raise ValueError("Ciphertext too short")
    
    iv = ciphertext[:iv_size]
    actual_ciphertext = ciphertext[iv_size:]
    
    # decrypt 
    cipher = CryptoAES.new(key, CryptoAES.MODE_CFB, iv)
    return cipher.decrypt(actual_ciphertext)

def encrypt_custom(data, key, iv=None):

    # generate IV 
    if iv is None:
        iv = get_custom_iv("CFB")
    
    # create AES instance
    aes = CustomAES(key)
    
    # pre-allocate bytearrays 
    result = bytearray()
    result.extend(iv)  # add IV to results
    
    # encrypt IV and XOR with plaintext
    shift_register = bytearray(iv)
    
    # process byte by byte (or chunks)
    for i in range(0, len(data)):
        # encrypt shift register
        encrypted_sr = aes.encrypt_block(bytes(shift_register))
        
        # XOR first byte of encrypted shift register with plaintext byte
        cipher_byte = data[i] ^ encrypted_sr[0]
        result.append(cipher_byte)
        
        # shift left and add new cipher byte
        shift_register = shift_register[1:] + bytearray([cipher_byte])
    
    return bytes(result)

def decrypt_custom(ciphertext, key):

    # Extract IV from ciphertext
    iv_size = 16
    
    if len(ciphertext) < iv_size:
        raise ValueError("Ciphertext too short")
    
    iv = ciphertext[:iv_size]
    actual_ciphertext = ciphertext[iv_size:]
    
    # create AES instance
    aes = CustomAES(key)
    
    # CFB mode decryption
    result = bytearray()
    shift_register = bytearray(iv)
    
    # process byte by byte
    for i in range(len(actual_ciphertext)):
        # encrypt the shift register
        encrypted_sr = aes.encrypt_block(bytes(shift_register))
        
        # XOR first byte of encrypted shift register with ciphertext byte
        plain_byte = actual_ciphertext[i] ^ encrypted_sr[0]
        result.append(plain_byte)
        
        # shift left and add ciphertext byte
        shift_register = shift_register[1:] + bytearray([actual_ciphertext[i]])
    
    return bytes(result) 
