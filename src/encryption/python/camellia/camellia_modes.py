from .camellia_core import CamelliaCore
from .camellia_utils import pad_data, unpad_data, generate_iv, validate_iv, xor_bytes

class CamelliaModes:
    
    def __init__(self, key):
        self.cipher = CamelliaCore(key)
    
    # ECB mode
    def encrypt_ecb(self, plaintext):

        # pad the plaintext
        padded_plaintext = pad_data(plaintext, 16)
        
        ciphertext = b''
        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i:i+16]
            encrypted_block = self.cipher.encrypt_block(block)
            ciphertext += encrypted_block
        
        return ciphertext
    
    def decrypt_ecb(self, ciphertext):

        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")
        
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_block = self.cipher.decrypt_block(block)
            plaintext += decrypted_block
        
        # remove padding
        return unpad_data(plaintext, 16)
    
    # CBC Mode
    def encrypt_cbc(self, plaintext, iv=None):

        if iv is None:
            iv = generate_iv()
        else:
            validate_iv(iv)
        
        # pad the plaintext
        padded_plaintext = pad_data(plaintext, 16)
        
        ciphertext = b''
        previous_block = iv
        
        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i:i+16]
            # xOR with previous ciphertext block (or IV)
            xored_block = xor_bytes(block, previous_block)
            # encrypt the XORed block
            encrypted_block = self.cipher.encrypt_block(xored_block)
            ciphertext += encrypted_block
            previous_block = encrypted_block
        
        return iv + ciphertext
    
    def decrypt_cbc(self, data):

        if len(data) < 32:
            raise ValueError("Data too short for CBC mode")
        
        # extract IV and ciphertext
        iv = data[:16]
        ciphertext = data[16:]
        
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16")
        
        plaintext = b''
        previous_block = iv
        
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            # decrypt the block
            decrypted_block = self.cipher.decrypt_block(block)
            # XOR with previous ciphertext block/IV
            xored_block = xor_bytes(decrypted_block, previous_block)
            plaintext += xored_block
            previous_block = block
        
        # remove padding
        return unpad_data(plaintext, 16)
    
    # CFB Mode
    def encrypt_cfb(self, plaintext, iv=None):

        if iv is None:
            iv = generate_iv()
        else:
            validate_iv(iv)
        
        ciphertext = b''
        feedback = iv
        
        for i in range(0, len(plaintext), 16):
            # encrypt the feedback to get keystream
            keystream = self.cipher.encrypt_block(feedback)
            
            # XOR plaintext with keystream
            block = plaintext[i:i+16]
            encrypted_block = xor_bytes(block, keystream[:len(block)])
            ciphertext += encrypted_block
            
            # update feedback for next iteration
            if len(encrypted_block) == 16:
                feedback = encrypted_block
            else:
                # shift feedback and add new ciphertext
                feedback = feedback[len(encrypted_block):] + encrypted_block
        
        return iv + ciphertext
    
    def decrypt_cfb(self, data):
        if len(data) < 16:
            raise ValueError("Data too short for CFB mode")
        
        # extract IV and ciphertext
        iv = data[:16]
        ciphertext = data[16:]
        
        plaintext = b''
        feedback = iv
        
        for i in range(0, len(ciphertext), 16):
            # encrypt the feedback to create keystream
            keystream = self.cipher.encrypt_block(feedback)
            
            # XOR ciphertext with keystream
            block = ciphertext[i:i+16]
            decrypted_block = xor_bytes(block, keystream[:len(block)])
            plaintext += decrypted_block
            
            # update feedback for next iteration 
            if len(block) == 16:
                feedback = block
            else:
                # shift feedback and add new ciphertext
                feedback = feedback[len(block):] + block
        
        return plaintext
    
    # OFB Mode
    def encrypt_ofb(self, plaintext, iv=None):
        if iv is None:
            iv = generate_iv()
        else:
            validate_iv(iv)
        
        ciphertext = b''
        feedback = iv
        
        for i in range(0, len(plaintext), 16):
            # encrypt the feedback to create keystream
            feedback = self.cipher.encrypt_block(feedback)
            
            # XOR plaintext with keystream
            block = plaintext[i:i+16]
            encrypted_block = xor_bytes(block, feedback[:len(block)])
            ciphertext += encrypted_block
        
        return iv + ciphertext
    
    def decrypt_ofb(self, data):
        if len(data) < 16:
            raise ValueError("Data too short for OFB mode")
        
        # extract IV and ciphertext
        iv = data[:16]
        ciphertext = data[16:]
        
        plaintext = b''
        feedback = iv
        
        for i in range(0, len(ciphertext), 16):
            # encrypt the feedback to create keystream
            feedback = self.cipher.encrypt_block(feedback)
            
            # XOR ciphertext with keystream
            block = ciphertext[i:i+16]
            decrypted_block = xor_bytes(block, feedback[:len(block)])
            plaintext += decrypted_block
        
        return plaintext 
