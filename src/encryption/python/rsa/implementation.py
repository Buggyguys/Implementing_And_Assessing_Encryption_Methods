#!/usr/bin/env python3
import os
import hashlib
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Signature
from Crypto.Hash import SHA256
from .base import RSAImplementationBase
from .key_utils import extract_key_components

# dictionary to track implementations
RSA_IMPLEMENTATIONS = {}

# local implementation of register_implementation to avoid circular imports
def register_rsa_variant(name):
    # register an RSA implementation variant
    def decorator(impl_class):
        RSA_IMPLEMENTATIONS[name] = impl_class
        return impl_class
    return decorator

@register_rsa_variant("rsa")
class RSAImplementation(RSAImplementationBase):
    
    def __init__(self, key_size="2048", **kwargs):

        super().__init__(key_size, **kwargs)
        
        if self.is_custom:
            self.description = f"Custom {self.description}"
        else:
            self.description = f"PyCryptodome {self.description}"
    
    def encrypt(self, data, public_key=None):
       
        if public_key is None:
            public_key = self.public_key
        elif hasattr(public_key, '__rotating_keys__'):
            # get the next key
            key_pair = public_key.get_next_key()
        
            public_key = key_pair[0]
        elif isinstance(public_key, tuple):
            # use the first element (public key)
            public_key = public_key[0]
        
        if not public_key:
            raise ValueError("Public key is required for encryption")
        
        if self.is_custom:
            return self._encrypt_custom(data, public_key)
        else:
            return self._encrypt_stdlib(data, public_key)
    
    def decrypt(self, ciphertext, private_key=None):
       
        if private_key is None:
            private_key = self.private_key
        elif hasattr(private_key, '__rotating_keys__'):
            # get the next key
            key_pair = private_key.get_next_key()

            private_key = key_pair[1]
        elif isinstance(private_key, tuple):
            # use the second element (private key)
            private_key = private_key[1]
        
        if not private_key:
            raise ValueError("Private key is required for decryption")
        
        if self.is_custom:
            return self._decrypt_custom(ciphertext, private_key)
        else:
            return self._decrypt_stdlib(ciphertext, private_key)
    
    def sign(self, data, private_key=None):
     
        if private_key is None:
            private_key = self.private_key
        elif isinstance(private_key, tuple):
            # use the second element (private key)
            private_key = private_key[1]
        
        if not private_key:
            raise ValueError("Private key is required for signing")
        
        if self.is_custom:
            return self._sign_custom(data, private_key)
        else:
            return self._sign_stdlib(data, private_key)
    
    def verify(self, data, signature, public_key=None):
        
        if public_key is None:
            public_key = self.public_key
        elif isinstance(public_key, tuple):
            # use the first element (public key)
            public_key = public_key[0]
        
        if not public_key:
            raise ValueError("Public key is required for verification")
        
        if self.is_custom:
            return self._verify_custom(data, signature, public_key)
        else:
            return self._verify_stdlib(data, signature, public_key)
    
    def _encrypt_stdlib(self, data, public_key):
        # encrypt data using the standard library with chunking for large data
        if self.use_oaep:
            cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        else:
            cipher = PKCS1_v1_5_Cipher.new(public_key)
        
        # calculate the maximum data size that can be encrypted per chunk
        key_size_bytes = public_key.size_in_bytes()
        
        # OAEP overhead: 2 * hash_size + 2 (42 bytes for SHA-256) 
        # PKCS#1 v1.5 overhead: 11 bytes minimum
        max_chunk_size = key_size_bytes - (2 * SHA256.digest_size + 2) if self.use_oaep else key_size_bytes - 11 
        
        # if data fits in one chunk, encrypt directly
        if len(data) <= max_chunk_size:
            return cipher.encrypt(data)
        
        # for larger data, encrypt in chunks with separators
        result = b""
        chunk_count = 0
        
        for i in range(0, len(data), max_chunk_size):
            chunk = data[i:i + max_chunk_size]
            encrypted_chunk = cipher.encrypt(chunk)
            
            # metadata: [chunk_number:4][encrypted_size:4][encrypted_chunk]
            chunk_header = chunk_count.to_bytes(4, byteorder='big') + len(encrypted_chunk).to_bytes(4, byteorder='big')
            result += chunk_header + encrypted_chunk
            chunk_count += 1
        
        return result
    
    def _decrypt_stdlib(self, ciphertext, private_key):
        # decrypt ciphertext using the standard library with chunk processing
        if self.use_oaep:
            cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        else:
            cipher = PKCS1_v1_5_Cipher.new(private_key)
        
        # calculate expected encrypted chunk size
        key_size_bytes = private_key.size_in_bytes()
        
        # check chunked data (has chunk headers)
        if len(ciphertext) < 8:  # too small to have chunk headers
            # try direct decryption
            try:
                if self.use_oaep:
                    return cipher.decrypt(ciphertext)
                else:
                    sentinel = b''
                    return cipher.decrypt(ciphertext, sentinel)
            except:
                return b''
        
        # check if it looks like chunked data by examining the first 8 bytes
        try:
            first_chunk_num = int.from_bytes(ciphertext[:4], byteorder='big')
            first_chunk_size = int.from_bytes(ciphertext[4:8], byteorder='big')
            
            # if chunk number is 0 and chunk size seems reasonable, assume chunked format
            if first_chunk_num == 0 and 0 < first_chunk_size <= key_size_bytes * 2:
                return self._decrypt_chunked_data(ciphertext, cipher)
            else:
                # try direct decryption
                try:
                    if self.use_oaep:
                        return cipher.decrypt(ciphertext)
                    else:
                        sentinel = b''
                        return cipher.decrypt(ciphertext, sentinel)
                except:
                    return b''
        except:
            # try direct decryption
            try:
                if self.use_oaep:
                    return cipher.decrypt(ciphertext)
                else:
                    sentinel = b''
                    return cipher.decrypt(ciphertext, sentinel)
            except:
                return b''
    
    def _decrypt_chunked_data(self, ciphertext, cipher):
        # decrypt chunked RSA data
        result = b""
        offset = 0
        expected_chunk_num = 0
        
        while offset < len(ciphertext):
            # read chunk header (8 bytes)
            if offset + 8 > len(ciphertext):
                break
            
            chunk_num = int.from_bytes(ciphertext[offset:offset+4], byteorder='big')
            encrypted_size = int.from_bytes(ciphertext[offset+4:offset+8], byteorder='big')
            offset += 8
            
            # verify chunk ordering
            if chunk_num != expected_chunk_num:
                return b''  # Chunks out of order
            
            # read encrypted chunk
            if offset + encrypted_size > len(ciphertext):
                break
            
            encrypted_chunk = ciphertext[offset:offset+encrypted_size]
            offset += encrypted_size
            expected_chunk_num += 1
            
            # decrypt chunk
            try:
                if hasattr(cipher, 'decrypt'):
                    if self.use_oaep:
                        decrypted_chunk = cipher.decrypt(encrypted_chunk)
                    else:
                        sentinel = b''
                        decrypted_chunk = cipher.decrypt(encrypted_chunk, sentinel)
                else:
                    decrypted_chunk = b''
                    
                result += decrypted_chunk
            except:
                return b''      
        
        return result

    def _sign_stdlib(self, data, private_key):
        # sign data using the standard library
        # create a hash of the data
        h = SHA256.new(data)
        
        # sign the hash with the private key
        signer = PKCS1_v1_5_Signature.new(private_key)
        signature = signer.sign(h)
        
        return signature
    
    def _verify_stdlib(self, data, signature, public_key):
        # verify signature using the standard library
        # create a hash of the data
        h = SHA256.new(data)
        
        # verify the signature
        verifier = PKCS1_v1_5_Signature.new(public_key)
        
        try:
            return verifier.verify(h, signature)
        except:
            return False
    
    def _encrypt_custom(self, data, public_key):
        # encrypt data using a custom RSA implementation 
        # extract key components
        n = public_key['n']
        e = public_key['e']
        
        # calculate the maximum data size that can be encrypted per chunk
        key_size_bytes = (n.bit_length() + 7) // 8
        
        # for custom implementation, support both OAEP and PKCS#1 v1.5
        if self.use_oaep:
            # OAEP overhead: 2 * hash_size + 2 (66 bytes for SHA-256: 32+32+2)
            hash_len = 32  # SHA-256 hash length
            max_chunk_size = key_size_bytes - 2 * hash_len - 2
        else:
            # PKCS#1 v1.5 overhead: 11 bytes minimum
            max_chunk_size = key_size_bytes - 11
        
        # if data fits in one chunk, encrypt directly
        if len(data) <= max_chunk_size:
            return self._encrypt_single_chunk_custom(data, public_key)
        
        # for larger data, encrypt in chunks with separators
        result = b""
        chunk_count = 0
        
        for i in range(0, len(data), max_chunk_size):
            chunk = data[i:i + max_chunk_size]
            encrypted_chunk = self._encrypt_single_chunk_custom(chunk, public_key)
            
            # metadata
            chunk_header = chunk_count.to_bytes(4, byteorder='big') + len(encrypted_chunk).to_bytes(4, byteorder='big')
            result += chunk_header + encrypted_chunk
            chunk_count += 1
        
        return result
    
    def _encrypt_single_chunk_custom(self, data, public_key):
        # encrypt a single chunk using custom RSA implementation
        # extract key components
        n = public_key['n']
        e = public_key['e']
        key_size_bytes = (n.bit_length() + 7) // 8
        
        if self.use_oaep:
            # simplified OAEP implementation
            hash_func = hashlib.sha256
            hash_len = hash_func().digest_size
            
            # generate random seed
            seed = os.urandom(hash_len)
            
            # build DB: lHash || PS || 0x01 || message
            # lHash is hash of empty label
            lhash = hash_func(b'').digest()
            
            # calculate DB length: key_size - hash_len - 1
            db_len = key_size_bytes - hash_len - 1
            
            # calculate padding string length
            ps_len = db_len - hash_len - len(data) - 1
            if ps_len < 0:
                raise ValueError("Data too long for OAEP padding")
            
            db = lhash + b'\x00' * ps_len + b'\x01' + data
            
            # simplified MGF1 (mask generation function)
            def mgf1(seed, length):
                counter = 0
                result = b''
                while len(result) < length:
                    c = counter.to_bytes(4, byteorder='big')
                    result += hash_func(seed + c).digest()
                    counter += 1
                return result[:length]
            
            # apply masks
            db_mask = mgf1(seed, len(db))
            masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
            
            seed_mask = mgf1(masked_db, hash_len)
            masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
            
            padded_data = b'\x00' + masked_seed + masked_db
        else:
            # PKCS#1 v1.5 padding
            ps_len = key_size_bytes - len(data) - 3
            if ps_len < 8:  # minimum 8 bytes of padding
                raise ValueError("Data too long for PKCS#1 v1.5 padding")
            
            ps = os.urandom(ps_len)
            # ensure no zero bytes in padding string
            ps = bytes(b if b != 0 else 1 for b in ps)
            
            padded_data = b'\x00\x02' + ps + b'\x00' + data
        
        # convert to integer
        m = int.from_bytes(padded_data, byteorder='big')
        
        # RSA encryption
        c = pow(m, e, n)
        
        # convert back to bytes
        return c.to_bytes(key_size_bytes, byteorder='big')
    
    def _decrypt_custom(self, ciphertext, private_key):
        # decrypt ciphertext using a custom RSA implementation 
        n = private_key['n']
        key_size_bytes = (n.bit_length() + 7) // 8
        
        # check for chunks
        if len(ciphertext) < 8:  # too small to have chunk headers
         
            return self._decrypt_single_chunk_custom(ciphertext, private_key)
        
        try:
            first_chunk_num = int.from_bytes(ciphertext[:4], byteorder='big')
            first_chunk_size = int.from_bytes(ciphertext[4:8], byteorder='big')
            
            # if chunk number is 0 and chunk size seems reasonable, assume chunked format
            if first_chunk_num == 0 and 0 < first_chunk_size <= key_size_bytes * 2:
                return self._decrypt_chunked_data_custom(ciphertext, private_key)
            else:
                # try direct decryption
                return self._decrypt_single_chunk_custom(ciphertext, private_key)
        except:
            # try direct decryption
            return self._decrypt_single_chunk_custom(ciphertext, private_key)
    
    def _decrypt_single_chunk_custom(self, ciphertext, private_key):
        # decrypt a single chunk using custom RSA implementation
        n = private_key['n']
        d = private_key['d']
        
        # convert ciphertext to integer
        c = int.from_bytes(ciphertext, byteorder='big')
        
        # RSA decryption
        m = pow(c, d, n)
        
        # Chinese Remainder Theorem for optimization
        if 'p' in private_key and 'q' in private_key:
            p = private_key['p']
            q = private_key['q']
            
            # compute message mod p
            dp = d % (p - 1)
            mp = pow(c % p, dp, p)
            
            # compute message mod q
            dq = d % (q - 1)
            mq = pow(c % q, dq, q)
            
            # combine results using CRT
            inv_q = pow(q, p - 2, p)  # q^-1 mod p
            m = (mq + q * (inv_q * (mp - mq) % p)) % (p * q)
        
        # convert back to bytes
        key_size_bytes = (n.bit_length() + 7) // 8
        padded_message = m.to_bytes(key_size_bytes, byteorder='big')
        
        if self.use_oaep:
            # simplified OAEP decryption
            hash_func = hashlib.sha256
            hash_len = hash_func().digest_size
            
            if len(padded_message) < 2 * hash_len + 2:
                return b''  # invalid padding
            
            if padded_message[0] != 0:
                return b''  # invalid padding
            
            masked_seed = padded_message[1:1+hash_len]
            masked_db = padded_message[1+hash_len:]
            
            # simplified MGF1 (mask generation function)
            def mgf1(seed, length):
                counter = 0
                result = b''
                while len(result) < length:
                    c = counter.to_bytes(4, byteorder='big')
                    result += hash_func(seed + c).digest()
                    counter += 1
                return result[:length]
            
            # remove masks
            seed_mask = mgf1(masked_db, hash_len)
            seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
            
            db_mask = mgf1(seed, len(masked_db))
            db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
            
            # extract message from DB
            if len(db) < hash_len + 1:
                return b''  # invalid padding
            
            # verify lHash
            hash_func = hashlib.sha256
            expected_lhash = hash_func(b'').digest()
            actual_lhash = db[:hash_len]
            
            if actual_lhash != expected_lhash:
                return b''  
            
            # find the 0x01 separator after lHash
            i = hash_len
            while i < len(db) and db[i] == 0:
                i += 1
            
            if i >= len(db) or db[i] != 1:
                return b''  # invalid padding
            
            return db[i+1:]
        else:
            # remove PKCS#1 v1.5 padding
            if len(padded_message) < 2 or padded_message[0:2] != b'\x00\x02':
                return b''  # invalid padding
            
            # find the first zero byte after the padding
            i = 2
            while i < len(padded_message) and padded_message[i] != 0:
                i += 1
            
            # message after padding
            if i < len(padded_message):
                return padded_message[i+1:]
            else:
                return b''  
    
    def _decrypt_chunked_data_custom(self, ciphertext, private_key):
        # decrypt chunked RSA data using custom implementation
        result = b""
        offset = 0
        expected_chunk_num = 0
        
        while offset < len(ciphertext):
            # read chunk header (8 bytes)
            if offset + 8 > len(ciphertext):
                break
            
            chunk_num = int.from_bytes(ciphertext[offset:offset+4], byteorder='big')
            encrypted_size = int.from_bytes(ciphertext[offset+4:offset+8], byteorder='big')
            offset += 8
            
            # verify chunk ordering
            if chunk_num != expected_chunk_num:
                return b''  # chunks out of order
            
            # read encrypted chunk
            if offset + encrypted_size > len(ciphertext):
                break
            
            encrypted_chunk = ciphertext[offset:offset+encrypted_size]
            offset += encrypted_size
            expected_chunk_num += 1
            
            # decrypt chunk
            try:
                decrypted_chunk = self._decrypt_single_chunk_custom(encrypted_chunk, private_key)
                result += decrypted_chunk
            except:
                return b''  # decryption failed
        
        return result
    
    def _sign_custom(self, data, private_key):
        # extract key components
        n = private_key['n']
        d = private_key['d']
        
        # hash the data
        hash_obj = hashlib.sha256(data)
        digest = hash_obj.digest()
        
        # PKCS#1 v1.5 DigestInfo encoding
        key_size_bytes = (n.bit_length() + 7) // 8
        padded_digest = b'\x00\x01' + b'\xff' * (key_size_bytes - len(digest) - 3) + b'\x00' + digest
        
        # convert to integer
        m = int.from_bytes(padded_digest, byteorder='big')
        
        # RSA signing
        s = pow(m, d, n)
        
        # convert back to bytes
        return s.to_bytes(key_size_bytes, byteorder='big')
    
    def _verify_custom(self, data, signature, public_key):
   
        n = public_key['n']
        e = public_key['e']
        
        # convert signature to integer
        s = int.from_bytes(signature, byteorder='big')
        
        # RSA verification
        m = pow(s, e, n)
        
        # convert back to bytes
        key_size_bytes = (n.bit_length() + 7) // 8
        padded_digest = m.to_bytes(key_size_bytes, byteorder='big')
        
        # check PKCS#1 v1.5 padding
        if padded_digest[0:2] != b'\x00\x01':
            return False
        
        # find the first zero byte after the padding
        i = 2
        while i < len(padded_digest) and padded_digest[i] == 0xff:
            i += 1
        
        # check that the next byte is zero
        if i < len(padded_digest) and padded_digest[i] == 0:
            # extract the digest
            extracted_digest = padded_digest[i+1:]
            
            # hash the data
            hash_obj = hashlib.sha256(data)
            digest = hash_obj.digest()
            
            # compare the digests
            return extracted_digest == digest
        else:
            return False
    
    def encrypt_stream(self, data, key, chunk_size=8192):
        
        # extract public key if a key pair is provided
        if isinstance(key, tuple):
            public_key = key[0]
        else:
            public_key = key
        
        return self.encrypt(data, public_key)
    
    def decrypt_stream(self, data, key, chunk_size=8192):
       
        # extract private key if a key pair is provided
        if isinstance(key, tuple):
            private_key = key[1]
        else:
            private_key = key
        
        return self.decrypt(data, private_key)

def create_custom_rsa_implementation(key_size, use_oaep=True):

    return RSAImplementation(key_size=key_size, is_custom=True, use_oaep=use_oaep)

def create_stdlib_rsa_implementation(key_size, use_oaep=True):

    return RSAImplementation(key_size=key_size, is_custom=False, use_oaep=use_oaep)

def register_all_rsa_variants():

    # different key sizes and padding schemes
    for key_size in ["1024", "2048", "3072", "4096"]:
        for padding in [True, False]:  # true for OAEP, false for PKCS#1 v1.5
            for custom in [True, False]:  # true for custom, false for standard
                padding_name = "oaep" if padding else "pkcs1"
                impl_name = "custom" if custom else "std"
                variant_name = f"rsa{key_size}_{padding_name}_{impl_name}"
                RSA_IMPLEMENTATIONS[variant_name] = lambda ks=key_size, p=padding, c=custom, **kwargs: RSAImplementation(
                    key_size=ks, use_oaep=p, is_custom=c, **kwargs
                )
    
    # also register simple names for backward compatibility
    for key_size in ["1024", "2048", "3072", "4096"]:
        # standard implementations with OAEP (default)
        RSA_IMPLEMENTATIONS[f"rsa{key_size}"] = lambda ks=key_size, **kwargs: RSAImplementation(
            key_size=ks, use_oaep=True, is_custom=False, **kwargs
        )
        # custom implementations with OAEP
        RSA_IMPLEMENTATIONS[f"rsa{key_size}_custom"] = lambda ks=key_size, **kwargs: RSAImplementation(
            key_size=ks, use_oaep=True, is_custom=True, **kwargs
        ) 