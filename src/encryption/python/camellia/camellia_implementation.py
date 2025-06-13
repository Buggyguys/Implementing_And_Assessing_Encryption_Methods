import os
import logging
from .camellia_modes import CamelliaModes
from .camellia_utils import generate_key, validate_key_size

logger = logging.getLogger(__name__)

class CamelliaImplementation:
    
    def __init__(self, key_size=256, mode="CBC", is_custom=False, **kwargs):
        self.key_size = key_size
        self.mode = mode.upper()
        self.is_custom = is_custom
        self.encryption_key = None
        
        # validate parameters
        if self.key_size not in [128, 192, 256]:
            raise ValueError(f"Invalid key size: {self.key_size} bits. Must be 128, 192, or 256.")
        
        if self.mode not in ["CBC", "ECB", "CFB", "OFB"]:
            raise ValueError(f"Invalid mode: {self.mode}. Must be CBC, ECB, CFB, or OFB.")
        
        # set description
        impl_type = "Custom" if self.is_custom else "Standard Library"
        self.name = f"Camellia-{self.key_size}-{self.mode}"
        self.description = f"{impl_type} {self.name}"
        
        logger.info(f"Initialized {self.description}")
    
    def generate_key(self):

        self.encryption_key = generate_key(self.key_size)
        return self.encryption_key
    
    def encrypt(self, data, key=None):

        if key is None:
            key = self.encryption_key
        
        if key is None:
            raise ValueError("No encryption key provided")
        
        validate_key_size(key)
        
        if self.is_custom:
            return self._encrypt_custom(data, key)
        else:
            return self._encrypt_stdlib(data, key)
    
    def decrypt(self, data, key=None):

        if key is None:
            key = self.encryption_key
        
        if key is None:
            raise ValueError("No decryption key provided")
        
        validate_key_size(key)
        
        if self.is_custom:
            return self._decrypt_custom(data, key)
        else:
            return self._decrypt_stdlib(data, key)
    
    def _encrypt_custom(self, data, key):
        try:
            cipher = CamelliaModes(key)
            
            if self.mode == "ECB":
                return cipher.encrypt_ecb(data)
            elif self.mode == "CBC":
                return cipher.encrypt_cbc(data)
            elif self.mode == "CFB":
                return cipher.encrypt_cfb(data)
            elif self.mode == "OFB":
                return cipher.encrypt_ofb(data)
            else:
                raise ValueError(f"Unsupported mode: {self.mode}")
                
        except Exception as e:
            logger.error(f"Custom encryption error: {str(e)}")
            raise
    
    def _decrypt_custom(self, data, key):
        try:
            cipher = CamelliaModes(key)
            
            if self.mode == "ECB":
                return cipher.decrypt_ecb(data)
            elif self.mode == "CBC":
                return cipher.decrypt_cbc(data)
            elif self.mode == "CFB":
                return cipher.decrypt_cfb(data)
            elif self.mode == "OFB":
                return cipher.decrypt_ofb(data)
            else:
                raise ValueError(f"Unsupported mode: {self.mode}")
                
        except Exception as e:
            logger.error(f"Custom decryption error: {str(e)}")
            raise
    
    def _encrypt_stdlib(self, data, key):
        try:
            # cryptography library first
            return self._encrypt_cryptography(data, key)
        except ImportError:
            try:
                # PyCryptodome
                return self._encrypt_pycryptodome(data, key)
            except ImportError:
                logger.warning("No standard library available, falling back to custom implementation")
                return self._encrypt_custom(data, key)
    
    def _decrypt_stdlib(self, data, key):
        try:
            # cryptography library first
            return self._decrypt_cryptography(data, key)
        except ImportError:
            try:
                # PyCryptodome
                return self._decrypt_pycryptodome(data, key)
            except ImportError:
                logger.warning("No standard library available, falling back to custom implementation")
                return self._decrypt_custom(data, key)
    
    def _encrypt_cryptography(self, data, key):

        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding
        
        if self.mode in ["CBC", "CFB", "OFB"]:
            iv = os.urandom(16)
        else:
            iv = None
        
        if self.mode == "ECB":
            mode_obj = modes.ECB()
        elif self.mode == "CBC":
            mode_obj = modes.CBC(iv)
        elif self.mode == "CFB":
            mode_obj = modes.CFB(iv)
        elif self.mode == "OFB":
            mode_obj = modes.OFB(iv)
        
        cipher = Cipher(algorithms.Camellia(key), mode_obj, backend=default_backend())
        encryptor = cipher.encryptor()
        
        # padding for block modes
        if self.mode in ["ECB", "CBC"]:
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        else:
            ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # return IV 
        if iv is not None:
            return iv + ciphertext
        else:
            return ciphertext
    
    def _decrypt_cryptography(self, data, key):

        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding
        
        # extract IV 
        if self.mode in ["CBC", "CFB", "OFB"]:
            if len(data) < 16:
                raise ValueError("Data too short to contain IV")
            iv = data[:16]
            ciphertext = data[16:]
        else:
            iv = None
            ciphertext = data
        
        # create cipher
        if self.mode == "ECB":
            mode_obj = modes.ECB()
        elif self.mode == "CBC":
            mode_obj = modes.CBC(iv)
        elif self.mode == "CFB":
            mode_obj = modes.CFB(iv)
        elif self.mode == "OFB":
            mode_obj = modes.OFB(iv)
        
        cipher = Cipher(algorithms.Camellia(key), mode_obj, backend=default_backend())
        decryptor = cipher.decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # handle padding 
        if self.mode in ["ECB", "CBC"]:
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(plaintext) + unpadder.finalize()
        
        return plaintext
    
    def _encrypt_pycryptodome(self, data, key):
        from Crypto.Cipher import Camellia
        from Crypto.Util.Padding import pad
        
        # generate IV 
        if self.mode in ["CBC", "CFB", "OFB"]:
            iv = os.urandom(16)
        else:
            iv = None
        
        # create cipher
        if self.mode == "ECB":
            cipher = Camellia.new(key, Camellia.MODE_ECB)
        elif self.mode == "CBC":
            cipher = Camellia.new(key, Camellia.MODE_CBC, iv)
        elif self.mode == "CFB":
            cipher = Camellia.new(key, Camellia.MODE_CFB, iv)
        elif self.mode == "OFB":
            cipher = Camellia.new(key, Camellia.MODE_OFB, iv)
        
        # handle padding for block modes
        if self.mode in ["ECB", "CBC"]:
            padded_data = pad(data, 16)
            ciphertext = cipher.encrypt(padded_data)
        else:
            ciphertext = cipher.encrypt(data)
        
        # return IV
        if iv is not None:
            return iv + ciphertext
        else:
            return ciphertext
    
    def _decrypt_pycryptodome(self, data, key):
        from Crypto.Cipher import Camellia
        from Crypto.Util.Padding import unpad
        
        # extract IV 
        if self.mode in ["CBC", "CFB", "OFB"]:
            if len(data) < 16:
                raise ValueError("Data too short to contain IV")
            iv = data[:16]
            ciphertext = data[16:]
        else:
            iv = None
            ciphertext = data
        
        # create cipher
        if self.mode == "ECB":
            cipher = Camellia.new(key, Camellia.MODE_ECB)
        elif self.mode == "CBC":
            cipher = Camellia.new(key, Camellia.MODE_CBC, iv)
        elif self.mode == "CFB":
            cipher = Camellia.new(key, Camellia.MODE_CFB, iv)
        elif self.mode == "OFB":
            cipher = Camellia.new(key, Camellia.MODE_OFB, iv)
        
        plaintext = cipher.decrypt(ciphertext)
        
        # handle padding
        if self.mode in ["ECB", "CBC"]:
            plaintext = unpad(plaintext, 16)
        
        return plaintext
    
    def encrypt_stream(self, data, key=None, chunk_size=8192):

        if key is None:
            key = self.encryption_key
        
        if key is None:
            raise ValueError("No encryption key provided")
        
        validate_key_size(key)
        
        if self.is_custom:
            return self._encrypt_stream_custom_v2(data, key, chunk_size)
        else:
            return self._encrypt_stream_stdlib_v2(data, key, chunk_size)
    
    def decrypt_stream(self, data, key=None, chunk_size=8192):

        if key is None:
            key = self.encryption_key
        
        if key is None:
            raise ValueError("No decryption key provided")
        
        validate_key_size(key)
        
        if self.is_custom:
            return self._decrypt_stream_custom_v2(data, key, chunk_size)
        else:
            return self._decrypt_stream_stdlib_v2(data, key, chunk_size)
    
    def _encrypt_stream_custom_v2(self, data, key, chunk_size):

        try:
            cipher = CamelliaModes(key)
            result = b""
            
            # process data in chunks
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                
                # encrypt the chunk
                if self.mode == "ECB":
                    encrypted_chunk = cipher.encrypt_ecb(chunk)
                elif self.mode == "CBC":
                    encrypted_chunk = cipher.encrypt_cbc(chunk)
                elif self.mode == "CFB":
                    encrypted_chunk = cipher.encrypt_cfb(chunk)
                elif self.mode == "OFB":
                    encrypted_chunk = cipher.encrypt_ofb(chunk)
                else:
                    raise ValueError(f"Unsupported mode: {self.mode}")
                
                # add chunk boundary marker: [encrypted_chunk_size:4][encrypted_chunk]
                chunk_header = len(encrypted_chunk).to_bytes(4, byteorder='big')
                result += chunk_header + encrypted_chunk
            
            return result
                    
        except Exception as e:
            logger.error(f"Custom stream encryption error: {str(e)}")
            raise
    
    def _decrypt_stream_custom_v2(self, data, key, chunk_size):

        try:
            cipher = CamelliaModes(key)
            result = b""
            offset = 0
            
            # process concatenated encrypted chunks
            while offset < len(data):
                # Read chunk size (4 bytes)
                if offset + 4 > len(data):
                    break
                
                encrypted_chunk_size = int.from_bytes(data[offset:offset+4], byteorder='big')
                offset += 4
                
                # read encrypted chunk
                if offset + encrypted_chunk_size > len(data):
                    break
                
                encrypted_chunk = data[offset:offset+encrypted_chunk_size]
                offset += encrypted_chunk_size
                
                # decrypt chunk
                if self.mode == "ECB":
                    decrypted_chunk = cipher.decrypt_ecb(encrypted_chunk)
                elif self.mode == "CBC":
                    decrypted_chunk = cipher.decrypt_cbc(encrypted_chunk)
                elif self.mode == "CFB":
                    decrypted_chunk = cipher.decrypt_cfb(encrypted_chunk)
                elif self.mode == "OFB":
                    decrypted_chunk = cipher.decrypt_ofb(encrypted_chunk)
                else:
                    raise ValueError(f"Unsupported mode: {self.mode}")
                
                result += decrypted_chunk
            
            return result
                    
        except Exception as e:
            logger.error(f"Custom stream decryption error: {str(e)}")
            raise
    
    def _encrypt_stream_stdlib_v2(self, data, key, chunk_size):

        try:
            # cryptography library first
            return self._encrypt_stream_cryptography_v2(data, key, chunk_size)
        except ImportError:
            try:
                # PyCryptodome
                return self._encrypt_stream_pycryptodome_v2(data, key, chunk_size)
            except ImportError:
                logger.warning("No standard library available, falling back to custom implementation")
                return self._encrypt_stream_custom_v2(data, key, chunk_size)
    
    def _decrypt_stream_stdlib_v2(self, data, key, chunk_size):

        try:
            # use cryptography library first
            return self._decrypt_stream_cryptography_v2(data, key, chunk_size)
        except ImportError:
            try:
                # PyCryptodome
                return self._decrypt_stream_pycryptodome_v2(data, key, chunk_size)
            except ImportError:
                logger.warning("No standard library available, falling back to custom implementation")
                return self._decrypt_stream_custom_v2(data, key, chunk_size)
    
    def _encrypt_stream_cryptography_v2(self, data, key, chunk_size):

        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding
        
        result = b""
        
        # process data in chunks
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            
            # generate IV 
            if self.mode in ["CBC", "CFB", "OFB"]:
                iv = os.urandom(16)
            else:
                iv = None
            
            # create cipher for this chunk
            if self.mode == "ECB":
                mode_obj = modes.ECB()
            elif self.mode == "CBC":
                mode_obj = modes.CBC(iv)
            elif self.mode == "CFB":
                mode_obj = modes.CFB(iv)
            elif self.mode == "OFB":
                mode_obj = modes.OFB(iv)
            
            cipher = Cipher(algorithms.Camellia(key), mode_obj, backend=default_backend())
            encryptor = cipher.encryptor()
            
            # handle padding 
            if self.mode in ["ECB", "CBC"]:
                padder = padding.PKCS7(128).padder()
                padded_chunk = padder.update(chunk) + padder.finalize()
                encrypted_chunk = encryptor.update(padded_chunk) + encryptor.finalize()
            else:
                encrypted_chunk = encryptor.update(chunk) + encryptor.finalize()
            
            # prepend IV if needed
            if iv is not None:
                encrypted_chunk = iv + encrypted_chunk
            
            # add chunk boundary marker
            chunk_header = len(encrypted_chunk).to_bytes(4, byteorder='big')
            result += chunk_header + encrypted_chunk
        
        return result
    
    def _decrypt_stream_cryptography_v2(self, data, key, chunk_size):

        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import padding
        
        result = b""
        offset = 0
        
        # process concatenated chunks
        while offset < len(data):
            # read chunk size (4 bytes)
            if offset + 4 > len(data):
                break
            
            encrypted_chunk_size = int.from_bytes(data[offset:offset+4], byteorder='big')
            offset += 4
            
            # read encrypted chunk
            if offset + encrypted_chunk_size > len(data):
                break
            
            encrypted_chunk = data[offset:offset+encrypted_chunk_size]
            offset += encrypted_chunk_size
            
            # extract IV 
            if self.mode in ["CBC", "CFB", "OFB"]:
                if len(encrypted_chunk) < 16:
                    raise ValueError("Encrypted chunk too short to contain IV")
                iv = encrypted_chunk[:16]
                ciphertext = encrypted_chunk[16:]
            else:
                iv = None
                ciphertext = encrypted_chunk
            
            # xreate cipher for chunk
            if self.mode == "ECB":
                mode_obj = modes.ECB()
            elif self.mode == "CBC":
                mode_obj = modes.CBC(iv)
            elif self.mode == "CFB":
                mode_obj = modes.CFB(iv)
            elif self.mode == "OFB":
                mode_obj = modes.OFB(iv)
            
            cipher = Cipher(algorithms.Camellia(key), mode_obj, backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted_chunk = decryptor.update(ciphertext) + decryptor.finalize()
            
            # handle padding
            if self.mode in ["ECB", "CBC"]:
                unpadder = padding.PKCS7(128).unpadder()
                decrypted_chunk = unpadder.update(decrypted_chunk) + unpadder.finalize()
            
            result += decrypted_chunk
        
        return result
    
    def _encrypt_stream_pycryptodome_v2(self, data, key, chunk_size):

        from Crypto.Cipher import Camellia
        from Crypto.Util.Padding import pad
        
        result = b""
        
        # process data in chunks
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            
            # generate IV 
            if self.mode in ["CBC", "CFB", "OFB"]:
                iv = os.urandom(16)
            else:
                iv = None
            
            # create cipher
            if self.mode == "ECB":
                cipher = Camellia.new(key, Camellia.MODE_ECB)
            elif self.mode == "CBC":
                cipher = Camellia.new(key, Camellia.MODE_CBC, iv)
            elif self.mode == "CFB":
                cipher = Camellia.new(key, Camellia.MODE_CFB, iv)
            elif self.mode == "OFB":
                cipher = Camellia.new(key, Camellia.MODE_OFB, iv)
            
            # handle padding 
            if self.mode in ["ECB", "CBC"]:
                padded_chunk = pad(chunk, 16)
                encrypted_chunk = cipher.encrypt(padded_chunk)
            else:
                encrypted_chunk = cipher.encrypt(chunk)
            
            # prepend IV 
            if iv is not None:
                encrypted_chunk = iv + encrypted_chunk
            
            # add chunk markers
            chunk_header = len(encrypted_chunk).to_bytes(4, byteorder='big')
            result += chunk_header + encrypted_chunk
        
        return result
    
    def _decrypt_stream_pycryptodome_v2(self, data, key, chunk_size):

        from Crypto.Cipher import Camellia
        from Crypto.Util.Padding import unpad
        
        result = b""
        offset = 0
        
        # process concatenated encrypted chunks
        while offset < len(data):
            # read chunk size
            if offset + 4 > len(data):
                break
            
            encrypted_chunk_size = int.from_bytes(data[offset:offset+4], byteorder='big')
            offset += 4
            
            # read encrypted chunk
            if offset + encrypted_chunk_size > len(data):
                break
            
            encrypted_chunk = data[offset:offset+encrypted_chunk_size]
            offset += encrypted_chunk_size
            
            # extract IV 
            if self.mode in ["CBC", "CFB", "OFB"]:
                if len(encrypted_chunk) < 16:
                    raise ValueError("Encrypted chunk too short to contain IV")
                iv = encrypted_chunk[:16]
                ciphertext = encrypted_chunk[16:]
            else:
                iv = None
                ciphertext = encrypted_chunk
            
            # xreate cipher for chunk
            if self.mode == "ECB":
                cipher = Camellia.new(key, Camellia.MODE_ECB)
            elif self.mode == "CBC":
                cipher = Camellia.new(key, Camellia.MODE_CBC, iv)
            elif self.mode == "CFB":
                cipher = Camellia.new(key, Camellia.MODE_CFB, iv)
            elif self.mode == "OFB":
                cipher = Camellia.new(key, Camellia.MODE_OFB, iv)
            
            decrypted_chunk = cipher.decrypt(ciphertext)
            
            # handle padding 
            if self.mode in ["ECB", "CBC"]:
                decrypted_chunk = unpad(decrypted_chunk, 16)
            
            result += decrypted_chunk
        
        return result
