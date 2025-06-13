import os
import hashlib
import hmac
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from .base import ECCImplementationBase
from .key_utils import (
    extract_key_components, point_add, scalar_multiply, 
    CURVE_PARAMS, P384, add_chunk_delimiter, split_delimited_chunks
)

class ECCP384Implementation(ECCImplementationBase):
    
    def __init__(self, **kwargs):
        # remove curve from kwargs if it exists to avoid conflict
        if 'curve' in kwargs:
            kwargs.pop('curve')
        super().__init__(curve="P-384", **kwargs)
        self.name = "ECC-P384"
        self.description = "P-384 (secp384r1)"
        if self.is_custom:
            self.description = f"Custom {self.description}"
        else:
            self.description = f"Cryptography.io {self.description}"
    
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
        # use the P-384 curve
        curve = ec.SECP384R1()
        
        # generate an ephemeral key pair for this session
        ephemeral_private = ec.generate_private_key(curve)
        ephemeral_public = ephemeral_private.public_key()
        
        # perform key agreement to get a shared secret
        shared_secret = ephemeral_private.exchange(
            ec.ECDH(),
            public_key
        )
        
        # use shared secret directly for XOR encryption
        derived_key = shared_secret
        
        # extend the key to match data length using SHA-256 key stretching
        extended_key = b''
        counter = 0
        while len(extended_key) < len(data):
            hash_input = derived_key + counter.to_bytes(4, 'big')
            extended_key += hashlib.sha256(hash_input).digest()
            counter += 1
        extended_key = extended_key[:len(data)]
        
        # random IV
        iv = os.urandom(16)
        
        # XOR encryption
        ciphertext = bytes(a ^ b for a, b in zip(data, extended_key))
        
        # serialize the ephemeral public key
        ephemeral_public_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # return the combined ciphertext: ephemeral_public_key || iv || ciphertext  
        # we include a simple header to separate the components
        return b'ECIES' + len(ephemeral_public_bytes).to_bytes(4, 'big') + ephemeral_public_bytes + \
               iv + ciphertext
    
    def _decrypt_stdlib(self, ciphertext, private_key):
        # check for our header
        if not ciphertext.startswith(b'ECIES'):
            raise ValueError(f"Invalid ciphertext format: data doesn't begin with ECIES header")
        
        try:
            # extract the ephemeral public key length
            key_len = int.from_bytes(ciphertext[5:9], 'big')
            
            # extract components
            ephemeral_public_bytes = ciphertext[9:9+key_len]
            iv = ciphertext[9+key_len:25+key_len]
            actual_ciphertext = ciphertext[25+key_len:]
            
            # load the ephemeral public key
            ephemeral_public = serialization.load_pem_public_key(ephemeral_public_bytes)
            
            # perform key agreement to get the shared secret
            shared_secret = private_key.exchange(
                ec.ECDH(),
                ephemeral_public
            )
            
            # use shared secret directly for XOR encryption
            derived_key = shared_secret
            
            # extend the key to match data length using SHA-256 key stretching
            extended_key = b''
            counter = 0
            while len(extended_key) < len(actual_ciphertext):
                hash_input = derived_key + counter.to_bytes(4, 'big')
                extended_key += hashlib.sha256(hash_input).digest()
                counter += 1
            extended_key = extended_key[:len(actual_ciphertext)]
            
            # decrypt the data using XOR
            plaintext = bytes(a ^ b for a, b in zip(actual_ciphertext, extended_key))
            return plaintext
            
        except InvalidTag:
            return b''
        except Exception as e:
            error_details = f"Error: {type(e).__name__}: {str(e)}"
            if len(ciphertext) < 20:
                error_details += f", Ciphertext length: {len(ciphertext)} (too short)"
            raise ValueError(f"Decryption failed: {error_details}")
    
    def _sign_stdlib(self, data, private_key):
        # hash the data with SHA384 (matching curve size)
        data_hash = hashlib.sha384(data).digest()
        
        # sign the hash
        signature = private_key.sign(
            data_hash,
            ec.ECDSA(hashes.SHA384())
        )
        
        return signature
    
    def _verify_stdlib(self, data, signature, public_key):
        # hash the data with SHA384 (matching curve size)
        data_hash = hashlib.sha384(data).digest()
        
        # verify the signature
        try:
            public_key.verify(
                signature,
                data_hash,
                ec.ECDSA(hashes.SHA384())
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def _encrypt_custom(self, data, public_key):
        curve = P384
        
        # extract public key coordinates
        pub_x = public_key["x"]
        pub_y = public_key["y"]
        
        # generate an ephemeral key pair
        ephemeral_d = secrets.randbelow(curve["n"] - 1) + 1
        G = (curve["G_x"], curve["G_y"])
        ephemeral_Q = scalar_multiply(ephemeral_d, G, curve)
        
        # compute the shared point: R = d_E * Q_B
        recipient_Q = (pub_x, pub_y)
        shared_point = scalar_multiply(ephemeral_d, recipient_Q, curve)
        
        # use the x-coordinate of the shared point as the shared secret
        shared_secret = shared_point[0].to_bytes((curve["bits"] + 7) // 8, byteorder='big')
        
        # derive encryption key using SHA384 (matching curve size)
        key_material = hmac.new(b'ECIES', shared_secret, hashlib.sha384).digest()
        encryption_key = key_material[:32]  # use a stronger key for P-384
        mac_key = key_material[32:64]
        
        # use shared secret directly for XOR encryption
        derived_key = shared_secret
        
        # extend the key to match data length using SHA-256 key stretching
        extended_key = b''
        counter = 0
        while len(extended_key) < len(data):
            hash_input = derived_key + counter.to_bytes(4, 'big')
            extended_key += hashlib.sha256(hash_input).digest()
            counter += 1
        extended_key = extended_key[:len(data)]
        
        # random IV
        iv = os.urandom(16)
        
        # simple XOR encryption
        ciphertext = bytes(a ^ b for a, b in zip(data, extended_key))
        
        # compute MAC over IV and ciphertext using SHA384
        mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha384).digest()
        
        # add curve information to the header
        curve_id = b'P384'
        curve_header = len(curve_id).to_bytes(1, byteorder='big') + curve_id
        
        # return curve info, ephemeral public key, IV, MAC, and ciphertext
        coord_size = (curve["bits"] + 7) // 8
        ephemeral_public_bytes = ephemeral_Q[0].to_bytes(coord_size, byteorder='big') + ephemeral_Q[1].to_bytes(coord_size, byteorder='big')
        return curve_header + ephemeral_public_bytes + iv + mac[:32] + ciphertext
    
    def _decrypt_custom(self, ciphertext, private_key):
        try:
            # first byte is the length of the curve ID
            if len(ciphertext) < 2:
                return b''  # not enough data
                
            curve_id_len = ciphertext[0]
            if len(ciphertext) < 1 + curve_id_len:
                return b''  # not enough data
                
            # extract curve ID and validate
            curve_id = ciphertext[1:1+curve_id_len].decode('utf-8')
            if curve_id != 'P384':
                return b''  # wrong curve
                
            # use P-384 curve parameters
            curve = P384
            coord_size = (curve["bits"] + 7) // 8
            
            # calculate offsets for the rest of the data
            header_size = 1 + curve_id_len
            point_size = 2 * coord_size  # x and y coordinates
            
            # ensure we have enough data
            if len(ciphertext) < header_size + point_size + 16 + 32:
                return b''  # not enough data
            
            # extract the ephemeral public key and other components
            ephemeral_x = int.from_bytes(ciphertext[header_size:header_size+coord_size], byteorder='big')
            ephemeral_y = int.from_bytes(ciphertext[header_size+coord_size:header_size+point_size], byteorder='big')
            
            # extract IV and MAC
            iv_offset = header_size + point_size
            iv = ciphertext[iv_offset:iv_offset+16]
            mac = ciphertext[iv_offset+16:iv_offset+16+32]
            actual_ciphertext = ciphertext[iv_offset+16+32:]
            
            # extract the private key
            d = private_key["d"]
            
            # compute the shared point: R = d_B * Q_E
            ephemeral_Q = (ephemeral_x, ephemeral_y)
            shared_point = scalar_multiply(d, ephemeral_Q, curve)
            
            # use the x-coordinate of the shared point as the shared secret
            shared_secret = shared_point[0].to_bytes(coord_size, byteorder='big')
            
            # derive encryption key using SHA384 (matching curve size)
            key_material = hmac.new(b'ECIES', shared_secret, hashlib.sha384).digest()
            encryption_key = key_material[:32]  # use a stronger key for P-384
            mac_key = key_material[32:64]
            
            # use shared secret directly for XOR encryption
            derived_key = shared_secret
            
            # extend the key to match data length using SHA-256 key stretching
            extended_key = b''
            counter = 0
            while len(extended_key) < len(actual_ciphertext):
                hash_input = derived_key + counter.to_bytes(4, 'big')
                extended_key += hashlib.sha256(hash_input).digest()
                counter += 1
            extended_key = extended_key[:len(actual_ciphertext)]
            
            # verify MAC
            computed_mac = hmac.new(mac_key, iv + actual_ciphertext, hashlib.sha384).digest()
            if not hmac.compare_digest(computed_mac[:32], mac):
                return b''
            
            # XOR decryption 
            plaintext = bytes(a ^ b for a, b in zip(actual_ciphertext, extended_key))
            return plaintext
        except Exception:
            return b''
    
    def _sign_custom(self, data, private_key):
        curve = P384
        
        # extract the private key
        d = private_key["d"]
        
        # hash the data with SHA384 (matching curve size)
        data_hash = hashlib.sha384(data).digest()
        e = int.from_bytes(data_hash, byteorder='big') % curve["n"]
        
        # RFC 6979 deterministic k generation (simplified)
        h1 = hashlib.sha384(data_hash + d.to_bytes((curve["bits"] + 7) // 8, byteorder='big')).digest()
        k = int.from_bytes(h1, byteorder='big') % curve["n"]
        if k == 0:  # ensure k is not 0
            k = 1
        
        # compute the point R = k * G
        G = (curve["G_x"], curve["G_y"])
        R = scalar_multiply(k, G, curve)
        
        # x-coordinate of R mod n
        r = R[0] % curve["n"]
        
        # s = k^-1 * (e + r * d) mod n 
        k_inv = pow(k, curve["n"] - 2, curve["n"])  # k^-1 mod n
        s = (k_inv * (e + r * d)) % curve["n"]
        
        # ensure s is in the lower range (for compatibility with low-s-only validators)
        if s > curve["n"] // 2:
            s = curve["n"] - s
        
        # the signature is (r, s)
        coord_size = (curve["bits"] + 7) // 8
        signature = r.to_bytes(coord_size, byteorder='big') + s.to_bytes(coord_size, byteorder='big')
        return signature
    
    def _verify_custom(self, data, signature, public_key):
        curve = P384
        coord_size = (curve["bits"] + 7) // 8
        
        # check signature length
        if len(signature) != 2 * coord_size:
            return False
        
        # extract signature components
        r = int.from_bytes(signature[:coord_size], byteorder='big')
        s = int.from_bytes(signature[coord_size:], byteorder='big')
        
        # check r and s are in the correct range
        if r <= 0 or r >= curve["n"] or s <= 0 or s >= curve["n"]:
            return False
        
        # extract public key
        pub_x = public_key["x"]
        pub_y = public_key["y"]
        Q = (pub_x, pub_y)
        
        # hash the data with SHA384 (matching curve size)
        data_hash = hashlib.sha384(data).digest()
        e = int.from_bytes(data_hash, byteorder='big') % curve["n"]
        
        # compute u1 and u2
        s_inv = pow(s, curve["n"] - 2, curve["n"])  # s^-1 mod n
        u1 = (e * s_inv) % curve["n"]
        u2 = (r * s_inv) % curve["n"]
        
        # compute the point R' = u1*G + u2*Q
        G = (curve["G_x"], curve["G_y"])
        point1 = scalar_multiply(u1, G, curve)
        point2 = scalar_multiply(u2, Q, curve)
        R_prime = point_add(point1, point2, curve)
        
        # the signature is valid if the x-coordinate of R' mod n equals r
        if R_prime is None:  # point at infinity
            return False
            
        v = R_prime[0] % curve["n"]
        return v == r 