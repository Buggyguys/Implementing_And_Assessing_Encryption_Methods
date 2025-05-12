"""
Handmade ECC Implementation

This module implements Elliptic Curve Cryptography from scratch, including
curve operations, key generation, and ECDH key exchange.
"""

import os
import hashlib
import random
from typing import Tuple, Dict, Union, Optional, List

class ECCHandmade:
    """
    A handmade implementation of Elliptic Curve Cryptography.
    """
    
    # Predefined curves (parameters are from SEC 2 document)
    CURVES = {
        # P-256 (secp256r1)
        "P-256": {
            "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
            "a": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
            "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
            "G_x": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
            "G_y": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
            "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
            "h": 1,
            "bit_size": 256
        },
        # P-384 (secp384r1)
        "P-384": {
            "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
            "a": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
            "b": 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
            "G_x": 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
            "G_y": 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
            "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
            "h": 1,
            "bit_size": 384
        },
        # P-521 (secp521r1)
        "P-521": {
            "p": 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
            "a": 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC,
            "b": 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,
            "G_x": 0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
            "G_y": 0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650,
            "n": 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
            "h": 1,
            "bit_size": 521
        }
    }
    
    def __init__(self, curve: str = "P-256"):
        """
        Initialize the ECC cipher with the specified curve.
        
        Args:
            curve: Curve name ("P-256", "P-384", or "P-521")
        """
        if curve not in self.CURVES:
            raise ValueError(f"Unknown curve: {curve}. Supported curves: {', '.join(self.CURVES.keys())}")
        
        self.curve_name = curve
        self.curve_params = self.CURVES[curve]
        
        # Extract curve parameters
        self.p = self.curve_params["p"]
        self.a = self.curve_params["a"]
        self.b = self.curve_params["b"]
        self.G = (self.curve_params["G_x"], self.curve_params["G_y"])  # Generator point
        self.n = self.curve_params["n"]  # Order of G
        self.h = self.curve_params["h"]  # Cofactor
        self.bit_size = self.curve_params["bit_size"]
    
    def generate_key(self) -> Dict[str, Union[int, Tuple[int, int]]]:
        """
        Generate an ECC key pair.
        
        Returns:
            Dict: ECC key components (private_key, public_key)
        """
        # Generate random private key (d)
        private_key = random.randint(1, self.n - 1)
        
        # Compute public key Q = d * G
        public_key = self._point_multiply(private_key, self.G)
        
        return {
            'private_key': private_key,
            'public_key': public_key,
            'curve': self.curve_name
        }
    
    def _mod_inverse(self, x: int, m: int) -> int:
        """
        Calculate the modular multiplicative inverse.
        
        Args:
            x: Integer
            m: Modulus
            
        Returns:
            int: x^(-1) mod m
        """
        if x % m == 0:
            raise ValueError("No modular inverse exists")
        
        # Extended Euclidean Algorithm
        def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, y = extended_gcd(x % m, m)
        
        if gcd != 1:
            raise ValueError("No modular inverse exists")
        
        return (x % m + m) % m
    
    def _is_on_curve(self, point: Tuple[int, int]) -> bool:
        """
        Check if a point is on the elliptic curve.
        
        Args:
            point: Point (x, y)
            
        Returns:
            bool: True if the point is on the curve, False otherwise
        """
        if point is None:  # Point at infinity
            return True
        
        x, y = point
        # Check if the point satisfies the curve equation: y^2 = x^3 + ax + b (mod p)
        left = (y * y) % self.p
        right = (x * x * x + self.a * x + self.b) % self.p
        
        return left == right
    
    def _point_add(self, P: Optional[Tuple[int, int]], Q: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
        """
        Add two points on the elliptic curve.
        
        Args:
            P, Q: Points (x, y) or None (point at infinity)
            
        Returns:
            Tuple[int, int] or None: The sum P + Q
        """
        # Handle points at infinity
        if P is None:
            return Q
        if Q is None:
            return P
        
        x1, y1 = P
        x2, y2 = Q
        
        # Check if the points are on the curve
        if not self._is_on_curve(P) or not self._is_on_curve(Q):
            raise ValueError("Points must be on the curve")
        
        # P + (-P) = O (point at infinity)
        if x1 == x2 and y1 == (self.p - y2) % self.p:
            return None
        
        # Calculate the slope
        if x1 == x2 and y1 == y2:  # Point doubling
            # s = (3x^2 + a) / (2y) mod p
            numerator = (3 * x1 * x1 + self.a) % self.p
            denominator = (2 * y1) % self.p
        else:  # Point addition
            # s = (y2 - y1) / (x2 - x1) mod p
            numerator = (y2 - y1) % self.p
            denominator = (x2 - x1) % self.p
        
        s = (numerator * self._mod_inverse(denominator, self.p)) % self.p
        
        # Calculate the result
        x3 = (s * s - x1 - x2) % self.p
        y3 = (s * (x1 - x3) - y1) % self.p
        
        return (x3, y3)
    
    def _point_double(self, P: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
        """
        Double a point on the elliptic curve.
        
        Args:
            P: Point (x, y) or None (point at infinity)
            
        Returns:
            Tuple[int, int] or None: The result 2*P
        """
        # Handle point at infinity
        if P is None:
            return None
        
        # Reuse the addition formula for doubling
        return self._point_add(P, P)
    
    def _point_multiply(self, k: int, P: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
        """
        Multiply a point by a scalar.
        
        Args:
            k: Scalar
            P: Point (x, y) or None (point at infinity)
            
        Returns:
            Tuple[int, int] or None: The result k*P
        """
        # Handle special cases
        if k == 0 or P is None:
            return None
        
        if k < 0:
            # If k is negative, compute -k * P
            k = -k
            P = (P[0], (self.p - P[1]) % self.p)  # Negate the y-coordinate
        
        # Double-and-add algorithm
        result = None
        addend = P
        
        while k:
            if k & 1:
                # If the least significant bit is 1, add the current addend
                result = self._point_add(result, addend)
            
            # Double the addend
            addend = self._point_double(addend)
            
            # Shift k right by 1 bit
            k >>= 1
        
        return result
    
    def ecdh_key_exchange(self, private_key: int, other_public_key: Tuple[int, int]) -> bytes:
        """
        Perform ECDH key exchange.
        
        Args:
            private_key: Own private key
            other_public_key: Other party's public key
            
        Returns:
            bytes: Shared secret
        """
        # Compute shared point: private_key * other_public_key
        shared_point = self._point_multiply(private_key, other_public_key)
        
        if shared_point is None:
            raise ValueError("ECDH key exchange failed: shared point is at infinity")
        
        # Use the x-coordinate as the shared secret
        shared_secret_int = shared_point[0]
        
        # Convert to bytes
        key_bytes = (self.bit_size + 7) // 8
        shared_secret = shared_secret_int.to_bytes(key_bytes, byteorder='big')
        
        # Typically, you would apply a KDF to the shared secret, but for simplicity:
        return hashlib.sha256(shared_secret).digest()
    
    def encrypt(self, plaintext: bytes, key: Optional[Dict[str, Union[int, Tuple[int, int]]]] = None) -> bytes:
        """
        Encrypt data using ECIES (simplified).
        
        Args:
            plaintext: Data to encrypt
            key: ECC key (if None, use a newly generated key)
            
        Returns:
            bytes: Encrypted data (ephemeral_public_key || ciphertext || mac)
        """
        if key is None:
            key = self.generate_key()
        
        # Extract the public key from the key dictionary
        if 'public_key' not in key:
            raise ValueError("Public key not found in the provided key")
        
        recipient_public_key = key['public_key']
        
        # Generate an ephemeral key pair
        ephemeral_key = self.generate_key()
        ephemeral_private_key = ephemeral_key['private_key']
        ephemeral_public_key = ephemeral_key['public_key']
        
        # Perform ECDH to derive a shared secret
        shared_secret = self.ecdh_key_exchange(ephemeral_private_key, recipient_public_key)
        
        # Derive encryption and MAC keys from the shared secret
        kdf_output = hashlib.sha512(shared_secret).digest()
        enc_key = kdf_output[:32]  # First 32 bytes for encryption
        mac_key = kdf_output[32:]  # Last 32 bytes for MAC
        
        # For simplicity, using a basic XOR cipher for encryption
        # In practice, you would use a proper symmetric cipher like AES
        ciphertext = bytearray(len(plaintext))
        for i in range(len(plaintext)):
            # Stretch the key by using a different byte for each position
            key_byte = enc_key[i % len(enc_key)]
            ciphertext[i] = plaintext[i] ^ key_byte
        
        # Generate a MAC
        mac_data = bytes(ciphertext)  # Convert ciphertext to bytes
        mac = hmac_sha256(mac_key, mac_data)
        
        # Serialize the ephemeral public key
        x_bytes = ephemeral_public_key[0].to_bytes((self.bit_size + 7) // 8, byteorder='big')
        y_bytes = ephemeral_public_key[1].to_bytes((self.bit_size + 7) // 8, byteorder='big')
        serialized_public_key = b'\x04' + x_bytes + y_bytes  # Uncompressed form
        
        # Return ephemeral_public_key || ciphertext || mac
        return serialized_public_key + bytes(ciphertext) + mac
    
    def decrypt(self, ciphertext: bytes, key: Dict[str, Union[int, Tuple[int, int]]]) -> bytes:
        """
        Decrypt data using ECIES.
        
        Args:
            ciphertext: Data to decrypt
            key: ECC key containing private_key
            
        Returns:
            bytes: Decrypted data
            
        Raises:
            ValueError: If decryption fails
        """
        if 'private_key' not in key:
            raise ValueError("Private key not found in the provided key")
        
        recipient_private_key = key['private_key']
        
        # Parse the input
        key_bytes = (self.bit_size + 7) // 8
        public_key_len = 1 + 2 * key_bytes  # Uncompressed form: 0x04 || x || y
        
        if len(ciphertext) < public_key_len + 32:  # Need at least public key and MAC
            raise ValueError("Invalid ciphertext length")
        
        serialized_public_key = ciphertext[:public_key_len]
        mac = ciphertext[-32:]
        actual_ciphertext = ciphertext[public_key_len:-32]
        
        # Deserialize the ephemeral public key
        if serialized_public_key[0] != 0x04:
            raise ValueError("Only uncompressed public keys are supported")
        
        x_bytes = serialized_public_key[1:1+key_bytes]
        y_bytes = serialized_public_key[1+key_bytes:1+2*key_bytes]
        ephemeral_public_key = (
            int.from_bytes(x_bytes, byteorder='big'),
            int.from_bytes(y_bytes, byteorder='big')
        )
        
        # Perform ECDH to derive the shared secret
        shared_secret = self.ecdh_key_exchange(recipient_private_key, ephemeral_public_key)
        
        # Derive encryption and MAC keys
        kdf_output = hashlib.sha512(shared_secret).digest()
        enc_key = kdf_output[:32]
        mac_key = kdf_output[32:]
        
        # Verify the MAC
        expected_mac = hmac_sha256(mac_key, actual_ciphertext)
        if not self._constant_time_compare(mac, expected_mac):
            raise ValueError("MAC verification failed")
        
        # Decrypt the ciphertext
        plaintext = bytearray(len(actual_ciphertext))
        for i in range(len(actual_ciphertext)):
            key_byte = enc_key[i % len(enc_key)]
            plaintext[i] = actual_ciphertext[i] ^ key_byte
        
        return bytes(plaintext)
    
    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """
        Compare two byte strings in constant time.
        
        Args:
            a, b: Byte strings to compare
            
        Returns:
            bool: True if equal, False otherwise
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        
        return result == 0


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """
    Simple HMAC-SHA256 implementation.
    
    Args:
        key: Key for HMAC
        message: Message to authenticate
        
    Returns:
        bytes: HMAC value
    """
    # Constants
    BLOCK_SIZE = 64  # SHA-256 block size
    
    # If key is longer than block size, hash it
    if len(key) > BLOCK_SIZE:
        key = hashlib.sha256(key).digest()
    
    # If key is shorter than block size, pad it
    if len(key) < BLOCK_SIZE:
        key = key + b'\x00' * (BLOCK_SIZE - len(key))
    
    # Prepare inner and outer padding
    ipad = bytes(x ^ 0x36 for x in key)
    opad = bytes(x ^ 0x5C for x in key)
    
    # Compute HMAC
    inner_hash = hashlib.sha256(ipad + message).digest()
    outer_hash = hashlib.sha256(opad + inner_hash).digest()
    
    return outer_hash 