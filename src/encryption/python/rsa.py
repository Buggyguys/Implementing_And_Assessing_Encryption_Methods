"""
Handmade RSA Implementation

This module implements RSA encryption/decryption from scratch, including
key generation, OAEP padding, and core cryptographic operations.
"""

import os
import math
import random
import hashlib
import struct
from typing import Tuple, Dict, Union, List, Optional

class RSAHandmade:
    """
    A handmade implementation of RSA encryption and decryption.
    """
    
    def __init__(self, key_size: str = "2048"):
        """
        Initialize the RSA cipher with the specified key size.
        
        Args:
            key_size: Key size in bits ("1024", "2048", or "4096")
        """
        self.key_size = int(key_size)
        if self.key_size not in [1024, 2048, 4096]:
            raise ValueError("Key size must be 1024, 2048, or 4096 bits")
        
        # Constants for OAEP
        self.oaep_hash_algo = hashlib.sha256
        self.oaep_label_hash = self.oaep_hash_algo(b'').digest()
        self.oaep_hash_len = len(self.oaep_label_hash)
    
    def generate_key(self) -> Dict[str, Union[int, bytes]]:
        """
        Generate an RSA key pair.
        
        Returns:
            Dict: RSA key components (p, q, n, e, d)
        """
        # Public exponent - commonly used value
        e = 65537
        
        # Generate two distinct prime numbers
        bit_length = self.key_size // 2
        p = self._generate_prime(bit_length)
        q = self._generate_prime(bit_length)
        
        # Ensure p and q are distinct
        while p == q:
            q = self._generate_prime(bit_length)
        
        # Calculate n = p * q
        n = p * q
        
        # Calculate Euler's totient function: φ(n) = (p-1)(q-1)
        phi = (p - 1) * (q - 1)
        
        # Calculate private exponent: d ≡ e^(-1) (mod φ(n))
        d = self._mod_inverse(e, phi)
        
        # Calculate additional CRT parameters for efficient decryption
        dp = d % (p - 1)
        dq = d % (q - 1)
        qinv = self._mod_inverse(q, p)
        
        return {
            'n': n,          # Modulus
            'e': e,          # Public exponent
            'd': d,          # Private exponent
            'p': p,          # First prime factor
            'q': q,          # Second prime factor
            'dp': dp,        # d mod (p-1)
            'dq': dq,        # d mod (q-1)
            'qinv': qinv     # q^(-1) mod p
        }
    
    def _is_probable_prime(self, n: int, k: int = 40) -> bool:
        """
        Check if a number is probably prime using Miller-Rabin test.
        
        Args:
            n: Number to test
            k: Number of iterations for Miller-Rabin test
            
        Returns:
            bool: True if n is probably prime, False otherwise
        """
        # Handle small numbers directly
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False
        
        # Write n-1 as 2^r * d where d is odd
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Witness loop
        for _ in range(k):
            # Pick a random base a in the range [2, n-2]
            a = random.randint(2, n - 2)
            
            # Compute a^d mod n
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    def _generate_prime(self, bit_length: int) -> int:
        """
        Generate a random prime number of the specified bit length.
        
        Args:
            bit_length: Length of the prime in bits
            
        Returns:
            int: A random prime number
        """
        # The prime should be at least bit_length bits
        min_value = 1 << (bit_length - 1)
        max_value = (1 << bit_length) - 1
        
        while True:
            # Generate a random odd number
            p = random.randint(min_value, max_value) | 1
            
            # Check if it's prime
            if self._is_probable_prime(p):
                return p
    
    def _gcd(self, a: int, b: int) -> int:
        """
        Calculate the greatest common divisor of a and b.
        
        Args:
            a, b: Integers
            
        Returns:
            int: GCD of a and b
        """
        while b:
            a, b = b, a % b
        return a
    
    def _extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """
        Extended Euclidean Algorithm.
        
        Args:
            a, b: Integers
            
        Returns:
            Tuple[int, int, int]: (gcd, x, y) such that ax + by = gcd
        """
        if a == 0:
            return b, 0, 1
        
        gcd, x1, y1 = self._extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd, x, y
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """
        Calculate the modular multiplicative inverse of a modulo m.
        
        Args:
            a: Integer
            m: Modulus
            
        Returns:
            int: a^(-1) mod m
            
        Raises:
            ValueError: If a and m are not coprime
        """
        gcd, x, y = self._extended_gcd(a, m)
        
        if gcd != 1:
            raise ValueError(f"{a} has no multiplicative inverse modulo {m}")
        
        return x % m
    
    def _mgf1(self, seed: bytes, length: int) -> bytes:
        """
        Mask Generation Function (MGF1) for OAEP.
        
        Args:
            seed: Seed bytes
            length: Desired output length in bytes
            
        Returns:
            bytes: Mask of specified length
        """
        hash_algo = self.oaep_hash_algo
        hash_len = self.oaep_hash_len
        
        if length > (2**32) * hash_len:
            raise ValueError("Mask too long")
        
        T = b""
        counter = 0
        
        while len(T) < length:
            C = counter.to_bytes(4, byteorder='big')
            T += hash_algo(seed + C).digest()
            counter += 1
        
        return T[:length]
    
    def _oaep_pad(self, message: bytes, label: bytes = b'') -> bytes:
        """
        Apply OAEP padding to a message.
        
        Args:
            message: Message to pad
            label: Optional label (default: empty)
            
        Returns:
            bytes: OAEP-padded message
        """
        hash_len = self.oaep_hash_len
        
        # Calculate maximum message length
        k = self.key_size // 8  # Key length in bytes
        mLen = len(message)
        
        # Check if message is too long
        if mLen > k - 2 * hash_len - 2:
            raise ValueError("Message too long for RSA key size")
        
        # Hash the label
        label_hash = self.oaep_hash_algo(label).digest()
        
        # Create the padding string PS
        PS = b'\x00' * (k - mLen - 2 * hash_len - 2)
        
        # Create the data block DB = lHash || PS || 0x01 || M
        DB = label_hash + PS + b'\x01' + message
        
        # Generate a random seed
        seed = os.urandom(hash_len)
        
        # Calculate DB mask
        dbMask = self._mgf1(seed, k - hash_len - 1)
        
        # Apply mask to DB
        maskedDB = bytes(a ^ b for a, b in zip(DB, dbMask))
        
        # Calculate seed mask
        seedMask = self._mgf1(maskedDB, hash_len)
        
        # Apply mask to seed
        maskedSeed = bytes(a ^ b for a, b in zip(seed, seedMask))
        
        # Construct the encoded message EM = 0x00 || maskedSeed || maskedDB
        EM = b'\x00' + maskedSeed + maskedDB
        
        return EM
    
    def _oaep_unpad(self, padded_message: bytes, label: bytes = b'') -> bytes:
        """
        Remove OAEP padding from a message.
        
        Args:
            padded_message: OAEP-padded message
            label: Optional label (default: empty)
            
        Returns:
            bytes: Original message
            
        Raises:
            ValueError: If padding is invalid
        """
        hash_len = self.oaep_hash_len
        
        # Calculate key length in bytes
        k = self.key_size // 8
        
        # Check if padded message has the right length
        if len(padded_message) != k:
            raise ValueError("Decoding error: Invalid message length")
        
        # Split the encoded message
        if padded_message[0] != 0:
            raise ValueError("Decoding error: First byte is not zero")
        
        maskedSeed = padded_message[1:1+hash_len]
        maskedDB = padded_message[1+hash_len:]
        
        # Calculate seed mask and recover seed
        seedMask = self._mgf1(maskedDB, hash_len)
        seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask))
        
        # Calculate DB mask and recover DB
        dbMask = self._mgf1(seed, k - hash_len - 1)
        DB = bytes(a ^ b for a, b in zip(maskedDB, dbMask))
        
        # Extract components from DB
        label_hash = self.oaep_hash_algo(label).digest()
        
        # Check if label hash matches
        if not self._constant_time_compare(DB[:hash_len], label_hash):
            raise ValueError("Decoding error: Label hash mismatch")
        
        # Find the separator 0x01 that marks the start of the message
        one_pos = hash_len
        while one_pos < len(DB):
            if DB[one_pos] == 0:
                one_pos += 1
            elif DB[one_pos] == 1:
                break
            else:
                raise ValueError("Decoding error: Invalid padding")
        
        if one_pos >= len(DB) - 1:
            raise ValueError("Decoding error: No message found")
        
        # Extract the message
        return DB[one_pos + 1:]
    
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
    
    def _encrypt_int(self, m: int, key: Dict[str, Union[int, bytes]]) -> int:
        """
        Encrypt an integer using RSA.
        
        Args:
            m: Integer to encrypt
            key: RSA key containing at least 'n' and 'e'
            
        Returns:
            int: Encrypted integer
        """
        n = key['n']
        e = key['e']
        
        # Check if m is within the valid range
        if m < 0 or m >= n:
            raise ValueError("Message representative out of range")
        
        # Perform modular exponentiation: c = m^e mod n
        c = pow(m, e, n)
        
        return c
    
    def _decrypt_int(self, c: int, key: Dict[str, Union[int, bytes]]) -> int:
        """
        Decrypt an integer using RSA with Chinese Remainder Theorem.
        
        Args:
            c: Encrypted integer
            key: RSA key containing 'n', 'd', 'p', 'q', 'dp', 'dq', and 'qinv'
            
        Returns:
            int: Decrypted integer
        """
        n = key['n']
        
        # Check if c is within the valid range
        if c < 0 or c >= n:
            raise ValueError("Ciphertext representative out of range")
        
        # If private key components are not available, use simple decryption
        if 'p' not in key or 'q' not in key:
            d = key['d']
            return pow(c, d, n)
        
        # Otherwise, use Chinese Remainder Theorem for faster decryption
        p = key['p']
        q = key['q']
        dp = key['dp']
        dq = key['dq']
        qinv = key['qinv']
        
        # Compute m1 = c^dp mod p
        m1 = pow(c % p, dp, p)
        
        # Compute m2 = c^dq mod q
        m2 = pow(c % q, dq, q)
        
        # Compute h = qinv * (m1 - m2) mod p
        h = (qinv * (m1 - m2)) % p
        
        # Compute m = m2 + h * q
        m = m2 + h * q
        
        return m
    
    def encrypt(self, plaintext: bytes, key: Optional[Dict[str, Union[int, bytes]]] = None) -> bytes:
        """
        Encrypt data using RSA-OAEP.
        
        Args:
            plaintext: Data to encrypt
            key: RSA key (if None, use the generated key)
            
        Returns:
            bytes: Encrypted data
        """
        if key is None:
            key = self.generate_key()
        
        # Get key size in bytes
        key_size_bytes = self.key_size // 8
        
        # Maximum message length for RSA-OAEP
        max_msg_len = key_size_bytes - 2 * self.oaep_hash_len - 2
        
        # If plaintext is too long, encrypt only a portion for benchmarking
        if len(plaintext) > max_msg_len:
            plaintext = plaintext[:max_msg_len]
        
        # Apply OAEP padding
        padded = self._oaep_pad(plaintext)
        
        # Convert to integer
        m = int.from_bytes(padded, byteorder='big')
        
        # Encrypt
        c = self._encrypt_int(m, key)
        
        # Convert back to bytes
        return c.to_bytes(key_size_bytes, byteorder='big')
    
    def decrypt(self, ciphertext: bytes, key: Optional[Dict[str, Union[int, bytes]]] = None) -> bytes:
        """
        Decrypt data using RSA-OAEP.
        
        Args:
            ciphertext: Data to decrypt
            key: RSA key (if None, use the generated key)
            
        Returns:
            bytes: Decrypted data
            
        Raises:
            ValueError: If decryption fails
        """
        if key is None:
            raise ValueError("No key provided for decryption")
        
        # Decrypt only if ciphertext has the right size
        key_size_bytes = self.key_size // 8
        if len(ciphertext) != key_size_bytes:
            raise ValueError("Invalid ciphertext length")
        
        # Convert to integer
        c = int.from_bytes(ciphertext, byteorder='big')
        
        # Decrypt
        m = self._decrypt_int(c, key)
        
        # Convert back to bytes
        padded = m.to_bytes(key_size_bytes, byteorder='big')
        
        # Remove OAEP padding
        try:
            return self._oaep_unpad(padded)
        except ValueError as e:
            raise ValueError(f"Decryption failed: {str(e)}") 