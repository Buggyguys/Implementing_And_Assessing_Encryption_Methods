#!/usr/bin/env python3
"""
CryptoBench Pro - RSA Key Utilities
Provides key generation and management functions for RSA implementations.
"""

import os
import random
import hashlib
from Crypto.PublicKey import RSA

def is_prime(n, k=5):
    """
    Custom Miller-Rabin primality test for large numbers.
    
    Args:
        n: Number to test for primality
        k: Number of test rounds
        
    Returns:
        bool: True if probably prime, False if definitely composite
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    
    # Find r, d such that n = 2^r * d + 1 where d is odd
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
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

def generate_prime(bits):
    """
    Generate a prime number of specified bit length.
    
    Args:
        bits: Bit length of the prime number
        
    Returns:
        int: A prime number of the specified bit length
    """
    # Generate a random odd number of the specified bit length
    lower = 1 << (bits - 1)
    upper = (1 << bits) - 1
    
    while True:
        p = random.randrange(lower, upper) | 1  # Ensure it's odd
        if is_prime(p):
            return p

def mod_inverse(a, m):
    """
    Find the modular multiplicative inverse of a under modulo m.
    
    Args:
        a: Integer to find inverse for
        m: Modulus
        
    Returns:
        int: Modular inverse of a under modulo m
    """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm to find gcd(a, b) and coefficients x, y
    such that ax + by = gcd(a, b).
    
    Args:
        a, b: Integers
        
    Returns:
        tuple: (gcd, x, y)
    """
    if a == 0:
        return b, 0, 1
    else:
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

def generate_key_pair(key_size=2048):
    """
    Generate RSA key pair using the standard library.
    
    Args:
        key_size: Key size in bits (1024, 2048, 3072, or 4096)
        
    Returns:
        tuple: (public_key, private_key) as PyCryptodome key objects
    """
    # Validate key size
    if key_size not in (1024, 2048, 3072, 4096):
        raise ValueError(f"Invalid key size: {key_size} bits. Must be 1024, 2048, 3072, or 4096 bits.")
    
    # Generate RSA key pair
    key = RSA.generate(key_size)
    return key.publickey(), key

def generate_custom_key_pair(key_size=2048):
    """
    Generate RSA key pair using a custom implementation.
    This is a simplified version for demonstration purposes.
    
    Args:
        key_size: Key size in bits (1024, 2048, 3072, or 4096)
        
    Returns:
        tuple: (public_key, private_key) as dictionaries with n, e, d components
    """
    # Validate key size
    if key_size not in (1024, 2048, 3072, 4096):
        raise ValueError(f"Invalid key size: {key_size} bits. Must be 1024, 2048, 3072, or 4096 bits.")
    
    # For custom implementation, we'll generate primes of bit_size/2 each
    prime_size = key_size // 2
    
    # Generate two distinct prime numbers
    p = generate_prime(prime_size)
    q = generate_prime(prime_size)
    
    # Ensure p and q are different
    while p == q:
        q = generate_prime(prime_size)
    
    # Compute n = p * q
    n = p * q
    
    # Compute Euler's totient function: φ(n) = (p-1) * (q-1)
    phi = (p - 1) * (q - 1)
    
    # Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
    e = 65537  # Common value for e, a prime number
    
    # Compute d such that (d * e) % φ(n) = 1
    d = mod_inverse(e, phi)
    
    # Public key: (n, e)
    public_key = {
        'n': n,
        'e': e
    }
    
    # Private key: (n, d)
    private_key = {
        'n': n,
        'd': d,
        'p': p,
        'q': q
    }
    
    return public_key, private_key

def extract_key_components(public_key, private_key, is_custom=False):
    """
    Extract components from key objects for easier handling.
    
    Args:
        public_key: Public key object or dictionary
        private_key: Private key object or dictionary
        is_custom: Whether the keys are from the custom implementation
        
    Returns:
        tuple: (n, e, d) components
    """
    if is_custom:
        # Custom implementation keys are already dictionaries
        n = public_key['n']
        e = public_key['e']
        d = private_key['d']
    else:
        # Standard library keys are PyCryptodome objects
        n = public_key.n
        e = public_key.e
        d = private_key.d
    
    return n, e, d

def save_keys_to_files(public_key, private_key, is_custom=False, prefix="rsa_key"):
    """
    Save keys to files.
    
    Args:
        public_key: Public key object or dictionary
        private_key: Private key object or dictionary
        is_custom: Whether the keys are from the custom implementation
        prefix: Prefix for the key files
        
    Returns:
        tuple: (public_key_file, private_key_file) paths
    """
    if is_custom:
        # Save custom keys as JSON
        import json
        public_key_file = f"{prefix}_public.json"
        private_key_file = f"{prefix}_private.json"
        
        with open(public_key_file, 'w') as f:
            json.dump(public_key, f)
        
        with open(private_key_file, 'w') as f:
            json.dump(private_key, f)
    else:
        # Save standard library keys in PEM format
        public_key_file = f"{prefix}_public.pem"
        private_key_file = f"{prefix}_private.pem"
        
        with open(public_key_file, 'wb') as f:
            f.write(public_key.export_key('PEM'))
        
        with open(private_key_file, 'wb') as f:
            f.write(private_key.export_key('PEM'))
    
    return public_key_file, private_key_file

def load_keys_from_files(public_key_file, private_key_file, is_custom=False):
    """
    Load keys from files.
    
    Args:
        public_key_file: Path to public key file
        private_key_file: Path to private key file
        is_custom: Whether the keys are from the custom implementation
        
    Returns:
        tuple: (public_key, private_key) objects or dictionaries
    """
    if is_custom:
        # Load custom keys from JSON
        import json
        
        with open(public_key_file, 'r') as f:
            public_key = json.load(f)
        
        with open(private_key_file, 'r') as f:
            private_key = json.load(f)
    else:
        # Load standard library keys from PEM format
        with open(public_key_file, 'rb') as f:
            public_key = RSA.import_key(f.read())
        
        with open(private_key_file, 'rb') as f:
            private_key = RSA.import_key(f.read())
    
    return public_key, private_key 