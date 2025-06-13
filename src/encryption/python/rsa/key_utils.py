import os
import random
import hashlib
from Crypto.PublicKey import RSA

def is_prime(n, k=5):
    
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    
    # find r, d such that n = 2^r * d + 1 where d is odd
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # witness loop
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
   
    # random odd number of the specified bit length
    lower = 1 << (bits - 1)
    upper = (1 << bits) - 1
    
    while True:
        p = random.randrange(lower, upper) | 1  # ensure it's odd
        if is_prime(p):
            return p

def mod_inverse(a, m):
    
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def extended_gcd(a, b):
    
    if a == 0:
        return b, 0, 1
    else:
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

def generate_key_pair(key_size=2048):
   
    # validate key size
    if key_size not in (1024, 2048, 3072, 4096):
        raise ValueError(f"Invalid key size: {key_size} bits. Must be 1024, 2048, 3072, or 4096 bits.")
    
    # generate RSA key pair
    key = RSA.generate(key_size)
    return key.publickey(), key

def generate_custom_key_pair(key_size=2048):
    
    # validate key size
    if key_size not in (1024, 2048, 3072, 4096):
        raise ValueError(f"Invalid key size: {key_size} bits. Must be 1024, 2048, 3072, or 4096 bits.")
    
    # generate primes of bit_size/2 each
    prime_size = key_size // 2
    
    # generate two distinct prime numbers
    p = generate_prime(prime_size)
    q = generate_prime(prime_size)
    
    # ensure p and q are different
    while p == q:
        q = generate_prime(prime_size)
    
    # compute n = p * q
    n = p * q
    
    # compute Euler's totient function: φ(n) = (p-1) * (q-1)
    phi = (p - 1) * (q - 1)
    
    # choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
    e = 65537  # common value for e

    # compute d such that (d * e) % φ(n) = 1
    d = mod_inverse(e, phi)
    
    # public key: (n, e)
    public_key = {
        'n': n,
        'e': e
    }
    
    # private key: (n, d)
    private_key = {
        'n': n,
        'd': d,
        'p': p,
        'q': q
    }
    
    return public_key, private_key

def extract_key_components(public_key, private_key, is_custom=False):
    
    if is_custom:
        # custom implementation keys are already dictionaries
        n = public_key['n']
        e = public_key['e']
        d = private_key['d']
    else:
        # standard library keys are PyCryptodome objects
        n = public_key.n
        e = public_key.e
        d = private_key.d
    
    return n, e, d

def save_keys_to_files(public_key, private_key, is_custom=False, prefix="rsa_key"):
    
    if is_custom:
        # save custom keys as JSON
        import json
        public_key_file = f"{prefix}_public.json"
        private_key_file = f"{prefix}_private.json"
        
        with open(public_key_file, 'w') as f:
            json.dump(public_key, f)
        
        with open(private_key_file, 'w') as f:
            json.dump(private_key, f)
    else:
        # save standard library keys in PEM format
        public_key_file = f"{prefix}_public.pem"
        private_key_file = f"{prefix}_private.pem"
        
        with open(public_key_file, 'wb') as f:
            f.write(public_key.export_key('PEM'))
        
        with open(private_key_file, 'wb') as f:
            f.write(private_key.export_key('PEM'))
    
    return public_key_file, private_key_file

def load_keys_from_files(public_key_file, private_key_file, is_custom=False):
    
    if is_custom:
        # load custom keys from JSON
        import json
        
        with open(public_key_file, 'r') as f:
            public_key = json.load(f)
        
        with open(private_key_file, 'r') as f:
            private_key = json.load(f)
    else:
        # load standard library keys from PEM format
        with open(public_key_file, 'rb') as f:
            public_key = RSA.import_key(f.read())
        
        with open(private_key_file, 'rb') as f:
            private_key = RSA.import_key(f.read())
    
    return public_key, private_key 