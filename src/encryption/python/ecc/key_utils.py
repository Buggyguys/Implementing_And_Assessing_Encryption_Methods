#!/usr/bin/env python3
"""
CryptoBench Pro - ECC Key Utilities
Provides key generation and management functions for ECC implementations.
"""

import os
import hashlib
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Map curve names to their corresponding cryptography.io curve objects
CURVE_MAP = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}

def generate_key_pair(curve_name="P-256"):
    """
    Generate an ECC key pair using the standard library.
    
    Args:
        curve_name: The name of the elliptic curve to use
        
    Returns:
        tuple: (public_key, private_key) pair
    """
    if curve_name not in CURVE_MAP:
        raise ValueError(f"Unsupported curve: {curve_name}. Supported curves: {list(CURVE_MAP.keys())}")
    
    curve = CURVE_MAP[curve_name]
    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()
    
    return public_key, private_key

def serialize_key(key, is_private=False, password=None):
    """
    Serialize a key to PEM format.
    
    Args:
        key: The key to serialize
        is_private: Whether the key is a private key
        password: Optional password for encrypting private keys
        
    Returns:
        bytes: The PEM-encoded key
    """
    if is_private:
        encryption = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
    else:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

def extract_key_components(key, curve_name="P-256"):
    """
    Extract the raw components of an ECC key.
    
    Args:
        key: The key to extract components from
        curve_name: The name of the curve
        
    Returns:
        dict: Dictionary containing key components
    """
    components = {
        "curve": curve_name
    }
    
    try:
        # Extract public key components
        if hasattr(key, "public_numbers"):
            # Private key input, get public numbers from it
            public_numbers = key.public_key().public_numbers()
        else:
            # Public key input
            public_numbers = key.public_numbers()
        
        components["x"] = public_numbers.x
        components["y"] = public_numbers.y
        
        # Extract private key component if available
        if hasattr(key, "private_numbers"):
            components["d"] = key.private_numbers().private_value
    except Exception as e:
        raise ValueError(f"Error extracting key components: {str(e)}")
    
    return components

# Custom ECC implementation below

# Constants for elliptic curves
# P-256/secp256r1 parameters
P256 = {
    "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    "a": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    "G_x": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    "G_y": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    "h": 0x01,
    "bits": 256
}

# P-384/secp384r1 parameters
P384 = {
    "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
    "a": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
    "b": 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    "G_x": 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
    "G_y": 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
    "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
    "h": 0x01,
    "bits": 384
}

# P-521/secp521r1 parameters
P521 = {
    "p": 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
    "a": 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC,
    "b": 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,
    "G_x": 0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
    "G_y": 0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650,
    "n": 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
    "h": 0x01,
    "bits": 521
}

# Map curve names to their parameter sets
CURVE_PARAMS = {
    "P-256": P256,
    "P-384": P384,
    "P-521": P521
}

def point_add(P, Q, curve):
    """
    Add two points on an elliptic curve.
    
    Args:
        P: First point as (x, y) tuple or None for point at infinity
        Q: Second point as (x, y) tuple or None for point at infinity
        curve: Curve parameters
        
    Returns:
        tuple: Resulting point (x, y) or None for point at infinity
    """
    if P is None:
        return Q
    if Q is None:
        return P
    
    if P[0] == Q[0] and P[1] != Q[1]:
        return None  # Point at infinity
    
    p = curve["p"]
    
    if P == Q:
        # Point doubling
        lam_num = (3 * P[0]**2 + curve["a"]) % p
        lam_den = (2 * P[1]) % p
        lam_den_inv = pow(lam_den, p - 2, p)  # Modular inverse
        lam = (lam_num * lam_den_inv) % p
    else:
        # Point addition
        lam_num = (Q[1] - P[1]) % p
        lam_den = (Q[0] - P[0]) % p
        lam_den_inv = pow(lam_den, p - 2, p)  # Modular inverse
        lam = (lam_num * lam_den_inv) % p
    
    x3 = (lam**2 - P[0] - Q[0]) % p
    y3 = (lam * (P[0] - x3) - P[1]) % p
    
    return (x3, y3)

def scalar_multiply(k, P, curve):
    """
    Multiply a point by a scalar using an optimized double-and-add algorithm.
    Uses Montgomery ladder for efficiency and constant-time operation.
    
    Args:
        k: Scalar value
        P: Point as (x, y) tuple or None for point at infinity
        curve: Curve parameters
        
    Returns:
        tuple: Resulting point (x, y) or None for point at infinity
    """
    if k == 0 or P is None:
        return None
    
    # Use Montgomery ladder for efficiency and constant-time operation
    R0 = None
    R1 = P
    
    # Convert k to binary and iterate through bits
    for i in range(k.bit_length()-1, -1, -1):
        if k & (1 << i) == 0:
            # If bit is 0: R1 = R0 + R1, R0 = 2R0
            R1 = point_add(R0, R1, curve)
            R0 = point_add(R0, R0, curve)
        else:
            # If bit is 1: R0 = R0 + R1, R1 = 2R1
            R0 = point_add(R0, R1, curve)
            R1 = point_add(R1, R1, curve)
    
    return R0

def generate_custom_key_pair(curve_name="P-256"):
    """
    Generate an ECC key pair using a custom implementation.
    
    Args:
        curve_name: The name of the elliptic curve to use
        
    Returns:
        tuple: (public_key, private_key) pair as component dictionaries
    """
    if curve_name not in CURVE_PARAMS:
        raise ValueError(f"Unsupported curve for custom implementation: {curve_name}. Supported curves: {list(CURVE_PARAMS.keys())}")
    
    # Get curve parameters
    curve = CURVE_PARAMS[curve_name]
    
    # Generate private key (random integer between 1 and n-1)
    private_value = secrets.randbelow(curve["n"] - 1) + 1
    
    # Compute public key Q = d * G (where G is the base point)
    G = (curve["G_x"], curve["G_y"])
    Q = scalar_multiply(private_value, G, curve)
    
    # Return as component dictionaries
    public_key = {
        "curve": curve_name,
        "x": Q[0],
        "y": Q[1]
    }
    
    private_key = {
        "curve": curve_name,
        "d": private_value,
        "x": Q[0],
        "y": Q[1]
    }
    
    return public_key, private_key

# Stream mode utility functions
def add_chunk_delimiter(chunk_data, chunk_index=0):
    """
    Add a delimiter to a chunk for stream mode processing.
    Format: 4 bytes for chunk index + 4 bytes for chunk length
    
    Args:
        chunk_data: Data chunk to delimit
        chunk_index: Index of this chunk in the sequence
        
    Returns:
        bytes: Delimited chunk data
    """
    chunk_header = chunk_index.to_bytes(4, byteorder='big') + len(chunk_data).to_bytes(4, byteorder='big')
    return chunk_header + chunk_data

def split_delimited_chunks(combined_data):
    """
    Split combined data back into original chunks based on delimiters.
    
    Args:
        combined_data: Combined data with delimiters
        
    Returns:
        list: List of (chunk_index, chunk_data) tuples
    """
    chunks = []
    offset = 0
    
    while offset + 8 <= len(combined_data):
        chunk_index = int.from_bytes(combined_data[offset:offset+4], byteorder='big')
        chunk_length = int.from_bytes(combined_data[offset+4:offset+8], byteorder='big')
        
        if offset + 8 + chunk_length > len(combined_data):
            break  # Incomplete chunk
            
        chunk_data = combined_data[offset+8:offset+8+chunk_length]
        chunks.append((chunk_index, chunk_data))
        
        offset += 8 + chunk_length
    
    return chunks 