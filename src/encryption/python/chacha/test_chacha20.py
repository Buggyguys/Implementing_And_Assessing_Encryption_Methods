#!/usr/bin/env python3
"""
CryptoBench Pro - ChaCha20 Test Script
Test both standard and custom ChaCha20 implementations.
"""

import os
import sys
import time
import random
import binascii

# Add the parent directory to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../..')))

# Import the implementations
try:
    from encryption.python.chacha.implementation import (
        ChaCha20Implementation,
        create_custom_chacha20_implementation,
        create_stdlib_chacha20_implementation
    )
except ImportError:
    from src.encryption.python.chacha.implementation import (
        ChaCha20Implementation,
        create_custom_chacha20_implementation,
        create_stdlib_chacha20_implementation
    )

def test_chacha20_implementation(impl, data_size=1024):
    """Test a ChaCha20 implementation with given settings."""
    impl_type = "Custom" if impl.is_custom else "Standard"
    
    print(f"\nTesting {impl_type} ChaCha20 implementation:")
    
    # Generate random data for encryption
    data = os.urandom(data_size)
    print(f"Original data ({len(data)} bytes): {binascii.hexlify(data[:24]).decode()}...")
    
    # Generate a key
    start_time = time.time()
    key = impl.generate_key()
    key_time = time.time() - start_time
    print(f"Key generation took {key_time * 1000:.2f} ms")
    print(f"Key: {binascii.hexlify(key).decode()}")
    
    # Encrypt
    start_time = time.time()
    ciphertext = impl.encrypt(data, key)
    encrypt_time = time.time() - start_time
    print(f"Encryption took {encrypt_time * 1000:.2f} ms")
    print(f"Ciphertext ({len(ciphertext)} bytes): {binascii.hexlify(ciphertext[:24]).decode()}...")
    
    # Decrypt
    start_time = time.time()
    decrypted = impl.decrypt(ciphertext, key)
    decrypt_time = time.time() - start_time
    print(f"Decryption took {decrypt_time * 1000:.2f} ms")
    
    # Verify
    if decrypted == data:
        print("✅ Decryption successful - data matches original")
    else:
        print("❌ Decryption failed - data does not match original!")
        print(f"Decrypted ({len(decrypted)} bytes): {binascii.hexlify(decrypted[:24]).decode()}...")

def run_tests(data_size=1024 * 1024):  # Default to 1MB
    """Run tests for various ChaCha20 configurations."""
    print("ChaCha20 Implementation Tests")
    print("-" * 50)
    
    # Check if PyCryptodome is available for standard implementations
    try:
        from Crypto.Cipher import ChaCha20
        standard_available = True
    except ImportError:
        standard_available = False
        print("PyCryptodome is not installed - standard implementations will be skipped")
        print("To install: pip install pycryptodome")
    
    if standard_available:
        # Test standard ChaCha20
        std_chacha20 = create_stdlib_chacha20_implementation()
        test_chacha20_implementation(std_chacha20, data_size=data_size)
    
    # Test custom ChaCha20
    custom_chacha20 = create_custom_chacha20_implementation()
    test_chacha20_implementation(custom_chacha20, data_size=data_size)
    
    print("\nAll tests completed!")

if __name__ == "__main__":
    # Default to 1MB data size, or use command line argument if provided
    data_size = 1024 * 1024  # 1MB
    if len(sys.argv) > 1:
        try:
            data_size = int(sys.argv[1])
        except ValueError:
            print(f"Invalid data size: {sys.argv[1]}. Using default 1MB.")
    
    run_tests(data_size=data_size) 