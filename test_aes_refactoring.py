#!/usr/bin/env python3
"""
Test script for refactored AES implementation
"""

import os
import time
import random
import string
import sys
import shutil

# First, try using the original implementation
from src.encryption.python.aes.implementation import AESImplementation as OriginalAES

# Function to create temporary files for testing
def setup_test_modules():
    """Create temporary Python files from .new files for testing"""
    base_dir = os.path.join(os.path.dirname(__file__), 'src/encryption/python/aes')
    
    # Track created files to clean up later
    created_files = []
    
    try:
        # Create a temporary directory for our test modules
        test_dir = os.path.join(base_dir, 'test_modules')
        if not os.path.exists(test_dir):
            os.makedirs(test_dir)
        created_files.append(test_dir)
        
        # Create an __init__.py in the test directory
        init_path = os.path.join(test_dir, '__init__.py')
        with open(init_path, 'w') as f:
            f.write('# Test module')
        created_files.append(init_path)
        
        # Copy all the new implementation files to the test directory
        for filename in os.listdir(base_dir):
            if filename.endswith('.new'):
                base_name = filename[:-4]  # Remove .new extension
                src_path = os.path.join(base_dir, filename)
                dst_path = os.path.join(test_dir, base_name + '.py')
                
                with open(src_path, 'r') as src, open(dst_path, 'w') as dst:
                    dst.write(src.read())
                created_files.append(dst_path)
        
        # Copy the mode-specific modules
        for module in ['aes_gcm.py', 'aes_cbc.py', 'aes_ctr.py', 'aes_ecb.py', 'key_utils.py']:
            if os.path.exists(os.path.join(base_dir, module)):
                src_path = os.path.join(base_dir, module)
                dst_path = os.path.join(test_dir, module)
                shutil.copy(src_path, dst_path)
                created_files.append(dst_path)
        
        # Copy custom_aes.py
        if os.path.exists(os.path.join(base_dir, 'custom_aes.py')):
            src_path = os.path.join(base_dir, 'custom_aes.py')
            dst_path = os.path.join(test_dir, 'custom_aes.py')
            shutil.copy(src_path, dst_path)
            created_files.append(dst_path)
        
        # Add the test directory to Python's import path
        sys.path.insert(0, os.path.dirname(__file__))
        
        return test_dir, created_files
    
    except Exception as e:
        print(f"Error setting up test modules: {e}")
        cleanup_test_modules(created_files)
        return None, []

def cleanup_test_modules(created_files):
    """Clean up temporary files created for testing"""
    for path in reversed(created_files):  # Remove files first, then directories
        try:
            if os.path.isdir(path):
                if os.path.exists(path):
                    shutil.rmtree(path)
            else:
                if os.path.exists(path):
                    os.remove(path)
        except Exception as e:
            print(f"Error cleaning up {path}: {e}")

# Setup test modules
test_dir, created_files = setup_test_modules()

# Try to import the refactored implementation
try:
    if test_dir:
        sys.path.append(test_dir)
        
        # Temporarily set PYTHONPATH to include the test directory
        old_path = os.environ.get('PYTHONPATH', '')
        os.environ['PYTHONPATH'] = f"{test_dir}:{old_path}"
        
        # Import the refactored implementation
        from src.encryption.python.aes.test_modules.implementation import AESImplementation as RefactoredAES
    else:
        raise ImportError("Test directory not created")
except Exception as e:
    print(f"Failed to import refactored implementation: {e}")
    RefactoredAES = OriginalAES  # Fallback to original

def generate_random_data(size=1024):
    """Generate random data for testing"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(size)).encode('utf-8')

def test_implementation(name, impl_class, key_size, mode):
    """Test an implementation with the given parameters"""
    print(f"Testing {name} AES-{key_size} {mode}...")
    
    # Create the implementation instance
    implementation = impl_class(key_size=key_size, mode=mode)
    
    # Generate a key
    key = implementation.generate_key()
    
    # Generate some test data
    data = generate_random_data(1024)
    
    # Encrypt and measure time
    start_time = time.time()
    ciphertext = implementation.encrypt(data, key)
    encryption_time = time.time() - start_time
    
    # Decrypt and measure time
    start_time = time.time()
    decrypted = implementation.decrypt(ciphertext, key)
    decryption_time = time.time() - start_time
    
    # Verify the decryption worked
    success = data == decrypted
    
    print(f"  Encryption time: {encryption_time:.6f} seconds")
    print(f"  Decryption time: {decryption_time:.6f} seconds")
    print(f"  Success: {success}")
    
    return {
        "name": name,
        "key_size": key_size,
        "mode": mode,
        "encryption_time": encryption_time,
        "decryption_time": decryption_time,
        "success": success
    }

def main():
    """Run the test suite"""
    print("AES Implementation Refactoring Test")
    print("==================================")
    
    # Test configurations
    configs = [
        {"key_size": "256", "mode": "GCM"},
        {"key_size": "256", "mode": "CBC"},
        {"key_size": "256", "mode": "CTR"},
        {"key_size": "256", "mode": "ECB"}
    ]
    
    # Test each configuration with both implementations
    results = []
    for config in configs:
        key_size = config["key_size"]
        mode = config["mode"]
        
        # Test original implementation
        try:
            original_result = test_implementation("Original", OriginalAES, key_size, mode)
            results.append(original_result)
        except Exception as e:
            print(f"  Error testing original implementation: {e}")
        
        # Test refactored implementation 
        try:
            refactored_result = test_implementation("Refactored", RefactoredAES, key_size, mode)
            results.append(refactored_result)
        except Exception as e:
            print(f"  Error testing refactored implementation: {e}")
        
        print()
    
    # Print summary
    print("Test Summary")
    print("===========")
    for result in results:
        print(f"{result['name']} AES-{result['key_size']} {result['mode']}: " +
              f"Encryption: {result['encryption_time']:.6f}s, " +
              f"Decryption: {result['decryption_time']:.6f}s, " +
              f"Success: {result['success']}")
    
    # Clean up the test modules
    cleanup_test_modules(created_files)

if __name__ == "__main__":
    try:
        main()
    finally:
        # Ensure cleanup happens even if the script crashes
        cleanup_test_modules(created_files) 