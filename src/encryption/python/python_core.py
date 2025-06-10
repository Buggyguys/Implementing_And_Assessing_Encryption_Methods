#!/usr/bin/env python3
"""
CryptoBench Pro - Python Core Benchmarking Module
Implements encryption benchmarking for Python implementations.
"""

import sys
import gc
import argparse
import json
import logging
import traceback
import os
from pathlib import Path

# Add the project root to the Python path
script_dir = Path(__file__).parent.absolute()
project_root = script_dir.parent.parent.parent  # Go up from python/core/ to project root
sys.path.insert(0, str(project_root))

# Setup logging
logger = logging.getLogger("PythonCore")
logger.setLevel(logging.INFO)

if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

# Import core functionality from the refactored modules
from src.encryption.python.core.registry import register_all_implementations
from src.encryption.python.core.benchmark_runner import run_benchmarks

def main(config=None):
    """Main entry point."""
    if not config:
        parser = argparse.ArgumentParser(description="Python Encryption Benchmarking")
        parser.add_argument("config_file", help="Path to the test configuration JSON file")
        args = parser.parse_args()
        
        # Load configuration
        try:
            with open(args.config_file, 'r') as f:
                config = json.load(f)
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
            return False
    
    # Store original garbage collection state
    gc_was_enabled = gc.isenabled()
    
    try:
        # Register all implementations
        implementations = register_all_implementations()
        
        # Run benchmarks
        result = run_benchmarks(config, implementations)
        
        # Force cleanup of any remaining objects
        implementations = None
        config = None
        
        # More aggressive cleanup
        gc.collect()
        gc.collect()  # Run twice to catch circular references
        
        return result
    except Exception as e:
        logger.error(f"Error in main function: {str(e)}")
        traceback.print_exc()
        return False
    finally:
        # Cleanup any remaining variables
        try:
            if 'implementations' in locals():
                implementations = None
            if 'config' in locals():
                config = None
        except:
            pass
        
        # Restore original garbage collection state
        if gc_was_enabled:
            gc.enable()
        else:
            gc.disable()
        
        # Final aggressive cleanup to prevent segfaults
        gc.collect()
        gc.collect()
        
        # Additional cleanup to prevent segmentation faults
        try:
            # Clear any global state that might interfere with subsequent runs
            import threading
            # Clear any thread-local storage that might be holding onto C objects
            if hasattr(threading, 'current_thread'):
                thread = threading.current_thread()
                if hasattr(thread, '__dict__'):
                    thread_dict = thread.__dict__
                    for key in list(thread_dict.keys()):
                        if 'crypto' in key.lower() or 'cipher' in key.lower():
                            try:
                                del thread_dict[key]
                            except:
                                pass
        except:
            pass

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 