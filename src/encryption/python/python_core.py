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
    
    # Set up memory management for better performance
    gc.disable()  # Disable automatic garbage collection
    
    try:
        # Register all implementations
        implementations = register_all_implementations()
        
        # Run benchmarks
        result = run_benchmarks(config, implementations)
        
        # Final cleanup
        gc.collect()
        
        return result
    except Exception as e:
        logger.error(f"Error in main function: {str(e)}")
        traceback.print_exc()
        return False
    finally:
        # Re-enable garbage collection before exiting
        gc.enable()

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 