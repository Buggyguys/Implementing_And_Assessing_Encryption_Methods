#!/usr/bin/env python3
"""
CryptoBench Pro - Python Core Runner

This module implements the benchmarking of handmade cryptographic algorithms in Python.
It handles test execution, metric collection, and result aggregation.
"""

import os
import sys
import json
import time
import psutil
import argparse
import logging
import statistics
from datetime import datetime

# Ensure src is in the path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Import handmade encryption implementations
from src.encryption.python.aes import AESHandmade
from src.encryption.python.chacha20 import ChaCha20Handmade
from src.encryption.python.rsa import RSAHandmade
from src.encryption.python.ecc import ECCHandmade
from src.encryption.python.mlkem import MLKEMHandmade

# Import standard library implementations
from src.encryption.python.stdlib_implementations import (
    AESStdLib, ChaCha20StdLib, RSAStdLib, ECCStdLib, MLKEMStdLib, MLKEM_AVAILABLE
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("Python-Runner")

# Check if cryptography is available
try:
    import cryptography
    STDLIB_AVAILABLE = True
except ImportError:
    logger.warning("Standard library 'cryptography' not available. Stdlib comparisons will be skipped.")
    logger.warning("To enable stdlib comparisons, install the cryptography package:")
    logger.warning("    pip install cryptography")
    STDLIB_AVAILABLE = False


class PythonCoreRunner:
    """Implements the Python core runner for cryptographic benchmarking."""

    def __init__(self, session_json_path):
        """Initialize the runner with the session configuration."""
        with open(session_json_path, 'r') as f:
            self.session_config = json.load(f)
        
        self.encryption_methods = self.session_config.get("encryption_methods", {})
        self.test_parameters = self.session_config.get("test_parameters", {})
        self.session_info = self.session_config.get("session_info", {})
        self.dataset_info = self.session_config.get("dataset_info", {})
        self.pc_specifications = self.session_config.get("pc_specifications", {})
        
        self.dataset_path = self.test_parameters.get("dataset_path", "")
        # RAM limit is disabled by default now (0 means no limit)
        self.ram_limit = 0
        self.iterations = self.test_parameters.get("iterations", 5)
        self.include_stdlibs = self.test_parameters.get("include_stdlibs", False)
        
        self.session_dir = self.session_info.get("session_dir", "")
        self.results_dir = os.path.join(self.session_dir, "results")
        
        # Results storage
        self.python_overall_results = []
        
        # Ensure results directory exists
        os.makedirs(self.results_dir, exist_ok=True)
    
    def run_benchmark(self):
        """Execute benchmarks for all enabled encryption methods."""
        logger.info("Starting Python benchmarking")
        
        # Disable stdlib comparison if cryptography module is not available
        if self.include_stdlibs and not STDLIB_AVAILABLE:
            logger.warning("Standard library comparison requested but cryptography module not available.")
            logger.warning("Disabling standard library comparison.")
            self.include_stdlibs = False
        
        # Check if dataset exists or create a test file
        if not self.dataset_path or not os.path.exists(self.dataset_path):
            logger.warning(f"Dataset not found at: {self.dataset_path}")
            logger.info("Creating a temporary test file for benchmarking")
            
            # Create a temporary test file with random data
            test_file_path = os.path.join(self.session_dir, "test_data.bin")
            with open(test_file_path, 'wb') as f:
                # Generate 100KB of random data
                f.write(os.urandom(1024 * 100))
            
            self.dataset_path = test_file_path
            logger.info(f"Using test file at: {self.dataset_path}")
        
        # Limit dataset size to avoid excessive processing times
        dataset_size = os.path.getsize(self.dataset_path)
        MAX_DATASET_SIZE = 50 * 1024 * 1024  # 50MB maximum for testing
        
        if dataset_size > MAX_DATASET_SIZE:
            logger.warning(f"Dataset is very large ({dataset_size/1024/1024:.2f} MB). Using a subset of the data.")
            # Create a temporary file with a subset of the data
            temp_dataset_path = os.path.join(self.session_dir, "test_data_subset.bin")
            with open(self.dataset_path, 'rb') as src, open(temp_dataset_path, 'wb') as dest:
                # Copy the first MAX_DATASET_SIZE bytes
                dest.write(src.read(MAX_DATASET_SIZE))
            
            self.dataset_path = temp_dataset_path
            logger.info(f"Using reduced dataset at: {self.dataset_path} ({MAX_DATASET_SIZE/1024/1024:.2f} MB)")
        
        # Process each encryption method
        algo_count = 0
        for algo_name, algo_params in self.encryption_methods.items():
            # Handle different ways the enabled flag might be set
            is_enabled = False
            if isinstance(algo_params, dict):
                # It could be "enabled", "is_enabled", or just a boolean
                if "enabled" in algo_params:
                    is_enabled = algo_params["enabled"]
                elif "is_enabled" in algo_params:
                    is_enabled = algo_params["is_enabled"]
                else:
                    # Look for any key that might indicate enabled state
                    for key in algo_params:
                        if "enable" in key.lower():
                            is_enabled = algo_params[key]
                            break
            else:
                # Direct boolean
                is_enabled = bool(algo_params)
            
            if is_enabled:
                algo_count += 1
                logger.info(f"Benchmarking {algo_name} ({algo_count}/{len(self.encryption_methods)})")
                self._benchmark_algorithm(algo_name, algo_params)
            else:
                logger.info(f"Skipping {algo_name} (not enabled)")
        
        # Generate final results
        self._generate_results()
        logger.info("Python benchmarking completed")
        return True
    
    def _benchmark_algorithm(self, algo_name, algo_params):
        """Benchmark a specific encryption algorithm."""
        logger.info(f"Starting tests for {algo_name}...")
        
        current_algo_results_list_self = []
        current_algo_results_list_stdlib = []
        
        # Get handmade implementation
        handmade_impl = self._get_handmade_implementation(algo_name, algo_params)
        if handmade_impl is None:
            logger.error(f"No handmade implementation available for {algo_name}")
            return
        
        # Get stdlib implementation if requested
        stdlib_impl = None
        if self.include_stdlibs and STDLIB_AVAILABLE:
            try:
                stdlib_impl = self._get_stdlib_implementation(algo_name, algo_params)
                if stdlib_impl is None:
                    logger.warning(f"No stdlib implementation available for {algo_name}")
            except Exception as e:
                logger.warning(f"Error setting up stdlib implementation for {algo_name}: {str(e)}")
                stdlib_impl = None
        elif self.include_stdlibs:
            logger.warning("Standard libraries requested but not available. Install 'cryptography' package.")
        
        # Run iterations
        for iter_num in range(self.iterations):
            logger.info(f"{algo_name} - Iteration {iter_num+1} of {self.iterations}")
            
            # Run handmade implementation
            try:
                iter_metrics_self = self._run_iteration(algo_name, algo_params, handmade_impl, "self")
                current_algo_results_list_self.append(iter_metrics_self)
            except Exception as e:
                logger.error(f"Error running handmade {algo_name} implementation: {str(e)}")
                import traceback
                traceback.print_exc()
            
            # Run stdlib implementation if available
            if stdlib_impl and self.include_stdlibs:
                try:
                    logger.info(f"{algo_name} - Iteration {iter_num+1} - Standard Library")
                    iter_metrics_stdlib = self._run_iteration(algo_name, algo_params, stdlib_impl, "stdlib")
                    current_algo_results_list_stdlib.append(iter_metrics_stdlib)
                except Exception as e:
                    logger.error(f"Error running stdlib {algo_name} implementation: {str(e)}")
                    import traceback
                    traceback.print_exc()
        
        # Aggregate results
        if current_algo_results_list_self:
            self._aggregate_algorithm_results(
                algo_name, 
                algo_params, 
                current_algo_results_list_self, 
                current_algo_results_list_stdlib
            )
        else:
            logger.warning(f"No results to aggregate for {algo_name}")
    
    def _get_handmade_implementation(self, algo_name, algo_params):
        """Get the handmade implementation for the specified algorithm."""
        try:
            if algo_name == "aes":
                return AESHandmade(key_size=algo_params.get("key_size", "128"))
            elif algo_name == "chacha20":
                return ChaCha20Handmade()
            elif algo_name == "rsa":
                return RSAHandmade(key_size=algo_params.get("key_size", "2048"))
            elif algo_name == "ecc":
                return ECCHandmade(curve=algo_params.get("curve", "P-256"))
            elif algo_name == "mlkem":
                return MLKEMHandmade(param_set=algo_params.get("param_set", "ML-KEM-512"))
            else:
                logger.error(f"Unknown algorithm: {algo_name}")
                return None
        except Exception as e:
            logger.error(f"Error initializing handmade {algo_name}: {str(e)}")
            return None
    
    def _get_stdlib_implementation(self, algo_name, algo_params):
        """Get the standard library implementation for the specified algorithm."""
        try:
            if algo_name == "aes":
                return AESStdLib(key_size=algo_params.get("key_size", "128"))
            elif algo_name == "chacha20":
                return ChaCha20StdLib()
            elif algo_name == "rsa":
                return RSAStdLib(key_size=algo_params.get("key_size", "2048"))
            elif algo_name == "ecc":
                return ECCStdLib(curve=algo_params.get("curve", "P-256"))
            elif algo_name == "mlkem" and MLKEM_AVAILABLE:
                return MLKEMStdLib(param_set=algo_params.get("param_set", "ML-KEM-512"))
            else:
                return None
        except Exception as e:
            logger.error(f"Error initializing stdlib {algo_name}: {str(e)}")
            return None
    
    def _run_iteration(self, algo_name, algo_params, implementation, impl_type):
        """Run a single benchmark iteration for an algorithm implementation."""
        metrics = {
            "algo_name": algo_name,
            "implementation": impl_type,
            "correctness_passed": True,
            "metrics": {}
        }
        
        # Open the dataset file
        with open(self.dataset_path, 'rb') as f:
            # Generate key
            key, key_metrics = self._generate_key(implementation, impl_type)
            metrics["metrics"].update(key_metrics)
            
            # Encrypt data
            ciphertext, encrypt_metrics = self._encrypt_data(f, implementation, key, impl_type)
            metrics["metrics"].update(encrypt_metrics)
            
            # Store ciphertext size
            metrics["metrics"]["ciphertext_size_bytes"] = len(ciphertext) if ciphertext else 0
            
            # Reset file pointer for comparison
            f.seek(0)
            original_data = f.read()
            
            # Decrypt data and verify
            decrypted, decrypt_metrics = self._decrypt_data(ciphertext, implementation, key, impl_type)
            metrics["metrics"].update(decrypt_metrics)
            
            # Check correctness
            if decrypted is None:
                logger.error(f"Decryption failed for {algo_name} ({impl_type})")
                metrics["correctness_passed"] = False
            elif len(decrypted) != len(original_data):
                logger.error(f"Length mismatch: Original {len(original_data)}, Decrypted {len(decrypted)}")
                metrics["correctness_passed"] = False
            elif decrypted != original_data:
                logger.error(f"Content mismatch for {algo_name} ({impl_type})")
                metrics["correctness_passed"] = False
            
            # Calculate throughput (Mbps)
            data_size_mb = len(original_data) / (1024 * 1024)  # Convert bytes to MB
            encrypt_time_s = metrics["metrics"]["encrypt_wall_time_ms"] / 1000  # Convert ms to s
            decrypt_time_s = metrics["metrics"]["decrypt_wall_time_ms"] / 1000  # Convert ms to s
            
            # Avoid division by zero
            if encrypt_time_s > 0:
                metrics["metrics"]["encrypt_throughput_mbps"] = data_size_mb / encrypt_time_s
            else:
                metrics["metrics"]["encrypt_throughput_mbps"] = 0
                
            if decrypt_time_s > 0:
                metrics["metrics"]["decrypt_throughput_mbps"] = data_size_mb / decrypt_time_s
            else:
                metrics["metrics"]["decrypt_throughput_mbps"] = 0
        
        return metrics
        
    def _generate_key(self, implementation, impl_type):
        """Generate a key for the given implementation."""
        metrics = {}
        
        if impl_type == "self":
            return self._generate_key_handmade(implementation)
        else:
            return self._generate_key_stdlib(implementation)
    
    def _generate_key_handmade(self, implementation):
        """Generate a key for a handmade implementation."""
        metrics = {}
        
        # Measure wall time
        start_wall_time = time.time()
        
        # Measure CPU time
        process = psutil.Process(os.getpid())
        start_cpu_times = process.cpu_times()
        
        # Generate key
        key = implementation.generate_key()
        
        # Measure CPU time again
        end_cpu_times = process.cpu_times()
        
        # Measure wall time again
        end_wall_time = time.time()
        
        # Calculate times
        wall_time_ms = (end_wall_time - start_wall_time) * 1000
        cpu_user_time_s = end_cpu_times.user - start_cpu_times.user
        cpu_system_time_s = end_cpu_times.system - start_cpu_times.system
        
        # Store metrics
        metrics["keygen_wall_time_ms"] = wall_time_ms
        metrics["keygen_cpu_user_time_s"] = cpu_user_time_s
        metrics["keygen_cpu_system_time_s"] = cpu_system_time_s
        
        return key, metrics
    
    def _generate_key_stdlib(self, implementation):
        """Generate a key for a standard library implementation."""
        metrics = {}
        
        # Measure wall time
        start_wall_time = time.time()
        
        # Measure CPU time
        process = psutil.Process(os.getpid())
        start_cpu_times = process.cpu_times()
        
        # Generate key
        key = implementation.generate_key()
        
        # Measure CPU time again
        end_cpu_times = process.cpu_times()
        
        # Measure wall time again
        end_wall_time = time.time()
        
        # Calculate times
        wall_time_ms = (end_wall_time - start_wall_time) * 1000
        cpu_user_time_s = end_cpu_times.user - start_cpu_times.user
        cpu_system_time_s = end_cpu_times.system - start_cpu_times.system
        
        # Store metrics
        metrics["keygen_wall_time_ms"] = wall_time_ms
        metrics["keygen_cpu_user_time_s"] = cpu_user_time_s
        metrics["keygen_cpu_system_time_s"] = cpu_system_time_s
        
        return key, metrics
    
    def _encrypt_data(self, file_obj, implementation, key, impl_type):
        """Encrypt data."""
        metrics = {}
        
        # Read the plaintext data in smaller chunks if it's large
        file_obj.seek(0)
        file_size = os.fstat(file_obj.fileno()).st_size
        
        # For very large files, use a smaller sample
        MAX_DATA_SIZE = 10 * 1024 * 1024  # 10MB maximum for encryption
        if file_size > MAX_DATA_SIZE:
            logger.warning(f"Large file detected ({file_size/1024/1024:.2f} MB). Using first {MAX_DATA_SIZE/1024/1024:.2f} MB for benchmark.")
            plaintext = file_obj.read(MAX_DATA_SIZE)
        else:
            plaintext = file_obj.read()
        
        logger.info(f"Encrypting {len(plaintext)/1024:.2f} KB of data with {impl_type} implementation")
        
        # Measure memory before
        process = psutil.Process(os.getpid())
        peak_memory_before = process.memory_info().rss
        
        # Record context switches before
        if hasattr(process, 'num_ctx_switches'):
            ctx_switches_before = process.num_ctx_switches()
        else:
            ctx_switches_before = None
        
        # Measure wall time
        start_wall_time = time.time()
        
        # Measure CPU time
        start_cpu_times = process.cpu_times()
        
        # Encrypt data - handle large files and pass key parameter
        try:
            # For standard library implementations that might have size limitations,
            # implement chunking for large files
            if impl_type == "stdlib" and len(plaintext) > (2**26):  # Chunk if > 64MB
                logger.info(f"Using chunking for large data ({len(plaintext)/1024/1024:.2f} MB)")
                chunks = []
                chunk_size = 2**20  # 1MB chunks (smaller to avoid memory issues)
                
                for i in range(0, len(plaintext), chunk_size):
                    if i % (10 * chunk_size) == 0:  # Log progress every 10 chunks
                        logger.info(f"Encrypting chunk {i//chunk_size + 1}/{(len(plaintext) + chunk_size - 1)//chunk_size}")
                        
                    chunk = plaintext[i:i+chunk_size]
                    encrypted_chunk = implementation.encrypt(chunk, key)
                    chunks.append(encrypted_chunk)
                
                # Join with a special marker
                ciphertext = b"CHUNKED:" + str(len(chunks)).encode() + b":" + b":".join(chunks)
            else:
                # Normal case: pass the key to encrypt
                ciphertext = implementation.encrypt(plaintext, key)
        except TypeError as e:
            # Fallback for older implementations that don't accept key parameter
            if "missing 1 required positional argument: 'key'" in str(e):
                logger.warning(f"Implementation {impl_type} doesn't accept key in encrypt method, using instance variable")
                # Set the key on the instance instead
                implementation.key = key
                ciphertext = implementation.encrypt(plaintext)
            else:
                raise
        
        # Measure CPU time again
        end_cpu_times = process.cpu_times()
        
        # Measure wall time again
        end_wall_time = time.time()
        
        # Measure memory after
        peak_memory_after = process.memory_info().rss
        
        # Record context switches after
        if hasattr(process, 'num_ctx_switches') and ctx_switches_before:
            ctx_switches_after = process.num_ctx_switches()
            vol_switches = ctx_switches_after.voluntary - ctx_switches_before.voluntary
            invol_switches = ctx_switches_after.involuntary - ctx_switches_before.involuntary
        else:
            vol_switches = 0
            invol_switches = 0
        
        # Calculate times
        wall_time_ms = (end_wall_time - start_wall_time) * 1000
        cpu_user_time_s = end_cpu_times.user - start_cpu_times.user
        cpu_system_time_s = end_cpu_times.system - start_cpu_times.system
        
        # Properly measure memory usage (use max to avoid negative values)
        memory_used = max(0, peak_memory_after - peak_memory_before)
        
        # Store metrics
        metrics["encrypt_wall_time_ms"] = wall_time_ms
        metrics["encrypt_cpu_user_time_s"] = cpu_user_time_s
        metrics["encrypt_cpu_system_time_s"] = cpu_system_time_s
        metrics["encrypt_peak_rss_bytes"] = memory_used
        metrics["encrypt_ctx_switches_voluntary"] = vol_switches
        metrics["encrypt_ctx_switches_involuntary"] = invol_switches
        
        logger.info(f"Encryption completed in {wall_time_ms/1000:.2f} seconds")
        return ciphertext, metrics
    
    def _decrypt_data(self, ciphertext, implementation, key, impl_type):
        """Decrypt data."""
        metrics = {}
        
        if ciphertext is None:
            logger.error("Cannot decrypt: ciphertext is None")
            metrics["decrypt_wall_time_ms"] = 0
            metrics["decrypt_cpu_user_time_s"] = 0
            metrics["decrypt_cpu_system_time_s"] = 0
            metrics["decrypt_peak_rss_bytes"] = 0
            metrics["decrypt_ctx_switches_voluntary"] = 0
            metrics["decrypt_ctx_switches_involuntary"] = 0
            return None, metrics
        
        logger.info(f"Decrypting {len(ciphertext)/1024:.2f} KB of data with {impl_type} implementation")
        
        # Measure memory before
        process = psutil.Process(os.getpid())
        peak_memory_before = process.memory_info().rss
        
        # Record context switches before
        if hasattr(process, 'num_ctx_switches'):
            ctx_switches_before = process.num_ctx_switches()
        else:
            ctx_switches_before = None
        
        # Measure wall time
        start_wall_time = time.time()
        
        # Measure CPU time
        start_cpu_times = process.cpu_times()
        
        # Decrypt data - handle chunked data and pass key parameter
        try:
            # Check if the data was chunked during encryption
            if isinstance(ciphertext, bytes) and ciphertext.startswith(b"CHUNKED:"):
                parts = ciphertext.split(b":", 2)
                num_chunks = int(parts[1].decode())
                chunks_data = parts[2]
                
                logger.info(f"Processing {num_chunks} chunks")
                
                # Split the chunks
                chunk_parts = chunks_data.split(b":", num_chunks)
                
                # Decrypt each chunk
                plaintext_chunks = []
                for i, chunk in enumerate(chunk_parts):
                    if i % 10 == 0:  # Log progress every 10 chunks
                        logger.info(f"Decrypting chunk {i+1}/{num_chunks}")
                    
                    decrypted_chunk = implementation.decrypt(chunk, key)
                    if decrypted_chunk is None:
                        logger.error(f"Failed to decrypt chunk {i+1}")
                        return None, metrics
                    plaintext_chunks.append(decrypted_chunk)
                
                # Combine the decrypted chunks
                plaintext = b"".join(plaintext_chunks)
            else:
                # Normal case: pass the key to decrypt
                plaintext = implementation.decrypt(ciphertext, key)
        except TypeError as e:
            # Fallback for older implementations that don't accept key parameter
            if "missing 1 required positional argument: 'key'" in str(e):
                logger.warning(f"Implementation {impl_type} doesn't accept key in decrypt method, using instance variable")
                # Set the key on the instance instead
                implementation.key = key
                plaintext = implementation.decrypt(ciphertext)
            else:
                raise
        
        # Measure CPU time again
        end_cpu_times = process.cpu_times()
        
        # Measure wall time again
        end_wall_time = time.time()
        
        # Measure memory after
        peak_memory_after = process.memory_info().rss
        
        # Record context switches after
        if hasattr(process, 'num_ctx_switches') and ctx_switches_before:
            ctx_switches_after = process.num_ctx_switches()
            vol_switches = ctx_switches_after.voluntary - ctx_switches_before.voluntary
            invol_switches = ctx_switches_after.involuntary - ctx_switches_before.involuntary
        else:
            vol_switches = 0
            invol_switches = 0
        
        # Calculate times
        wall_time_ms = (end_wall_time - start_wall_time) * 1000
        cpu_user_time_s = end_cpu_times.user - start_cpu_times.user
        cpu_system_time_s = end_cpu_times.system - start_cpu_times.system
        
        # Properly measure memory usage (use max to avoid negative values)
        memory_used = max(0, peak_memory_after - peak_memory_before)
        
        # Store metrics
        metrics["decrypt_wall_time_ms"] = wall_time_ms
        metrics["decrypt_cpu_user_time_s"] = cpu_user_time_s
        metrics["decrypt_cpu_system_time_s"] = cpu_system_time_s
        metrics["decrypt_peak_rss_bytes"] = memory_used
        metrics["decrypt_ctx_switches_voluntary"] = vol_switches
        metrics["decrypt_ctx_switches_involuntary"] = invol_switches
        
        logger.info(f"Decryption completed in {wall_time_ms/1000:.2f} seconds")
        return plaintext, metrics
    
    def _aggregate_algorithm_results(self, algo_name, algo_params, self_results, stdlib_results):
        """Aggregate results for an algorithm across all iterations."""
        result_entry = {
            "algorithm": algo_name,
            "parameters": algo_params.copy()
        }
        
        # Aggregate handmade implementation results
        if self_results:
            self_aggregated = self._calculate_aggregate_metrics(self_results)
            self_aggregated["correctness_all_iterations_passed"] = all(
                result.get("correctness_passed", False) for result in self_results
            )
            result_entry["self_implementation"] = self_aggregated
        
        # Aggregate stdlib implementation results
        if stdlib_results:
            stdlib_aggregated = self._calculate_aggregate_metrics(stdlib_results)
            stdlib_aggregated["correctness_all_iterations_passed"] = all(
                result.get("correctness_passed", False) for result in stdlib_results
            )
            result_entry["stdlib_implementation"] = stdlib_aggregated
        elif self.include_stdlibs:
            result_entry["stdlib_implementation"] = None
        
        self.python_overall_results.append(result_entry)
    
    def _calculate_aggregate_metrics(self, iteration_results):
        """Calculate aggregate statistics across iterations."""
        # Extract all metrics
        metrics = {}
        
        # Get all metric keys from the first result
        if iteration_results and "metrics" in iteration_results[0]:
            metric_keys = iteration_results[0]["metrics"].keys()
            
            # For each metric, calculate mean and standard deviation
            for key in metric_keys:
                values = [result["metrics"].get(key, 0) for result in iteration_results]
                metrics[f"{key}_mean"] = statistics.mean(values)
                
                # Calculate standard deviation (need at least 2 values)
                if len(values) > 1:
                    metrics[f"{key}_stddev"] = statistics.stdev(values)
                else:
                    metrics[f"{key}_stddev"] = 0.0
        
        return {"metrics": metrics}
    
    def _generate_results(self):
        """Generate final results and write to files."""
        timestamp = datetime.now().isoformat()
        
        # Create overall Python results
        python_results = {
            "language": "python",
            "timestamp": timestamp,
            "session_id": self.session_info.get("session_id", "unknown"),
            "pc_specifications": self.pc_specifications,
            "test_parameters": {
                "ram_limit": 0,  # Always set to 0 (no limit) to avoid confusion
                "respect_sentences": self.test_parameters.get("respect_sentences", False),
                "include_stdlibs": self.include_stdlibs,
                "iterations": self.iterations,
                "dataset_path": self.dataset_path
            },
            "results": self.python_overall_results
        }
        
        # Write Python results to file
        python_results_path = os.path.join(self.results_dir, "python_results.json")
        with open(python_results_path, 'w') as f:
            json.dump(python_results, f, indent=2)
        
        logger.info(f"Python results written to: {python_results_path}")
        return python_results_path


def main():
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description="CryptoBench Pro Python Runner")
    parser.add_argument("--config", required=True, help="Path to session JSON configuration")
    args = parser.parse_args()
    
    runner = PythonCoreRunner(args.config)
    success = runner.run_benchmark()
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main()) 