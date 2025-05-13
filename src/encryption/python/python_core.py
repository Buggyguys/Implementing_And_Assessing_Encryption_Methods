#!/usr/bin/env python3
"""
CryptoBench Pro - Python Core Benchmarking Module
Implements encryption benchmarking for Python implementations.
"""

import os
import sys
import json
import time
import psutil
import logging
import argparse
from pathlib import Path
from datetime import datetime
import traceback
import gc

# We'll import AES implementations after defining register_implementation
# to avoid circular imports
# from src.encryption.python.aes import AESImplementation
# from src.encryption.python.aes import create_custom_aes_implementation
# from src.encryption.python.aes import create_stdlib_aes_implementation

# Setup logging
logger = logging.getLogger("PythonCore")
logger.setLevel(logging.INFO)

if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

# Dictionary to store implementations
ENCRYPTION_IMPLEMENTATIONS = {}

class BenchmarkMetrics:
    """Collects and stores benchmark metrics for encryption operations."""
    
    def __init__(self, process=None):
        """Initialize with optional psutil process object."""
        self.process = process or psutil.Process()
        self.has_io_counters = hasattr(self.process, "io_counters")
        self.reset()
    
    def reset(self):
        """Reset all metrics."""
        # Key Generation metrics
        self.keygen_wall_time_ms = 0
        self.keygen_cpu_user_time_s = 0
        self.keygen_cpu_system_time_s = 0
        self.keygen_peak_rss_bytes = 0
        self.keygen_ctx_switches_voluntary = 0
        self.keygen_ctx_switches_involuntary = 0
        self.key_components = {}
        
        # Encryption metrics
        self.encrypt_wall_time_ms = 0
        self.encrypt_cpu_user_time_s = 0
        self.encrypt_cpu_system_time_s = 0
        self.encrypt_peak_rss_bytes = 0
        self.encrypt_disk_read_bytes = 0
        self.encrypt_disk_write_bytes = 0
        self.encrypt_ctx_switches_voluntary = 0
        self.encrypt_ctx_switches_involuntary = 0
        self.ciphertext_total_bytes = 0
        
        # Decryption metrics
        self.decrypt_wall_time_ms = 0
        self.decrypt_cpu_user_time_s = 0
        self.decrypt_cpu_system_time_s = 0
        self.decrypt_peak_rss_bytes = 0
        self.decrypt_disk_read_bytes = 0
        self.decrypt_disk_write_bytes = 0
        self.decrypt_ctx_switches_voluntary = 0
        self.decrypt_ctx_switches_involuntary = 0
        self.correctness_passed = False
    
    def measure_keygen(self, key_gen_func, *args, **kwargs):
        """Measure key generation performance."""
        # Get initial metrics
        initial_io = self.process.io_counters() if self.has_io_counters else None
        initial_ctx = self.process.num_ctx_switches()
        initial_cpu_times = self.process.cpu_times()
        
        # Measure wall time
        start_time = time.perf_counter()
        key = key_gen_func(*args, **kwargs)
        end_time = time.perf_counter()
        
        # Calculate metrics
        self.keygen_wall_time_ms = (end_time - start_time) * 1000  # Convert to ms
        
        # Get final metrics
        final_cpu_times = self.process.cpu_times()
        final_ctx = self.process.num_ctx_switches()
        
        # Update CPU time metrics
        self.keygen_cpu_user_time_s = final_cpu_times.user - initial_cpu_times.user
        self.keygen_cpu_system_time_s = final_cpu_times.system - initial_cpu_times.system
        
        # Update context switch metrics
        self.keygen_ctx_switches_voluntary = final_ctx.voluntary - initial_ctx.voluntary
        self.keygen_ctx_switches_involuntary = final_ctx.involuntary - initial_ctx.involuntary
        
        # Record peak memory usage
        self.keygen_peak_rss_bytes = self.process.memory_info().rss
        
        return key
    
    def measure_encrypt(self, encrypt_func, plaintext, key, *args, **kwargs):
        """Measure encryption performance."""
        # Get initial metrics
        initial_io = self.process.io_counters() if self.has_io_counters else None
        initial_ctx = self.process.num_ctx_switches()
        initial_cpu_times = self.process.cpu_times()
        
        # Measure wall time
        start_time = time.perf_counter()
        ciphertext = encrypt_func(plaintext, key, *args, **kwargs)
        end_time = time.perf_counter()
        
        # Calculate metrics
        self.encrypt_wall_time_ms = (end_time - start_time) * 1000  # Convert to ms
        
        # Get final metrics
        final_cpu_times = self.process.cpu_times()
        final_ctx = self.process.num_ctx_switches()
        
        # Update CPU time metrics
        self.encrypt_cpu_user_time_s = final_cpu_times.user - initial_cpu_times.user
        self.encrypt_cpu_system_time_s = final_cpu_times.system - initial_cpu_times.system
        
        # Update IO metrics
        if self.has_io_counters:
            final_io = self.process.io_counters()
            self.encrypt_disk_read_bytes = final_io.read_bytes - initial_io.read_bytes
            self.encrypt_disk_write_bytes = final_io.write_bytes - initial_io.write_bytes
        
        # Update context switch metrics
        self.encrypt_ctx_switches_voluntary = final_ctx.voluntary - initial_ctx.voluntary
        self.encrypt_ctx_switches_involuntary = final_ctx.involuntary - initial_ctx.involuntary
        
        # Record peak memory usage and ciphertext size
        self.encrypt_peak_rss_bytes = self.process.memory_info().rss
        self.ciphertext_total_bytes = len(ciphertext) if hasattr(ciphertext, '__len__') else 0
        
        return ciphertext
    
    def measure_decrypt(self, decrypt_func, ciphertext, key, original_plaintext, *args, **kwargs):
        """Measure decryption performance and verify correctness."""
        # Get initial metrics
        initial_io = self.process.io_counters() if self.has_io_counters else None
        initial_ctx = self.process.num_ctx_switches()
        initial_cpu_times = self.process.cpu_times()
        
        # Measure wall time
        start_time = time.perf_counter()
        decrypted_text = decrypt_func(ciphertext, key, *args, **kwargs)
        end_time = time.perf_counter()
        
        # Calculate metrics
        self.decrypt_wall_time_ms = (end_time - start_time) * 1000  # Convert to ms
        
        # Get final metrics
        final_cpu_times = self.process.cpu_times()
        final_ctx = self.process.num_ctx_switches()
        
        # Update CPU time metrics
        self.decrypt_cpu_user_time_s = final_cpu_times.user - initial_cpu_times.user
        self.decrypt_cpu_system_time_s = final_cpu_times.system - initial_cpu_times.system
        
        # Update IO metrics
        if self.has_io_counters:
            final_io = self.process.io_counters()
            self.decrypt_disk_read_bytes = final_io.read_bytes - initial_io.read_bytes
            self.decrypt_disk_write_bytes = final_io.write_bytes - initial_io.write_bytes
        
        # Update context switch metrics
        self.decrypt_ctx_switches_voluntary = final_ctx.voluntary - initial_ctx.voluntary
        self.decrypt_ctx_switches_involuntary = final_ctx.involuntary - initial_ctx.involuntary
        
        # Record peak memory usage
        self.decrypt_peak_rss_bytes = self.process.memory_info().rss
        
        # Check correctness
        self.correctness_passed = (decrypted_text == original_plaintext)
        
        return decrypted_text
    
    def to_dict(self):
        """Convert metrics to a dictionary."""
        return {
            # Key Generation metrics
            "keygen_wall_time_ms": self.keygen_wall_time_ms,
            "keygen_cpu_user_time_s": self.keygen_cpu_user_time_s,
            "keygen_cpu_system_time_s": self.keygen_cpu_system_time_s,
            "keygen_peak_rss_bytes": self.keygen_peak_rss_bytes,
            "keygen_ctx_switches_voluntary": self.keygen_ctx_switches_voluntary,
            "keygen_ctx_switches_involuntary": self.keygen_ctx_switches_involuntary,
            "key_components": self.key_components,
            
            # Encryption metrics
            "encrypt_wall_time_ms": self.encrypt_wall_time_ms,
            "encrypt_cpu_user_time_s": self.encrypt_cpu_user_time_s,
            "encrypt_cpu_system_time_s": self.encrypt_cpu_system_time_s,
            "encrypt_peak_rss_bytes": self.encrypt_peak_rss_bytes,
            "encrypt_disk_read_bytes": self.encrypt_disk_read_bytes,
            "encrypt_disk_write_bytes": self.encrypt_disk_write_bytes,
            "encrypt_ctx_switches_voluntary": self.encrypt_ctx_switches_voluntary,
            "encrypt_ctx_switches_involuntary": self.encrypt_ctx_switches_involuntary,
            "ciphertext_total_bytes": self.ciphertext_total_bytes,
            
            # Decryption metrics
            "decrypt_wall_time_ms": self.decrypt_wall_time_ms,
            "decrypt_cpu_user_time_s": self.decrypt_cpu_user_time_s,
            "decrypt_cpu_system_time_s": self.decrypt_cpu_system_time_s,
            "decrypt_peak_rss_bytes": self.decrypt_peak_rss_bytes,
            "decrypt_disk_read_bytes": self.decrypt_disk_read_bytes,
            "decrypt_disk_write_bytes": self.decrypt_disk_write_bytes,
            "decrypt_ctx_switches_voluntary": self.decrypt_ctx_switches_voluntary,
            "decrypt_ctx_switches_involuntary": self.decrypt_ctx_switches_involuntary,
            "correctness_passed": self.correctness_passed
        }

class MemoryMappedDataset:
    """Memory-mapped dataset handler for efficient memory usage with large files."""
    
    def __init__(self, file_path, read_only=True):
        """Initialize with file path."""
        import mmap
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path)
        self.file = open(file_path, 'rb')
        self.mmap = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ if read_only else mmap.ACCESS_COPY)
        self.read_only = read_only
        self._closed = False
    
    def __len__(self):
        """Return the file size."""
        return self.file_size
    
    def read(self, offset=0, size=None):
        """Read a portion of the file."""
        if self._closed:
            raise ValueError("Cannot read from closed memory-mapped dataset")
            
        if size is None:
            size = self.file_size - offset
        
        # Ensure we don't read past the end
        size = min(size, self.file_size - offset)
        
        self.mmap.seek(offset)
        return self.mmap.read(size)
    
    def read_all(self):
        """Read the entire file."""
        return self.read(0, self.file_size)
    
    def close(self):
        """Close the memory map and file."""
        if self._closed:
            return
            
        try:
            if hasattr(self, 'mmap') and self.mmap:
                self.mmap.close()
        except ValueError:
            # Already closed or invalid, just ignore
            pass
        except Exception as e:
            logger.warning(f"Error closing memory map: {str(e)}")
        
        try:
            if hasattr(self, 'file') and self.file:
                self.file.close()
        except Exception as e:
            logger.warning(f"Error closing file: {str(e)}")
            
        self._closed = True
    
    def __del__(self):
        """Ensure resources are properly cleaned up."""
        try:
            self.close()
        except Exception:
            # Suppress all exceptions during garbage collection
            pass

def register_implementation(name):
    """Register an encryption implementation."""
    def decorator(impl_class):
        ENCRYPTION_IMPLEMENTATIONS[name] = impl_class
        return impl_class
    return decorator

def load_dataset(dataset_path, use_mmap=False):
    """
    Load dataset from file while minimizing memory footprint.
    
    Args:
        dataset_path: Path to the dataset file
        use_mmap: If True, use memory mapping for very large files
    
    Returns:
        The dataset content or a MemoryMappedDataset object
    """
    try:
        # Get file size to make memory estimation
        file_size = os.path.getsize(dataset_path)
        
        logger.info(f"Loading dataset ({file_size / (1024*1024):.2f} MB) from {dataset_path}")
        
        # Check available system memory
        available_mem = psutil.virtual_memory().available
        logger.info(f"Available system memory: {available_mem / (1024*1024):.2f} MB")
        
        # Determine if we should use memory mapping
        # If file is > 40% of available memory, recommend memory mapping
        should_use_mmap = file_size > (available_mem * 0.4)
        
        if should_use_mmap:
            logger.warning(
                f"Dataset size ({file_size / (1024*1024):.2f} MB) is large relative to "
                f"available memory ({available_mem / (1024*1024):.2f} MB). "
                f"Using memory-mapped mode to reduce RAM usage."
            )
            use_mmap = True
        elif file_size > available_mem * 0.6:
            logger.warning(
                f"Dataset size ({file_size / (1024*1024):.2f} MB) is large relative to "
                f"available memory ({available_mem / (1024*1024):.2f} MB). "
                f"Consider using Stream processing mode or a smaller dataset."
            )
        
        if use_mmap:
            # Use memory mapping for efficient handling of large files
            logger.info("Using memory-mapped file access for efficient memory usage")
            return MemoryMappedDataset(dataset_path)
        else:
            # Read file in one go (most memory efficient for smaller files)
            with open(dataset_path, 'rb') as f:
                data = f.read()
            
            # Force garbage collection after loading large dataset
            gc.collect()
            
            return data
    except Exception as e:
        logger.error(f"Error loading dataset: {str(e)}")
        return None

def calculate_aggregated_metrics(iterations_data, dataset_size_bytes):
    """Calculate aggregated metrics from iteration data."""
    if not iterations_data:
        return {}
    
    # Count successful iterations
    iterations_completed = len(iterations_data)
    all_correctness_checks_passed = all(iter_data.get("correctness_passed", False) for iter_data in iterations_data)
    
    # Initialize sum variables
    total_keygen_wall_time_ms = 0
    total_keygen_cpu_user_time_s = 0
    total_keygen_cpu_system_time_s = 0
    total_keygen_peak_rss_bytes = 0
    
    total_encrypt_wall_time_ms = 0
    total_encrypt_cpu_user_time_s = 0
    total_encrypt_cpu_system_time_s = 0
    total_encrypt_peak_rss_bytes = 0
    total_encrypt_disk_read_bytes = 0
    total_encrypt_disk_write_bytes = 0
    total_encrypt_ctx_switches = 0
    
    total_decrypt_wall_time_ms = 0
    total_decrypt_cpu_user_time_s = 0
    total_decrypt_cpu_system_time_s = 0
    total_decrypt_peak_rss_bytes = 0
    total_decrypt_disk_read_bytes = 0
    total_decrypt_disk_write_bytes = 0
    total_decrypt_ctx_switches = 0
    
    total_ciphertext_bytes = 0
    
    # Sum up metrics
    for data in iterations_data:
        # Key generation
        total_keygen_wall_time_ms += data.get("keygen_wall_time_ms", 0)
        total_keygen_cpu_user_time_s += data.get("keygen_cpu_user_time_s", 0)
        total_keygen_cpu_system_time_s += data.get("keygen_cpu_system_time_s", 0)
        total_keygen_peak_rss_bytes += data.get("keygen_peak_rss_bytes", 0)
        
        # Encryption
        total_encrypt_wall_time_ms += data.get("encrypt_wall_time_ms", 0)
        total_encrypt_cpu_user_time_s += data.get("encrypt_cpu_user_time_s", 0)
        total_encrypt_cpu_system_time_s += data.get("encrypt_cpu_system_time_s", 0)
        total_encrypt_peak_rss_bytes += data.get("encrypt_peak_rss_bytes", 0)
        total_encrypt_disk_read_bytes += data.get("encrypt_disk_read_bytes", 0)
        total_encrypt_disk_write_bytes += data.get("encrypt_disk_write_bytes", 0)
        total_encrypt_ctx_switches += (data.get("encrypt_ctx_switches_voluntary", 0) + 
                                       data.get("encrypt_ctx_switches_involuntary", 0))
        
        # Decryption
        total_decrypt_wall_time_ms += data.get("decrypt_wall_time_ms", 0)
        total_decrypt_cpu_user_time_s += data.get("decrypt_cpu_user_time_s", 0)
        total_decrypt_cpu_system_time_s += data.get("decrypt_cpu_system_time_s", 0)
        total_decrypt_peak_rss_bytes += data.get("decrypt_peak_rss_bytes", 0)
        total_decrypt_disk_read_bytes += data.get("decrypt_disk_read_bytes", 0)
        total_decrypt_disk_write_bytes += data.get("decrypt_disk_write_bytes", 0)
        total_decrypt_ctx_switches += (data.get("decrypt_ctx_switches_voluntary", 0) + 
                                      data.get("decrypt_ctx_switches_involuntary", 0))
        
        # Ciphertext
        total_ciphertext_bytes += data.get("ciphertext_total_bytes", 0)
    
    # Calculate averages
    avg_keygen_wall_time_ms = total_keygen_wall_time_ms / iterations_completed
    avg_keygen_cpu_total_time_s = (total_keygen_cpu_user_time_s + total_keygen_cpu_system_time_s) / iterations_completed
    avg_keygen_peak_rss_mb = (total_keygen_peak_rss_bytes / iterations_completed) / (1024 * 1024)
    
    avg_encrypt_wall_time_ms = total_encrypt_wall_time_ms / iterations_completed
    avg_encrypt_cpu_total_time_s = (total_encrypt_cpu_user_time_s + total_encrypt_cpu_system_time_s) / iterations_completed
    avg_encrypt_cpu_percentage = (avg_encrypt_cpu_total_time_s / (avg_encrypt_wall_time_ms / 1000.0)) * 100 if avg_encrypt_wall_time_ms > 0 else 0
    avg_encrypt_peak_rss_mb = (total_encrypt_peak_rss_bytes / iterations_completed) / (1024 * 1024)
    avg_encrypt_disk_read_bytes = total_encrypt_disk_read_bytes / iterations_completed
    avg_encrypt_disk_write_bytes = total_encrypt_disk_write_bytes / iterations_completed
    avg_encrypt_ctx_switches_total = total_encrypt_ctx_switches / iterations_completed
    
    avg_decrypt_wall_time_ms = total_decrypt_wall_time_ms / iterations_completed
    avg_decrypt_cpu_total_time_s = (total_decrypt_cpu_user_time_s + total_decrypt_cpu_system_time_s) / iterations_completed
    avg_decrypt_cpu_percentage = (avg_decrypt_cpu_total_time_s / (avg_decrypt_wall_time_ms / 1000.0)) * 100 if avg_decrypt_wall_time_ms > 0 else 0
    avg_decrypt_peak_rss_mb = (total_decrypt_peak_rss_bytes / iterations_completed) / (1024 * 1024)
    avg_decrypt_disk_read_bytes = total_decrypt_disk_read_bytes / iterations_completed
    avg_decrypt_disk_write_bytes = total_decrypt_disk_write_bytes / iterations_completed
    avg_decrypt_ctx_switches_total = total_decrypt_ctx_switches / iterations_completed
    
    avg_ciphertext_total_bytes = total_ciphertext_bytes / iterations_completed
    avg_ciphertext_overhead_percent = ((avg_ciphertext_total_bytes - dataset_size_bytes) / dataset_size_bytes) * 100 if dataset_size_bytes > 0 else 0
    
    # Calculate throughput
    avg_throughput_encrypt_mb_per_s = (dataset_size_bytes / (1024 * 1024)) / (avg_encrypt_wall_time_ms / 1000.0) if avg_encrypt_wall_time_ms > 0 else 0
    avg_throughput_decrypt_mb_per_s = (dataset_size_bytes / (1024 * 1024)) / (avg_decrypt_wall_time_ms / 1000.0) if avg_decrypt_wall_time_ms > 0 else 0
    
    # Construct and return the aggregated metrics dictionary
    return {
        "iterations_completed": iterations_completed,
        "all_correctness_checks_passed": all_correctness_checks_passed,
        "avg_keygen_wall_time_ms": avg_keygen_wall_time_ms,
        "avg_keygen_cpu_total_time_s": avg_keygen_cpu_total_time_s,
        "avg_keygen_peak_rss_mb": avg_keygen_peak_rss_mb,
        "avg_encrypt_wall_time_ms": avg_encrypt_wall_time_ms,
        "avg_encrypt_cpu_total_time_s": avg_encrypt_cpu_total_time_s,
        "avg_encrypt_cpu_percentage": avg_encrypt_cpu_percentage,
        "avg_encrypt_peak_rss_mb": avg_encrypt_peak_rss_mb,
        "avg_encrypt_disk_read_bytes": avg_encrypt_disk_read_bytes,
        "avg_encrypt_disk_write_bytes": avg_encrypt_disk_write_bytes,
        "avg_encrypt_ctx_switches_total": avg_encrypt_ctx_switches_total,
        "avg_decrypt_wall_time_ms": avg_decrypt_wall_time_ms,
        "avg_decrypt_cpu_total_time_s": avg_decrypt_cpu_total_time_s,
        "avg_decrypt_cpu_percentage": avg_decrypt_cpu_percentage,
        "avg_decrypt_peak_rss_mb": avg_decrypt_peak_rss_mb,
        "avg_decrypt_disk_read_bytes": avg_decrypt_disk_read_bytes,
        "avg_decrypt_disk_write_bytes": avg_decrypt_disk_write_bytes,
        "avg_decrypt_ctx_switches_total": avg_decrypt_ctx_switches_total,
        "avg_ciphertext_total_bytes": avg_ciphertext_total_bytes,
        "avg_ciphertext_overhead_percent": avg_ciphertext_overhead_percent,
        "avg_throughput_encrypt_mb_per_s": avg_throughput_encrypt_mb_per_s,
        "avg_throughput_decrypt_mb_per_s": avg_throughput_decrypt_mb_per_s
    }

def measure_encryption_metrics(metrics, process_func, implementation, data, key, is_memory_mapped=False):
    """
    Universal method to measure encryption metrics regardless of implementation approach.
    Works for both regular memory processing and memory-mapped processing.
    
    Args:
        metrics: BenchmarkMetrics instance to update
        process_func: Function to measure (encrypt or decrypt)
        implementation: The encryption implementation
        data: Data to process (plaintext or ciphertext)
        key: Encryption key
        is_memory_mapped: Whether data is memory-mapped
        
    Returns:
        The processed data (ciphertext or plaintext)
    """
    process = metrics.process
    
    # Get initial metrics
    initial_io = process.io_counters() if metrics.has_io_counters else None
    initial_ctx = process.num_ctx_switches()
    initial_cpu_times = process.cpu_times()
    
    # Measure wall time
    start_time = time.perf_counter()
    
    # Handle regular or memory-mapped data
    if is_memory_mapped:
        # For memory-mapped files, read in chunks but track as single operation
        chunk_size = 16 * 1024 * 1024
        result_parts = []
        
        # Calculate total chunks
        total_size = len(data)
        total_chunks = (total_size + chunk_size - 1) // chunk_size
        
        # Process in chunks
        for chunk_idx in range(total_chunks):
            offset = chunk_idx * chunk_size
            if process_func.__name__ == 'encrypt':
                chunk = data.read(offset, chunk_size)
                result_parts.append(implementation.encrypt(chunk, key))
            else:  # decrypt
                # For decryption of memory-mapped data, we need special handling
                # Assume the entire ciphertext is already in memory (data)
                # and we're comparing against memory-mapped original
                return implementation.decrypt(data, key)
            
            # Log progress periodically
            if chunk_idx % 10 == 0 or chunk_idx == total_chunks - 1:
                progress = ((chunk_idx + 1) / total_chunks) * 100
                logger.info(f"Progress: {progress:.1f}% (chunk {chunk_idx + 1}/{total_chunks})")
        
        # Combine result parts
        if process_func.__name__ == 'encrypt':
            result = b''.join(result_parts)
        else:
            # This code path shouldn't be reached for decryption with memory-mapped data
            # since we return early above
            result = None
    else:
        # Standard in-memory processing
        result = process_func(data, key)
    
    end_time = time.perf_counter()
    
    # Calculate metrics
    wall_time_ms = (end_time - start_time) * 1000  # Convert to ms
    
    # Get final metrics
    final_cpu_times = process.cpu_times()
    final_ctx = process.num_ctx_switches()
    
    # Update the correct metrics based on function name
    if process_func.__name__ == 'encrypt':
        metrics.encrypt_wall_time_ms = wall_time_ms
        metrics.encrypt_cpu_user_time_s = final_cpu_times.user - initial_cpu_times.user
        metrics.encrypt_cpu_system_time_s = final_cpu_times.system - initial_cpu_times.system
        metrics.encrypt_ctx_switches_voluntary = final_ctx.voluntary - initial_ctx.voluntary
        metrics.encrypt_ctx_switches_involuntary = final_ctx.involuntary - initial_ctx.involuntary
        metrics.encrypt_peak_rss_bytes = process.memory_info().rss
        metrics.ciphertext_total_bytes = len(result) if hasattr(result, '__len__') else 0
        
        # Update IO metrics
        if metrics.has_io_counters:
            final_io = process.io_counters()
            metrics.encrypt_disk_read_bytes = final_io.read_bytes - initial_io.read_bytes
            metrics.encrypt_disk_write_bytes = final_io.write_bytes - initial_io.write_bytes
    else:  # decrypt
        metrics.decrypt_wall_time_ms = wall_time_ms
        metrics.decrypt_cpu_user_time_s = final_cpu_times.user - initial_cpu_times.user
        metrics.decrypt_cpu_system_time_s = final_cpu_times.system - initial_cpu_times.system
        metrics.decrypt_ctx_switches_voluntary = final_ctx.voluntary - initial_ctx.voluntary
        metrics.decrypt_ctx_switches_involuntary = final_ctx.involuntary - initial_ctx.involuntary
        metrics.decrypt_peak_rss_bytes = process.memory_info().rss
        
        # Update IO metrics
        if metrics.has_io_counters:
            final_io = process.io_counters()
            metrics.decrypt_disk_read_bytes = final_io.read_bytes - initial_io.read_bytes
            metrics.decrypt_disk_write_bytes = final_io.write_bytes - initial_io.write_bytes
    
    return result

def _register_implementations():
    """Register all available implementations."""
    # Import here to avoid circular import
    from src.encryption.python.aes.implementation import (
        AES_IMPLEMENTATIONS, 
        AESImplementation,
        create_custom_aes_implementation,
        create_stdlib_aes_implementation
    )
    
    # Register AES implementation directly
    ENCRYPTION_IMPLEMENTATIONS["aes"] = AESImplementation
    
    # Register custom AES implementation
    ENCRYPTION_IMPLEMENTATIONS["aes_custom"] = lambda **kwargs: create_custom_aes_implementation(
        kwargs.get("key_size", "256"), 
        kwargs.get("mode", "GCM")
    )
    
    # Register all AES variants
    for name, impl in AES_IMPLEMENTATIONS.items():
        if name not in ["aes", "aes_custom"]:  # We already registered these implementations
            ENCRYPTION_IMPLEMENTATIONS[name] = impl
            
    # Add more implementations as they are developed

def run_benchmarks(config):
    """Run all benchmarks based on the configuration."""
    # Get session information
    session_dir = config["session_info"]["session_dir"]
    session_id = config["session_info"]["session_id"]
    
    logger.info(f"Starting Python benchmarks for session {session_id}")
    
    # Extract test parameters
    iterations = config["test_parameters"]["iterations"]
    dataset_path = config["test_parameters"]["dataset_path"]
    include_stdlibs = config["test_parameters"].get("include_stdlibs", True)
    processing_strategy = config["test_parameters"].get("processing_strategy", "Memory")
    
    logger.info(f"Standard library comparison is {'enabled' if include_stdlibs else 'disabled'}")
    
    # Parse chunk size
    chunk_size_text = config["test_parameters"].get("chunk_size", "1MB")
    chunk_size_mb = 1  # Default: 1MB
    
    # Parse the chunk size from the text
    if chunk_size_text.endswith("KB"):
        chunk_size_kb = int(chunk_size_text.replace("KB", ""))
        chunk_size = chunk_size_kb * 1024
    elif chunk_size_text.endswith("MB"):
        chunk_size_mb = int(chunk_size_text.replace("MB", ""))
        chunk_size = chunk_size_mb * 1024 * 1024
    else:
        chunk_size = 1 * 1024 * 1024  # Default: 1MB
    
    logger.info(f"Using processing strategy: {processing_strategy}")
    if processing_strategy == "Stream":
        logger.info(f"Using chunk size: {chunk_size_text} ({chunk_size} bytes)")
    
    # Enable memory monitoring
    try:
        import tracemalloc
        tracemalloc.start()
        memory_tracking = True
        logger.info("Memory tracking enabled")
    except ImportError:
        memory_tracking = False
        logger.info("Memory tracking not available (tracemalloc not installed)")
    
    # Set a flag to use memory mapping for really large files
    use_mmap = processing_strategy == "Memory" and os.path.exists(dataset_path) and os.path.getsize(dataset_path) > 1024 * 1024 * 1024  # > 1GB
    
    # Load dataset based on processing strategy
    if processing_strategy == "Memory":
        # Load entire dataset into memory or use memory mapping for large files
        logger.info(f"Loading dataset using {'memory-mapped' if use_mmap else 'full memory'} mode from {dataset_path}")
        plaintext_data = load_dataset(dataset_path, use_mmap=use_mmap)
        if plaintext_data is None:
            logger.error("Failed to load dataset. Aborting.")
            return False
        
        dataset_size_bytes = len(plaintext_data)
        logger.info(f"Dataset loaded successfully: {dataset_size_bytes / (1024*1024):.2f} MB")
        
        # Check if we're using memory mapping
        is_memory_mapped = isinstance(plaintext_data, MemoryMappedDataset)
        if is_memory_mapped:
            logger.info("Using memory-mapped dataset to minimize RAM usage")
        
        # Log memory usage after loading dataset
        if memory_tracking:
            current, peak = tracemalloc.get_traced_memory()
            logger.info(f"Current memory usage: {current / (1024*1024):.2f} MB, Peak: {peak / (1024*1024):.2f} MB")
    else:
        # For stream processing, just check if the file exists and get its size
        logger.info(f"Using streaming strategy for dataset {dataset_path}")
        if not os.path.exists(dataset_path):
            logger.error(f"Dataset file not found at {dataset_path}. Aborting.")
            return False
        
        dataset_size_bytes = os.path.getsize(dataset_path)
        logger.info(f"Dataset file exists: {dataset_size_bytes / (1024*1024):.2f} MB")
        plaintext_data = None  # Will be loaded in chunks during benchmarking
    
    # Get enabled encryption methods
    enabled_methods = []
    for method_name, settings in config["encryption_methods"].items():
        if settings.get("enabled", False):
            # Add the standard implementation
            method_settings = settings.copy()
            enabled_methods.append((method_name, method_settings))
            
            # If standard library comparison is enabled, also add a custom implementation
            if include_stdlibs and method_name == "aes":
                # Add the custom implementation
                custom_settings = settings.copy()
                custom_settings["is_custom"] = True
                enabled_methods.append(("aes_custom", custom_settings))
    
    if not enabled_methods:
        logger.error("No encryption methods enabled in configuration. Aborting.")
        return False
    
    # Debug: Print encryption implementations
    logger.info(f"Available implementations: {list(ENCRYPTION_IMPLEMENTATIONS.keys())}")
    logger.info(f"Enabled methods for benchmarking: {[method for method, _ in enabled_methods]}")
    
    # Initialize results dictionary
    results = {
        "timestamp": datetime.now().isoformat(),
        "session_id": session_id,
        "language": "python",
        "dataset": {
            "path": dataset_path,
            "size_bytes": dataset_size_bytes
        },
        "encryption_results": {}
    }
    
    # Run benchmarks for each enabled encryption method
    for method_name, settings in enabled_methods:
        impl_name = method_name
        is_custom = method_name == "aes_custom"
        
        if is_custom:
            impl_description = "Custom AES Implementation"
        else:
            impl_description = f"Standard {method_name.upper()} Implementation"
            
        logger.info(f"Running benchmark for {impl_description}")
        
        # Check if implementation exists
        if method_name not in ENCRYPTION_IMPLEMENTATIONS:
            logger.warning(f"No implementation found for {method_name}. Skipping.")
            continue
        
        # Initialize implementation
        try:
            # Get the implementation function or class
            implementation_factory = ENCRYPTION_IMPLEMENTATIONS[method_name]
            
            # Create an instance with the settings
            implementation = implementation_factory(**settings)
            
            # Run iterations
            iteration_results = []
            for i in range(iterations):
                logger.info(f"Running iteration {i+1}/{iterations} for {impl_description}")
                
                # Create metrics collector
                metrics = BenchmarkMetrics()
                
                try:
                    # Key generation (same for both strategies)
                    key = metrics.measure_keygen(implementation.generate_key)
                    
                    if processing_strategy == "Memory":
                        # Process the entire dataset in memory
                        logger.info(f"Encrypting dataset (Memory mode)...")
                        
                        # Handle memory-mapped datasets with improved metrics
                        if isinstance(plaintext_data, MemoryMappedDataset):
                            # For memory-mapped files, use our universal metrics function
                            ciphertext = measure_encryption_metrics(
                                metrics, 
                                implementation.encrypt, 
                                implementation, 
                                plaintext_data, 
                                key, 
                                is_memory_mapped=True
                            )
                            
                            # Force garbage collection before decryption
                            gc.collect()
                            
                            logger.info(f"Decrypting dataset (Memory mode)...")
                            
                            # For decryption, we need to read all data for verification
                            original_data = plaintext_data.read_all()
                            
                            # Measure decryption with proper metrics
                            decrypted_data = measure_encryption_metrics(
                                metrics,
                                implementation.decrypt,
                                implementation,
                                ciphertext,
                                key,
                                is_memory_mapped=False  # Ciphertext is already in memory
                            )
                            
                            # Check correctness
                            metrics.correctness_passed = (decrypted_data == original_data)
                            
                            # Clear variables to free memory
                            del ciphertext, original_data, decrypted_data
                            gc.collect()
                        else:
                            # Regular in-memory processing
                            ciphertext = metrics.measure_encrypt(implementation.encrypt, plaintext_data, key)
                            
                            # Force garbage collection before decryption
                            gc.collect()
                            
                            logger.info(f"Decrypting dataset (Memory mode)...")
                            metrics.measure_decrypt(implementation.decrypt, ciphertext, key, plaintext_data)
                            
                            # Clear variables to free memory
                            del ciphertext
                            gc.collect()
                    else:
                        # Stream processing with improved metrics tracking
                        logger.info(f"Encrypting dataset (Stream mode)...")
                        
                        # Get initial metrics
                        process = metrics.process
                        initial_io = process.io_counters() if metrics.has_io_counters else None
                        initial_ctx = process.num_ctx_switches()
                        initial_cpu_times = process.cpu_times()
                        
                        # Start timing
                        encryption_start_time = time.perf_counter()
                        ciphertext_parts = []
                        total_processed = 0
                        
                        # Process in chunks
                        with open(dataset_path, 'rb') as f:
                            while True:
                                chunk = f.read(chunk_size)
                                if not chunk:
                                    break
                                
                                # Encrypt the chunk
                                encrypted_chunk = implementation.encrypt(chunk, key)
                                ciphertext_parts.append(encrypted_chunk)
                                total_processed += len(chunk)
                                
                                # Log progress periodically
                                if total_processed % (50 * 1024 * 1024) < chunk_size:  # Log every ~50MB
                                    progress = (total_processed / dataset_size_bytes) * 100
                                    logger.info(f"Processed {total_processed / (1024*1024):.2f} MB ({progress:.1f}%)")
                        
                        # End timing
                        encryption_end_time = time.perf_counter()
                        
                        # Calculate metrics
                        metrics.encrypt_wall_time_ms = (encryption_end_time - encryption_start_time) * 1000
                        
                        # Get final metrics
                        final_cpu_times = process.cpu_times()
                        final_ctx = process.num_ctx_switches()
                        
                        # Update CPU time metrics
                        metrics.encrypt_cpu_user_time_s = final_cpu_times.user - initial_cpu_times.user
                        metrics.encrypt_cpu_system_time_s = final_cpu_times.system - initial_cpu_times.system
                        
                        # Update IO metrics
                        if metrics.has_io_counters:
                            final_io = process.io_counters()
                            metrics.encrypt_disk_read_bytes = final_io.read_bytes - initial_io.read_bytes
                            metrics.encrypt_disk_write_bytes = final_io.write_bytes - initial_io.write_bytes
                        
                        # Update context switch metrics
                        metrics.encrypt_ctx_switches_voluntary = final_ctx.voluntary - initial_ctx.voluntary
                        metrics.encrypt_ctx_switches_involuntary = final_ctx.involuntary - initial_ctx.involuntary
                        
                        # Record peak memory usage
                        metrics.encrypt_peak_rss_bytes = process.memory_info().rss
                        
                        # Combined ciphertext (needed for some algorithms that maintain state)
                        combined_ciphertext = b''.join(ciphertext_parts) if isinstance(ciphertext_parts[0], bytes) else ciphertext_parts
                        metrics.ciphertext_total_bytes = len(combined_ciphertext) if hasattr(combined_ciphertext, '__len__') else sum(len(part) for part in ciphertext_parts)
                        
                        logger.info(f"Decrypting dataset (Stream mode)...")
                        
                        # For decryption, read original data for verification
                        with open(dataset_path, 'rb') as f:
                            original_data = f.read()
                        
                        # Get initial metrics for decryption
                        initial_io = process.io_counters() if metrics.has_io_counters else None
                        initial_ctx = process.num_ctx_switches()
                        initial_cpu_times = process.cpu_times()
                        
                        # Measure decryption
                        decryption_start_time = time.perf_counter()
                        decrypted_data = implementation.decrypt(combined_ciphertext, key)
                        decryption_end_time = time.perf_counter()
                        
                        # Calculate metrics
                        metrics.decrypt_wall_time_ms = (decryption_end_time - decryption_start_time) * 1000
                        
                        # Get final metrics
                        final_cpu_times = process.cpu_times()
                        final_ctx = process.num_ctx_switches()
                        
                        # Update CPU time metrics
                        metrics.decrypt_cpu_user_time_s = final_cpu_times.user - initial_cpu_times.user
                        metrics.decrypt_cpu_system_time_s = final_cpu_times.system - initial_cpu_times.system
                        
                        # Update IO metrics
                        if metrics.has_io_counters:
                            final_io = process.io_counters()
                            metrics.decrypt_disk_read_bytes = final_io.read_bytes - initial_io.read_bytes
                            metrics.decrypt_disk_write_bytes = final_io.write_bytes - initial_io.write_bytes
                        
                        # Update context switch metrics
                        metrics.decrypt_ctx_switches_voluntary = final_ctx.voluntary - initial_ctx.voluntary
                        metrics.decrypt_ctx_switches_involuntary = final_ctx.involuntary - initial_ctx.involuntary
                        
                        # Record peak memory usage
                        metrics.decrypt_peak_rss_bytes = process.memory_info().rss
                        
                        # Check correctness
                        metrics.correctness_passed = (decrypted_data == original_data)
                        
                        # Clean up memory
                        del combined_ciphertext, ciphertext_parts, original_data, decrypted_data
                        gc.collect()
                    
                    # Add results to list
                    iteration_results.append(metrics.to_dict())
                    
                    # Log iteration status
                    if metrics.correctness_passed:
                        logger.info(f"Iteration {i+1} completed successfully")
                    else:
                        logger.warning(f"Iteration {i+1} failed correctness check")
                    
                    # Log memory usage after iteration
                    if memory_tracking:
                        current, peak = tracemalloc.get_traced_memory()
                        logger.info(f"Memory after iteration {i+1}: Current {current / (1024*1024):.2f} MB, Peak {peak / (1024*1024):.2f} MB")
                        
                        # Reset peak memory tracking between iterations
                        tracemalloc.reset_peak()
                
                except Exception as e:
                    logger.error(f"Error in iteration {i+1}: {str(e)}")
                    traceback.print_exc()
                
                # Force garbage collection between iterations
                gc.collect()
            
            # Calculate aggregated metrics
            aggregated_metrics = calculate_aggregated_metrics(iteration_results, dataset_size_bytes)
            
            # Add to results with appropriate naming
            results["encryption_results"][impl_name] = {
                "iterations": iteration_results,
                "aggregated_metrics": aggregated_metrics,
                "configuration": settings,
                "is_custom_implementation": is_custom,
                "description": impl_description
            }
            
            logger.info(f"Benchmark completed for {impl_description}")
        
        except Exception as e:
            logger.error(f"Error in benchmark for {impl_description}: {str(e)}")
            traceback.print_exc()
    
    # Stop memory tracking
    if memory_tracking:
        tracemalloc.stop()
    
    # Clean up memory-mapped dataset if used
    if processing_strategy == "Memory" and isinstance(plaintext_data, MemoryMappedDataset):
        plaintext_data.close()
        logger.info("Closed memory-mapped dataset")
    
    # Save results
    results_file = os.path.join(session_dir, "results", "python_results.json")
    try:
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=4)
        logger.info(f"Results saved to {results_file}")
    except Exception as e:
        logger.error(f"Error saving results: {str(e)}")
        return False
    
    # Final memory cleanup
    gc.collect()
    
    return True

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
        # Import all implementations in advance
        _register_implementations()
        
        # Run benchmarks
        result = run_benchmarks(config)
        
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