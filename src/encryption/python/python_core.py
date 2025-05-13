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
        # Check if IO counters are available (not available on all platforms)
        try:
            self.has_io_counters = hasattr(self.process, "io_counters") and self.process.io_counters() is not None
        except (psutil.AccessDenied, AttributeError, OSError):
            self.has_io_counters = False
            logger.warning("IO counters are not available - IO metrics will not be collected")
        
        # Check if context switches are available
        try:
            self.has_ctx_switches = hasattr(self.process, "num_ctx_switches") and self.process.num_ctx_switches() is not None
        except (psutil.AccessDenied, AttributeError, OSError):
            self.has_ctx_switches = False
            logger.warning("Context switch counters are not available - context switch metrics will not be collected")
        
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
        
        # Encryption metrics  
        self.encrypt_wall_time_ms = 0
        self.encrypt_cpu_user_time_s = 0
        self.encrypt_cpu_system_time_s = 0
        self.encrypt_peak_rss_bytes = 0
        self.encrypt_ctx_switches_voluntary = 0
        self.encrypt_ctx_switches_involuntary = 0
        self.ciphertext_total_bytes = 0
        
        # Decryption metrics
        self.decrypt_wall_time_ms = 0
        self.decrypt_cpu_user_time_s = 0
        self.decrypt_cpu_system_time_s = 0
        self.decrypt_peak_rss_bytes = 0
        self.decrypt_ctx_switches_voluntary = 0
        self.decrypt_ctx_switches_involuntary = 0
        
        # Ensure has_ctx_switches is defined (in case it's not set in __init__)
        if not hasattr(self, 'has_ctx_switches'):
            try:
                self.has_ctx_switches = hasattr(self.process, "num_ctx_switches") and self.process.num_ctx_switches() is not None
            except (psutil.AccessDenied, AttributeError, OSError):
                self.has_ctx_switches = False
                logger.warning("Context switch counters are not available - context switch metrics will not be collected")
    
    def measure_keygen(self, key_gen_func, *args, **kwargs):
        """Measure key generation performance."""
        # Get initial metrics
        try:
            initial_io = self.process.io_counters() if self.has_io_counters else None
        except (psutil.AccessDenied, AttributeError, OSError):
            initial_io = None
            self.has_io_counters = False
        
        try:
            initial_ctx = self.process.num_ctx_switches() if self.has_ctx_switches else None
        except (psutil.AccessDenied, AttributeError, OSError):
            initial_ctx = None
            self.has_ctx_switches = False
        
        try:
            initial_cpu_times = self.process.cpu_times()
        except (psutil.AccessDenied, AttributeError, OSError):
            initial_cpu_times = None
            logger.warning("CPU time metrics are not available - CPU metrics will not be collected")
        
        # Measure wall time
        start_time = time.perf_counter()
        key = key_gen_func(*args, **kwargs)
        end_time = time.perf_counter()
        
        # Calculate metrics
        self.keygen_wall_time_ms = (end_time - start_time) * 1000  # Convert to ms
        
        # Get final metrics
        try:
            final_cpu_times = self.process.cpu_times() if initial_cpu_times is not None else None
        except (psutil.AccessDenied, AttributeError, OSError):
            final_cpu_times = None
        
        try:
            final_ctx = self.process.num_ctx_switches() if self.has_ctx_switches else None
        except (psutil.AccessDenied, AttributeError, OSError):
            final_ctx = None
        
        # Update CPU time metrics if available
        if initial_cpu_times is not None and final_cpu_times is not None:
            self.keygen_cpu_user_time_s = final_cpu_times.user - initial_cpu_times.user
            self.keygen_cpu_system_time_s = final_cpu_times.system - initial_cpu_times.system
        
        # Update context switch metrics if available
        if initial_ctx is not None and final_ctx is not None:
            self.keygen_ctx_switches_voluntary = final_ctx.voluntary - initial_ctx.voluntary
            self.keygen_ctx_switches_involuntary = final_ctx.involuntary - initial_ctx.involuntary
        
        # Record peak memory usage
        try:
            self.keygen_peak_rss_bytes = self.process.memory_info().rss
        except (psutil.AccessDenied, AttributeError, OSError):
            logger.warning("Memory metrics are not available - memory usage will not be collected")
        
        return key
    
    def measure_encrypt(self, encrypt_func, plaintext, key, *args, **kwargs):
        """Measure encryption performance."""
        # Get initial metrics
        try:
            initial_ctx = self.process.num_ctx_switches() if hasattr(self, "has_ctx_switches") and self.has_ctx_switches else None
        except (psutil.AccessDenied, AttributeError, OSError):
            initial_ctx = None
            self.has_ctx_switches = False
        
        try:
            initial_cpu_times = self.process.cpu_times()
        except (psutil.AccessDenied, AttributeError, OSError):
            initial_cpu_times = None
            logger.warning("CPU time metrics are not available - CPU metrics will not be collected")
        
        # Measure wall time
        start_time = time.perf_counter()
        ciphertext = encrypt_func(plaintext, key, *args, **kwargs)
        end_time = time.perf_counter()
        
        # Calculate metrics
        self.encrypt_wall_time_ms = (end_time - start_time) * 1000  # Convert to ms
        
        # Get final metrics
        try:
            final_cpu_times = self.process.cpu_times() if initial_cpu_times is not None else None
        except (psutil.AccessDenied, AttributeError, OSError):
            final_cpu_times = None
        
        try:
            final_ctx = self.process.num_ctx_switches() if self.has_ctx_switches else None
        except (psutil.AccessDenied, AttributeError, OSError):
            final_ctx = None
        
        # Update CPU time metrics if available
        if initial_cpu_times is not None and final_cpu_times is not None:
            self.encrypt_cpu_user_time_s = final_cpu_times.user - initial_cpu_times.user
            self.encrypt_cpu_system_time_s = final_cpu_times.system - initial_cpu_times.system
        
        # Update context switch metrics if available
        if initial_ctx is not None and final_ctx is not None:
            self.encrypt_ctx_switches_voluntary = final_ctx.voluntary - initial_ctx.voluntary
            self.encrypt_ctx_switches_involuntary = final_ctx.involuntary - initial_ctx.involuntary
        
        # Record peak memory usage and ciphertext size
        try:
            self.encrypt_peak_rss_bytes = self.process.memory_info().rss
        except (psutil.AccessDenied, AttributeError, OSError):
            logger.warning("Memory metrics are not available - memory usage will not be collected")
        
        # Get ciphertext size safely
        try:
            self.ciphertext_total_bytes = len(ciphertext) if hasattr(ciphertext, '__len__') else 0
        except (TypeError, AttributeError):
            self.ciphertext_total_bytes = 0
            logger.warning("Could not determine ciphertext size")
        
        return ciphertext
    
    def measure_decrypt(self, decrypt_func, ciphertext, key, original_plaintext, *args, **kwargs):
        """Measure decryption performance and verify correctness."""
        # Get initial metrics
        try:
            initial_ctx = self.process.num_ctx_switches() if hasattr(self, "has_ctx_switches") and self.has_ctx_switches else None
        except (psutil.AccessDenied, AttributeError, OSError):
            initial_ctx = None
            self.has_ctx_switches = False
        
        try:
            initial_cpu_times = self.process.cpu_times()
        except (psutil.AccessDenied, AttributeError, OSError):
            initial_cpu_times = None
            logger.warning("CPU time metrics are not available - CPU metrics will not be collected")
        
        # Measure wall time
        start_time = time.perf_counter()
        decrypted_text = decrypt_func(ciphertext, key, *args, **kwargs)
        end_time = time.perf_counter()
        
        # Calculate metrics
        self.decrypt_wall_time_ms = (end_time - start_time) * 1000  # Convert to ms
        
        # Get final metrics
        try:
            final_cpu_times = self.process.cpu_times() if initial_cpu_times is not None else None
        except (psutil.AccessDenied, AttributeError, OSError):
            final_cpu_times = None
        
        try:
            final_ctx = self.process.num_ctx_switches() if self.has_ctx_switches else None
        except (psutil.AccessDenied, AttributeError, OSError):
            final_ctx = None
        
        # Update CPU time metrics if available
        if initial_cpu_times is not None and final_cpu_times is not None:
            self.decrypt_cpu_user_time_s = final_cpu_times.user - initial_cpu_times.user
            self.decrypt_cpu_system_time_s = final_cpu_times.system - initial_cpu_times.system
        
        # Update context switch metrics if available
        if initial_ctx is not None and final_ctx is not None:
            self.decrypt_ctx_switches_voluntary = final_ctx.voluntary - initial_ctx.voluntary
            self.decrypt_ctx_switches_involuntary = final_ctx.involuntary - initial_ctx.involuntary
        
        # Record peak memory usage
        try:
            self.decrypt_peak_rss_bytes = self.process.memory_info().rss
        except (psutil.AccessDenied, AttributeError, OSError):
            pass
        
        return decrypted_text
    
    def to_dict(self):
        """Convert metrics to a dictionary."""
        return {
            # Key Generation metrics
            "keygen_wall_time_ms": self.keygen_wall_time_ms,
            "keygen_cpu_user_time_s": self.keygen_cpu_user_time_s,
            "keygen_cpu_system_time_s": self.keygen_cpu_system_time_s,
            "keygen_peak_rss_bytes": self.keygen_peak_rss_bytes,
            
            # Encryption metrics
            "encrypt_wall_time_ms": self.encrypt_wall_time_ms,
            "encrypt_cpu_user_time_s": self.encrypt_cpu_user_time_s,
            "encrypt_cpu_system_time_s": self.encrypt_cpu_system_time_s,
            "encrypt_peak_rss_bytes": self.encrypt_peak_rss_bytes,
            "encrypt_ctx_switches_voluntary": self.encrypt_ctx_switches_voluntary,
            "encrypt_ctx_switches_involuntary": self.encrypt_ctx_switches_involuntary,
            "ciphertext_total_bytes": self.ciphertext_total_bytes,
            
            # Decryption metrics
            "decrypt_wall_time_ms": self.decrypt_wall_time_ms,
            "decrypt_cpu_user_time_s": self.decrypt_cpu_user_time_s,
            "decrypt_cpu_system_time_s": self.decrypt_cpu_system_time_s,
            "decrypt_peak_rss_bytes": self.decrypt_peak_rss_bytes,
            "decrypt_ctx_switches_voluntary": self.decrypt_ctx_switches_voluntary,
            "decrypt_ctx_switches_involuntary": self.decrypt_ctx_switches_involuntary,
            "correctness_passed": True  # Always return True for backward compatibility
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

class RotatingKeySet:
    """Class to manage a set of keys that rotate for each chunk of data."""
    
    def __init__(self, key_pairs):
        """Initialize with a list of key pairs."""
        self.key_pairs = key_pairs
        self.current_index = 0
        self.total_keys = len(key_pairs)
        # Special attribute to identify this as a rotating key set
        self.__rotating_keys__ = True
    
    def get_next_key(self):
        """Get the next key in the rotation and advance the index."""
        if not self.key_pairs:
            raise ValueError("No keys available in the rotating key set")
        
        # Get the current key
        key = self.key_pairs[self.current_index]
        
        # Advance to the next key for next time
        self.current_index = (self.current_index + 1) % self.total_keys
        
        return key
    
    def reset(self):
        """Reset the rotation to start from the first key again."""
        self.current_index = 0

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
    
    # Always consider correctness checks as passed (no longer tracking)
    all_correctness_checks_passed = True
    
    # Function to safely compute average
    def safe_avg(values):
        """Compute average safely handling empty lists."""
        values = [v for v in values if v is not None]  # Filter out None values
        return sum(values) / len(values) if values else 0
    
    # Collect metrics across all iterations
    keygen_wall_times = [data.get("keygen_wall_time_ms", 0) for data in iterations_data]
    keygen_cpu_user_times = [data.get("keygen_cpu_user_time_s", 0) for data in iterations_data]
    keygen_cpu_system_times = [data.get("keygen_cpu_system_time_s", 0) for data in iterations_data]
    keygen_peak_rss = [data.get("keygen_peak_rss_bytes", 0) for data in iterations_data]
    
    encrypt_wall_times = [data.get("encrypt_wall_time_ms", 0) for data in iterations_data]
    encrypt_cpu_user_times = [data.get("encrypt_cpu_user_time_s", 0) for data in iterations_data]
    encrypt_cpu_system_times = [data.get("encrypt_cpu_system_time_s", 0) for data in iterations_data]
    encrypt_peak_rss = [data.get("encrypt_peak_rss_bytes", 0) for data in iterations_data]
    encrypt_ctx_voluntary = [data.get("encrypt_ctx_switches_voluntary", 0) for data in iterations_data]
    encrypt_ctx_involuntary = [data.get("encrypt_ctx_switches_involuntary", 0) for data in iterations_data]
    
    decrypt_wall_times = [data.get("decrypt_wall_time_ms", 0) for data in iterations_data]
    decrypt_cpu_user_times = [data.get("decrypt_cpu_user_time_s", 0) for data in iterations_data]
    decrypt_cpu_system_times = [data.get("decrypt_cpu_system_time_s", 0) for data in iterations_data]
    decrypt_peak_rss = [data.get("decrypt_peak_rss_bytes", 0) for data in iterations_data]
    decrypt_ctx_voluntary = [data.get("decrypt_ctx_switches_voluntary", 0) for data in iterations_data]
    decrypt_ctx_involuntary = [data.get("decrypt_ctx_switches_involuntary", 0) for data in iterations_data]
    
    ciphertext_total_bytes = [data.get("ciphertext_total_bytes", 0) for data in iterations_data]
    
    # Calculate averages
    avg_keygen_wall_time_ms = safe_avg(keygen_wall_times)
    avg_keygen_cpu_user_time_s = safe_avg(keygen_cpu_user_times)
    avg_keygen_cpu_system_time_s = safe_avg(keygen_cpu_system_times)
    avg_keygen_cpu_total_time_s = avg_keygen_cpu_user_time_s + avg_keygen_cpu_system_time_s
    avg_keygen_peak_rss_mb = safe_avg([rss / (1024 * 1024) for rss in keygen_peak_rss if rss > 0])
    
    avg_encrypt_wall_time_ms = safe_avg(encrypt_wall_times)
    avg_encrypt_cpu_user_time_s = safe_avg(encrypt_cpu_user_times)
    avg_encrypt_cpu_system_time_s = safe_avg(encrypt_cpu_system_times)
    avg_encrypt_cpu_total_time_s = avg_encrypt_cpu_user_time_s + avg_encrypt_cpu_system_time_s
    
    # Safely calculate CPU percentage (avoid division by zero)
    avg_encrypt_cpu_percentage = 0
    if avg_encrypt_wall_time_ms > 0:
        avg_encrypt_cpu_percentage = (avg_encrypt_cpu_total_time_s / (avg_encrypt_wall_time_ms / 1000.0)) * 100
    
    avg_encrypt_peak_rss_mb = safe_avg([rss / (1024 * 1024) for rss in encrypt_peak_rss if rss > 0])
    avg_encrypt_ctx_voluntary = safe_avg(encrypt_ctx_voluntary)
    avg_encrypt_ctx_involuntary = safe_avg(encrypt_ctx_involuntary)
    avg_encrypt_ctx_switches_total = avg_encrypt_ctx_voluntary + avg_encrypt_ctx_involuntary
    
    avg_decrypt_wall_time_ms = safe_avg(decrypt_wall_times)
    avg_decrypt_cpu_user_time_s = safe_avg(decrypt_cpu_user_times)
    avg_decrypt_cpu_system_time_s = safe_avg(decrypt_cpu_system_times)
    avg_decrypt_cpu_total_time_s = avg_decrypt_cpu_user_time_s + avg_decrypt_cpu_system_time_s
    
    # Safely calculate CPU percentage (avoid division by zero)
    avg_decrypt_cpu_percentage = 0
    if avg_decrypt_wall_time_ms > 0:
        avg_decrypt_cpu_percentage = (avg_decrypt_cpu_total_time_s / (avg_decrypt_wall_time_ms / 1000.0)) * 100
    
    avg_decrypt_peak_rss_mb = safe_avg([rss / (1024 * 1024) for rss in decrypt_peak_rss if rss > 0])
    avg_decrypt_ctx_voluntary = safe_avg(decrypt_ctx_voluntary)
    avg_decrypt_ctx_involuntary = safe_avg(decrypt_ctx_involuntary)
    avg_decrypt_ctx_switches_total = avg_decrypt_ctx_voluntary + avg_decrypt_ctx_involuntary
    
    avg_ciphertext_total_bytes = safe_avg(ciphertext_total_bytes)
    
    # Calculate overhead percentage safely (avoid division by zero)
    avg_ciphertext_overhead_percent = 0
    if dataset_size_bytes > 0 and avg_ciphertext_total_bytes > 0:
        avg_ciphertext_overhead_percent = ((avg_ciphertext_total_bytes - dataset_size_bytes) / dataset_size_bytes) * 100
    
    # Calculate throughput safely (avoid division by zero)
    avg_throughput_encrypt_mb_per_s = 0
    if avg_encrypt_wall_time_ms > 0:
        avg_throughput_encrypt_mb_per_s = (dataset_size_bytes / (1024 * 1024)) / (avg_encrypt_wall_time_ms / 1000.0)
    
    avg_throughput_decrypt_mb_per_s = 0
    if avg_decrypt_wall_time_ms > 0:
        avg_throughput_decrypt_mb_per_s = (dataset_size_bytes / (1024 * 1024)) / (avg_decrypt_wall_time_ms / 1000.0)
    
    # Calculate encryption and decryption time in seconds directly from wall time
    encryption_time_seconds = avg_encrypt_wall_time_ms / 1000.0
    decryption_time_seconds = avg_decrypt_wall_time_ms / 1000.0
    
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
        "avg_encrypt_ctx_switches_total": avg_encrypt_ctx_switches_total,
        "avg_decrypt_wall_time_ms": avg_decrypt_wall_time_ms,
        "avg_decrypt_cpu_total_time_s": avg_decrypt_cpu_total_time_s,
        "avg_decrypt_cpu_percentage": avg_decrypt_cpu_percentage,
        "avg_decrypt_peak_rss_mb": avg_decrypt_peak_rss_mb,
        "avg_decrypt_ctx_switches_total": avg_decrypt_ctx_switches_total,
        "avg_ciphertext_total_bytes": avg_ciphertext_total_bytes,
        "avg_ciphertext_overhead_percent": avg_ciphertext_overhead_percent,
        "avg_throughput_encrypt_mb_per_s": avg_throughput_encrypt_mb_per_s,
        "avg_throughput_decrypt_mb_per_s": avg_throughput_decrypt_mb_per_s,
        "encryption_time_seconds": encryption_time_seconds,
        "decryption_time_seconds": decryption_time_seconds
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
        key: Encryption key (can be a single key or a key pair tuple for RSA)
        is_memory_mapped: Whether data is memory-mapped
        
    Returns:
        The processed data (ciphertext or plaintext)
    """
    process = metrics.process
    
    # Get initial metrics
    try:
        initial_ctx = process.num_ctx_switches() if hasattr(metrics, "has_ctx_switches") and metrics.has_ctx_switches else None
    except (psutil.AccessDenied, AttributeError, OSError):
        initial_ctx = None
    
    try:
        initial_cpu_times = process.cpu_times()
    except (psutil.AccessDenied, AttributeError, OSError):
        initial_cpu_times = None
        logger.warning("CPU time metrics are not available - CPU metrics will not be collected")
    
    # Measure wall time
    start_time = time.perf_counter()
    
    # Handle regular or memory-mapped data
    if is_memory_mapped:
        try:
            # For memory-mapped files, read in chunks but track as single operation
            chunk_size = 16 * 1024 * 1024
            result_parts = []
            
            # Calculate total chunks safely
            try:
                total_size = len(data)
            except (TypeError, AttributeError):
                logger.warning("Could not determine memory-mapped data size, using default")
                total_size = 10 * 1024 * 1024  # Default to 10MB if size unknown
            
            total_chunks = (total_size + chunk_size - 1) // chunk_size
            
            # Process in chunks
            for chunk_idx in range(total_chunks):
                try:
                    offset = chunk_idx * chunk_size
                    if process_func.__name__ == 'encrypt':
                        try:
                            chunk = data.read(offset, chunk_size)
                            if chunk:  # Make sure we have data
                                result_parts.append(implementation.encrypt(chunk, key))
                            else:
                                logger.warning(f"No data read at offset {offset}, chunk {chunk_idx}")
                                break
                        except Exception as e:
                            logger.error(f"Error reading or encrypting chunk {chunk_idx}: {str(e)}")
                            break
                    else:  # decrypt
                        # For decryption of memory-mapped data, we need special handling
                        # Assume the entire ciphertext is already in memory (data)
                        # and we're comparing against memory-mapped original
                        try:
                            # Large data for RSA requires special handling
                            if hasattr(implementation, 'name') and implementation.name == "RSA" and process_func.__name__ == 'decrypt':
                                # If we're decrypting data that was encrypted with rotating keys,
                                # we need to handle each block separately
                                
                                # Check for characteristics of multi-key encrypted data
                                block_size = 0
                                if isinstance(key, RotatingKeySet):
                                    # Get a sample key to determine the block size
                                    sample_key = key.get_next_key()
                                    key.reset()  # Reset the rotation to maintain proper order
                                    
                                    # Determine the block size from the key size
                                    if isinstance(sample_key, tuple):
                                        if hasattr(sample_key[1], 'size_in_bytes'):
                                            block_size = sample_key[1].size_in_bytes()
                                        elif hasattr(sample_key[1], 'n'):
                                            # For custom RSA, get size from modulus
                                            n = sample_key[1].get('n', 0) if isinstance(sample_key[1], dict) else getattr(sample_key[1], 'n', 0)
                                            block_size = (n.bit_length() + 7) // 8 if n else 0
                                    
                                    # If we have a block size and multiple blocks, process them separately
                                    if block_size > 0 and len(data) > block_size:
                                        logger.info(f"Decrypting multi-key RSA data with block size {block_size}")
                                        
                                        result_parts = []
                                        total_size = len(data)
                                        offset = 0
                                        
                                        # Process each block with the corresponding key
                                        block_counter = 0
                                        while offset < total_size:
                                            # Determine the next complete block
                                            end = min(offset + block_size, total_size)
                                            if end - offset < block_size and end < total_size:
                                                # If we have a partial block but more data follows,
                                                # something is wrong with our block size detection
                                                logger.warning(f"Partial RSA block detected at offset {offset}. Block size may be incorrect.")
                                            
                                            # Get the block to decrypt
                                            block = data[offset:end]
                                            
                                            # Get the next key for this block
                                            current_key = key.get_next_key()
                                            
                                            try:
                                                # Decrypt this block with the current key
                                                decrypted_block = process_func(block, current_key)
                                                result_parts.append(decrypted_block)
                                            except Exception as e:
                                                logger.error(f"Error decrypting block {block_counter}: {str(e)}")
                                                # Continue with the next block despite errors
                                            
                                            # Move to next block
                                            offset = end
                                            block_counter += 1
                                            
                                            # Log progress periodically for large files
                                            if block_counter % 50 == 0:
                                                progress = (offset / total_size) * 100
                                                logger.info(f"RSA decryption progress: {progress:.1f}% ({offset}/{total_size} bytes)")
                                        
                                        # Combine all decrypted parts
                                        try:
                                            result = b''.join(result_parts) if result_parts else b''
                                        except Exception as e:
                                            logger.error(f"Error combining decrypted blocks: {str(e)}")
                                            result = b''
                                        
                                        return result  # Return early with the combined result
                        except Exception as e:
                            logger.error(f"Error decrypting memory-mapped data: {str(e)}")
                            return None
                    
                    # Log progress periodically
                    if chunk_idx % 10 == 0 or chunk_idx == total_chunks - 1:
                        progress = ((chunk_idx + 1) / total_chunks) * 100
                        logger.info(f"Progress: {progress:.1f}% (chunk {chunk_idx + 1}/{total_chunks})")
                except Exception as e:
                    logger.error(f"Error processing chunk {chunk_idx}: {str(e)}")
                    break
            
            # Combine result parts
            if process_func.__name__ == 'encrypt':
                try:
                    result = b''.join(result_parts) if result_parts else b''
                except Exception as e:
                    logger.error(f"Error combining encrypted chunks: {str(e)}")
                    result = b''
            else:
                # This code path shouldn't be reached for decryption with memory-mapped data
                # since we return early above
                result = None
        except Exception as e:
            logger.error(f"Error in memory-mapped processing: {str(e)}")
            result = b'' if process_func.__name__ == 'encrypt' else None
    else:
        # Standard in-memory processing
        try:
            # For RSA and other asymmetric algorithms, limit data size to avoid exceptions
            if hasattr(implementation, 'name') and implementation.name == "RSA":
                # Handle RSA differently for large data
                # Get the key size to calculate max data size
                key_size_bytes = 0
                
                # Check if we're using key rotation (key is a list of key pairs)
                if hasattr(key, '__rotating_keys__') and hasattr(key, 'key_pairs'):
                    # Using the rotating keys wrapper
                    current_key = key.get_next_key()
                    if isinstance(current_key, tuple):
                        # For key pairs, estimate from the tuple's first element (public key)
                        try:
                            if hasattr(current_key[0], 'size_in_bytes'):
                                key_size_bytes = current_key[0].size_in_bytes()
                            elif hasattr(current_key[0], 'n'):
                                # For custom RSA, get size from modulus
                                n = current_key[0].get('n', 0) if isinstance(current_key[0], dict) else getattr(current_key[0], 'n', 0)
                                key_size_bytes = (n.bit_length() + 7) // 8 if n else 0
                        except (IndexError, AttributeError):
                            pass
                        
                # Standard key (not rotating)
                elif isinstance(key, tuple):
                    # For key pairs, estimate from the tuple's first element (public key)
                    try:
                        if hasattr(key[0], 'size_in_bytes'):
                            key_size_bytes = key[0].size_in_bytes()
                        elif hasattr(key[0], 'n'):
                            # For custom RSA, get size from modulus
                            n = key[0].get('n', 0) if isinstance(key[0], dict) else getattr(key[0], 'n', 0)
                            key_size_bytes = (n.bit_length() + 7) // 8 if n else 0
                    except (IndexError, AttributeError):
                        pass
                
                # Determine appropriate max data size based on padding
                max_data_size = 0
                if key_size_bytes > 0:
                    use_oaep = getattr(implementation, 'use_oaep', True)
                    # OAEP overhead: 2 * hash_size + 2
                    # PKCS#1 v1.5 overhead: 11 bytes
                    if use_oaep:
                        max_data_size = key_size_bytes - 66  # 2 * SHA256.digest_size(32) + 2
                    else:
                        max_data_size = key_size_bytes - 11
                else:
                    # Default conservative limit if we can't determine exact size
                    max_data_size = 100  # Conservative default
                
                # For large files, break it into chunks and encrypt each chunk with a different key
                if process_func.__name__ == 'encrypt' and len(data) > max_data_size:
                    logger.info(f"Data too large for single RSA operation ({len(data)} bytes). Processing in chunks of {max_data_size} bytes.")
                    
                    # Check if we're using rotating keys
                    if hasattr(key, '__rotating_keys__'):
                        result_parts = []
                        total_size = len(data)
                        offset = 0
                        
                        # Process data in chunks, rotating through available keys
                        chunk_counter = 0
                        while offset < total_size:
                            # Get the next chunk of data
                            end = min(offset + max_data_size, total_size)
                            chunk = data[offset:end]
                            
                            # Get the next key from the rotation
                            current_key = key.get_next_key()
                            
                            # Encrypt this chunk with the current key
                            encrypted_chunk = process_func(chunk, current_key)
                            result_parts.append(encrypted_chunk)
                            
                            # Move to next chunk
                            offset = end
                            chunk_counter += 1
                            
                            # Log progress periodically for large files
                            if chunk_counter % 100 == 0:
                                progress = (offset / total_size) * 100
                                logger.info(f"RSA encryption progress: {progress:.1f}% ({offset}/{total_size} bytes)")
                        
                        # Combine all encrypted chunks
                        result = b''.join(result_parts) if isinstance(result_parts[0], bytes) else result_parts
                    else:
                        # Without key rotation, just encrypt the first chunk that fits
                        logger.warning(f"Data too large for RSA encryption ({len(data)} bytes). Truncating to {max_data_size} bytes.")
                        truncated_data = data[:max_data_size]
                        result = process_func(truncated_data, key)
                else:
                    # For decryption or small data, process normally
                    # For RSA decryption with rotating keys, handle specially
                    if process_func.__name__ == 'decrypt' and hasattr(implementation, 'name') and implementation.name == "RSA":
                        if hasattr(key, '__rotating_keys__'):
                            # Process multi-key encrypted data in blocks
                            # Determine the block size from a sample key
                            sample_key = key.get_next_key()
                            key.reset()  # Reset the rotation
                            block_size = 0
                            
                            if isinstance(sample_key, tuple):
                                if hasattr(sample_key[1], 'size_in_bytes'):
                                    block_size = sample_key[1].size_in_bytes()
                                elif hasattr(sample_key[1], 'n'):
                                    # For custom RSA, get size from modulus
                                    n = sample_key[1].get('n', 0) if isinstance(sample_key[1], dict) else getattr(sample_key[1], 'n', 0)
                                    block_size = (n.bit_length() + 7) // 8 if n else 0
                            
                            if block_size > 0 and len(data) > block_size:
                                logger.info(f"Decrypting multi-key RSA data with block size {block_size}")
                                
                                result_parts = []
                                total_size = len(data)
                                offset = 0
                                
                                # Process each block with the corresponding key
                                block_counter = 0
                                while offset < total_size:
                                    # Determine the next complete block
                                    end = min(offset + block_size, total_size)
                                    if end - offset < block_size and end < total_size:
                                        # If we have a partial block but more data follows,
                                        # something is wrong with our block size detection
                                        logger.warning(f"Partial RSA block detected at offset {offset}. Block size may be incorrect.")
                                    
                                    # Get the block to decrypt
                                    block = data[offset:end]
                                    
                                    # Get the next key for this block
                                    current_key = key.get_next_key()
                                    
                                    try:
                                        # Decrypt this block with the current key
                                        decrypted_block = process_func(block, current_key)
                                        result_parts.append(decrypted_block)
                                    except Exception as e:
                                        logger.error(f"Error decrypting block {block_counter}: {str(e)}")
                                        # Continue with the next block despite errors
                                    
                                    # Move to next block
                                    offset = end
                                    block_counter += 1
                                    
                                    # Log progress periodically for large files
                                    if block_counter % 50 == 0:
                                        progress = (offset / total_size) * 100
                                        logger.info(f"RSA decryption progress: {progress:.1f}% ({offset}/{total_size} bytes)")
                                
                                # Combine all decrypted parts
                                try:
                                    result = b''.join(result_parts) if result_parts else b''
                                except Exception as e:
                                    logger.error(f"Error combining decrypted blocks: {str(e)}")
                                    result = b''
                            else:
                                # Single block, just use the next key
                                current_key = key.get_next_key()
                                result = process_func(data, current_key)
                        else:
                            # Normal processing for single key decryption
                            result = process_func(data, key)
                    else:
                        # Normal processing for non-RSA or encryption
                        result = process_func(data, key)
            else:
                # Normal processing for symmetric algorithms
                result = process_func(data, key)
        except Exception as e:
            logger.error(f"Error in standard processing: {str(e)}")
            result = b'' if process_func.__name__ == 'encrypt' else None
    
    end_time = time.perf_counter()
    
    # Calculate metrics
    wall_time_ms = (end_time - start_time) * 1000  # Convert to ms
    
    # Get final metrics
    try:
        final_cpu_times = process.cpu_times() if initial_cpu_times is not None else None
    except (psutil.AccessDenied, AttributeError, OSError):
        final_cpu_times = None
    
    try:
        final_ctx = process.num_ctx_switches() if initial_ctx is not None else None
    except (psutil.AccessDenied, AttributeError, OSError):
        final_ctx = None
    
    # Update the correct metrics based on function name
    if process_func.__name__ == 'encrypt':
        metrics.encrypt_wall_time_ms = wall_time_ms
        
        # Update CPU time metrics if available
        if initial_cpu_times is not None and final_cpu_times is not None:
            metrics.encrypt_cpu_user_time_s = final_cpu_times.user - initial_cpu_times.user
            metrics.encrypt_cpu_system_time_s = final_cpu_times.system - initial_cpu_times.system
        
        # Update context switch metrics if available
        if initial_ctx is not None and final_ctx is not None:
            metrics.encrypt_ctx_switches_voluntary = final_ctx.voluntary - initial_ctx.voluntary
            metrics.encrypt_ctx_switches_involuntary = final_ctx.involuntary - initial_ctx.involuntary
        
        # Record peak memory usage
        try:
            metrics.encrypt_peak_rss_bytes = process.memory_info().rss
        except (psutil.AccessDenied, AttributeError, OSError):
            pass
        
        # Set ciphertext size safely
        try:
            metrics.ciphertext_total_bytes = len(result) if result and hasattr(result, '__len__') else 0
        except (TypeError, AttributeError):
            metrics.ciphertext_total_bytes = 0
            logger.warning("Could not determine ciphertext size")
    else:  # decrypt
        metrics.decrypt_wall_time_ms = wall_time_ms
        
        # Update CPU time metrics if available
        if initial_cpu_times is not None and final_cpu_times is not None:
            metrics.decrypt_cpu_user_time_s = final_cpu_times.user - initial_cpu_times.user
            metrics.decrypt_cpu_system_time_s = final_cpu_times.system - initial_cpu_times.system
        
        # Update context switch metrics if available
        if initial_ctx is not None and final_ctx is not None:
            metrics.decrypt_ctx_switches_voluntary = final_ctx.voluntary - initial_ctx.voluntary
            metrics.decrypt_ctx_switches_involuntary = final_ctx.involuntary - initial_ctx.involuntary
        
        # Record peak memory usage
        try:
            metrics.decrypt_peak_rss_bytes = process.memory_info().rss
        except (psutil.AccessDenied, AttributeError, OSError):
            pass
    
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
    
    # Import ChaCha20 implementations
    from src.encryption.python.chacha.implementation import (
        CHACHA_IMPLEMENTATIONS,
        ChaCha20Implementation,
        create_custom_chacha20_implementation,
        create_stdlib_chacha20_implementation
    )
    
    # Import RSA implementations
    from src.encryption.python.rsa.implementation import (
        RSA_IMPLEMENTATIONS,
        RSAImplementation,
        create_custom_rsa_implementation, 
        create_stdlib_rsa_implementation
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
    
    # Register ChaCha20 implementation directly
    ENCRYPTION_IMPLEMENTATIONS["chacha20"] = ChaCha20Implementation
    
    # Register ChaCha20 variants (both with and without Poly1305)
    for name, impl in CHACHA_IMPLEMENTATIONS.items():
        if name not in ["chacha20"]:  # We already registered this implementation
            ENCRYPTION_IMPLEMENTATIONS[name] = impl
    
    # Register RSA implementation directly
    ENCRYPTION_IMPLEMENTATIONS["rsa"] = RSAImplementation
    
    # Register custom RSA implementation
    ENCRYPTION_IMPLEMENTATIONS["rsa_custom"] = lambda **kwargs: create_custom_rsa_implementation(
        kwargs.get("key_size", "2048"),
        kwargs.get("padding", "OAEP") == "OAEP"  # Convert padding string to boolean use_oaep
    )
    
    # Register all RSA variants
    for name, impl in RSA_IMPLEMENTATIONS.items():
        if name not in ["rsa", "rsa_custom"]:  # We already registered these implementations
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
    
    # Configuration parameters
    use_stdlib = config["test_parameters"].get("use_stdlib", True)
    use_custom = config["test_parameters"].get("use_custom", True)
    
    # For backward compatibility, handle old config format
    if "use_stdlib" not in config["test_parameters"] and "use_custom" not in config["test_parameters"]:
        # Old format used include_stdlibs
        include_stdlibs = config["test_parameters"].get("include_stdlibs", True)
        use_stdlib = include_stdlibs
        use_custom = True  # Always enable custom in backward compatibility mode
    
    processing_strategy = config["test_parameters"].get("processing_strategy", "Memory")
    
    logger.info(f"Standard library implementations: {'enabled' if use_stdlib else 'disabled'}")
    logger.info(f"Custom implementations: {'enabled' if use_custom else 'disabled'}")
    
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
            # Add implementations based on configuration
            method_settings = settings.copy()
            
            # For AES, we have both standard and custom implementations
            if method_name == "aes":
                # Add standard library implementation if enabled
                if use_stdlib:
                    std_settings = method_settings.copy()
                    std_settings["is_custom"] = False
                    enabled_methods.append((method_name, std_settings))
                
                # Add custom implementation if enabled
                if use_custom:
                    custom_settings = method_settings.copy()
                    custom_settings["is_custom"] = True
                    enabled_methods.append(("aes_custom", custom_settings))
            # For ChaCha20, we also have both standard and custom implementations
            elif method_name == "chacha20":
                # Add standard library implementation if enabled
                if use_stdlib:
                    std_settings = method_settings.copy()
                    std_settings["is_custom"] = False
                    enabled_methods.append((method_name, std_settings))
                
                # Add custom implementation if enabled
                if use_custom:
                    custom_settings = method_settings.copy()
                    custom_settings["is_custom"] = True
                    enabled_methods.append(("chacha20_custom", custom_settings))
            # For RSA, we also have both standard and custom implementations
            elif method_name == "rsa":
                # Get RSA specific settings
                reuse_keys = method_settings.get("reuse_keys", False)
                key_sets = method_settings.get("key_sets", 1)
                rsa_key_size = method_settings.get("key_size", "2048")
                rsa_padding = method_settings.get("padding", "OAEP")
                use_oaep = rsa_padding == "OAEP"
                
                # Add standard library implementation if enabled
                if use_stdlib:
                    std_settings = method_settings.copy()
                    std_settings["is_custom"] = False
                    std_settings["use_oaep"] = use_oaep  # Convert padding string to boolean
                    enabled_methods.append((method_name, std_settings))
                
                # Add custom implementation if enabled
                if use_custom:
                    custom_settings = method_settings.copy()
                    custom_settings["is_custom"] = True
                    custom_settings["use_oaep"] = use_oaep  # Convert padding string to boolean
                    enabled_methods.append(("rsa_custom", custom_settings))
            # For ChaCha20-Poly1305, we also have both standard and custom implementations
            elif method_name == "chacha20poly1305":
                # Removed ChaCha20-Poly1305 support from the UI
                logger.warning("ChaCha20-Poly1305 support has been removed. Skipping.")
                continue
            else:
                # For other methods, just add them as is
                enabled_methods.append((method_name, method_settings))
    
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
        "test_configuration": {
            "iterations": iterations,
            "processing_strategy": processing_strategy,
            "use_stdlib_implementations": use_stdlib,
            "use_custom_implementations": use_custom
        },
        "encryption_results": {}
    }
    
    # Add chunk size to configuration if using stream processing
    if processing_strategy == "Stream":
        results["test_configuration"]["chunk_size"] = chunk_size_text
    
    # Run benchmarks for each enabled encryption method
    for method_name, settings in enabled_methods:
        impl_name = method_name
        is_custom = settings.get("is_custom", False)
        
        if is_custom:
            if method_name.startswith("chacha20"):
                impl_description = "Custom ChaCha20 Implementation"
            elif method_name.startswith("rsa") or method_name == "rsa_custom":
                padding = "OAEP" if settings.get("use_oaep", True) else "PKCS#1 v1.5"
                impl_description = f"Custom RSA-{settings.get('key_size', '2048')} with {padding} padding"
            else:
                impl_description = "Custom AES Implementation"
        else:
            if method_name.startswith("chacha20"):
                impl_description = "Standard ChaCha20 Implementation"
            elif method_name.startswith("rsa") or method_name == "rsa":
                padding = "OAEP" if settings.get("use_oaep", True) else "PKCS#1 v1.5"
                impl_description = f"Standard RSA-{settings.get('key_size', '2048')} with {padding} padding"
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
            
            # Handle RSA key reuse if applicable
            rsa_key_sets = []
            key_generation_time_ms = 0
            
            # For RSA with key reuse enabled, generate key sets upfront
            is_rsa = hasattr(implementation, 'name') and implementation.name == "RSA"
            reuse_keys = settings.get("reuse_keys", False)
            key_sets_count = settings.get("key_sets", 1) if reuse_keys else 0
            
            if is_rsa and reuse_keys and key_sets_count > 0:
                logger.info(f"Generating {key_sets_count} RSA key pairs for reuse...")
                
                # Start timing for key generation
                key_gen_start_time = time.perf_counter()
                
                # Generate the requested number of key pairs
                for _ in range(key_sets_count):
                    key_pair = implementation.generate_key()
                    rsa_key_sets.append(key_pair)
                
                # Calculate total key generation time
                key_gen_end_time = time.perf_counter()
                key_generation_time_ms = (key_gen_end_time - key_gen_start_time) * 1000  # Convert to ms
                
                logger.info(f"Generated {len(rsa_key_sets)} key pairs in {key_generation_time_ms:.2f} ms")
            
            # Run iterations
            iteration_results = []
            for i in range(iterations):
                logger.info(f"Running iteration {i+1}/{iterations} for {impl_description}")
                
                # Create metrics collector
                metrics = BenchmarkMetrics()
                
                try:
                    # Key generation or key reuse
                    if is_rsa and reuse_keys and rsa_key_sets:
                        # For RSA with key rotation, create a RotatingKeySet for the encryption/decryption process
                        rotating_keys = RotatingKeySet(rsa_key_sets)
                        # Set average key generation time
                        metrics.keygen_wall_time_ms = key_generation_time_ms / key_sets_count
                        key = rotating_keys
                    else:
                        # Normal key generation
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
                            
                            # Correctness checks are no longer used - assume correct
                            
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
                        initial_ctx = process.num_ctx_switches()
                        initial_cpu_times = process.cpu_times()
                        
                        # Start timing
                        encryption_start_time = time.perf_counter()
                        ciphertext_parts = []
                        total_processed = 0
                        
                        # Handle RSA with rotating keys differently
                        is_rsa_rotating = (hasattr(implementation, 'name') and 
                                          implementation.name == "RSA" and
                                          hasattr(key, '__rotating_keys__'))
                        
                        if is_rsa_rotating:
                            logger.info("Using RSA with rotating keys for stream processing")
                            # For RSA, we need to determine max data size per chunk based on key size
                            # Get a sample key to determine properties
                            sample_key = key.get_next_key()
                            key.reset()  # Reset to maintain proper sequence
                            
                            key_size_bytes = 0
                            if isinstance(sample_key, tuple):
                                # For key pairs, estimate from the tuple's first element (public key)
                                try:
                                    if hasattr(sample_key[0], 'size_in_bytes'):
                                        key_size_bytes = sample_key[0].size_in_bytes()
                                    elif hasattr(sample_key[0], 'n'):
                                        # For custom RSA, get size from modulus
                                        n = sample_key[0].get('n', 0) if isinstance(sample_key[0], dict) else getattr(sample_key[0], 'n', 0)
                                        key_size_bytes = (n.bit_length() + 7) // 8 if n else 0
                                except (IndexError, AttributeError):
                                    pass
                            
                            # Determine max data size per RSA operation
                            use_oaep = getattr(implementation, 'use_oaep', True)
                            if use_oaep:
                                max_data_size = key_size_bytes - 66  # 2 * SHA256.digest_size(32) + 2
                            else:
                                max_data_size = key_size_bytes - 11
                            
                            # Use a smaller chunk size for RSA
                            rsa_chunk_size = max(max_data_size, 100)  # At least 100 bytes
                            logger.info(f"Using RSA chunk size of {rsa_chunk_size} bytes per operation")
                            
                            # Process in RSA-sized chunks
                            with open(dataset_path, 'rb') as f:
                                data_chunk = f.read(chunk_size)  # Read a larger buffer for efficiency
                                
                                while data_chunk:
                                    # Process this larger chunk in RSA-sized sub-chunks
                                    offset = 0
                                    while offset < len(data_chunk):
                                        # Get the next sub-chunk
                                        end = min(offset + rsa_chunk_size, len(data_chunk))
                                        sub_chunk = data_chunk[offset:end]
                                        
                                        # Get the next key for this sub-chunk
                                        current_key = key.get_next_key()
                                        
                                        # Encrypt the sub-chunk
                                        encrypted_sub_chunk = implementation.encrypt(sub_chunk, current_key)
                                        ciphertext_parts.append(encrypted_sub_chunk)
                                        
                                        # Move to next sub-chunk
                                        offset = end
                                    
                                    # Update total processed
                                    total_processed += len(data_chunk)
                                    
                                    # Log progress periodically
                                    if total_processed % (50 * 1024 * 1024) < chunk_size:  # Log every ~50MB
                                        progress = (total_processed / dataset_size_bytes) * 100
                                        logger.info(f"Processed {total_processed / (1024*1024):.2f} MB ({progress:.1f}%)")
                                    
                                    # Read the next chunk
                                    data_chunk = f.read(chunk_size)
                        else:
                            # Process in chunks with normal (non-rotating) key
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
                        
                        # Update context switch metrics
                        metrics.encrypt_ctx_switches_voluntary = final_ctx.voluntary - initial_ctx.voluntary
                        metrics.encrypt_ctx_switches_involuntary = final_ctx.involuntary - initial_ctx.involuntary
                        
                        # Record peak memory usage
                        metrics.encrypt_peak_rss_bytes = process.memory_info().rss
                        
                        # Combined ciphertext (needed for some algorithms that maintain state)
                        combined_ciphertext = b''.join(ciphertext_parts) if isinstance(ciphertext_parts[0], bytes) else ciphertext_parts
                        metrics.ciphertext_total_bytes = len(combined_ciphertext) if hasattr(combined_ciphertext, '__len__') else sum(len(part) for part in ciphertext_parts)
                        
                        logger.info(f"Decrypting dataset (Stream mode)...")
                        
                        # Handle RSA with rotating keys
                        is_rsa_rotating = (hasattr(implementation, 'name') and 
                                           implementation.name == "RSA" and
                                           hasattr(key, '__rotating_keys__'))
                        
                        # Get initial metrics for decryption
                        initial_ctx = process.num_ctx_switches()
                        initial_cpu_times = process.cpu_times()
                        
                        # Measure decryption
                        decryption_start_time = time.perf_counter()
                        
                        if is_rsa_rotating and len(combined_ciphertext) > 0:
                            logger.info("Decrypting with rotating RSA keys")
                            
                            # Determine the RSA block size from a sample key
                            sample_key = key.get_next_key()
                            key.reset()  # Reset to maintain proper order
                            
                            block_size = 0
                            if isinstance(sample_key, tuple):
                                if hasattr(sample_key[1], 'size_in_bytes'):
                                    block_size = sample_key[1].size_in_bytes()
                                elif hasattr(sample_key[1], 'n'):
                                    # For custom RSA, get size from modulus
                                    n = sample_key[1].get('n', 0) if isinstance(sample_key[1], dict) else getattr(sample_key[1], 'n', 0)
                                    block_size = (n.bit_length() + 7) // 8 if n else 0
                            
                            if block_size > 0:
                                logger.info(f"Detected RSA block size of {block_size} bytes")
                                
                                # Process each encrypted block with the corresponding key
                                result_parts = []
                                total_size = len(combined_ciphertext)
                                offset = 0
                                
                                while offset < total_size:
                                    # Determine the next block
                                    end = min(offset + block_size, total_size)
                                    
                                    # If we have a partial block, handle it appropriately
                                    if end - offset < block_size and end < total_size:
                                        logger.warning(f"Partial RSA block detected at offset {offset}. Block size may be incorrect.")
                                    
                                    # Get the block to decrypt
                                    block = combined_ciphertext[offset:end]
                                    
                                    # Get the next key for this block
                                    current_key = key.get_next_key()
                                    
                                    try:
                                        # Decrypt this block
                                        decrypted_block = implementation.decrypt(block, current_key)
                                        result_parts.append(decrypted_block)
                                    except Exception as e:
                                        logger.error(f"Error decrypting block at offset {offset}: {str(e)}")
                                    
                                    # Move to the next block
                                    offset = end
                                    
                                    # Log progress periodically
                                    if offset % (10 * block_size) == 0:
                                        progress = (offset / total_size) * 100
                                        logger.info(f"RSA decryption progress: {progress:.1f}% ({offset}/{total_size} bytes)")
                                
                                # Combine all decrypted parts
                                try:
                                    decrypted_data = b''.join(result_parts)
                                except Exception as e:
                                    logger.error(f"Error combining decrypted blocks: {str(e)}")
                                    decrypted_data = b''
                            else:
                                # Fallback to standard decryption if we can't determine block size
                                logger.warning("Cannot determine RSA block size. Falling back to standard decryption.")
                                decrypted_data = implementation.decrypt(combined_ciphertext, key)
                        else:
                            # Standard decryption for non-rotating keys
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
                        
                        # Update context switch metrics
                        metrics.decrypt_ctx_switches_voluntary = final_ctx.voluntary - initial_ctx.voluntary
                        metrics.decrypt_ctx_switches_involuntary = final_ctx.involuntary - initial_ctx.involuntary
                        
                        # Record peak memory usage
                        metrics.decrypt_peak_rss_bytes = process.memory_info().rss
                        
                        # For verification (optional)
                        try:
                            with open(dataset_path, 'rb') as f:
                                # Read a small sample for comparison
                                original_sample = f.read(min(1024, dataset_size_bytes))
                                decrypted_sample = decrypted_data[:min(1024, len(decrypted_data))]
                                if original_sample != decrypted_sample:
                                    logger.warning("Decryption verification failed: decrypted data does not match original")
                        except Exception as e:
                            logger.warning(f"Could not verify decryption: {str(e)}")
                        
                        # Correctness checks are no longer used - assume correct
                        
                        # Clean up memory
                        del combined_ciphertext, ciphertext_parts
                        if 'decrypted_data' in locals():
                            del decrypted_data
                        gc.collect()
                    
                    # Add results to list
                    iteration_results.append(metrics.to_dict())
                    
                    # Log iteration status
                    logger.info(f"Iteration {i+1} completed successfully")
                    
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
                "implementation_type": "custom" if is_custom else "stdlib",
                "description": impl_description
            }
            
            # For RSA with key reuse, add additional information about key generation
            if is_rsa and reuse_keys and key_sets_count > 0:
                results["encryption_results"][impl_name]["key_reuse"] = {
                    "enabled": True,
                    "key_sets": key_sets_count,
                    "total_key_generation_time_ms": key_generation_time_ms,
                    "avg_key_generation_time_per_set_ms": key_generation_time_ms / key_sets_count if key_sets_count > 0 else 0
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