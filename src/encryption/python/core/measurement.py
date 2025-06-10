#!/usr/bin/env python3
"""
CryptoBench Pro - Measurement Module
Provides functions for measuring encryption and decryption performance.
"""

import time
import logging
import psutil
import gc

# Setup logging
logger = logging.getLogger("PythonCore")

def measure_encryption_metrics(metrics, process_func, implementation, data, key, original_plaintext=None):
    """
    Universal method to measure encryption metrics regardless of implementation approach.
    Works for both regular memory processing and memory-mapped processing.
    
    Args:
        metrics: BenchmarkMetrics instance to update
        process_func: Function to measure (encrypt or decrypt)
        implementation: The encryption implementation
        data: Data to process (plaintext or ciphertext)
        key: Encryption key (can be a single key or a key pair tuple for RSA)
        original_plaintext: For decryption, the original plaintext for correctness checking
        
    Returns:
        The processed data (ciphertext or plaintext)
    """
    # For encryption, use the built-in metrics measurement
    if process_func.__name__ == 'encrypt':
        return metrics.measure_encrypt(process_func, data, key)
    
    # For decryption, use the built-in metrics measurement with correctness check
    elif process_func.__name__ == 'decrypt':
        return metrics.measure_decrypt(process_func, data, key, original_plaintext or data)
    
    # Fallback for other operations (shouldn't happen with current implementation)
    else:
        logger.warning(f"Unexpected function name: {process_func.__name__}")
        return process_func(data, key)

def measure_chunked_encryption(metrics, process_func, implementation, chunks, key, chunk_size=1024*1024):
    """
    Measure encryption metrics when processing data in chunks (for stream mode).
    
    Args:
        metrics: BenchmarkMetrics instance to update
        process_func: Function to measure (encrypt_stream or decrypt_stream)
        implementation: The encryption implementation
        chunks: List of data chunks to process
        key: Encryption key (can be a single key or a key pair tuple for RSA)
        chunk_size: Size of each chunk in bytes
        
    Returns:
        List of processed chunks
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
    
    try:
        initial_memory = process.memory_info()
    except (psutil.AccessDenied, AttributeError, OSError):
        initial_memory = None
    
    # Process each chunk
    results = []
    total_bytes = 0
    
    # Measure wall time with nanosecond precision
    start_time = time.perf_counter_ns()
    
    for i, chunk in enumerate(chunks):
        try:
            # Check if we're working with a rotating key set 
            if hasattr(key, '__rotating_keys__'):
                # For encryption with chunked data and rotating keys, we want to use a consistent key
                # within each chunk, but rotate for different chunks
                actual_key = key.get_next_key()
                
                # Handle special stream encryption methods if available
                if hasattr(implementation, 'encrypt_stream') and process_func.__name__ == 'encrypt':
                    result = implementation.encrypt_stream(chunk, actual_key, i)
                elif hasattr(implementation, 'decrypt_stream') and process_func.__name__ == 'decrypt':
                    result = implementation.decrypt_stream(chunk, actual_key)
                else:
                    # Fallback to normal processing
                    result = process_func(chunk, actual_key)
            else:
                # Use special stream methods if available
                if hasattr(implementation, 'encrypt_stream') and process_func.__name__ == 'encrypt':
                    result = implementation.encrypt_stream(chunk, key, i)
                elif hasattr(implementation, 'decrypt_stream') and process_func.__name__ == 'decrypt':
                    result = implementation.decrypt_stream(chunk, key)
                else:
                    # Fallback to normal processing
                    result = process_func(chunk, key)
                
            results.append(result)
            total_bytes += len(result) if result and hasattr(result, '__len__') else 0
                
        except Exception as e:
            logger.error(f"Error in {process_func.__name__} chunk {i}: {str(e)}")
            results.append(b'')
    
    end_time = time.perf_counter_ns()
    
    # Calculate metrics
    operation_time_ns = end_time - start_time
    
    # Get final metrics
    try:
        final_cpu_times = process.cpu_times() if initial_cpu_times is not None else None
    except (psutil.AccessDenied, AttributeError, OSError):
        final_cpu_times = None
    
    try:
        final_ctx = process.num_ctx_switches() if initial_ctx is not None else None
    except (psutil.AccessDenied, AttributeError, OSError):
        final_ctx = None
    
    try:
        final_memory = process.memory_info()
    except (psutil.AccessDenied, AttributeError, OSError):
        final_memory = None
    
    # Update the correct metrics based on function name
    if process_func.__name__ == 'encrypt':
        metrics.encrypt_time_ns = operation_time_ns
        
        # Update CPU time metrics if available
        if initial_cpu_times is not None and final_cpu_times is not None:
            cpu_user_diff = final_cpu_times.user - initial_cpu_times.user
            cpu_system_diff = final_cpu_times.system - initial_cpu_times.system
            total_cpu_time = cpu_user_diff + cpu_system_diff
            
            # Convert to nanoseconds
            metrics.encrypt_cpu_time_ns = int(total_cpu_time * 1_000_000_000)
            
            # Calculate CPU percentage
            wall_time_s = operation_time_ns / 1_000_000_000
            if wall_time_s > 0:
                metrics.encrypt_cpu_percent = (total_cpu_time / wall_time_s) * 100
        
        # Update context switch metrics if available
        if initial_ctx is not None and final_ctx is not None:
            metrics.encrypt_ctx_switches_voluntary = max(0, final_ctx.voluntary - initial_ctx.voluntary)
            metrics.encrypt_ctx_switches_involuntary = max(0, final_ctx.involuntary - initial_ctx.involuntary)
        
        # Record peak memory usage
        if final_memory is not None:
            metrics.encrypt_peak_memory_bytes = final_memory.rss
            if initial_memory is not None:
                metrics.encrypt_allocated_memory_bytes = max(0, final_memory.rss - initial_memory.rss)
        
        # Set ciphertext size
        metrics.ciphertext_size_bytes = total_bytes
    else:  # decrypt
        metrics.decrypt_time_ns = operation_time_ns
        
        # Update CPU time metrics if available
        if initial_cpu_times is not None and final_cpu_times is not None:
            cpu_user_diff = final_cpu_times.user - initial_cpu_times.user
            cpu_system_diff = final_cpu_times.system - initial_cpu_times.system
            total_cpu_time = cpu_user_diff + cpu_system_diff
            
            # Convert to nanoseconds
            metrics.decrypt_cpu_time_ns = int(total_cpu_time * 1_000_000_000)
            
            # Calculate CPU percentage
            wall_time_s = operation_time_ns / 1_000_000_000
            if wall_time_s > 0:
                metrics.decrypt_cpu_percent = (total_cpu_time / wall_time_s) * 100
        
        # Update context switch metrics if available
        if initial_ctx is not None and final_ctx is not None:
            metrics.decrypt_ctx_switches_voluntary = max(0, final_ctx.voluntary - initial_ctx.voluntary)
            metrics.decrypt_ctx_switches_involuntary = max(0, final_ctx.involuntary - initial_ctx.involuntary)
        
        # Record peak memory usage
        if final_memory is not None:
            metrics.decrypt_peak_memory_bytes = final_memory.rss
            if initial_memory is not None:
                metrics.decrypt_allocated_memory_bytes = max(0, final_memory.rss - initial_memory.rss)
    
    return results

# More specialized measurement functions for different algorithms and modes
# could be added here in the future 