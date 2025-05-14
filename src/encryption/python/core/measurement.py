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

def measure_encryption_metrics(metrics, process_func, implementation, data, key, is_memory_mapped=False, chunk_index=0):
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
        chunk_index: For stream mode, the index of the current chunk
        
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
    
    # Process based on the type of function and data
    try:
        # Check if we're working with a rotating key set 
        if hasattr(key, '__rotating_keys__'):
            # Get the next key from the rotating key set
            actual_key = key.get_next_key()
            
            # Special handling for RSA in stream mode
            if hasattr(implementation, 'name') and 'rsa' in implementation.name.lower():
                logger.debug(f"Using rotating key set for RSA {process_func.__name__} (chunk {chunk_index})")
            
            # Execute with the rotated key
            result = process_func(data, actual_key)
        else:
            # Regular key processing
            result = process_func(data, key)
    except Exception as e:
        logger.error(f"Error in {process_func.__name__}: {str(e)}")
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
    
    # Process each chunk
    results = []
    total_bytes = 0
    
    # Measure wall time
    start_time = time.perf_counter()
    
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
        
        # Set ciphertext size
        metrics.ciphertext_total_bytes = total_bytes
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
    
    return results

# More specialized measurement functions for different algorithms and modes
# could be added here in the future 