import time
import logging
import psutil
import gc

# setup logging
logger = logging.getLogger("PythonCore")

def measure_encryption_metrics(metrics, process_func, implementation, data, key, original_plaintext=None):
    # for encryption, use the built-in metrics measurement
    if process_func.__name__ == 'encrypt':
        return metrics.measure_encrypt(process_func, data, key)
    
    # for decryption, use the built-in metrics measurement with correctness check
    elif process_func.__name__ == 'decrypt':
        return metrics.measure_decrypt(process_func, data, key, original_plaintext or data)
    

    else:
        logger.warning(f"Unexpected function name: {process_func.__name__}")
        return process_func(data, key)

def measure_chunked_encryption(metrics, process_func, implementation, chunks, key, chunk_size=1024*1024, original_chunks=None):
    if process_func.__name__ == 'encrypt':
        # for encryption, measure the overall encryption process
        results = []
        total_start_time = time.perf_counter_ns()
        
        # get initial system metrics
        process = metrics.process
        initial_cpu_times = None
        initial_memory = None
        
        try:
            initial_cpu_times = process.cpu_times()
            initial_memory = process.memory_info()
        except (psutil.AccessDenied, AttributeError, OSError):
            logger.warning("System metrics not available for chunked processing")
        
        # process all chunks
        for i, chunk in enumerate(chunks):
            try:
                chunk_result = process_func(chunk, key)
                results.append(chunk_result)
            except Exception as e:
                logger.error(f"Error encrypting chunk {i}: {e}")
                results.append(b'')
        
        total_end_time = time.perf_counter_ns()
        
        # calculate final metrics
        try:
            final_cpu_times = process.cpu_times() if initial_cpu_times else None
            final_memory = process.memory_info() if initial_memory else None
        except (psutil.AccessDenied, AttributeError, OSError):
            final_cpu_times = None
            final_memory = None
        
        # set timing metrics
        metrics.encrypt_time_ns = total_end_time - total_start_time
        
        # set CPU metrics if available
        if initial_cpu_times and final_cpu_times:
            cpu_user_diff = final_cpu_times.user - initial_cpu_times.user
            cpu_system_diff = final_cpu_times.system - initial_cpu_times.system
            total_cpu_time = cpu_user_diff + cpu_system_diff
            metrics.encrypt_cpu_time_ns = int(total_cpu_time * 1_000_000_000)
            wall_time_s = (total_end_time - total_start_time) / 1_000_000_000
            if wall_time_s > 0:
                metrics.encrypt_cpu_percent = (total_cpu_time / wall_time_s) * 100
        else:
            metrics.encrypt_cpu_time_ns = 0
            metrics.encrypt_cpu_percent = 100  # Default assumption
        
        # set memory metrics if available
        if final_memory:
            metrics.encrypt_peak_memory_bytes = final_memory.rss
            if initial_memory:
                metrics.encrypt_allocated_memory_bytes = max(0, final_memory.rss - initial_memory.rss)
        
        # set ciphertext size
        metrics.ciphertext_size_bytes = sum(len(r) for r in results if r)
        
        return results
        
    elif process_func.__name__ == 'decrypt':
        # for decryption, measure the overall decryption process
        results = []
        total_start_time = time.perf_counter_ns()
        
        # get initial system metrics  
        process = metrics.process
        initial_cpu_times = None
        initial_memory = None
        
        try:
            initial_cpu_times = process.cpu_times()
            initial_memory = process.memory_info()
        except (psutil.AccessDenied, AttributeError, OSError):
            logger.warning("System metrics not available for chunked processing")
        
        # process all chunks
        for i, chunk in enumerate(chunks):
            try:
                chunk_result = process_func(chunk, key)
                results.append(chunk_result)
            except Exception as e:
                logger.error(f"Error decrypting chunk {i}: {e}")
                results.append(b'')
        
        total_end_time = time.perf_counter_ns()
        
        # calculate final metrics
        try:
            final_cpu_times = process.cpu_times() if initial_cpu_times else None
            final_memory = process.memory_info() if initial_memory else None
        except (psutil.AccessDenied, AttributeError, OSError):
            final_cpu_times = None
            final_memory = None
        
        # set timing metrics
        metrics.decrypt_time_ns = total_end_time - total_start_time
        
        # set CPU metrics if available
        if initial_cpu_times and final_cpu_times:
            cpu_user_diff = final_cpu_times.user - initial_cpu_times.user
            cpu_system_diff = final_cpu_times.system - initial_cpu_times.system
            total_cpu_time = cpu_user_diff + cpu_system_diff
            metrics.decrypt_cpu_time_ns = int(total_cpu_time * 1_000_000_000)
            wall_time_s = (total_end_time - total_start_time) / 1_000_000_000
            if wall_time_s > 0:
                metrics.decrypt_cpu_percent = (total_cpu_time / wall_time_s) * 100
        else:
            metrics.decrypt_cpu_time_ns = 0
            metrics.decrypt_cpu_percent = 100  # Default assumption
        
        # set memory metrics if available
        if final_memory:
            metrics.decrypt_peak_memory_bytes = final_memory.rss
            if initial_memory:
                metrics.decrypt_allocated_memory_bytes = max(0, final_memory.rss - initial_memory.rss)
        
        # verify correctness by comparing a few chunks
        if original_chunks:
            correctness_checks = min(5, len(original_chunks), len(results))
            for i in range(correctness_checks):
                if original_chunks[i] != results[i]:
                    metrics.correctness_passed = False
                    logger.error(f"Correctness check failed for chunk {i} in chunked decryption")
                    break
            else:
                metrics.correctness_passed = True
        
        return results
    
    else:
        # fallback for unknown function types
        logger.warning(f"Unknown function type for chunked encryption: {process_func.__name__}")
        results = []
        for chunk in chunks:
            try:
                result = process_func(chunk, key)
                results.append(result)
            except Exception as e:
                logger.error(f"Error processing chunk: {e}")
                results.append(b'')
        return results

# more specialized measurement functions for different algorithms and modes
# could be added here in the future 