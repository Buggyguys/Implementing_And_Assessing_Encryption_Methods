import os
import json
import logging

# setup logging
logger = logging.getLogger("PythonCore")

def calculate_aggregated_metrics(iterations_data, dataset_size_bytes):
    # calculate aggregated metrics from iteration data 
    if not iterations_data:
        return {}
    
    # count successful iterations
    iterations_completed = len(iterations_data)
    
    # check correctness - all iterations must pass
    all_correctness_checks_passed = all(
        data.get("correctness_passed", True) for data in iterations_data
    )
    
    # function to safely compute average
    def safe_avg(values):
        # compute average safely handling empty lists
        values = [v for v in values if v is not None]  # filter out None values
        return sum(values) / len(values) if values else 0
    
    # extract timing metrics (all in nanoseconds)
    keygen_times_ns = [data.get("keygen_time_ns", 0) for data in iterations_data]
    encrypt_times_ns = [data.get("encrypt_time_ns", 0) for data in iterations_data]
    decrypt_times_ns = [data.get("decrypt_time_ns", 0) for data in iterations_data]
    
    # CPU timing metrics (all in nanoseconds)
    keygen_cpu_times_ns = [data.get("keygen_cpu_time_ns", 0) for data in iterations_data]
    encrypt_cpu_times_ns = [data.get("encrypt_cpu_time_ns", 0) for data in iterations_data]
    decrypt_cpu_times_ns = [data.get("decrypt_cpu_time_ns", 0) for data in iterations_data]
    
    # CPU percentages
    keygen_cpu_percentages = [data.get("keygen_cpu_percent", 100) for data in iterations_data]
    encrypt_cpu_percentages = [data.get("encrypt_cpu_percent", 100) for data in iterations_data]
    decrypt_cpu_percentages = [data.get("decrypt_cpu_percent", 100) for data in iterations_data]
    
    # memory metrics
    keygen_memory = [data.get("keygen_peak_memory_bytes", 0) for data in iterations_data]
    encrypt_memory = [data.get("encrypt_peak_memory_bytes", 0) for data in iterations_data]
    decrypt_memory = [data.get("decrypt_peak_memory_bytes", 0) for data in iterations_data]
    
    # key and ciphertext sizes
    key_sizes = [data.get("key_size_bytes", 0) for data in iterations_data]
    ciphertext_sizes = [data.get("ciphertext_size_bytes", 0) for data in iterations_data]
    
    # calculate averages
    avg_keygen_time_ns = safe_avg(keygen_times_ns)
    avg_encrypt_time_ns = safe_avg(encrypt_times_ns)
    avg_decrypt_time_ns = safe_avg(decrypt_times_ns)
    
    avg_keygen_cpu_time_ns = safe_avg(keygen_cpu_times_ns)
    avg_encrypt_cpu_time_ns = safe_avg(encrypt_cpu_times_ns)
    avg_decrypt_cpu_time_ns = safe_avg(decrypt_cpu_times_ns)
    
    avg_keygen_cpu_percent = safe_avg(keygen_cpu_percentages)
    avg_encrypt_cpu_percent = safe_avg(encrypt_cpu_percentages)
    avg_decrypt_cpu_percent = safe_avg(decrypt_cpu_percentages)
    
    avg_keygen_memory = safe_avg([m for m in keygen_memory if m > 0])
    avg_encrypt_memory = safe_avg([m for m in encrypt_memory if m > 0])
    avg_decrypt_memory = safe_avg([m for m in decrypt_memory if m > 0])
    
    avg_key_size_bytes = safe_avg([k for k in key_sizes if k > 0])
    avg_ciphertext_size_bytes = safe_avg(ciphertext_sizes)
    
    # convert times to seconds for additional metrics
    avg_keygen_time_s = avg_keygen_time_ns / 1_000_000_000
    avg_encrypt_time_s = avg_encrypt_time_ns / 1_000_000_000
    avg_decrypt_time_s = avg_decrypt_time_ns / 1_000_000_000
    
    # calculate throughput safely (avoid division by zero)
    avg_encrypt_throughput_bps = 0
    avg_decrypt_throughput_bps = 0
    avg_throughput_encrypt_mb_per_s = 0
    avg_throughput_decrypt_mb_per_s = 0
    
    if avg_encrypt_time_s > 0:
        avg_encrypt_throughput_bps = dataset_size_bytes / avg_encrypt_time_s
        avg_throughput_encrypt_mb_per_s = (dataset_size_bytes / (1024 * 1024)) / avg_encrypt_time_s
    
    if avg_decrypt_time_s > 0:
        avg_decrypt_throughput_bps = dataset_size_bytes / avg_decrypt_time_s
        avg_throughput_decrypt_mb_per_s = (dataset_size_bytes / (1024 * 1024)) / avg_decrypt_time_s
    
    # calculate overhead percentage safely (avoid division by zero)
    avg_ciphertext_overhead_percent = 0
    if dataset_size_bytes > 0 and avg_ciphertext_size_bytes > 0:
        avg_ciphertext_overhead_percent = ((avg_ciphertext_size_bytes - dataset_size_bytes) / dataset_size_bytes) * 100
    
    # totals
    total_keygen_time_ns = sum(keygen_times_ns)
    total_encrypt_time_ns = sum(encrypt_times_ns)
    total_decrypt_time_ns = sum(decrypt_times_ns)
    total_num_keys = len([k for k in key_sizes if k > 0])
    total_key_size_bytes = sum([k for k in key_sizes if k > 0])
    correctness_failures = len([d for d in iterations_data if not d.get("correctness_passed", True)])
    
    # get operational metrics from the first iteration (assuming they're constant across iterations)
    first_iter = iterations_data[0] if iterations_data else {}
    thread_count = first_iter.get("thread_count", 1)
    process_priority = first_iter.get("process_priority", 0)
    block_size_bytes = first_iter.get("block_size_bytes")
    iv_size_bytes = first_iter.get("iv_size_bytes")
    num_rounds = first_iter.get("num_rounds")
    is_custom_implementation = first_iter.get("is_custom_implementation", False)
    library_version = first_iter.get("library_version", "PyCryptodome")
    
    # build the aggregated metrics dictionary  
    result = {
        "iterations_completed": iterations_completed,
        "all_correctness_checks_passed": all_correctness_checks_passed,
        
        # average timing metrics (nanoseconds)
        "avg_keygen_time_ns": avg_keygen_time_ns,
        "avg_encrypt_time_ns": avg_encrypt_time_ns,
        "avg_decrypt_time_ns": avg_decrypt_time_ns,
        
        # average timing metrics (seconds)
        "avg_keygen_time_s": avg_keygen_time_s,
        "avg_encrypt_time_s": avg_encrypt_time_s,
        "avg_decrypt_time_s": avg_decrypt_time_s,
        
        # average CPU timing metrics (nanoseconds)
        "avg_keygen_cpu_time_ns": avg_keygen_cpu_time_ns,
        "avg_encrypt_cpu_time_ns": avg_encrypt_cpu_time_ns,
        "avg_decrypt_cpu_time_ns": avg_decrypt_cpu_time_ns,
        
        # average CPU percentages
        "avg_keygen_cpu_percent": avg_keygen_cpu_percent,
        "avg_encrypt_cpu_percent": avg_encrypt_cpu_percent,
        "avg_decrypt_cpu_percent": avg_decrypt_cpu_percent,
        
        # average memory metrics
        "avg_keygen_peak_memory_bytes": avg_keygen_memory,
        "avg_encrypt_peak_memory_bytes": avg_encrypt_memory,
        "avg_decrypt_peak_memory_bytes": avg_decrypt_memory,
        "avg_keygen_peak_memory_mb": avg_keygen_memory / (1024 * 1024) if avg_keygen_memory > 0 else 0,
        "avg_encrypt_peak_memory_mb": avg_encrypt_memory / (1024 * 1024) if avg_encrypt_memory > 0 else 0,
        "avg_decrypt_peak_memory_mb": avg_decrypt_memory / (1024 * 1024) if avg_decrypt_memory > 0 else 0,
        
        # key and data metrics
        "avg_key_size_bytes": avg_key_size_bytes,
        "avg_ciphertext_size_bytes": avg_ciphertext_size_bytes,
        
        # operational metrics
        "thread_count": thread_count,
        "process_priority": process_priority,
        "is_custom_implementation": is_custom_implementation,
        "library_version": library_version,
        
        # throughput metrics
        "avg_encrypt_throughput_bps": avg_encrypt_throughput_bps,
        "avg_decrypt_throughput_bps": avg_decrypt_throughput_bps,
        "avg_throughput_encrypt_mb_per_s": avg_throughput_encrypt_mb_per_s,
        "avg_throughput_decrypt_mb_per_s": avg_throughput_decrypt_mb_per_s,
        "avg_ciphertext_overhead_percent": avg_ciphertext_overhead_percent,
        
        # total metrics
        "total_keygen_time_ns": total_keygen_time_ns,
        "total_encrypt_time_ns": total_encrypt_time_ns,
        "total_decrypt_time_ns": total_decrypt_time_ns,
        "total_num_keys": total_num_keys,
        "total_key_size_bytes": total_key_size_bytes,
        "correctness_failures": correctness_failures
    }
    
    # add algorithm-specific fields if available
    if block_size_bytes is not None:
        result["block_size_bytes"] = block_size_bytes
    if iv_size_bytes is not None:
        result["iv_size_bytes"] = iv_size_bytes
    if num_rounds is not None:
        result["num_rounds"] = num_rounds
    
    return result

def save_results(results, session_dir, session_id):
    # save benchmark results to a JSON file
    try:
        # ensure the results directory exists
        results_dir = os.path.join(session_dir, "results")
        os.makedirs(results_dir, exist_ok=True)
        
        # create results filename
        results_filename = f"python_results.json"
        results_path = os.path.join(results_dir, results_filename)
        
        # save results to file
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=4)
        
        logger.info(f"Results saved to {results_path}")
        return results_path
        
    except Exception as e:
        logger.error(f"Failed to save results: {str(e)}")
        return None 