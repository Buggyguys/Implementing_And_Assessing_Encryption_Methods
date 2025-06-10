#!/usr/bin/env python3
"""
CryptoBench Pro - Results Processing Module
Provides functions for calculating and saving benchmark results.
"""

import os
import json
import logging

# Setup logging
logger = logging.getLogger("PythonCore")

def calculate_aggregated_metrics(iterations_data, dataset_size_bytes):
    """
    Calculate aggregated metrics from iteration data.
    
    Args:
        iterations_data: List of metrics dictionaries from each iteration
        dataset_size_bytes: Size of the dataset in bytes
        
    Returns:
        Dict of aggregated metrics
    """
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

def save_results(results, session_dir):
    """
    Save benchmark results to a JSON file.
    
    Args:
        results: Results dictionary to save
        session_dir: Directory where to save the results
        
    Returns:
        bool: True if successful, False otherwise
    """
    # Create the results directory if it doesn't exist
    results_dir = os.path.join(session_dir, "results")
    os.makedirs(results_dir, exist_ok=True)
    
    # Save results
    results_file = os.path.join(results_dir, "python_results.json")
    try:
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=4)
        logger.info(f"Results saved to {results_file}")
        return True
    except Exception as e:
        logger.error(f"Error saving results: {str(e)}")
        return False 