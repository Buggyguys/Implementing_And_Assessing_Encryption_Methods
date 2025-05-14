#!/usr/bin/env python3
"""
CryptoBench Pro - Benchmark Runner Module
Provides the core functionality for running benchmarks.
"""

import os
import gc
import time
import logging
import traceback
from datetime import datetime

from .metrics import BenchmarkMetrics
from .results import calculate_aggregated_metrics, save_results
from .utils import MemoryMappedDataset, RotatingKeySet, load_dataset
from .measurement import measure_encryption_metrics, measure_chunked_encryption

# Setup logging
logger = logging.getLogger("PythonCore")

def run_benchmarks(config, implementations):
    """
    Run all benchmarks based on the configuration.
    
    Args:
        config: Configuration dictionary
        implementations: Dictionary of registered implementations
        
    Returns:
        bool: True if successful, False otherwise
    """
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
            method_settings = settings.copy()
            
            if method_name == "aes":
                # AES implementations
                if use_stdlib:
                    std_settings = method_settings.copy()
                    std_settings["is_custom"] = False
                    enabled_methods.append((method_name, std_settings))
                
                if use_custom:
                    custom_settings = method_settings.copy()
                    custom_settings["is_custom"] = True
                    enabled_methods.append(("aes_custom", custom_settings))
            elif method_name == "chacha20":
                # ChaCha20 implementations
                if use_stdlib:
                    std_settings = method_settings.copy()
                    std_settings["is_custom"] = False
                    enabled_methods.append((method_name, std_settings))
                
                if use_custom:
                    custom_settings = method_settings.copy()
                    custom_settings["is_custom"] = True
                    enabled_methods.append(("chacha20_custom", custom_settings))
            elif method_name == "rsa":
                # RSA implementations
                reuse_keys = method_settings.get("reuse_keys", False)
                key_sets = method_settings.get("key_sets", 1)
                rsa_key_size = method_settings.get("key_size", "2048")
                rsa_padding = method_settings.get("padding", "OAEP")
                use_oaep = rsa_padding == "OAEP"
                
                if use_stdlib:
                    std_settings = method_settings.copy()
                    std_settings["is_custom"] = False
                    std_settings["use_oaep"] = use_oaep
                    std_settings["reuse_keys"] = reuse_keys
                    std_settings["key_sets"] = key_sets
                    enabled_methods.append((method_name, std_settings))
                
                if use_custom:
                    custom_settings = method_settings.copy()
                    custom_settings["is_custom"] = True
                    custom_settings["use_oaep"] = use_oaep
                    custom_settings["reuse_keys"] = reuse_keys
                    custom_settings["key_sets"] = key_sets
                    enabled_methods.append(("rsa_custom", custom_settings))
            elif method_name == "ecc":
                # ECC implementations
                curve = method_settings.get("curve", "P-256")
                
                if use_stdlib:
                    std_settings = method_settings.copy()
                    std_settings["is_custom"] = False
                    
                    # Use specialized implementation names for different curves
                    curve_safe_name = curve.lower().replace("-", "")
                    impl_name = f"ecc_{curve_safe_name}"
                    if impl_name in implementations:
                        enabled_methods.append((impl_name, std_settings))
                    else:
                        # Fallback to generic ECC implementation
                        enabled_methods.append((method_name, std_settings))
                
                if use_custom:
                    # Custom ECC implementation - use specialized implementations
                    custom_settings = {
                        "curve": curve if curve in ["P-256", "P-384", "P-521"] else "P-256",
                        "is_custom": True
                    }
                    
                    # Use specialized custom implementation names for different curves
                    curve_safe_name = curve.lower().replace("-", "")
                    custom_impl_name = f"ecc_{curve_safe_name}_custom"
                    if custom_impl_name in implementations:
                        enabled_methods.append((custom_impl_name, custom_settings))
                    else:
                        # Fallback to generic custom ECC implementation
                        enabled_methods.append(("ecc_custom", custom_settings))
            else:
                # Other methods
                enabled_methods.append((method_name, method_settings))
    
    if not enabled_methods:
        logger.error("No encryption methods enabled in configuration. Aborting.")
        return False
    
    # Debug: Print encryption implementations
    logger.info(f"Available implementations: {list(implementations.keys())}")
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
        # Get basic info about this method
        impl_name = method_name
        is_custom = settings.get("is_custom", False)
        
        # Create description for logging
        if is_custom:
            impl_description = f"Custom {method_name.upper()} Implementation"
        else:
            impl_description = f"Standard {method_name.upper()} Implementation"
            
        logger.info(f"Running benchmark for {impl_description}")
        
        # Check if implementation exists
        if method_name not in implementations:
            logger.warning(f"No implementation found for {method_name}. Skipping.")
            continue
        
        # Run the benchmark for this method
        try:
            implementation_factory = implementations[method_name]
            implementation = implementation_factory(**settings)
            
            # For RSA with key reuse, pre-generate key sets
            reuse_keys = settings.get("reuse_keys", False)
            key_sets_count = settings.get("key_sets", 1)
            rsa_rotating_keys = None
            
            # Pre-generate RSA keys if key reuse is enabled
            if reuse_keys and ("rsa" in method_name.lower()) and key_sets_count > 0:
                logger.info(f"Pre-generating {key_sets_count} RSA key sets for reuse")
                key_pairs = []
                
                # Track key generation time separately
                key_gen_metrics = BenchmarkMetrics()
                for i in range(key_sets_count):
                    key_pairs.append(key_gen_metrics.measure_keygen(implementation.generate_key))
                
                # Create a rotating key set with these key pairs
                rsa_rotating_keys = RotatingKeySet(key_pairs)
                logger.info(f"Created rotating key set with {key_sets_count} RSA key pairs")
            
            # Run iterations
            iteration_results = []
            for i in range(iterations):
                logger.info(f"Running iteration {i+1}/{iterations} for {impl_description}")
                
                # Create metrics collector
                metrics = BenchmarkMetrics()
                
                try:
                    # Key generation or key selection
                    if rsa_rotating_keys:
                        # Use a key from the rotating key set
                        logger.info(f"Using pre-generated RSA key from rotating key set")
                        key = rsa_rotating_keys.get_next_key()
                        # Add placeholder key generation time (we already measured it)
                        metrics.keygen_wall_time_ms = key_gen_metrics.keygen_wall_time_ms / key_sets_count
                        metrics.keygen_cpu_user_time_s = key_gen_metrics.keygen_cpu_user_time_s / key_sets_count
                        metrics.keygen_cpu_system_time_s = key_gen_metrics.keygen_cpu_system_time_s / key_sets_count
                        metrics.keygen_peak_rss_bytes = key_gen_metrics.keygen_peak_rss_bytes
                    else:
                        # Generate a new key for each iteration
                        key = metrics.measure_keygen(implementation.generate_key)
                    
                    # Encryption
                    if processing_strategy == "Memory":
                        # Memory mode
                        logger.info(f"Encrypting dataset (Memory mode)...")
                        ciphertext = measure_encryption_metrics(
                            metrics, 
                            implementation.encrypt, 
                            implementation, 
                            plaintext_data, 
                            key, 
                            is_memory_mapped=isinstance(plaintext_data, MemoryMappedDataset)
                        )
                        
                        # Force GC before decryption
                        gc.collect()
                        
                        # Decryption
                        logger.info(f"Decrypting dataset (Memory mode)...")
                        if isinstance(plaintext_data, MemoryMappedDataset):
                            # For memory-mapped, we need to get original data for verification
                            original_data = plaintext_data.read_all()
                            decrypted_data = measure_encryption_metrics(
                                metrics,
                                implementation.decrypt,
                                implementation,
                                ciphertext,
                                key,
                                is_memory_mapped=False
                            )
                            del original_data
                        else:
                            # Standard in-memory processing
                            decrypted_data = measure_encryption_metrics(
                                metrics,
                                implementation.decrypt,
                                implementation,
                                ciphertext,
                                key,
                                is_memory_mapped=False
                            )
                            
                        # Clean up memory
                        del ciphertext
                        if 'decrypted_data' in locals():
                            del decrypted_data
                        gc.collect()
                    else:
                        # Stream mode processing
                        logger.info(f"Processing dataset in Stream mode with chunk size {chunk_size_text}...")
                        
                        # Calculate number of chunks
                        total_chunks = (dataset_size_bytes + chunk_size - 1) // chunk_size
                        logger.info(f"Dataset will be processed in {total_chunks} chunks")
                        
                        # Process data in chunks
                        with open(dataset_path, 'rb') as f:
                            # Split the file into chunks for processing
                            chunks = []
                            chunk_number = 0
                            
                            while True:
                                chunk_data = f.read(chunk_size)
                                if not chunk_data:
                                    break
                                chunks.append(chunk_data)
                                chunk_number += 1
                                if chunk_number % 10 == 0:
                                    logger.info(f"Loaded {chunk_number} chunks...")
                            
                            logger.info(f"Loaded {len(chunks)} chunks for processing")
                            
                            # Use the chunked encryption measurement
                            logger.info(f"Encrypting chunks in Stream mode...")
                            encrypted_chunks = measure_chunked_encryption(
                                metrics,
                                implementation.encrypt,
                                implementation,
                                chunks,
                                key,
                                chunk_size=chunk_size
                            )
                            
                            # Force GC before decryption
                            gc.collect()
                            
                            # Decrypt the chunks
                            logger.info(f"Decrypting chunks in Stream mode...")
                            decrypted_chunks = measure_chunked_encryption(
                                metrics,
                                implementation.decrypt,
                                implementation,
                                encrypted_chunks,
                                key,
                                chunk_size=chunk_size
                            )
                            
                            # Clean up
                            del chunks
                            del encrypted_chunks
                            del decrypted_chunks
                            gc.collect()
                    
                    # Add results
                    iteration_results.append(metrics.to_dict())
                    logger.info(f"Iteration {i+1} completed successfully")
                    
                    # Memory usage logging
                    if memory_tracking:
                        current, peak = tracemalloc.get_traced_memory()
                        logger.info(f"Memory after iteration {i+1}: Current {current / (1024*1024):.2f} MB, Peak {peak / (1024*1024):.2f} MB")
                        tracemalloc.reset_peak()
                        
                except Exception as e:
                    logger.error(f"Error in iteration {i+1}: {str(e)}")
                    traceback.print_exc()
                
                # Force GC between iterations
                gc.collect()
            
            # Calculate aggregated metrics
            aggregated_metrics = calculate_aggregated_metrics(iteration_results, dataset_size_bytes)
            
            # Add to results
            results["encryption_results"][impl_name] = {
                "iterations": iteration_results,
                "aggregated_metrics": aggregated_metrics,
                "configuration": settings,
                "implementation_type": "custom" if is_custom else "stdlib",
                "description": impl_description
            }
            
            logger.info(f"Benchmark completed for {impl_description}")
            
        except Exception as e:
            logger.error(f"Error in benchmark for {impl_description}: {str(e)}")
            traceback.print_exc()
    
    # Cleanup
    if memory_tracking:
        tracemalloc.stop()
    
    if processing_strategy == "Memory" and isinstance(plaintext_data, MemoryMappedDataset):
        plaintext_data.close()
        logger.info("Closed memory-mapped dataset")
    
    # Save results
    success = save_results(results, session_dir)
    gc.collect()
    
    return success 