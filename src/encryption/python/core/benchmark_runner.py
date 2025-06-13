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

def get_key_size_bytes(key, implementation):
    """
    Helper function to get key size in bytes for different key types.
    
    Args:
        key: The key object (can be various types)
        implementation: The implementation object to get context
        
    Returns:
        int: Key size in bytes
    """
    try:
        # Handle tuple keys (RSA public/private key pairs)
        if isinstance(key, tuple):
            # RSA keys - get the key size from the public key
            if hasattr(key[0], 'size_in_bytes'):
                return key[0].size_in_bytes()
            elif hasattr(key[0], 'key_size'):
                return key[0].key_size // 8  # Convert bits to bytes
            elif hasattr(key[0], 'n'):  # RSA key with modulus
                # Calculate key size from modulus bit length
                return (key[0].n.bit_length() + 7) // 8
            else:
                logger.warning(f"Unknown RSA key type: {type(key[0])}")
                return 256  # Default to 2048 bits / 8 = 256 bytes
        
        # Handle ECC keys
        elif hasattr(key, 'private_value') or hasattr(key, 'public_key'):  # ECC private key
            if hasattr(key, 'key_size'):
                return key.key_size // 8
            elif hasattr(key, 'curve'):
                # Determine key size from curve
                curve_name = getattr(key.curve, 'name', '').lower()
                if 'p256' in curve_name or 'secp256r1' in curve_name:
                    return 32  # 256 bits / 8
                elif 'p384' in curve_name or 'secp384r1' in curve_name:
                    return 48  # 384 bits / 8
                elif 'p521' in curve_name or 'secp521r1' in curve_name:
                    return 66  # 521 bits / 8 (rounded up)
                else:
                    logger.warning(f"Unknown ECC curve: {curve_name}")
                    return 32  # Default to P-256
            else:
                logger.warning(f"Unknown ECC key type: {type(key)}")
                return 32  # Default to P-256
        
        # Handle RSA keys (single key object)
        elif hasattr(key, 'size_in_bytes'):
            return key.size_in_bytes()
        elif hasattr(key, 'key_size'):
            return key.key_size // 8  # Convert bits to bytes
        elif hasattr(key, 'n'):  # RSA key with modulus
            return (key.n.bit_length() + 7) // 8
        
        # Handle bytes/string keys (AES, ChaCha20, etc.)
        elif hasattr(key, '__len__'):
            return len(key)
        
        # Fallback - try to get from implementation name
        else:
            impl_name = getattr(implementation, 'name', '').lower()
            if 'aes256' in impl_name or 'chacha20' in impl_name:
                return 32  # 256 bits
            elif 'aes192' in impl_name:
                return 24  # 192 bits
            elif 'aes128' in impl_name or 'aes' in impl_name:
                return 16  # 128 bits
            elif 'camellia256' in impl_name:
                return 32
            elif 'camellia192' in impl_name:
                return 24
            elif 'camellia' in impl_name:
                return 16  # Default Camellia-128
            elif 'rsa' in impl_name:
                return 256  # Default to 2048 bits
            elif 'ecc' in impl_name:
                return 32   # Default to P-256
            else:
                logger.warning(f"Could not determine key size for implementation: {impl_name}")
                return 32  # Default fallback
                
    except Exception as e:
        logger.error(f"Error determining key size: {e}")
        return 32  # Safe fallback

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
    
    # Handle both old and new dataset configuration formats
    dataset_info = config["test_parameters"].get("dataset_info")
    if dataset_info:
        # New format with separate symmetric/asymmetric datasets
        symmetric_dataset_path = dataset_info.get("symmetric", {}).get("path")
        asymmetric_dataset_path = dataset_info.get("asymmetric", {}).get("path")
        logger.info(f"Using new dual dataset format:")
        if symmetric_dataset_path:
            logger.info(f"  Symmetric dataset: {symmetric_dataset_path}")
        if asymmetric_dataset_path:
            logger.info(f"  Asymmetric dataset: {asymmetric_dataset_path}")
    else:
        # Old format with single dataset path (for backward compatibility)
        dataset_path = config["test_parameters"].get("dataset_path")
        symmetric_dataset_path = dataset_path
        asymmetric_dataset_path = dataset_path
        logger.info(f"Using legacy single dataset format: {dataset_path}")
    
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
    use_mmap = False  # Disable memory mapping completely to use full in-memory loading
    
    # Initialize variables to avoid UnboundLocalError
    cached_symmetric_dataset = None
    cached_asymmetric_dataset = None
    memory_mapped_symmetric_dataset = None
    memory_mapped_asymmetric_dataset = None
    
    # Load datasets based on processing strategy
    if processing_strategy == "Memory":
        # Memory mode: Load entire datasets
        if symmetric_dataset_path:
            cached_symmetric_dataset = load_dataset(symmetric_dataset_path)
            if cached_symmetric_dataset is None:
                logger.error("Failed to load symmetric dataset. Aborting.")
                return False
            symmetric_size_bytes = len(cached_symmetric_dataset)
            logger.info(f"Symmetric dataset loaded successfully: {symmetric_size_bytes / (1024*1024):.2f} MB")
        
        if asymmetric_dataset_path:
            cached_asymmetric_dataset = load_dataset(asymmetric_dataset_path)
            if cached_asymmetric_dataset is None:
                logger.error("Failed to load asymmetric dataset. Aborting.")
                return False
            asymmetric_size_bytes = len(cached_asymmetric_dataset)
            logger.info(f"Asymmetric dataset loaded successfully: {asymmetric_size_bytes / (1024*1024):.2f} MB")
    else:
        # Stream mode: Use memory-mapped datasets
        if symmetric_dataset_path:
            memory_mapped_symmetric_dataset = MemoryMappedDataset(symmetric_dataset_path)
            symmetric_size_bytes = os.path.getsize(symmetric_dataset_path)
            logger.info(f"Memory-mapped symmetric dataset initialized: {symmetric_size_bytes / (1024*1024):.2f} MB")
        
        if asymmetric_dataset_path:
            memory_mapped_asymmetric_dataset = MemoryMappedDataset(asymmetric_dataset_path)
            asymmetric_size_bytes = os.path.getsize(asymmetric_dataset_path)
            logger.info(f"Memory-mapped asymmetric dataset initialized: {asymmetric_size_bytes / (1024*1024):.2f} MB")
    
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
            elif method_name == "camellia":
                # Camellia implementations
                key_size = method_settings.get("key_size", "256")
                mode = method_settings.get("mode", "GCM").upper()
                
                if use_stdlib:
                    # Special case: Skip Camellia-GCM for standard library mode
                    if mode == "GCM":
                        logger.warning(f"Skipping Camellia-GCM in standard library mode - GCM mode is not supported by standard libraries.")
                        logger.info(f"Camellia-GCM limitation: PyCryptodome doesn't include Camellia cipher, and cryptography.io supports Camellia but not in GCM mode.")
                        logger.info(f"To test both standard and custom Camellia implementations, use CBC, ECB, OFB, or CFB mode instead.")
                        logger.info(f"Supported Camellia modes in standard libraries: CBC, ECB, OFB, CFB")
                    else:
                        std_settings = method_settings.copy()
                        std_settings["is_custom"] = False
                        
                        # Use specialized implementation names for different key sizes and modes
                        if mode in ["CBC", "CTR", "GCM", "ECB", "CFB", "OFB"]:
                            impl_name = f"camellia{key_size}_{mode.lower()}"
                            if impl_name in implementations:
                                enabled_methods.append((impl_name, std_settings))
                            else:
                                # Fallback to generic Camellia implementation
                                enabled_methods.append((method_name, std_settings))
                        else:
                            # Fallback for other modes
                                enabled_methods.append((method_name, std_settings))
                
                if use_custom:
                    custom_settings = method_settings.copy()
                    custom_settings["is_custom"] = True
                    
                    # Use specialized custom implementation names for different key sizes and modes
                    if mode in ["CBC", "CTR", "GCM", "ECB", "CFB", "OFB"]:
                        custom_impl_name = f"camellia{key_size}_{mode.lower()}_custom"
                        if custom_impl_name in implementations:
                            enabled_methods.append((custom_impl_name, custom_settings))
                        else:
                            # Fallback to generic custom Camellia implementation
                            enabled_methods.append(("camellia_custom", custom_settings))
                    else:
                        # Fallback for other modes
                            enabled_methods.append(("camellia_custom", custom_settings))
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
        "datasets": {
            "symmetric": {
                "path": symmetric_dataset_path,
                "size_bytes": symmetric_size_bytes if symmetric_dataset_path else 0
            },
            "asymmetric": {
                "path": asymmetric_dataset_path,
                "size_bytes": asymmetric_size_bytes if asymmetric_dataset_path else 0
            }
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
                        metrics.keygen_time_ns = int(key_gen_metrics.keygen_time_ns / key_sets_count)
                        metrics.keygen_cpu_time_ns = int(key_gen_metrics.keygen_cpu_time_ns / key_sets_count)
                        metrics.keygen_cpu_percent = key_gen_metrics.keygen_cpu_percent
                        metrics.keygen_peak_memory_bytes = key_gen_metrics.keygen_peak_memory_bytes
                        # Set algorithm metadata
                        key_size_bytes = get_key_size_bytes(key, implementation)
                        metrics.set_algorithm_metadata(implementation, key_size_bytes)
                    else:
                        # Generate a new key for each iteration
                        key = metrics.measure_keygen(implementation.generate_key)
                        # Set algorithm metadata after key generation
                        key_size_bytes = get_key_size_bytes(key, implementation)
                        metrics.set_algorithm_metadata(implementation, key_size_bytes)
                    
                    # Determine if this is a symmetric or asymmetric algorithm
                    is_asymmetric = any(keyword in method_name.lower() for keyword in ['rsa', 'ecc'])
                    
                    # Select appropriate dataset based on algorithm type
                    if is_asymmetric:
                        current_dataset_path = asymmetric_dataset_path
                        current_cached_dataset = cached_asymmetric_dataset
                        current_memory_mapped_dataset = memory_mapped_asymmetric_dataset
                        current_dataset_size = asymmetric_size_bytes if asymmetric_dataset_path else 0
                        dataset_type = "asymmetric"
                    else:
                        current_dataset_path = symmetric_dataset_path
                        current_cached_dataset = cached_symmetric_dataset
                        current_memory_mapped_dataset = memory_mapped_symmetric_dataset
                        current_dataset_size = symmetric_size_bytes if symmetric_dataset_path else 0
                        dataset_type = "symmetric"
                    
                    # Check if we have the required dataset for this algorithm type
                    if not current_dataset_path:
                        logger.warning(f"No {dataset_type} dataset available for {impl_description}. Skipping.")
                        continue
                    
                    logger.info(f"Using {dataset_type} dataset for {impl_description}: {current_dataset_path}")
                    
                    # Load or map dataset based on processing strategy
                    if processing_strategy == "Stream" and not is_asymmetric:
                        # Use stream mode for symmetric algorithms (asymmetric doesn't work well with chunking)
                        
                        # Check if the implementation has explicit stream methods
                        if hasattr(implementation, 'encrypt_stream') and hasattr(implementation, 'decrypt_stream'):
                            # Use implementation's own stream methods with user-specified chunk size
                            logger.info(f"Using implementation's native stream mode with chunk size {chunk_size} bytes")
                            
                            # Load the entire dataset for stream processing
                            if current_cached_dataset is None:
                                current_cached_dataset = load_dataset(current_dataset_path)
                                if is_asymmetric:
                                    cached_asymmetric_dataset = current_cached_dataset
                                else:
                                    cached_symmetric_dataset = current_cached_dataset
                            
                            # Use the implementation's stream methods
                            # Create wrapper functions with proper names for measurement
                            def encrypt_stream_wrapper(data, key):
                                return implementation.encrypt_stream(data, key, chunk_size)
                            encrypt_stream_wrapper.__name__ = 'encrypt'
                            
                            def decrypt_stream_wrapper(data, key):
                                return implementation.decrypt_stream(data, key, chunk_size)
                            decrypt_stream_wrapper.__name__ = 'decrypt'
                            
                            ciphertext = measure_encryption_metrics(
                                metrics, 
                                encrypt_stream_wrapper, 
                                implementation, 
                                current_cached_dataset, 
                                key
                            )
                            
                            plaintext = measure_encryption_metrics(
                                metrics, 
                                decrypt_stream_wrapper, 
                                implementation, 
                                ciphertext, 
                                key,
                                current_cached_dataset  # For correctness checking
                            )
                            
                            # Verify correctness
                            if current_cached_dataset == plaintext:
                                metrics.correctness_passed = True
                                logger.info(f"Correctness check passed for {impl_description}")
                            else:
                                metrics.correctness_passed = False
                                logger.error(f"Correctness check failed for {impl_description}")
                            
                            # Set additional metrics
                            metrics.input_size_bytes = len(current_cached_dataset)
                            metrics.decrypted_size_bytes = len(plaintext) if hasattr(plaintext, '__len__') else 0
                            
                            # Clean up
                            del ciphertext
                            del plaintext
                            gc.collect()
                            
                        else:
                            # Fallback to chunked processing using regular encrypt/decrypt methods
                            logger.info(f"Using chunked fallback mode (implementation lacks native stream methods)")
                            
                            if current_memory_mapped_dataset is None:
                                current_memory_mapped_dataset = MemoryMappedDataset(current_dataset_path)
                                if is_asymmetric:
                                    memory_mapped_asymmetric_dataset = current_memory_mapped_dataset
                                else:
                                    memory_mapped_symmetric_dataset = current_memory_mapped_dataset
                                
                            # Use streaming processing with chunked approach (use user-specified chunk size)
                            total_chunks = (current_dataset_size + chunk_size - 1) // chunk_size
                            
                            logger.info(f"Processing {total_chunks} chunks of {chunk_size} bytes each using fallback chunked mode")
                            
                            # Collect all chunks first for proper measurement
                            all_chunks = list(current_memory_mapped_dataset.create_chunks(chunk_size))
                            
                            # Use the proper measurement system for encryption
                            encrypted_chunks = measure_chunked_encryption(
                                metrics,
                                implementation.encrypt,
                                implementation,
                                all_chunks,
                                key,
                                chunk_size
                            )
                            
                            # Use the proper measurement system for decryption
                            decrypted_chunks = measure_chunked_encryption(
                                metrics,
                                implementation.decrypt,
                                implementation,
                                encrypted_chunks,
                                key,
                                chunk_size,
                                all_chunks  # Pass original chunks for correctness checking
                            )
                            
                            # Verify correctness by comparing chunks
                            correctness_checks = min(5, len(all_chunks))  # Check up to 5 chunks
                            for check_idx in range(correctness_checks):
                                if all_chunks[check_idx] != decrypted_chunks[check_idx]:
                                    logger.error(f"Correctness check failed for chunk {check_idx}")
                                    metrics.correctness_passed = False
                                    break
                            else:
                                metrics.correctness_passed = True
                                
                            # Set additional metrics
                            metrics.input_size_bytes = current_dataset_size
                            metrics.decrypted_size_bytes = sum(len(chunk) for chunk in decrypted_chunks)
                            
                            # Clean up chunks to free memory
                            del all_chunks
                            del encrypted_chunks
                            del decrypted_chunks
                            gc.collect()
                        
                    else:
                        # Memory mode: Load entire dataset (or force memory mode for asymmetric algorithms)
                        if processing_strategy == "Stream" and is_asymmetric:
                            logger.info(f"Using Memory mode for {dataset_type} algorithm (chunking not recommended)")
                        
                        if current_cached_dataset is None:
                            current_cached_dataset = load_dataset(current_dataset_path)
                            # Update the appropriate cached dataset variable
                            if is_asymmetric:
                                cached_asymmetric_dataset = current_cached_dataset
                            else:
                                cached_symmetric_dataset = current_cached_dataset
                        
                        # Perform encryption
                        ciphertext = measure_encryption_metrics(
                            metrics, 
                            implementation.encrypt, 
                            implementation, 
                            current_cached_dataset, 
                            key
                        )
                        
                        # Perform decryption
                        plaintext = measure_encryption_metrics(
                            metrics, 
                            implementation.decrypt, 
                            implementation, 
                            ciphertext, 
                            key,
                            current_cached_dataset  # Pass original plaintext for correctness checking
                        )
                        
                        # The correctness check is handled by measure_decrypt in the metrics
                        # But let's verify it was set correctly
                        if not hasattr(metrics, 'correctness_passed') or metrics.correctness_passed is None:
                            # Fallback verification
                            if current_cached_dataset == plaintext:
                                metrics.correctness_passed = True
                                logger.info(f"Correctness check passed for {impl_description}")
                            else:
                                metrics.correctness_passed = False
                                logger.error(f"Correctness check failed for {impl_description}")
                        
                        # Set additional metrics
                        metrics.input_size_bytes = len(current_cached_dataset)
                        metrics.decrypted_size_bytes = len(plaintext) if hasattr(plaintext, '__len__') else 0
                            
                        # Clean up
                        del ciphertext
                        del plaintext
                        gc.collect()
                    
                    # Add results
                    iteration_results.append(metrics.to_dict(i + 1))  # Pass iteration number
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
            aggregated_metrics = calculate_aggregated_metrics(iteration_results, current_dataset_size)
            
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
    
    # Clean up memory tracking if enabled
    if memory_tracking:
        tracemalloc.stop()
    
    # Clean up memory-mapped datasets if used
    if memory_mapped_symmetric_dataset is not None:
        memory_mapped_symmetric_dataset.close()
        logger.info("Closed memory-mapped symmetric dataset")
    
    if memory_mapped_asymmetric_dataset is not None:
        memory_mapped_asymmetric_dataset.close()
        logger.info("Closed memory-mapped asymmetric dataset")
    
    # Save results
    session_id = os.path.basename(session_dir)  # Extract session name from path
    success = save_results(results, session_dir, session_id)
    gc.collect()
    
    return success 