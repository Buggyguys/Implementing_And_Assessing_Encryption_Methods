import os
import gc
import time
import logging
import traceback
from datetime import datetime

from .metrics import BenchmarkMetrics
from .results import calculate_aggregated_metrics, save_results
from .utils import MemoryMappedDataset, load_dataset
from .measurement import measure_encryption_metrics, measure_chunked_encryption

logger = logging.getLogger("PythonCore")

def get_key_size_bytes(key, implementation):
    try:
        # RSA
        # handle tuple keys (public/private keys)
        if isinstance(key, tuple):
            # get key size from the public key
            if hasattr(key[0], 'size_in_bytes'):
                return key[0].size_in_bytes()
            elif hasattr(key[0], 'key_size'):
                return key[0].key_size // 8  # bits to bytes
            elif hasattr(key[0], 'n'):  # key with modulus
                # get key size from modulus bit length
                return (key[0].n.bit_length() + 7) // 8
            else:
                logger.warning(f"Unknown RSA key type: {type(key[0])}")
                return 256  # default to 2048 bits / 8 = 256 bytes
        
        # ECC keys
        elif hasattr(key, 'private_value') or hasattr(key, 'public_key'):  # ECC private key
            if hasattr(key, 'key_size'):
                return key.key_size // 8
            elif hasattr(key, 'curve'):
                # key size from curve
                curve_name = getattr(key.curve, 'name', '').lower()
                if 'p256' in curve_name or 'secp256r1' in curve_name:
                    return 32  # 256 bits / 8
                elif 'p384' in curve_name or 'secp384r1' in curve_name:
                    return 48  # 384 bits / 8
                elif 'p521' in curve_name or 'secp521r1' in curve_name:
                    return 66  # 521 bits / 8 (rounded up)
                else:
                    logger.warning(f"Unknown ECC curve: {curve_name}")
                    return 32  # default to P-256
            else:
                logger.warning(f"Unknown ECC key type: {type(key)}")
                return 32  # default to P-256
        
        # RSA keys (single key object)
        elif hasattr(key, 'size_in_bytes'):
            return key.size_in_bytes()
        elif hasattr(key, 'key_size'):
            return key.key_size // 8  # bits to bytes
        elif hasattr(key, 'n'):  # key with modulus
            return (key.n.bit_length() + 7) // 8
        
        # bytes/string keys (AES, ChaCha20, Camellia)
        elif hasattr(key, '__len__'):
            return len(key)
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
                return 32  
                
    except Exception as e:
        logger.error(f"Error determining key size: {e}")
        return 32  

def run_benchmarks(config, implementations):
    # get session information
    session_dir = config["session_info"]["session_dir"]
    session_id = config["session_info"]["session_id"]
    
    logger.info(f"Starting Python benchmarks for session {session_id}")
    
    # extract test parameters
    iterations = config["test_parameters"]["iterations"]
    
    # handle both old and new dataset configuration formats
    dataset_info = config["test_parameters"].get("dataset_info")
    if dataset_info:
        # format with separate symmetric/asymmetric datasets
        symmetric_dataset_path = dataset_info.get("symmetric", {}).get("path")
        asymmetric_dataset_path = dataset_info.get("asymmetric", {}).get("path")
        logger.info(f"Using new dual dataset format:")
        if symmetric_dataset_path:
            logger.info(f"  Symmetric dataset: {symmetric_dataset_path}")
        if asymmetric_dataset_path:
            logger.info(f"  Asymmetric dataset: {asymmetric_dataset_path}")
    else:
        # format with single dataset path 
        dataset_path = config["test_parameters"].get("dataset_path")
        symmetric_dataset_path = dataset_path
        asymmetric_dataset_path = dataset_path
        logger.info(f"Using legacy single dataset format: {dataset_path}")
    
    # configuration parameters
    use_stdlib = config["test_parameters"].get("use_stdlib", True)
    use_custom = config["test_parameters"].get("use_custom", True)
    
    # handle old config format
    if "use_stdlib" not in config["test_parameters"] and "use_custom" not in config["test_parameters"]:
        include_stdlibs = config["test_parameters"].get("include_stdlibs", True)
        use_stdlib = include_stdlibs
        use_custom = True  # always enable custom in backward compatibility mode
    
    processing_strategy = config["test_parameters"].get("processing_strategy", "Memory")
    
    logger.info(f"Standard library implementations: {'enabled' if use_stdlib else 'disabled'}")
    logger.info(f"Custom implementations: {'enabled' if use_custom else 'disabled'}")
    
    # parse chunk size
    chunk_size_text = config["test_parameters"].get("chunk_size", "1MB")
    chunk_size_mb = 1  # Default: 1MB
    
    # parse the chunk size from the text
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
    
    # enable memory monitoring
    try:
        import tracemalloc
        tracemalloc.start()
        memory_tracking = True
        logger.info("Memory tracking enabled")
    except ImportError:
        memory_tracking = False
        logger.info("Memory tracking not available (tracemalloc not installed)")
    
    # set a flag to use memory mapping for really large files
    use_mmap = False  # disable memory mapping completely
    
    # initialize variables
    cached_symmetric_dataset = None
    cached_asymmetric_dataset = None
    memory_mapped_symmetric_dataset = None
    memory_mapped_asymmetric_dataset = None
    
    # load datasets based on processing strategy
    if processing_strategy == "Memory":
        # memory mode -> load entire datasets
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
        # stream mode -> use memory-mapped datasets
        if symmetric_dataset_path:
            memory_mapped_symmetric_dataset = MemoryMappedDataset(symmetric_dataset_path)
            symmetric_size_bytes = os.path.getsize(symmetric_dataset_path)
            logger.info(f"Memory-mapped symmetric dataset initialized: {symmetric_size_bytes / (1024*1024):.2f} MB")
        
        if asymmetric_dataset_path:
            memory_mapped_asymmetric_dataset = MemoryMappedDataset(asymmetric_dataset_path)
            asymmetric_size_bytes = os.path.getsize(asymmetric_dataset_path)
            logger.info(f"Memory-mapped asymmetric dataset initialized: {asymmetric_size_bytes / (1024*1024):.2f} MB")
    
    # get enabled encryptions
    enabled_methods = []
    for method_name, settings in config["encryption_methods"].items():
        if settings.get("enabled", False):
            method_settings = settings.copy()
            
            if method_name == "aes":
                # AES implementations - supported modes: GCM, OFB, CFB, CBC
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
                # Camellia implementations - supported modes: CBC, OFB, CFB, ECB
                key_size = method_settings.get("key_size", "256")
                mode = method_settings.get("mode", "CBC").upper()
                
                # validate mode for Camellia
                if mode not in ["CBC", "OFB", "CFB", "ECB"]:
                    logger.warning(f"Unsupported Camellia mode '{mode}'. Supported modes: CBC, OFB, CFB, ECB. Defaulting to CBC.")
                    mode = "CBC"
                    method_settings["mode"] = mode
                
                if use_stdlib:
                    std_settings = method_settings.copy()
                    std_settings["is_custom"] = False
            
                    # use specialized implementation names for different key sizes and modes
                    impl_name = f"camellia{key_size}_{mode.lower()}"
                    if impl_name in implementations:
                        enabled_methods.append((impl_name, std_settings))
                    else:
                        enabled_methods.append((method_name, std_settings))
                
                if use_custom:
                    custom_settings = method_settings.copy()
                    custom_settings["is_custom"] = True
                    custom_impl_name = f"camellia{key_size}_{mode.lower()}_custom"
                    if custom_impl_name in implementations:
                        enabled_methods.append((custom_impl_name, custom_settings))
                    else:
                        enabled_methods.append(("camellia_custom", custom_settings))
            elif method_name == "rsa":
                # RSA implementations
                rsa_key_size = method_settings.get("key_size", "2048")
                rsa_padding = method_settings.get("padding", "OAEP")
                use_oaep = rsa_padding == "OAEP"
                
                if use_stdlib:
                    std_settings = method_settings.copy()
                    std_settings["is_custom"] = False
                    std_settings["use_oaep"] = use_oaep
                    enabled_methods.append((method_name, std_settings))
                
                if use_custom:
                    custom_settings = method_settings.copy()
                    custom_settings["is_custom"] = True
                    custom_settings["use_oaep"] = use_oaep
                    enabled_methods.append(("rsa_custom", custom_settings))
            elif method_name == "ecc":
                # ECC implementations
                curve = method_settings.get("curve", "P-256")
                
                if use_stdlib:
                    std_settings = method_settings.copy()
                    std_settings["is_custom"] = False
                    curve_safe_name = curve.lower().replace("-", "")
                    impl_name = f"ecc_{curve_safe_name}"
                    if impl_name in implementations:
                        enabled_methods.append((impl_name, std_settings))
                    else:
                        enabled_methods.append((method_name, std_settings))
                
                if use_custom:
                    custom_settings = {
                        "curve": curve if curve in ["P-256", "P-384", "P-521"] else "P-256",
                        "is_custom": True
                    }
                    curve_safe_name = curve.lower().replace("-", "")
                    custom_impl_name = f"ecc_{curve_safe_name}_custom"
                    if custom_impl_name in implementations:
                        enabled_methods.append((custom_impl_name, custom_settings))
                    else:
                        enabled_methods.append(("ecc_custom", custom_settings))
            else:
                enabled_methods.append((method_name, method_settings))
    
    if not enabled_methods:
        logger.error("No encryption methods enabled in configuration. Aborting.")
        return False
    
    # print encryption implementations
    logger.info(f"Available implementations: {list(implementations.keys())}")
    logger.info(f"Enabled methods for benchmarking: {[method for method, _ in enabled_methods]}")
    
    # initialize results dictionary
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
    
    # add chunk size to configuration if using stream processing
    if processing_strategy == "Stream":
        results["test_configuration"]["chunk_size"] = chunk_size_text
    
    # run benchmarks for each enabled encryption method
    for method_name, settings in enabled_methods:
        # get basic info about this method
        impl_name = method_name
        is_custom = settings.get("is_custom", False)
        
        # description for logging
        if is_custom:
            impl_description = f"Custom {method_name.upper()} Implementation"
        else:
            impl_description = f"Standard {method_name.upper()} Implementation"
            
        logger.info(f"Running benchmark for {impl_description}")
        
        # check if implementation exists
        if method_name not in implementations:
            logger.warning(f"No implementation found for {method_name}. Skipping.")
            continue
        
        # run the benchmark for this method
        try:
            implementation_factory = implementations[method_name]
            implementation = implementation_factory(**settings)
            
            # run iterations
            iteration_results = []
            for i in range(iterations):
                logger.info(f"Running iteration {i+1}/{iterations} for {impl_description}")
                
                # create metrics collector
                metrics = BenchmarkMetrics()
                
                try:
                    # generate a new key for each iteration
                    key = metrics.measure_keygen(implementation.generate_key)
                    # set algorithm metadata after key generation
                    key_size_bytes = get_key_size_bytes(key, implementation)
                    metrics.set_algorithm_metadata(implementation, key_size_bytes)
                    
                    # determine if this is a symmetric or asymmetric algorithm
                    is_asymmetric = any(keyword in method_name.lower() for keyword in ['rsa', 'ecc'])
                    
                    # select appropriate dataset based on algorithm type
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
                    
                    # check if we have the required dataset for this algorithm type
                    if not current_dataset_path:
                        logger.warning(f"No {dataset_type} dataset available for {impl_description}. Skipping.")
                        continue
                    
                    logger.info(f"Using {dataset_type} dataset for {impl_description}: {current_dataset_path}")
                    
                    # load or map dataset based on processing strategy
                    if processing_strategy == "Stream" and not is_asymmetric:
                        # use stream mode for symmetric algorithms (asymmetric doesn't work well with chunking)
                        
                        # check if the implementation has explicit stream methods
                        if hasattr(implementation, 'encrypt_stream') and hasattr(implementation, 'decrypt_stream'):
                            # use implementation's own stream methods with user-specified chunk size
                            logger.info(f"Using implementation's native stream mode with chunk size {chunk_size} bytes")
                            
                            # load the entire dataset for stream processing
                            if current_cached_dataset is None:
                                current_cached_dataset = load_dataset(current_dataset_path)
                                if is_asymmetric:
                                    cached_asymmetric_dataset = current_cached_dataset
                                else:
                                    cached_symmetric_dataset = current_cached_dataset
                            
                            # use implementation's stream methods
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
                                current_cached_dataset  # for correctness checking
                            )
                            
                            # verify correctness
                            if current_cached_dataset == plaintext:
                                metrics.correctness_passed = True
                                logger.info(f"Correctness check passed for {impl_description}")
                            else:
                                metrics.correctness_passed = False
                                logger.error(f"Correctness check failed for {impl_description}")
                            
                            # set additional metrics
                            metrics.input_size_bytes = len(current_cached_dataset)
                            metrics.decrypted_size_bytes = len(plaintext) if hasattr(plaintext, '__len__') else 0
                            
                            # clean up
                            del ciphertext
                            del plaintext
                            gc.collect()
                            
                        else:
                            # fallback to chunked processing using regular encrypt/decrypt methods
                            logger.info(f"Using chunked fallback mode (implementation lacks native stream methods)")
                            
                            if current_memory_mapped_dataset is None:
                                current_memory_mapped_dataset = MemoryMappedDataset(current_dataset_path)
                                if is_asymmetric:
                                    memory_mapped_asymmetric_dataset = current_memory_mapped_dataset
                                else:
                                    memory_mapped_symmetric_dataset = current_memory_mapped_dataset
                                
                            # use streaming processing with chunked approach (user-specified chunk size)
                            total_chunks = (current_dataset_size + chunk_size - 1) // chunk_size
                            
                            logger.info(f"Processing {total_chunks} chunks of {chunk_size} bytes each using fallback chunked mode")
                            
                            # collect all chunks first for proper measurement
                            all_chunks = list(current_memory_mapped_dataset.create_chunks(chunk_size))
                            
                            # use the proper measurement system for encryption
                            encrypted_chunks = measure_chunked_encryption(
                                metrics,
                                implementation.encrypt,
                                implementation,
                                all_chunks,
                                key,
                                chunk_size
                            )
                            
                            # use the proper measurement system for decryption
                            decrypted_chunks = measure_chunked_encryption(
                                metrics,
                                implementation.decrypt,
                                implementation,
                                encrypted_chunks,
                                key,
                                chunk_size,
                                all_chunks  # pass original chunks for correctness checking
                            )
                            
                            # verify correctness by comparing chunks
                            correctness_checks = min(5, len(all_chunks))  # check up to 5 chunks
                            for check_idx in range(correctness_checks):
                                if all_chunks[check_idx] != decrypted_chunks[check_idx]:
                                    logger.error(f"Correctness check failed for chunk {check_idx}")
                                    metrics.correctness_passed = False
                                    break
                            else:
                                metrics.correctness_passed = True
                                
                            # set additional metrics
                            metrics.input_size_bytes = current_dataset_size
                            metrics.decrypted_size_bytes = sum(len(chunk) for chunk in decrypted_chunks)
                            
                            # clean up chunks to free memory
                            del all_chunks
                            del encrypted_chunks
                            del decrypted_chunks
                            gc.collect()
                        
                    else:
                        # load entire dataset (or force memory mode for asymmetric algorithms)
                        if processing_strategy == "Stream" and is_asymmetric:
                            logger.info(f"Using Memory mode for {dataset_type} algorithm (chunking not recommended)")
                        
                        if current_cached_dataset is None:
                            current_cached_dataset = load_dataset(current_dataset_path)
                            # update the appropriate cached dataset variable
                            if is_asymmetric:
                                cached_asymmetric_dataset = current_cached_dataset
                            else:
                                cached_symmetric_dataset = current_cached_dataset
                        
                        # perform encryption
                        ciphertext = measure_encryption_metrics(
                            metrics, 
                            implementation.encrypt, 
                            implementation, 
                            current_cached_dataset, 
                            key
                        )
                        
                        # perform decryption
                        plaintext = measure_encryption_metrics(
                            metrics, 
                            implementation.decrypt, 
                            implementation, 
                            ciphertext, 
                            key,
                            current_cached_dataset  # pass original plaintext for correctness checking
                        )
                        
                        # the correctness check is handled by measure_decrypt in the metrics
                        if not hasattr(metrics, 'correctness_passed') or metrics.correctness_passed is None:
                            # fallback verification
                            if current_cached_dataset == plaintext:
                                metrics.correctness_passed = True
                                logger.info(f"Correctness check passed for {impl_description}")
                            else:
                                metrics.correctness_passed = False
                                logger.error(f"Correctness check failed for {impl_description}")
                        
                        # set additional metrics
                        metrics.input_size_bytes = len(current_cached_dataset)
                        metrics.decrypted_size_bytes = len(plaintext) if hasattr(plaintext, '__len__') else 0
                            
                        # clean up
                        del ciphertext
                        del plaintext
                        gc.collect()
                    
                    # add results
                    iteration_results.append(metrics.to_dict(i + 1))  # pass iteration number
                    logger.info(f"Iteration {i+1} completed successfully")
                    
                    # memory usage logging
                    if memory_tracking:
                        current, peak = tracemalloc.get_traced_memory()
                        logger.info(f"Memory after iteration {i+1}: Current {current / (1024*1024):.2f} MB, Peak {peak / (1024*1024):.2f} MB")
                        tracemalloc.reset_peak()
                        
                except Exception as e:
                    logger.error(f"Error in iteration {i+1}: {str(e)}")
                    traceback.print_exc()
                
                # force GC between iterations
                gc.collect()
            
            # calculate aggregated metrics
            aggregated_metrics = calculate_aggregated_metrics(iteration_results, current_dataset_size)
            
            # add to results
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
    
    # clean up memory tracking if enabled
    if memory_tracking:
        tracemalloc.stop()
    
    # clean up memory-mapped datasets if used
    if memory_mapped_symmetric_dataset is not None:
        memory_mapped_symmetric_dataset.close()
        logger.info("Closed memory-mapped symmetric dataset")
    
    if memory_mapped_asymmetric_dataset is not None:
        memory_mapped_asymmetric_dataset.close()
        logger.info("Closed memory-mapped asymmetric dataset")
    
    # save results
    session_id = os.path.basename(session_dir)  # extract session name from path
    success = save_results(results, session_dir, session_id)
    gc.collect()
    
    return success 
