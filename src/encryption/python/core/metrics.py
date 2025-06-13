import time
import logging
import psutil
import os

# setup logging
logger = logging.getLogger("PythonCore")

class BenchmarkMetrics:
    def __init__(self, process=None):
        # initialize with optional psutil process object
        self.process = process or psutil.Process()
        # check if IO counters are available
        try:
            self.has_io_counters = hasattr(self.process, "io_counters") and self.process.io_counters() is not None
        except (psutil.AccessDenied, AttributeError, OSError):
            self.has_io_counters = False
            logger.warning("IO counters are not available - IO metrics will not be collected")
        
        # check if context switches are available
        try:
            self.has_ctx_switches = hasattr(self.process, "num_ctx_switches") and self.process.num_ctx_switches() is not None
        except (psutil.AccessDenied, AttributeError, OSError):
            self.has_ctx_switches = False
            logger.warning("Context switch counters are not available - context switch metrics will not be collected")
        
        self.reset()
    
    def reset(self):
        # reset all metrics
        self.keygen_time_ns = 0
        self.keygen_cpu_time_ns = 0
        self.keygen_cpu_percent = 100
        self.keygen_peak_memory_bytes = 0
        self.keygen_allocated_memory_bytes = 0
        self.keygen_page_faults = 0
        self.keygen_ctx_switches_voluntary = 0
        self.keygen_ctx_switches_involuntary = 0
        
        # encryption metrics 
        self.encrypt_time_ns = 0
        self.encrypt_cpu_time_ns = 0
        self.encrypt_cpu_percent = 100
        self.encrypt_peak_memory_bytes = 0
        self.encrypt_allocated_memory_bytes = 0
        self.encrypt_page_faults = 0
        self.encrypt_ctx_switches_voluntary = 0
        self.encrypt_ctx_switches_involuntary = 0
        self.input_size_bytes = 0
        self.ciphertext_size_bytes = 0
        
        # decryption metrics    
        self.decrypt_time_ns = 0
        self.decrypt_cpu_time_ns = 0
        self.decrypt_cpu_percent = 100
        self.decrypt_peak_memory_bytes = 0
        self.decrypt_allocated_memory_bytes = 0
        self.decrypt_page_faults = 0
        self.decrypt_ctx_switches_voluntary = 0
        self.decrypt_ctx_switches_involuntary = 0
        self.decrypted_size_bytes = 0
        
        # additional metrics 
        self.correctness_passed = True
        self.key_size_bytes = 0
        self.key_size_bits = 0
        self.thread_count = 1
        self.process_priority = 0
        
        # algorithm-specific metrics
        self.block_size_bytes = None
        self.iv_size_bytes = None
        self.num_rounds = None
        self.is_custom_implementation = False
        self.library_version = "PyCryptodome"
        
        # ensure has_ctx_switches is defined (in case it's not set in __init__)
        if not hasattr(self, 'has_ctx_switches'):
            try:
                self.has_ctx_switches = hasattr(self.process, "num_ctx_switches") and self.process.num_ctx_switches() is not None
            except (psutil.AccessDenied, AttributeError, OSError):
                self.has_ctx_switches = False
                logger.warning("Context switch counters are not available - context switch metrics will not be collected")
    
    def set_algorithm_metadata(self, implementation, key_size_bytes):
        # set algorithm-specific metadata based on the implementation
        self.key_size_bytes = key_size_bytes
        self.key_size_bits = key_size_bytes * 8
        
        # set custom implementation flag
        self.is_custom_implementation = getattr(implementation, 'is_custom', False)
        self.library_version = "custom" if self.is_custom_implementation else "PyCryptodome"
        
        # get algorithm name from implementation
        algo_name = getattr(implementation, 'name', '').lower()
        
        # set algorithm-specific metadata
        if 'aes' in algo_name or 'camellia' in algo_name:
            # block ciphers
            self.block_size_bytes = 16  # 128 bits for AES/Camellia
            self.iv_size_bytes = 16     # standard IV size
            
            # number of rounds based on key size and algorithm
            if 'aes' in algo_name:
                if key_size_bytes == 16:    # AES-128
                    self.num_rounds = 10
                elif key_size_bytes == 24:  # AES-192
                    self.num_rounds = 12
                else:                       # AES-256
                    self.num_rounds = 14
            elif 'camellia' in algo_name:
                if key_size_bytes == 16:    # Camellia-128
                    self.num_rounds = 18
                else:                       # Camellia-192/256
                    self.num_rounds = 24
        elif 'chacha' in algo_name:
            # chacha20 specific
            self.num_rounds = 20
            # no block size or IV size for stream ciphers in this context
        
        # get thread count and process priority
        try:
            self.thread_count = self.process.num_threads()
        except (psutil.AccessDenied, AttributeError, OSError):
            self.thread_count = 1
        
        try:
            # get process priority (nice value on Unix systems)
            self.process_priority = self.process.nice()
        except (psutil.AccessDenied, AttributeError, OSError):
            self.process_priority = 0
    
    def measure_keygen(self, key_gen_func, *args, **kwargs):
        # get initial metrics
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
        
        try:
            initial_memory = self.process.memory_info()
        except (psutil.AccessDenied, AttributeError, OSError):
            initial_memory = None
        
        # measure wall time with nanosecond precision
        start_time = time.perf_counter_ns()
        key = key_gen_func(*args, **kwargs)
        end_time = time.perf_counter_ns()
        
        # calculate metrics
        self.keygen_time_ns = end_time - start_time
        
        # get final metrics
        try:
            final_cpu_times = self.process.cpu_times() if initial_cpu_times is not None else None
        except (psutil.AccessDenied, AttributeError, OSError):
            final_cpu_times = None
        
        try:
            final_ctx = self.process.num_ctx_switches() if self.has_ctx_switches else None
        except (psutil.AccessDenied, AttributeError, OSError):
            final_ctx = None
        
        try:
            final_memory = self.process.memory_info()
        except (psutil.AccessDenied, AttributeError, OSError):
            final_memory = None
        
        # update CPU time metrics if available
        if initial_cpu_times is not None and final_cpu_times is not None:
            cpu_user_diff = final_cpu_times.user - initial_cpu_times.user
            cpu_system_diff = final_cpu_times.system - initial_cpu_times.system
            total_cpu_time = cpu_user_diff + cpu_system_diff
            
            # convert to nanoseconds
            self.keygen_cpu_time_ns = int(total_cpu_time * 1_000_000_000)
            
            # calculate CPU percentage
            wall_time_s = self.keygen_time_ns / 1_000_000_000
            if wall_time_s > 0:
                self.keygen_cpu_percent = (total_cpu_time / wall_time_s) * 100
        
        # update context switch metrics if available
        if initial_ctx is not None and final_ctx is not None:
            self.keygen_ctx_switches_voluntary = max(0, final_ctx.voluntary - initial_ctx.voluntary)
            self.keygen_ctx_switches_involuntary = max(0, final_ctx.involuntary - initial_ctx.involuntary)
        
        # record peak memory usage
        if final_memory is not None:
            self.keygen_peak_memory_bytes = final_memory.rss
            if initial_memory is not None:
                self.keygen_allocated_memory_bytes = max(0, final_memory.rss - initial_memory.rss)
        
        return key
    
    def measure_encrypt(self, encrypt_func, plaintext, key, *args, **kwargs):
        # store input size
        self.input_size_bytes = len(plaintext) if hasattr(plaintext, '__len__') else 0
        
        # get initial metrics
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
        
        try:
            initial_memory = self.process.memory_info()
        except (psutil.AccessDenied, AttributeError, OSError):
            initial_memory = None
        
        # measure wall time with nanosecond precision
        start_time = time.perf_counter_ns()
        ciphertext = encrypt_func(plaintext, key, *args, **kwargs)
        end_time = time.perf_counter_ns()
        
        # calculate metrics
        self.encrypt_time_ns = end_time - start_time
        
        # get final metrics
        try:
            final_cpu_times = self.process.cpu_times() if initial_cpu_times is not None else None
        except (psutil.AccessDenied, AttributeError, OSError):
            final_cpu_times = None
        
        try:
            final_ctx = self.process.num_ctx_switches() if self.has_ctx_switches else None
        except (psutil.AccessDenied, AttributeError, OSError):
            final_ctx = None
        
        try:
            final_memory = self.process.memory_info()
        except (psutil.AccessDenied, AttributeError, OSError):
            final_memory = None
        
        # update CPU time metrics if available
        if initial_cpu_times is not None and final_cpu_times is not None:
            cpu_user_diff = final_cpu_times.user - initial_cpu_times.user
            cpu_system_diff = final_cpu_times.system - initial_cpu_times.system
            total_cpu_time = cpu_user_diff + cpu_system_diff
            
            # convert to nanoseconds
            self.encrypt_cpu_time_ns = int(total_cpu_time * 1_000_000_000)
            
            # calculate CPU percentage
            wall_time_s = self.encrypt_time_ns / 1_000_000_000
            if wall_time_s > 0:
                self.encrypt_cpu_percent = (total_cpu_time / wall_time_s) * 100
        
        # update context switch metrics if available
        if initial_ctx is not None and final_ctx is not None:
            self.encrypt_ctx_switches_voluntary = max(0, final_ctx.voluntary - initial_ctx.voluntary)
            self.encrypt_ctx_switches_involuntary = max(0, final_ctx.involuntary - initial_ctx.involuntary)
        
        # record peak memory usage and ciphertext size
        if final_memory is not None:
            self.encrypt_peak_memory_bytes = final_memory.rss
            if initial_memory is not None:
                self.encrypt_allocated_memory_bytes = max(0, final_memory.rss - initial_memory.rss)
        
        # get ciphertext size safely
        try:
            self.ciphertext_size_bytes = len(ciphertext) if hasattr(ciphertext, '__len__') else 0
        except (TypeError, AttributeError):
            self.ciphertext_size_bytes = 0
            logger.warning("Could not determine ciphertext size")
        
        return ciphertext
    
    def measure_decrypt(self, decrypt_func, ciphertext, key, original_plaintext, *args, **kwargs):
        # get initial metrics
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
        
        try:
            initial_memory = self.process.memory_info()
        except (psutil.AccessDenied, AttributeError, OSError):
            initial_memory = None
        
        # measure wall time with nanosecond precision
        start_time = time.perf_counter_ns()
        decrypted_text = decrypt_func(ciphertext, key, *args, **kwargs)
        end_time = time.perf_counter_ns()
        
        # calculate metrics
        self.decrypt_time_ns = end_time - start_time
        
        # get final metrics
        try:
            final_cpu_times = self.process.cpu_times() if initial_cpu_times is not None else None
        except (psutil.AccessDenied, AttributeError, OSError):
            final_cpu_times = None
        
        try:
            final_ctx = self.process.num_ctx_switches() if self.has_ctx_switches else None
        except (psutil.AccessDenied, AttributeError, OSError):
            final_ctx = None
        
        try:
            final_memory = self.process.memory_info()
        except (psutil.AccessDenied, AttributeError, OSError):
            final_memory = None
        
        # update CPU time metrics if available
        if initial_cpu_times is not None and final_cpu_times is not None:
            cpu_user_diff = final_cpu_times.user - initial_cpu_times.user
            cpu_system_diff = final_cpu_times.system - initial_cpu_times.system
            total_cpu_time = cpu_user_diff + cpu_system_diff
            
            # convert to nanoseconds
            self.decrypt_cpu_time_ns = int(total_cpu_time * 1_000_000_000)
            
            # calculate CPU percentage
            wall_time_s = self.decrypt_time_ns / 1_000_000_000
            if wall_time_s > 0:
                self.decrypt_cpu_percent = (total_cpu_time / wall_time_s) * 100
        
        # update context switch metrics if available
        if initial_ctx is not None and final_ctx is not None:
            self.decrypt_ctx_switches_voluntary = max(0, final_ctx.voluntary - initial_ctx.voluntary)
            self.decrypt_ctx_switches_involuntary = max(0, final_ctx.involuntary - initial_ctx.involuntary)
        
        # record peak memory usage
        if final_memory is not None:
            self.decrypt_peak_memory_bytes = final_memory.rss
            if initial_memory is not None:
                self.decrypt_allocated_memory_bytes = max(0, final_memory.rss - initial_memory.rss)
        
        # store decrypted size
        try:
            self.decrypted_size_bytes = len(decrypted_text) if hasattr(decrypted_text, '__len__') else 0
        except (TypeError, AttributeError):
            self.decrypted_size_bytes = 0
        
        # verify correctness
        try:
            self.correctness_passed = (decrypted_text == original_plaintext)
        except Exception as e:
            logger.warning(f"Could not verify decryption correctness: {e}")
            self.correctness_passed = False
        
        return decrypted_text
    
    def to_dict(self, iteration_number=1):
        result = {
            # iteration info
            "iteration": iteration_number,
            
            # key generation metrics
            "keygen_time_ns": self.keygen_time_ns,
            "keygen_cpu_time_ns": self.keygen_cpu_time_ns,
            "keygen_cpu_percent": self.keygen_cpu_percent,
            "keygen_peak_memory_bytes": self.keygen_peak_memory_bytes,
            "keygen_allocated_memory_bytes": self.keygen_allocated_memory_bytes,
            "keygen_page_faults": self.keygen_page_faults,
            "keygen_ctx_switches_voluntary": self.keygen_ctx_switches_voluntary,
            "keygen_ctx_switches_involuntary": self.keygen_ctx_switches_involuntary,
            "key_size_bytes": self.key_size_bytes,
            "key_size_bits": self.key_size_bits,
            "thread_count": self.thread_count,
            "process_priority": self.process_priority,
            
            # encryption metrics
            "encrypt_time_ns": self.encrypt_time_ns,
            "encrypt_cpu_time_ns": self.encrypt_cpu_time_ns,
            "encrypt_cpu_percent": self.encrypt_cpu_percent,
            "encrypt_peak_memory_bytes": self.encrypt_peak_memory_bytes,
            "encrypt_allocated_memory_bytes": self.encrypt_allocated_memory_bytes,
            "encrypt_page_faults": self.encrypt_page_faults,
            "encrypt_ctx_switches_voluntary": self.encrypt_ctx_switches_voluntary,
            "encrypt_ctx_switches_involuntary": self.encrypt_ctx_switches_involuntary,
            "input_size_bytes": self.input_size_bytes,
            "ciphertext_size_bytes": self.ciphertext_size_bytes,
            
            # decryption metrics
            "decrypt_time_ns": self.decrypt_time_ns,
            "decrypt_cpu_time_ns": self.decrypt_cpu_time_ns,
            "decrypt_cpu_percent": self.decrypt_cpu_percent,
            "decrypt_peak_memory_bytes": self.decrypt_peak_memory_bytes,
            "decrypt_allocated_memory_bytes": self.decrypt_allocated_memory_bytes,
            "decrypt_page_faults": self.decrypt_page_faults,
            "decrypt_ctx_switches_voluntary": self.decrypt_ctx_switches_voluntary,
            "decrypt_ctx_switches_involuntary": self.decrypt_ctx_switches_involuntary,
            "decrypted_size_bytes": self.decrypted_size_bytes,
            "correctness_passed": self.correctness_passed,
            
            # implementation details
            "is_custom_implementation": self.is_custom_implementation,
            "library_version": self.library_version
        }
        
        # add algorithm-specific fields if available
        if self.block_size_bytes is not None:
            result["block_size_bytes"] = self.block_size_bytes
        if self.iv_size_bytes is not None:
            result["iv_size_bytes"] = self.iv_size_bytes
        if self.num_rounds is not None:
            result["num_rounds"] = self.num_rounds
            
        return result 