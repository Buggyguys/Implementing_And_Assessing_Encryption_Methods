"""
CryptoBench Pro - Dataset Management Tab
Allows users to select existing datasets or create new ones.
"""

import os
import random
import string
import math
import multiprocessing
import tempfile
import shutil
import time
import mmap
import numpy as np
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
    QRadioButton, QPushButton, QFileDialog, QLabel,
    QComboBox, QSpinBox, QLineEdit, QProgressBar,
    QFormLayout, QSizePolicy, QScrollArea, QCheckBox,
    QSlider, QDoubleSpinBox, QButtonGroup
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, pyqtSlot, QSize


# Pre-computed values for fast generation
_RANDOM_CHAR_CACHE = {}
_WORD_CACHE = {}


def _get_random_chars(charset, length=1000000):
    """Get or create a cache of random characters from the charset."""
    key = ''.join(sorted(charset))
    if key not in _RANDOM_CHAR_CACHE or len(_RANDOM_CHAR_CACHE[key]) < length:
        # Generate a large random block for reuse
        _RANDOM_CHAR_CACHE[key] = ''.join(random.choice(charset) for _ in range(length))
    return _RANDOM_CHAR_CACHE[key]


def _get_random_words(count=10000, min_length=3, max_length=10):
    """Get or create a cache of random words."""
    key = f"{min_length}_{max_length}"
    if key not in _WORD_CACHE or len(_WORD_CACHE[key]) < count:
        charset = string.ascii_lowercase
        _WORD_CACHE[key] = [
            ''.join(random.choice(charset) for _ in range(random.randint(min_length, max_length)))
            for _ in range(count)
        ]
    return _WORD_CACHE[key]


def _generate_binary_chunk(chunk_size):
    """Generate a chunk of binary data."""
    # For very large chunks, use numpy's efficient random generation
    if chunk_size > 10 * 1024 * 1024:  # 10MB threshold
        # Generate random bytes using numpy which is much faster
        return np.random.bytes(chunk_size)
    return os.urandom(chunk_size)


def _generate_words_chunk(chunk_size, params):
    """Generate a chunk of random words using block repetition for speed."""
    min_word_length = params.get("min_word_length", 3)
    max_word_length = params.get("max_word_length", 10)
    include_spaces = params.get("include_spaces", True)
    space_frequency = params.get("space_frequency", 1.0)
    uppercase_option = params.get("uppercase_option", "none")
    uppercase_probability = params.get("uppercase_probability", 0.2)
    
    # Use pre-generated words for efficiency
    random_words = _get_random_words(10000, min_word_length, max_word_length)
    
    words = []
    current_size = 0
    
    # For large chunks, use repetition of blocks
    if chunk_size > 1024 * 1024:  # 1MB threshold
        # Create a template block that we'll repeat
        template_block = []
        template_size = 0
        target_template_size = min(chunk_size // 10, 1024 * 1024)  # 1MB max template
        
        while template_size < target_template_size:
            word = random.choice(random_words)
            
            # Apply uppercase options
            if uppercase_option == "first_letter":
                word = word.capitalize()
            elif uppercase_option == "random":
                word = ''.join(c.upper() if random.random() < uppercase_probability else c for c in word)
            elif uppercase_option == "all":
                word = word.upper()
            
            # Add space according to frequency
            if include_spaces and random.random() < space_frequency:
                word += " "
                
            template_block.append(word)
            template_size += len(word.encode('utf-8'))
        
        # Join the template once
        template_text = ''.join(template_block)
        template_bytes = len(template_text.encode('utf-8'))
        
        # Calculate how many full templates we need
        num_templates = chunk_size // template_bytes
        remaining_size = chunk_size - (num_templates * template_bytes)
        
        # Add the templates
        for _ in range(num_templates):
            words.append(template_text)
            current_size += template_bytes
        
        # Now add remaining content if needed
        if remaining_size > 0:
            # Add individual words until we reach the target size
            while current_size < chunk_size:
                word = random.choice(random_words)
                
                # Apply uppercase options
                if uppercase_option == "first_letter":
                    word = word.capitalize()
                elif uppercase_option == "random":
                    word = ''.join(c.upper() if random.random() < uppercase_probability else c for c in word)
                elif uppercase_option == "all":
                    word = word.upper()
                
                # Add space according to frequency
                if include_spaces and random.random() < space_frequency:
                    word += " "
                    
                words.append(word)
                current_size += len(word.encode('utf-8'))
    else:
        # For small chunks, just generate words normally
        while current_size < chunk_size:
            word = random.choice(random_words)
            
            # Apply uppercase options
            if uppercase_option == "first_letter":
                word = word.capitalize()
            elif uppercase_option == "random":
                word = ''.join(c.upper() if random.random() < uppercase_probability else c for c in word)
            elif uppercase_option == "all":
                word = word.upper()
            
            # Add space according to frequency
            if include_spaces and random.random() < space_frequency:
                word += " "
                
            words.append(word)
            current_size += len(word.encode('utf-8'))
    
    return ''.join(words)


def _generate_sentences_chunk(chunk_size, params):
    """Generate a chunk of sentences using block repetition for speed."""
    min_words_per_sentence = params.get("min_words_per_sentence", 3)
    max_words_per_sentence = params.get("max_words_per_sentence", 15)
    min_word_length = params.get("min_word_length", 2)
    max_word_length = params.get("max_word_length", 10)
    include_numbers = params.get("include_numbers", False)
    include_punctuation = params.get("include_punctuation", True)
    punctuation_frequency = params.get("punctuation_frequency", 0.2)
    sentence_spacing = params.get("sentence_spacing", 1)
    always_capitalize = params.get("always_capitalize", True)
    
    # Use pre-generated words for efficiency
    random_words = _get_random_words(5000, min_word_length, max_word_length)
    lowercase_chars = string.ascii_lowercase
    uppercase_chars = string.ascii_uppercase
    digits = string.digits if include_numbers else ""
    end_punctuation = ".!?"
    mid_punctuation = ",;:"
    
    # For large chunks, use repetition of blocks
    if chunk_size > 1024 * 1024:  # 1MB threshold
        # Create a template block of sentences that we'll repeat
        template_sentences = []
        template_size = 0
        target_template_size = min(chunk_size // 10, 1024 * 1024)  # 1MB max template
        
        while template_size < target_template_size:
            words_count = random.randint(min_words_per_sentence, max_words_per_sentence)
            sentence = []
            
            for i in range(words_count):
                if i == 0 and always_capitalize:
                    # Use a cached word and capitalize first letter
                    word = random.choice(random_words)
                    word = word[0].upper() + word[1:] if word else ""
                else:
                    word = random.choice(random_words)
                
                if include_numbers and random.random() < 0.1:
                    num_length = random.randint(1, 5)
                    word = ''.join(random.choice(digits) for _ in range(num_length))
                
                sentence.append(word)
                
                if include_punctuation and i < words_count - 1 and random.random() < punctuation_frequency:
                    sentence[-1] += random.choice(mid_punctuation)
            
            full_sentence = ' '.join(sentence)
            
            if include_punctuation:
                full_sentence += random.choice(end_punctuation)
            
            if sentence_spacing == 1:
                full_sentence += " "
            elif sentence_spacing == 2:
                full_sentence += "  "
            elif sentence_spacing == "random":
                full_sentence += " " * random.randint(1, 3)
            
            template_sentences.append(full_sentence)
            template_size += len(full_sentence.encode('utf-8'))
        
        # Join the template once
        template_text = ''.join(template_sentences)
        template_bytes = len(template_text.encode('utf-8'))
        
        # Calculate how many full templates we need
        num_templates = chunk_size // template_bytes
        remaining_size = chunk_size - (num_templates * template_bytes)
        
        # Start with the repetitions
        result = template_text * num_templates
        current_size = num_templates * template_bytes
        
        # Add remaining sentences if needed
        sentences = []
        while current_size < chunk_size:
            words_count = random.randint(min_words_per_sentence, max_words_per_sentence)
            sentence = []
            
            for i in range(words_count):
                if i == 0 and always_capitalize:
                    word = random.choice(random_words)
                    word = word[0].upper() + word[1:] if word else ""
                else:
                    word = random.choice(random_words)
                
                if include_numbers and random.random() < 0.1:
                    num_length = random.randint(1, 5)
                    word = ''.join(random.choice(digits) for _ in range(num_length))
                
                sentence.append(word)
                
                if include_punctuation and i < words_count - 1 and random.random() < punctuation_frequency:
                    sentence[-1] += random.choice(mid_punctuation)
            
            full_sentence = ' '.join(sentence)
            
            if include_punctuation:
                full_sentence += random.choice(end_punctuation)
            
            if sentence_spacing == 1:
                full_sentence += " "
            elif sentence_spacing == 2:
                full_sentence += "  "
            elif sentence_spacing == "random":
                full_sentence += " " * random.randint(1, 3)
            
            sentences.append(full_sentence)
            current_size += len(full_sentence.encode('utf-8'))
        
        return result + ''.join(sentences)
    else:
        # For small chunks, generate normally
        sentences = []
        current_size = 0
        
        while current_size < chunk_size:
            words_count = random.randint(min_words_per_sentence, max_words_per_sentence)
            sentence = []
            
            for i in range(words_count):
                if i == 0 and always_capitalize:
                    word = random.choice(random_words)
                    word = word[0].upper() + word[1:] if word else ""
                else:
                    word = random.choice(random_words)
                
                if include_numbers and random.random() < 0.1:
                    num_length = random.randint(1, 5)
                    word = ''.join(random.choice(digits) for _ in range(num_length))
                
                sentence.append(word)
                
                if include_punctuation and i < words_count - 1 and random.random() < punctuation_frequency:
                    sentence[-1] += random.choice(mid_punctuation)
            
            full_sentence = ' '.join(sentence)
            
            if include_punctuation:
                full_sentence += random.choice(end_punctuation)
            
            if sentence_spacing == 1:
                full_sentence += " "
            elif sentence_spacing == 2:
                full_sentence += "  "
            elif sentence_spacing == "random":
                full_sentence += " " * random.randint(1, 3)
            
            sentences.append(full_sentence)
            current_size += len(full_sentence.encode('utf-8'))
        
        return ''.join(sentences)


def _generate_numbers_chunk(chunk_size, params):
    """Generate a chunk of numbers using block repetition for speed."""
    number_type = params.get("number_type", "decimal")
    min_digits = params.get("min_digits", 1)
    max_digits = params.get("max_digits", 10)
    include_spaces = params.get("include_spaces", True)
    include_prefix = params.get("include_prefix", False)
    include_grouping = params.get("include_grouping", False)
    
    if number_type == "decimal":
        chars = string.digits
        prefix = ""
    elif number_type == "binary":
        chars = "01"
        prefix = "0b" if include_prefix else ""
    elif number_type == "hexadecimal":
        chars = string.hexdigits.lower()
        prefix = "0x" if include_prefix else ""
    else:
        chars = string.digits
        prefix = ""
    
    # For large chunks, use block repetition
    if chunk_size > 1024 * 1024:  # 1MB threshold
        # Create a template block that we'll repeat
        template_numbers = []
        template_size = 0
        target_template_size = min(chunk_size // 10, 1024 * 1024)  # 1MB max template
        
        # Pre-generate a set of numbers for reuse
        pregenerated_numbers = []
        for _ in range(1000):
            digits_count = random.randint(min_digits, max_digits)
            number = ''.join(random.choice(chars) for _ in range(digits_count))
            
            if include_grouping and len(number) > 3:
                if number_type == "decimal":
                    grouped = ""
                    for i, digit in enumerate(reversed(number)):
                        if i > 0 and i % 3 == 0:
                            grouped = "_" + grouped
                        grouped = digit + grouped
                    number = grouped
                elif number_type == "binary":
                    grouped = ""
                    for i, digit in enumerate(reversed(number)):
                        if i > 0 and i % 4 == 0:
                            grouped = "_" + grouped
                        grouped = digit + grouped
                    number = grouped
                elif number_type == "hexadecimal":
                    grouped = ""
                    for i, digit in enumerate(reversed(number)):
                        if i > 0 and i % 2 == 0:
                            grouped = "_" + grouped
                        grouped = digit + grouped
                    number = grouped
            
            formatted_number = prefix + number
            if include_spaces:
                formatted_number += " "
                
            pregenerated_numbers.append(formatted_number)
        
        # Create the template
        while template_size < target_template_size:
            number = random.choice(pregenerated_numbers)
            template_numbers.append(number)
            template_size += len(number.encode('utf-8'))
        
        # Join the template once
        template_text = ''.join(template_numbers)
        template_bytes = len(template_text.encode('utf-8'))
        
        # Calculate how many full templates we need
        num_templates = chunk_size // template_bytes
        remaining_size = chunk_size - (num_templates * template_bytes)
        
        # Start with the repetitions
        result = template_text * num_templates
        current_size = num_templates * template_bytes
        
        # Add remaining numbers if needed
        numbers = []
        while current_size < chunk_size:
            number = random.choice(pregenerated_numbers)
            numbers.append(number)
            current_size += len(number.encode('utf-8'))
        
        return result + ''.join(numbers)
    else:
        # For small chunks, generate normally
        numbers = []
        current_size = 0
        
        while current_size < chunk_size:
            digits_count = random.randint(min_digits, max_digits)
            number = ''.join(random.choice(chars) for _ in range(digits_count))
            
            if include_grouping and len(number) > 3:
                if number_type == "decimal":
                    grouped = ""
                    for i, digit in enumerate(reversed(number)):
                        if i > 0 and i % 3 == 0:
                            grouped = "_" + grouped
                        grouped = digit + grouped
                    number = grouped
                elif number_type == "binary":
                    grouped = ""
                    for i, digit in enumerate(reversed(number)):
                        if i > 0 and i % 4 == 0:
                            grouped = "_" + grouped
                        grouped = digit + grouped
                    number = grouped
                elif number_type == "hexadecimal":
                    grouped = ""
                    for i, digit in enumerate(reversed(number)):
                        if i > 0 and i % 2 == 0:
                            grouped = "_" + grouped
                        grouped = digit + grouped
                    number = grouped
            
            formatted_number = prefix + number
            
            if include_spaces:
                formatted_number += " "
            
            numbers.append(formatted_number)
            current_size += len(formatted_number.encode('utf-8'))
        
        return ''.join(numbers)


def _generate_custom_charset_chunk(chunk_size, params):
    """Generate a chunk of custom charset data using numpy for speed."""
    charset = params.get("charset", string.ascii_letters + string.digits)
    
    if not charset:
        charset = string.ascii_letters + string.digits
    
    # For very large chunks, use numpy's vectorization
    if chunk_size > 5 * 1024 * 1024:  # 5MB threshold
        charset_array = np.array(list(charset), dtype='U1')
        # Generate random indices using numpy (much faster than Python's random)
        indices = np.random.randint(0, len(charset), chunk_size)
        # Convert to string (this is very fast in numpy)
        return ''.join(charset_array[indices])
    else:
        # For smaller chunks, use the cached character approach
        random_chars = _get_random_chars(charset)
        
        # Use repetition for efficiency
        block_size = len(random_chars)
        num_blocks = chunk_size // block_size
        remaining = chunk_size % block_size
        
        if num_blocks > 0:
            result = random_chars * num_blocks
            if remaining > 0:
                result += random_chars[:remaining]
            return result
        else:
            return random_chars[:chunk_size]


def _write_chunk_to_file(chunk_data, chunk_path, is_binary=False):
    """Write a chunk to a file efficiently."""
    if is_binary:
        with open(chunk_path, 'wb') as f:
            f.write(chunk_data)
    else:
        with open(chunk_path, 'w') as f:
            f.write(chunk_data)
    return chunk_path


class DatasetGenerationWorker(QThread):
    """Worker thread for dataset generation using multi-processing."""
    
    progress_updated = pyqtSignal(int)
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, dataset_type, size_value, size_unit, params=None):
        super().__init__()
        self.dataset_type = dataset_type
        self.size_value = size_value
        self.size_unit = size_unit
        self.params = params or {}
        self.is_canceled = False
        
        # Calculate total size in bytes
        multipliers = {"KB": 1024, "MB": 1024**2, "GB": 1024**3}
        self.total_bytes = size_value * multipliers.get(size_unit, 1024)
        
        # Determine optimal number of processes based on CPU count and dataset size
        self.num_processes = min(multiprocessing.cpu_count(), 12)  # Use up to 12 processes
        if self.total_bytes < 10 * 1024 * 1024:  # Less than 10MB
            self.num_processes = 1  # Not worth the overhead
        elif self.total_bytes < 100 * 1024 * 1024:  # Less than 100MB
            self.num_processes = min(2, self.num_processes)
        
        # Determine chunk size (larger for binary data)
        if dataset_type == "Binary":
            # For binary, use much larger chunks as it's more efficient
            self.chunk_size = 100 * 1024 * 1024  # 100MB chunks
        else:
            # For text, use appropriate sized chunks
            if self.total_bytes > 1024 * 1024 * 1024:  # >1GB
                self.chunk_size = 50 * 1024 * 1024  # 50MB chunks
            else:
                self.chunk_size = 20 * 1024 * 1024  # 20MB chunks
    
    def run(self):
        """Generate the dataset using multiple processes."""
        try:
            start_time = time.time()
            
            # Check if the dataset directory exists
            dataset_dir = os.path.join("src", "datasets")
            os.makedirs(dataset_dir, exist_ok=True)
            
            # Create a filename based on parameters
            custom_name = self.params.get("custom_name", "").strip()
            if custom_name:
                # Format with custom name: dataset_CustomName_Type_SizeUnit.dat
                sanitized_name = ''.join(c if c.isalnum() or c == '_' else '_' for c in custom_name)
                filename = f"dataset_{sanitized_name}_{self.dataset_type}_{self.size_value}{self.size_unit}.dat"
            else:
                # Standard format: dataset_Type_SizeUnit.dat
                filename = f"dataset_{self.dataset_type}_{self.size_value}{self.size_unit}.dat"
            
            file_path = os.path.join(dataset_dir, filename)
            
            is_binary = self.dataset_type == "Binary"
            
            # For very large files (>10GB), use memory mapping for efficiency
            if self.total_bytes > 10 * 1024 * 1024 * 1024 and is_binary:
                self._generate_with_mmap(file_path)
            else:
                # For normal sized files, use the process pool approach
                self._generate_with_process_pool(file_path)
            
            # Log the generation time for debugging
            generation_time = time.time() - start_time
            print(f"Generated {self.size_value}{self.size_unit} {self.dataset_type} dataset in {generation_time:.2f} seconds")
            
            # Emit finished signal with the path to the generated dataset
            self.finished.emit(file_path)
            
        except Exception as e:
            self.error.emit(f"Error generating dataset: {str(e)}")
    
    def _generate_with_mmap(self, file_path):
        """Generate a very large binary dataset using memory mapping."""
        try:
            # Create the file and set its size
            with open(file_path, 'wb') as f:
                # Initialize with zeros
                f.seek(self.total_bytes - 1)
                f.write(b'\0')
            
            # Memory map the file for faster access
            with open(file_path, 'r+b') as f:
                # Map the entire file to memory
                mm = mmap.mmap(f.fileno(), 0)
                
                # Fill it with random data in chunks
                chunk_size = 100 * 1024 * 1024  # 100MB chunks
                bytes_written = 0
                
                with ProcessPoolExecutor(max_workers=self.num_processes) as executor:
                    while bytes_written < self.total_bytes:
                        if self.is_canceled:
                            mm.close()
                            os.remove(file_path)
                            self.error.emit("Dataset generation canceled")
                            return
                        
                        # Calculate current chunk size
                        current_chunk_size = min(chunk_size, self.total_bytes - bytes_written)
                        
                        # Generate random data
                        random_data = _generate_binary_chunk(current_chunk_size)
                        
                        # Write to the memory-mapped file
                        mm[bytes_written:bytes_written + current_chunk_size] = random_data
                        
                        # Update progress
                        bytes_written += current_chunk_size
                        progress = min(100, int((bytes_written / self.total_bytes) * 100))
                        self.progress_updated.emit(progress)
                
                # Flush changes to disk
                mm.flush()
                mm.close()
        except Exception as e:
            if os.path.exists(file_path):
                os.remove(file_path)
            raise e
    
    def _generate_with_process_pool(self, file_path):
        """Generate a dataset using multiple processes."""
        # Create a temporary directory for the chunk files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Calculate the number of chunks needed
            num_chunks = max(1, self.num_processes, math.ceil(self.total_bytes / self.chunk_size))
            chunk_sizes = self._calculate_chunk_sizes(num_chunks)
            
            # Generate chunks in parallel using a process pool
            chunk_paths = []
            
            with ProcessPoolExecutor(max_workers=self.num_processes) as executor:
                futures = []
                
                for i, chunk_size in enumerate(chunk_sizes):
                    if self.is_canceled:
                        break
                    
                    chunk_path = os.path.join(temp_dir, f"chunk_{i}.dat")
                    chunk_paths.append(chunk_path)
                    
                    # Submit the appropriate task to the process pool
                    if self.dataset_type == "Words":
                        future = executor.submit(_generate_words_chunk, chunk_size, self.params)
                    elif self.dataset_type == "Sentences":
                        future = executor.submit(_generate_sentences_chunk, chunk_size, self.params)
                    elif self.dataset_type == "Numbers":
                        future = executor.submit(_generate_numbers_chunk, chunk_size, self.params)
                    elif self.dataset_type == "Binary":
                        future = executor.submit(_generate_binary_chunk, chunk_size)
                    elif self.dataset_type == "Custom Char Set":
                        future = executor.submit(_generate_custom_charset_chunk, chunk_size, self.params)
                    else:
                        raise ValueError(f"Unknown dataset type: {self.dataset_type}")
                    
                    futures.append((future, i, chunk_path))
                
                # Process completed chunks and update progress
                bytes_processed = 0
                
                # First, collect all futures
                results = []
                for future, i, chunk_path in futures:
                    if self.is_canceled:
                        break
                    
                    try:
                        chunk_data = future.result()
                        results.append((chunk_data, i, chunk_path))
                        
                        # Update progress for generation phase
                        bytes_processed += chunk_sizes[i]
                        progress = min(50, int((bytes_processed / self.total_bytes) * 50))
                        self.progress_updated.emit(progress)
                        
                    except Exception as e:
                        self.error.emit(f"Error generating chunk {i}: {str(e)}")
                        raise
                
                # Then write all chunks in parallel (I/O bound operation)
                write_futures = []
                is_binary = self.dataset_type == "Binary"
                
                for chunk_data, i, chunk_path in results:
                    if self.is_canceled:
                        break
                    
                    # Submit write operation
                    write_future = executor.submit(_write_chunk_to_file, chunk_data, chunk_path, is_binary)
                    write_futures.append((write_future, i))
                
                # Wait for all writes to complete
                for write_future, i in write_futures:
                    if self.is_canceled:
                        break
                    
                    try:
                        write_future.result()
                        
                        # Update progress for write phase
                        progress = 50 + min(40, int((i / len(write_futures)) * 40))
                        self.progress_updated.emit(progress)
                        
                    except Exception as e:
                        self.error.emit(f"Error writing chunk {i}: {str(e)}")
                        raise
            
            if self.is_canceled:
                self.error.emit("Dataset generation canceled")
                return
            
            # Combine chunks into the final file
            if self.dataset_type == "Binary":
                with open(file_path, 'wb', buffering=16*1024*1024) as outfile:
                    for chunk_path in chunk_paths:
                        if os.path.exists(chunk_path):
                            with open(chunk_path, 'rb') as infile:
                                shutil.copyfileobj(infile, outfile, 16*1024*1024)
            else:
                with open(file_path, 'w', buffering=16*1024*1024) as outfile:
                    for chunk_path in chunk_paths:
                        if os.path.exists(chunk_path):
                            with open(chunk_path, 'r') as infile:
                                shutil.copyfileobj(infile, outfile, 16*1024*1024)
            
            # Update progress to 100%
            self.progress_updated.emit(100)
    
    def _calculate_chunk_sizes(self, num_chunks):
        """Calculate the size of each chunk."""
        base_chunk_size = self.total_bytes // num_chunks
        chunk_sizes = [base_chunk_size] * num_chunks
        
        # Distribute remaining bytes
        remaining = self.total_bytes - (base_chunk_size * num_chunks)
        for i in range(remaining):
            chunk_sizes[i] += 1
        
        return chunk_sizes
    
    def cancel(self):
        """Cancel the generation process."""
        self.is_canceled = True


class DatasetTab(QWidget):
    """Dataset Management tab widget."""
    
    status_message = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        
        # Initialize member variables
        self.worker = None
        self.selected_dataset_path = None
        
        # Set up the UI
        self._setup_ui()
    
    def _setup_ui(self):
        """Set up the UI components."""
        # Main layout
        main_layout = QVBoxLayout(self)
        
        # Create a scroll area for the content
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        
        # Option group
        option_group = QGroupBox("Dataset Selection")
        option_layout = QVBoxLayout()
        
        # Option 1: Select Existing Dataset
        self.option1_radio = QRadioButton("Select Existing Dataset")
        option_layout.addWidget(self.option1_radio)
        
        # Dataset selection - use a list widget instead of file dialog
        self.datasets_list = QComboBox()
        self.datasets_list.setMinimumWidth(400)
        option_layout.addWidget(self.datasets_list)
        
        # Refresh datasets button
        refresh_layout = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh Datasets")
        self.dataset_info_label = QLabel("No dataset selected")
        refresh_layout.addWidget(self.refresh_button)
        refresh_layout.addWidget(self.dataset_info_label)
        refresh_layout.addStretch()
        option_layout.addLayout(refresh_layout)
        
        # Option 2: Create New Dataset
        self.option2_radio = QRadioButton("Create New Dataset")
        option_layout.addWidget(self.option2_radio)
        
        # Dataset creation form
        creation_group = QGroupBox("Dataset Creation Parameters")
        creation_layout = QFormLayout()
        
        # Dataset type
        self.dataset_type_combo = QComboBox()
        self.dataset_type_combo.addItems([
            "Words", 
            "Sentences", 
            "Numbers", 
            "Binary", 
            "Custom Char Set"
        ])
        creation_layout.addRow("Type:", self.dataset_type_combo)
        
        # Dataset name field
        self.dataset_name_edit = QLineEdit()
        self.dataset_name_edit.setPlaceholderText("Optional custom name (leave empty for auto-naming)")
        creation_layout.addRow("Name:", self.dataset_name_edit)
        
        # Size parameters
        size_layout = QHBoxLayout()
        
        # Total size value
        self.total_size_spin = QSpinBox()
        self.total_size_spin.setRange(1, 50000)  
        self.total_size_spin.setValue(1024)  # Default to 1MB
        size_layout.addWidget(self.total_size_spin)
        
        # Size unit selection
        self.size_unit_combo = QComboBox()
        self.size_unit_combo.addItems(["KB", "MB", "GB"])
        self.size_unit_combo.setCurrentIndex(0)  # Default to KB
        size_layout.addWidget(self.size_unit_combo)
        
        # Add a label to show the size in bytes for reference
        self.size_tooltip_label = QLabel("(Range: 500KB - 50GB)")
        size_layout.addWidget(self.size_tooltip_label)
        
        creation_layout.addRow("Total Size:", size_layout)
        
        # Custom parameters (shown/hidden based on selected type)
        self.custom_params_group = QGroupBox("Type-Specific Settings")
        self.custom_params_layout = QFormLayout(self.custom_params_group)
        
        creation_layout.addRow(self.custom_params_group)
        
        # Set layout for creation group
        creation_group.setLayout(creation_layout)
        option_layout.addWidget(creation_group)
        
        # Progress bar for dataset generation
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        option_layout.addWidget(self.progress_bar)
        
        # Generate dataset button
        self.generate_button = QPushButton("Generate Dataset")
        option_layout.addWidget(self.generate_button)
        
        # Add option layout to group
        option_group.setLayout(option_layout)
        
        # Add groups to scroll layout
        scroll_layout.addWidget(option_group)
        
        # Add spacing
        scroll_layout.addStretch()
        
        # Set the scroll content and add to main layout
        scroll_area.setWidget(scroll_content)
        main_layout.addWidget(scroll_area)
        
        # Default selection
        self.option1_radio.setChecked(True)
        self._update_ui_state()
        
        # Connect signals
        self._connect_signals()
        
        # Update custom parameters for default selection
        self._update_custom_params()
        
        # Populate the datasets list
        self._refresh_datasets_list()
    
    def _connect_signals(self):
        """Connect signals to slots."""
        # Radio button signals
        self.option1_radio.toggled.connect(self._update_ui_state)
        self.option2_radio.toggled.connect(self._update_ui_state)
        
        # Button signals
        self.refresh_button.clicked.connect(self._refresh_datasets_list)
        self.generate_button.clicked.connect(self._generate_dataset)
        
        # Combo box signals
        self.dataset_type_combo.currentIndexChanged.connect(self._update_custom_params)
        self.datasets_list.currentIndexChanged.connect(self._dataset_selected)
        
        # Size unit change
        self.size_unit_combo.currentIndexChanged.connect(self._update_size_limits)
    
    def _update_ui_state(self):
        """Update UI components based on selected option."""
        # Update file selection controls
        self.datasets_list.setEnabled(self.option1_radio.isChecked())
        self.refresh_button.setEnabled(self.option1_radio.isChecked())
        
        # Update dataset creation controls
        enable_creation = self.option2_radio.isChecked()
        self.dataset_type_combo.setEnabled(enable_creation)
        self.dataset_name_edit.setEnabled(enable_creation)
        self.total_size_spin.setEnabled(enable_creation)
        self.size_unit_combo.setEnabled(enable_creation)
        self.custom_params_group.setEnabled(enable_creation)
        
        # Enable/disable generate button
        self.generate_button.setEnabled(enable_creation)
    
    def _update_size_limits(self):
        """Update size limits based on selected unit."""
        unit = self.size_unit_combo.currentText()
        
        if unit == "KB":
            self.total_size_spin.setMinimum(500)  # Min 500 KB
            self.total_size_spin.setMaximum(50000)  # Max 50,000 KB
            if self.total_size_spin.value() < 500:
                self.total_size_spin.setValue(500)
        elif unit == "MB":
            self.total_size_spin.setMinimum(1)  # Min 1 MB
            self.total_size_spin.setMaximum(50000)  # Max 50,000 MB
            if self.total_size_spin.value() < 1:
                self.total_size_spin.setValue(1)
        elif unit == "GB":
            self.total_size_spin.setMinimum(1)  # Min 1 GB
            self.total_size_spin.setMaximum(50)  # Max 50 GB
            if self.total_size_spin.value() > 50:
                self.total_size_spin.setValue(50)
                
        # Show the valid range instead of bytes size
        self.size_tooltip_label.setText("(Range: 500KB - 50GB)")
    
    def _format_size(self, size_bytes):
        """Format size in bytes to a human-readable string."""
        if size_bytes < 1024:
            return f"{size_bytes} bytes"
        elif size_bytes < 1024**2:
            return f"{size_bytes/1024:.2f} KB"
        elif size_bytes < 1024**3:
            return f"{size_bytes/1024**2:.2f} MB"
        elif size_bytes < 1024**4:
            return f"{size_bytes/1024**3:.2f} GB"
        else:
            return f"{size_bytes/1024**4:.2f} TB"
    
    def _clear_layout(self, layout):
        """Clear all widgets and nested layouts from a layout."""
        if layout is None:
            return
        
        # Get all items in reverse order (to avoid index shifting when items are removed)
        for i in reversed(range(layout.count())):
            item = layout.itemAt(i)
            
            if item.widget():
                # If it's a widget, set its parent to None (removes it from layout)
                item.widget().setParent(None)
            elif item.layout():
                # If it's a layout, recursively clear it
                self._clear_layout(item.layout())
                # Then remove it from the parent layout
                layout.removeItem(item)
            else:
                # For spacer items or other types
                layout.removeItem(item)

    def _update_custom_params(self):
        """Update custom parameters based on selected dataset type."""
        # Only enable if option 2 is selected
        enable_custom = self.option2_radio.isChecked()
        
        # Get selected dataset type
        dataset_type = self.dataset_type_combo.currentText()
        
        # Clear all custom params using recursive clearing
        self._clear_layout(self.custom_params_layout)
        
        # Add appropriate params based on type
        if dataset_type == "Words":
            # Word length range
            length_layout = QHBoxLayout()
            
            self.min_word_length_spin = QSpinBox()
            self.min_word_length_spin.setRange(1, 50)
            self.min_word_length_spin.setValue(3)
            self.min_word_length_spin.setEnabled(enable_custom)
            length_layout.addWidget(QLabel("Min:"))
            length_layout.addWidget(self.min_word_length_spin)
            
            self.max_word_length_spin = QSpinBox()
            self.max_word_length_spin.setRange(1, 100)
            self.max_word_length_spin.setValue(10)
            self.max_word_length_spin.setEnabled(enable_custom)
            length_layout.addWidget(QLabel("Max:"))
            length_layout.addWidget(self.max_word_length_spin)
            
            self.custom_params_layout.addRow("Word Length:", length_layout)
            
            # Spaces options
            spaces_layout = QVBoxLayout()
            
            self.include_spaces_check = QCheckBox("Include spaces between words")
            self.include_spaces_check.setChecked(True)
            self.include_spaces_check.setEnabled(enable_custom)
            spaces_layout.addWidget(self.include_spaces_check)
            
            # Space frequency slider
            slider_layout = QHBoxLayout()
            slider_layout.addWidget(QLabel("Space Frequency:"))
            
            self.space_frequency_slider = QSlider(Qt.Orientation.Horizontal)
            self.space_frequency_slider.setRange(1, 100)
            self.space_frequency_slider.setValue(100)  # 100% by default
            self.space_frequency_slider.setEnabled(enable_custom)
            slider_layout.addWidget(self.space_frequency_slider)
            
            self.space_frequency_label = QLabel("100%")
            slider_layout.addWidget(self.space_frequency_label)
            
            # Connect slider to label
            self.space_frequency_slider.valueChanged.connect(
                lambda value: self.space_frequency_label.setText(f"{value}%")
            )
            
            spaces_layout.addLayout(slider_layout)
            self.custom_params_layout.addRow("Spaces:", spaces_layout)
            
            # Uppercase options
            uppercase_layout = QVBoxLayout()
            
            self.uppercase_group = QButtonGroup(self)
            self.uppercase_none_radio = QRadioButton("No uppercase letters")
            self.uppercase_first_radio = QRadioButton("Capitalize first letter")
            self.uppercase_random_radio = QRadioButton("Random uppercase letters")
            self.uppercase_all_radio = QRadioButton("All uppercase letters")
            
            self.uppercase_group.addButton(self.uppercase_none_radio)
            self.uppercase_group.addButton(self.uppercase_first_radio)
            self.uppercase_group.addButton(self.uppercase_random_radio)
            self.uppercase_group.addButton(self.uppercase_all_radio)
            
            self.uppercase_none_radio.setChecked(True)
            
            uppercase_layout.addWidget(self.uppercase_none_radio)
            uppercase_layout.addWidget(self.uppercase_first_radio)
            uppercase_layout.addWidget(self.uppercase_random_radio)
            uppercase_layout.addWidget(self.uppercase_all_radio)
            
            # Add probability slider for random uppercase
            prob_layout = QHBoxLayout()
            prob_layout.addWidget(QLabel("Random Uppercase Probability:"))
            
            self.uppercase_prob_slider = QSlider(Qt.Orientation.Horizontal)
            self.uppercase_prob_slider.setRange(1, 100)
            self.uppercase_prob_slider.setValue(20)  # 20% by default
            self.uppercase_prob_slider.setEnabled(enable_custom)
            prob_layout.addWidget(self.uppercase_prob_slider)
            
            self.uppercase_prob_label = QLabel("20%")
            prob_layout.addWidget(self.uppercase_prob_label)
            
            # Connect slider to label
            self.uppercase_prob_slider.valueChanged.connect(
                lambda value: self.uppercase_prob_label.setText(f"{value}%")
            )
            
            uppercase_layout.addLayout(prob_layout)
            self.custom_params_layout.addRow("Uppercase:", uppercase_layout)
            
            # Connect random radio to enable the slider
            self.uppercase_random_radio.toggled.connect(
                lambda checked: self.uppercase_prob_slider.setEnabled(checked and enable_custom)
            )
            self.uppercase_prob_slider.setEnabled(self.uppercase_random_radio.isChecked() and enable_custom)
        
        elif dataset_type == "Sentences":
            # Sentence length range (in words)
            length_layout = QHBoxLayout()
            
            self.min_sentence_length_spin = QSpinBox()
            self.min_sentence_length_spin.setRange(1, 50)
            self.min_sentence_length_spin.setValue(3)
            self.min_sentence_length_spin.setEnabled(enable_custom)
            length_layout.addWidget(QLabel("Min:"))
            length_layout.addWidget(self.min_sentence_length_spin)
            
            self.max_sentence_length_spin = QSpinBox()
            self.max_sentence_length_spin.setRange(1, 100)
            self.max_sentence_length_spin.setValue(15)
            self.max_sentence_length_spin.setEnabled(enable_custom)
            length_layout.addWidget(QLabel("Max:"))
            length_layout.addWidget(self.max_sentence_length_spin)
            
            self.custom_params_layout.addRow("Words per Sentence:", length_layout)
            
            # Word length range
            word_length_layout = QHBoxLayout()
            
            self.min_word_length_spin = QSpinBox()
            self.min_word_length_spin.setRange(1, 20)
            self.min_word_length_spin.setValue(2)
            self.min_word_length_spin.setEnabled(enable_custom)
            word_length_layout.addWidget(QLabel("Min:"))
            word_length_layout.addWidget(self.min_word_length_spin)
            
            self.max_word_length_spin = QSpinBox()
            self.max_word_length_spin.setRange(1, 30)
            self.max_word_length_spin.setValue(10)
            self.max_word_length_spin.setEnabled(enable_custom)
            word_length_layout.addWidget(QLabel("Max:"))
            word_length_layout.addWidget(self.max_word_length_spin)
            
            self.custom_params_layout.addRow("Word Length:", word_length_layout)
            
            # Include numbers option
            self.include_numbers_check = QCheckBox("Include numbers")
            self.include_numbers_check.setChecked(False)
            self.include_numbers_check.setEnabled(enable_custom)
            self.custom_params_layout.addRow(self.include_numbers_check)
            
            # Always capitalize first letter
            self.capitalize_check = QCheckBox("Always capitalize first letter of sentences")
            self.capitalize_check.setChecked(True)
            self.capitalize_check.setEnabled(enable_custom)
            self.custom_params_layout.addRow(self.capitalize_check)
            
            # Punctuation options
            punctuation_layout = QVBoxLayout()
            
            self.include_punctuation_check = QCheckBox("Include punctuation")
            self.include_punctuation_check.setChecked(True)
            self.include_punctuation_check.setEnabled(enable_custom)
            punctuation_layout.addWidget(self.include_punctuation_check)
            
            # Punctuation frequency slider
            punct_slider_layout = QHBoxLayout()
            punct_slider_layout.addWidget(QLabel("Punctuation Frequency:"))
            
            self.punctuation_freq_slider = QSlider(Qt.Orientation.Horizontal)
            self.punctuation_freq_slider.setRange(1, 100)
            self.punctuation_freq_slider.setValue(20)  # 20% by default
            self.punctuation_freq_slider.setEnabled(enable_custom)
            punct_slider_layout.addWidget(self.punctuation_freq_slider)
            
            self.punctuation_freq_label = QLabel("20%")
            punct_slider_layout.addWidget(self.punctuation_freq_label)
            
            # Connect slider to label
            self.punctuation_freq_slider.valueChanged.connect(
                lambda value: self.punctuation_freq_label.setText(f"{value}%")
            )
            
            punctuation_layout.addLayout(punct_slider_layout)
            self.custom_params_layout.addRow("Punctuation:", punctuation_layout)
            
            # Connect check to enable slider
            self.include_punctuation_check.toggled.connect(
                lambda checked: self.punctuation_freq_slider.setEnabled(checked and enable_custom)
            )
            self.punctuation_freq_slider.setEnabled(self.include_punctuation_check.isChecked() and enable_custom)
            
            # Sentence spacing options
            spacing_layout = QHBoxLayout()
            spacing_layout.addWidget(QLabel("Spacing between sentences:"))
            
            self.sentence_spacing_combo = QComboBox()
            self.sentence_spacing_combo.addItems(["Single space", "Double space", "Random (1-3 spaces)"])
            self.sentence_spacing_combo.setEnabled(enable_custom)
            spacing_layout.addWidget(self.sentence_spacing_combo)
            
            self.custom_params_layout.addRow("Spacing:", spacing_layout)
        
        elif dataset_type == "Numbers":
            # Number type
            self.number_type_combo = QComboBox()
            self.number_type_combo.addItems(["decimal", "binary", "hexadecimal"])
            self.number_type_combo.setEnabled(enable_custom)
            self.custom_params_layout.addRow("Number Type:", self.number_type_combo)
            
            # Number length range (in digits)
            length_layout = QHBoxLayout()
            
            self.min_digits_spin = QSpinBox()
            self.min_digits_spin.setRange(1, 100)
            self.min_digits_spin.setValue(1)
            self.min_digits_spin.setEnabled(enable_custom)
            length_layout.addWidget(QLabel("Min:"))
            length_layout.addWidget(self.min_digits_spin)
            
            self.max_digits_spin = QSpinBox()
            self.max_digits_spin.setRange(1, 1000)
            self.max_digits_spin.setValue(10)
            self.max_digits_spin.setEnabled(enable_custom)
            length_layout.addWidget(QLabel("Max:"))
            length_layout.addWidget(self.max_digits_spin)
            
            self.custom_params_layout.addRow("Digits per Number:", length_layout)
            
            # Spaces option
            self.number_spaces_check = QCheckBox("Include spaces between numbers")
            self.number_spaces_check.setChecked(True)
            self.number_spaces_check.setEnabled(enable_custom)
            self.custom_params_layout.addRow(self.number_spaces_check)
            
            # Format options
            format_layout = QVBoxLayout()
            
            self.include_prefix_check = QCheckBox("Include prefixes (0x, 0b)")
            self.include_prefix_check.setChecked(False)
            self.include_prefix_check.setEnabled(enable_custom)
            format_layout.addWidget(self.include_prefix_check)
            
            self.include_grouping_check = QCheckBox("Include grouping separators (_)")
            self.include_grouping_check.setChecked(False)
            self.include_grouping_check.setEnabled(enable_custom)
            format_layout.addWidget(self.include_grouping_check)
            
            self.custom_params_layout.addRow("Format:", format_layout)
        
        elif dataset_type == "Binary":
            # No special params for binary
            info_label = QLabel("Binary datasets contain completely random binary data.")
            info_label.setWordWrap(True)
            self.custom_params_layout.addRow(info_label)
        
        elif dataset_type == "Custom Char Set":
            # Custom charset
            self.custom_charset_edit = QLineEdit()
            self.custom_charset_edit.setPlaceholderText("e.g., abcdefABCDEF0123456789")
            self.custom_charset_edit.setEnabled(enable_custom)
            self.custom_params_layout.addRow("Custom Charset:", self.custom_charset_edit)
            
            # Predefined charset selections
            preset_layout = QHBoxLayout()
            preset_layout.addWidget(QLabel("Presets:"))
            
            self.charset_preset_combo = QComboBox()
            self.charset_preset_combo.addItems([
                "Select preset...",
                "Alphanumeric",
                "Lowercase letters only",
                "Uppercase letters only",
                "Digits only",
                "Hex digits",
                "ASCII printable",
                "Base64 characters"
            ])
            self.charset_preset_combo.setEnabled(enable_custom)
            preset_layout.addWidget(self.charset_preset_combo)
            
            # Connect preset selection to charset edit
            self.charset_preset_combo.currentIndexChanged.connect(self._update_charset_preset)
            
            self.custom_params_layout.addRow("Presets:", preset_layout)
    
    def _refresh_datasets_list(self):
        """Refresh the list of available datasets."""
        self.datasets_list.clear()
        self.datasets_list.addItem("-- Select a dataset --")
        
        # Check if the dataset directory exists
        dataset_dir = os.path.join("src", "datasets")
        if not os.path.exists(dataset_dir):
            os.makedirs(dataset_dir, exist_ok=True)
            return
        
        # Get all dataset files
        dataset_files = []
        for file in os.listdir(dataset_dir):
            if file.startswith("dataset_") and os.path.isfile(os.path.join(dataset_dir, file)):
                # Get file size
                file_size = os.path.getsize(os.path.join(dataset_dir, file))
                file_size_str = self._format_size(file_size)
                
                # Parse dataset type and size from filename
                try:
                    # Format: dataset_Type_SizeUnit.dat or dataset_CustomName_Type_SizeUnit.dat
                    if file.count('_') == 2:
                        _, data_type, size_part = file.split('_', 2)
                        size_part = size_part.replace('.dat', '')
                        display_name = f"{data_type} ({size_part}) - {file_size_str}"
                    else:
                        parts = file.split('_')
                        custom_name = '_'.join(parts[1:-2])
                        data_type = parts[-2]
                        size_part = parts[-1].replace('.dat', '')
                        display_name = f"{custom_name} - {data_type} ({size_part}) - {file_size_str}"
                except:
                    # If parsing fails, just use the filename
                    display_name = f"{file} - {file_size_str}"
                
                # Add to list with full path as data
                dataset_files.append((display_name, os.path.join(dataset_dir, file)))
        
        # Sort by name
        dataset_files.sort()
        
        # Add to combobox
        for display_name, file_path in dataset_files:
            self.datasets_list.addItem(display_name, file_path)
    
    def _dataset_selected(self, index):
        """Handle dataset selection from the dropdown."""
        if index <= 0:
            self.selected_dataset_path = None
            self.dataset_info_label.setText("No dataset selected")
            return
        
        # Get selected dataset path
        self.selected_dataset_path = self.datasets_list.itemData(index)
        
        # Update info label
        filename = os.path.basename(self.selected_dataset_path)
        file_size = os.path.getsize(self.selected_dataset_path)
        self.dataset_info_label.setText(f"Selected: {filename} ({self._format_size(file_size)})")
        
        self.status_message.emit(f"Selected dataset: {filename}")
    
    def _generate_dataset(self):
        """Generate a new dataset based on the specified parameters."""
        # Check if a worker is already running
        if self.worker and self.worker.isRunning():
            # Stop the current worker
            self.worker.cancel()
            self.worker.wait()
            self.progress_bar.setVisible(False)
            self.generate_button.setText("Generate Dataset")
            self.status_message.emit("Dataset generation canceled")
            return
        
        # Get basic parameters
        dataset_type = self.dataset_type_combo.currentText()
        size_value = self.total_size_spin.value()
        size_unit = self.size_unit_combo.currentText()
        
        # Get type-specific parameters
        params = {
            "custom_name": self.dataset_name_edit.text().strip()
        }
        
        if dataset_type == "Words":
            params["min_word_length"] = self.min_word_length_spin.value()
            params["max_word_length"] = self.max_word_length_spin.value()
            params["include_spaces"] = self.include_spaces_check.isChecked()
            params["space_frequency"] = self.space_frequency_slider.value() / 100.0
            
            # Get uppercase option
            if self.uppercase_first_radio.isChecked():
                params["uppercase_option"] = "first_letter"
            elif self.uppercase_random_radio.isChecked():
                params["uppercase_option"] = "random"
                params["uppercase_probability"] = self.uppercase_prob_slider.value() / 100.0
            elif self.uppercase_all_radio.isChecked():
                params["uppercase_option"] = "all"
            else:
                params["uppercase_option"] = "none"
        
        elif dataset_type == "Sentences":
            params["min_words_per_sentence"] = self.min_sentence_length_spin.value()
            params["max_words_per_sentence"] = self.max_sentence_length_spin.value()
            params["min_word_length"] = self.min_word_length_spin.value()
            params["max_word_length"] = self.max_word_length_spin.value()
            params["include_numbers"] = self.include_numbers_check.isChecked()
            params["always_capitalize"] = self.capitalize_check.isChecked()
            params["include_punctuation"] = self.include_punctuation_check.isChecked()
            params["punctuation_frequency"] = self.punctuation_freq_slider.value() / 100.0
            
            # Get sentence spacing option
            spacing_option = self.sentence_spacing_combo.currentText()
            if spacing_option == "Single space":
                params["sentence_spacing"] = 1
            elif spacing_option == "Double space":
                params["sentence_spacing"] = 2
            else:  # Random
                params["sentence_spacing"] = "random"
        
        elif dataset_type == "Numbers":
            params["number_type"] = self.number_type_combo.currentText()
            params["min_digits"] = self.min_digits_spin.value()
            params["max_digits"] = self.max_digits_spin.value()
            params["include_spaces"] = self.number_spaces_check.isChecked()
            params["include_prefix"] = self.include_prefix_check.isChecked()
            params["include_grouping"] = self.include_grouping_check.isChecked()
        
        elif dataset_type == "Custom Char Set":
            params["charset"] = self.custom_charset_edit.text()
        
        # Create worker thread
        self.worker = DatasetGenerationWorker(dataset_type, size_value, size_unit, params)
        
        # Connect signals
        self.worker.progress_updated.connect(self._update_progress)
        self.worker.finished.connect(self._dataset_generation_finished)
        self.worker.error.connect(self._dataset_generation_error)
        
        # Update UI
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.generate_button.setText("Cancel Generation")
        
        # Create a descriptive message
        msg = f"Generating {dataset_type} dataset ({size_value} {size_unit}"
        if dataset_type == "Words":
            msg += f", word length {params['min_word_length']}-{params['max_word_length']}"
        elif dataset_type == "Sentences":
            msg += f", {params['min_words_per_sentence']}-{params['max_words_per_sentence']} words/sentence"
        elif dataset_type == "Numbers":
            msg += f", {params['number_type']} type"
        msg += ")..."
        
        self.status_message.emit(msg)
        
        # Start worker
        self.worker.start()
    
    @pyqtSlot(int)
    def _update_progress(self, value):
        """Update progress bar value."""
        self.progress_bar.setValue(value)
    
    @pyqtSlot(str)
    def _dataset_generation_finished(self, file_path):
        """Handle dataset generation finished."""
        # Update UI
        self.progress_bar.setVisible(False)
        self.generate_button.setText("Generate Dataset")
        
        # Update selected dataset
        self.selected_dataset_path = file_path
        self.status_message.emit(f"Dataset generated successfully: {os.path.basename(file_path)}")
        
        # Switch to option 1 and refresh the list
        self.option1_radio.setChecked(True)
        self._refresh_datasets_list()
        
        # Select the newly created dataset
        for i in range(self.datasets_list.count()):
            if self.datasets_list.itemData(i) == file_path:
                self.datasets_list.setCurrentIndex(i)
                break
    
    @pyqtSlot(str)
    def _dataset_generation_error(self, error_message):
        """Handle dataset generation error."""
        # Update UI
        self.progress_bar.setVisible(False)
        self.generate_button.setText("Generate Dataset")
        
        # Display error message
        self.status_message.emit(f"Error: {error_message}")
    
    def get_selected_dataset(self):
        """Get the selected dataset path."""
        if self.option1_radio.isChecked() and self.selected_dataset_path:
            return self.selected_dataset_path
        return None

    def _update_charset_preset(self):
        """Update the charset edit field based on the selected preset."""
        if not hasattr(self, 'charset_preset_combo') or not hasattr(self, 'custom_charset_edit'):
            return
            
        preset = self.charset_preset_combo.currentText()
        
        if preset == "Alphanumeric":
            self.custom_charset_edit.setText(string.ascii_letters + string.digits)
        elif preset == "Lowercase letters only":
            self.custom_charset_edit.setText(string.ascii_lowercase)
        elif preset == "Uppercase letters only":
            self.custom_charset_edit.setText(string.ascii_uppercase)
        elif preset == "Digits only":
            self.custom_charset_edit.setText(string.digits)
        elif preset == "Hex digits":
            self.custom_charset_edit.setText(string.hexdigits)
        elif preset == "ASCII printable":
            self.custom_charset_edit.setText(string.printable)
        elif preset == "Base64 characters":
            self.custom_charset_edit.setText(string.ascii_letters + string.digits + "+/=") 