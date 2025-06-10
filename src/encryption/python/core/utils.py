#!/usr/bin/env python3
"""
CryptoBench Pro - Python Core Utility Functions
Provides utility classes and functions for benchmarking.
"""

import os
import gc
import logging

# Setup logging
logger = logging.getLogger("PythonCore")

class MemoryMappedDataset:
    """Memory-mapped dataset handler for efficient memory usage with large files."""
    
    def __init__(self, file_path, read_only=True):
        """Initialize with file path."""
        import mmap
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path)
        self.file = open(file_path, 'rb')
        self.mmap = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ if read_only else mmap.ACCESS_COPY)
        self.read_only = read_only
        self._closed = False
    
    def __len__(self):
        """Return the file size."""
        return self.file_size
    
    def read(self, offset=0, size=None):
        """Read a portion of the file."""
        if self._closed:
            raise ValueError("Cannot read from closed memory-mapped dataset")
            
        if size is None:
            size = self.file_size - offset
        
        # Ensure we don't read past the end
        size = min(size, self.file_size - offset)
        
        self.mmap.seek(offset)
        return self.mmap.read(size)
    
    def read_all(self):
        """Read the entire file."""
        return self.read(0, self.file_size)
    
    def __getitem__(self, key):
        """Support for subscript access - dataset[x] or dataset[start:end]."""
        if isinstance(key, slice):
            start = 0 if key.start is None else key.start
            stop = self.file_size if key.stop is None else key.stop
            size = stop - start
            return self.read(start, size)
        elif isinstance(key, int):
            if key < 0:  # Handle negative indices
                key = self.file_size + key
            return self.read(key, 1)
        else:
            raise TypeError(f"Invalid index type: {type(key)}")
    
    def close(self):
        """Close the memory map and file."""
        if self._closed:
            return
            
        try:
            if hasattr(self, 'mmap') and self.mmap:
                self.mmap.close()
        except ValueError:
            # Already closed or invalid, just ignore
            pass
        except Exception as e:
            logger.warning(f"Error closing memory map: {str(e)}")
        
        try:
            if hasattr(self, 'file') and self.file:
                self.file.close()
        except Exception as e:
            logger.warning(f"Error closing file: {str(e)}")
            
        self._closed = True
    
    def __del__(self):
        """Ensure resources are properly cleaned up."""
        try:
            self.close()
        except Exception:
            # Suppress all exceptions during garbage collection
            pass

class RotatingKeySet:
    """Class to manage a set of keys that rotate for each chunk of data."""
    
    def __init__(self, key_pairs):
        """Initialize with a list of key pairs."""
        self.key_pairs = key_pairs
        self.current_index = 0
        self.total_keys = len(key_pairs)
        # Special attribute to identify this as a rotating key set
        self.__rotating_keys__ = True
    
    def get_next_key(self):
        """Get the next key in the rotation and advance the index."""
        if not self.key_pairs:
            raise ValueError("No keys available in the rotating key set")
        
        # Get the current key
        key = self.key_pairs[self.current_index]
        
        # Advance to the next key for next time
        self.current_index = (self.current_index + 1) % self.total_keys
        
        return key
    
    def reset(self):
        """Reset the rotation to start from the first key again."""
        self.current_index = 0

def load_dataset(dataset_path, use_mmap=False):
    """
    Load dataset from file while minimizing memory footprint.
    
    Args:
        dataset_path: Path to the dataset file
        use_mmap: If True, use memory mapping for very large files
    
    Returns:
        The dataset content or a MemoryMappedDataset object
    """
    try:
        import psutil
        
        # Get file size to make memory estimation
        file_size = os.path.getsize(dataset_path)
        
        logger.info(f"Loading dataset ({file_size / (1024*1024):.2f} MB) from {dataset_path}")
        
        # Check available system memory
        available_mem = psutil.virtual_memory().available
        logger.info(f"Available system memory: {available_mem / (1024*1024):.2f} MB")
        
        # Determine if we should use memory mapping
        # If file is > 40% of available memory, recommend memory mapping
        should_use_mmap = file_size > (available_mem * 0.4)
        
        if should_use_mmap:
            logger.warning(
                f"Dataset size ({file_size / (1024*1024):.2f} MB) is large relative to "
                f"available memory ({available_mem / (1024*1024):.2f} MB). "
                f"Using memory-mapped mode to reduce RAM usage."
            )
            use_mmap = True
        elif file_size > available_mem * 0.6:
            logger.warning(
                f"Dataset size ({file_size / (1024*1024):.2f} MB) is large relative to "
                f"available memory ({available_mem / (1024*1024):.2f} MB). "
                f"Consider using Stream processing mode or a smaller dataset."
            )
        
        if use_mmap:
            # Use memory mapping for efficient handling of large files
            logger.info("Using memory-mapped file access for efficient memory usage")
            return MemoryMappedDataset(dataset_path)
        else:
            # Read file in one go (most memory efficient for smaller files)
            with open(dataset_path, 'rb') as f:
                data = f.read()
            
            # Force garbage collection after loading large dataset
            gc.collect()
            
            return data
    except Exception as e:
        logger.error(f"Error loading dataset: {str(e)}")
        return None 