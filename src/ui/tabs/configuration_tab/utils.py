"""
CryptoBench Pro - Configuration Tab Utilities Module
Contains utility functions for dataset analysis, PC specs collection, and other helpers.
"""

import os
import platform
import psutil
import subprocess


class SystemInfoCollector:
    """Collects system information and specifications."""
    
    @staticmethod
    def collect_pc_specs():
        """Collect information about the system."""
        specs = {
            "cpu": {
                "name": platform.processor() or "Unknown",
                "architecture": platform.machine(),
                "cores": psutil.cpu_count(logical=False),
                "logical_cores": psutil.cpu_count(logical=True)
            },
            "memory": {
                "total_ram_gb": round(psutil.virtual_memory().total / (1024 ** 3), 2),
                "available_ram_gb": round(psutil.virtual_memory().available / (1024 ** 3), 2)
            },
            "os": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version()
            }
        }
        
        # Try to get more detailed CPU information on macOS
        if platform.system() == "Darwin":
            try:
                result = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], 
                                       capture_output=True, text=True, check=True)
                specs["cpu"]["name"] = result.stdout.strip()
                
                # Check if it's Apple Silicon
                if "Apple" in specs["cpu"]["name"]:
                    specs["cpu"]["type"] = "Apple Silicon"
                    # Get GPU cores for Apple Silicon
                    try:
                        result = subprocess.run(["sysctl", "-n", "hw.perflevel0.gpu.cores"],
                                               capture_output=True, text=True, check=True)
                        specs["gpu"] = {"cores": int(result.stdout.strip())}
                    except:
                        specs["gpu"] = {"cores": "Unknown"}
            except:
                # Fall back to platform.processor() which was already set
                pass
        
        return specs


class DatasetAnalyzer:
    """Analyzes datasets and provides information about their content."""
    
    @staticmethod
    def get_dataset_info(dataset_path):
        """Get information about the dataset."""
        info = {
            "file_name": os.path.basename(dataset_path),
            "file_size_kb": round(os.path.getsize(dataset_path) / 1024, 2),
            "content_type": "Unknown"
        }
        
        # Try to determine content type by reading a bit of the file
        try:
            with open(dataset_path, 'r', errors='ignore') as f:
                sample = f.read(4096)  # Read first 4KB
                
                # Check if sample contains various character types
                info["has_alphabetic"] = any(c.isalpha() for c in sample)
                info["has_digits"] = any(c.isdigit() for c in sample)
                info["has_spaces"] = any(c.isspace() for c in sample)
                info["has_punctuation"] = any(c in ",.;:!?-\"'()[]{}" for c in sample)
                info["has_special_chars"] = any(not (c.isalnum() or c.isspace() or c in ",.;:!?-\"'()[]{}") for c in sample)
                
                # Guess the content type
                if all(c.isdigit() or c.isspace() or c in ",.;:" for c in sample):
                    info["content_type"] = "Numbers"
                elif info["has_alphabetic"] and info["has_spaces"] and sample.count(".") > 0:
                    info["content_type"] = "Sentences"
                elif info["has_alphabetic"] and info["has_spaces"]:
                    info["content_type"] = "Words"
                elif info["has_alphabetic"] and not info["has_spaces"]:
                    info["content_type"] = "Custom Char Set"
                elif not info["has_alphabetic"] and not info["has_digits"]:
                    info["content_type"] = "Binary"
        except:
            info["content_type"] = "Unknown (Could not analyze)"
        
        return info

    @staticmethod
    def get_dataset_sample(dataset_path, sample_size=200):
        """Get a sample from the dataset that's more representative."""
        try:
            # Get file size
            file_size = os.path.getsize(dataset_path)
            
            # Detect dataset type
            dataset_info = DatasetAnalyzer.get_dataset_info(dataset_path)
            content_type = dataset_info["content_type"]

            # First, try to detect if it's binary data
            try:
                with open(dataset_path, 'rb') as f:
                    # Read small chunk to detect if it's binary
                    header = f.read(100)
                    
                    # Check if this looks like binary data
                    if b'\x00' in header or not all(32 <= b <= 126 or b in (9, 10, 13) for b in header):
                        # This is binary data - return hexdump style sample
                        sample = []
                        
                        # Sample from start
                        with open(dataset_path, 'rb') as f:
                            start_bytes = f.read(sample_size // 2)
                            hex_dump = ' '.join(f'{b:02x}' for b in start_bytes)
                            sample.append(f"Start: {hex_dump}")
                        
                        # Sample from middle
                        if file_size > sample_size:
                            middle_pos = file_size // 2
                            with open(dataset_path, 'rb') as f:
                                f.seek(max(0, middle_pos - sample_size // 4))
                                mid_bytes = f.read(sample_size // 2)
                                hex_dump = ' '.join(f'{b:02x}' for b in mid_bytes)
                                sample.append(f"Middle: {hex_dump}")
                        
                        return "\n".join(sample)
            except:
                pass  # Fallback to text processing
            
            # Try to get text sample with different strategies
            with open(dataset_path, 'r', errors='ignore') as f:
                if content_type == "Sentences":
                    # For sentences, try to get whole sentences
                    content = f.read(sample_size * 20)  # Read enough for several sentences
                    
                    # Split by common sentence endings
                    all_sentences = []
                    for end_mark in [".", "!", "?"]:
                        parts = content.split(end_mark)
                        for part in parts[:-1]:  # Skip the last part as it might be incomplete
                            if part.strip():  # Ensure non-empty
                                all_sentences.append(part.strip() + end_mark)
                    
                    # Return a few sentences
                    if all_sentences:
                        sample_sentences = all_sentences[:3]  # Take first 3 sentences
                        return " ".join(sample_sentences)
                    else:
                        # Fallback if no sentence endings found
                        return content[:sample_size].strip()
                    
                elif content_type == "Words":
                    # For words, ensure we don't cut words in half
                    content = f.read(sample_size * 10)
                    words = content.split()
                    
                    # Take words up to sample_size characters
                    sample_text = ""
                    for word in words:
                        if len(sample_text) + len(word) + 1 <= sample_size * 2:
                            sample_text += word + " "
                        else:
                            break
                    
                    return sample_text.strip()
                    
                elif content_type == "Numbers":
                    # For numbers, try to take complete numbers
                    content = f.read(sample_size * 5)
                    
                    # Check if there are spaces
                    if " " in content:
                        numbers = content.split()
                        # Take numbers up to sample_size characters
                        sample_text = ""
                        for number in numbers:
                            if len(sample_text) + len(number) + 1 <= sample_size * 2:
                                sample_text += number + " "
                            else:
                                break
                        return sample_text.strip()
                    else:
                        # No spaces, just take the raw characters
                        return content[:sample_size]
                
                else:
                    # For other types or unknown, do simple random sampling
                    samples = []
                    
                    # Sample from beginning
                    f.seek(0)
                    samples.append(f.read(sample_size // 2))
                    
                    # Sample from middle if large enough
                    if file_size > sample_size:
                        f.seek(max(0, file_size // 2 - sample_size // 4))
                        samples.append(f.read(sample_size // 2))
                    
                    return " ... ".join(samples)
                    
        except Exception as e:
            return f"Could not read sample from dataset: {str(e)}"


class ConfigurationHelper:
    """Helper functions for configuration management."""
    
    @staticmethod
    def generate_test_params(ui_state):
        """Generate test parameters from UI state."""
        params = {
            "iterations": ui_state.get("iterations", 3),
            "processing_strategy": ui_state.get("processing_strategy", "Memory"),
            "chunk_size": ui_state.get("chunk_size", "1MB"),
            "use_stdlib": ui_state.get("use_stdlib", True),
            "use_custom": ui_state.get("use_custom", True),
            "dataset_path": ui_state.get("dataset_path"),
            "encryption_settings": {
                "aes": {
                    "key_size": ui_state.get("aes_key_size", "256"),
                    "mode": ui_state.get("aes_mode", "GCM")
                },
                "chacha20": {},
                "rsa": {
                    "key_size": ui_state.get("rsa_key_size", "2048"),
                    "padding": ui_state.get("rsa_padding", "OAEP")
                },
                "ecc": {
                    "curve": ui_state.get("ecc_curve", "P-256")
                },
                "camellia": {
                    "key_size": ui_state.get("camellia_key_size", "256"),
                    "mode": ui_state.get("camellia_mode", "GCM")
                }
            }
        }
        return params 