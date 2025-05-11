"""
CryptoBench Pro - Test Configuration Tab
Allows users to configure benchmarking tests.
"""

import os
import json
import platform
import psutil
from datetime import datetime
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
    QCheckBox, QPushButton, QFileDialog, QLabel,
    QComboBox, QSpinBox, QLineEdit, QProgressBar,
    QFormLayout, QSizePolicy, QScrollArea, QMessageBox,
    QGridLayout, QTabWidget, QMainWindow
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, pyqtSlot


class ConfigurationTab(QWidget):
    """Test Configuration tab widget."""
    
    status_message = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        
        # Initialize member variables
        self.config_path = None
        
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
        
        # Programming Languages group
        languages_group = QGroupBox("Programming Languages")
        languages_layout = QGridLayout()
        
        # Language checkboxes
        self.lang_python_check = QCheckBox("Python")
        self.lang_c_check = QCheckBox("C")
        self.lang_rust_check = QCheckBox("Rust")
        self.lang_go_check = QCheckBox("Go")
        self.lang_assembly_check = QCheckBox("Assembly")
        
        # Add checkboxes to grid
        languages_layout.addWidget(self.lang_python_check, 0, 0)
        languages_layout.addWidget(self.lang_c_check, 0, 1)
        languages_layout.addWidget(self.lang_rust_check, 0, 2)
        languages_layout.addWidget(self.lang_go_check, 1, 0)
        languages_layout.addWidget(self.lang_assembly_check, 1, 1)
        
        # Set layout for languages group
        languages_group.setLayout(languages_layout)
        
        # Encryption Methods group
        methods_group = QGroupBox("Encryption Methods")
        methods_layout = QVBoxLayout()
        
        # AES
        aes_layout = QHBoxLayout()
        self.aes_check = QCheckBox("AES")
        aes_layout.addWidget(self.aes_check)
        
        aes_layout.addWidget(QLabel("Key Size:"))
        self.aes_key_size_combo = QComboBox()
        self.aes_key_size_combo.addItems(["128", "192", "256"])
        aes_layout.addWidget(self.aes_key_size_combo)
        aes_layout.addStretch()
        methods_layout.addLayout(aes_layout)
        
        # ChaCha20
        chacha_layout = QHBoxLayout()
        self.chacha_check = QCheckBox("ChaCha20-Poly1305")
        chacha_layout.addWidget(self.chacha_check)
        chacha_layout.addStretch()
        methods_layout.addLayout(chacha_layout)
        
        # RSA
        rsa_layout = QHBoxLayout()
        self.rsa_check = QCheckBox("RSA")
        rsa_layout.addWidget(self.rsa_check)
        
        rsa_layout.addWidget(QLabel("Key Size:"))
        self.rsa_key_size_combo = QComboBox()
        self.rsa_key_size_combo.addItems(["1024", "2048", "3072", "4096"])
        rsa_layout.addWidget(self.rsa_key_size_combo)
        rsa_layout.addStretch()
        methods_layout.addLayout(rsa_layout)
        
        # ECC
        ecc_layout = QHBoxLayout()
        self.ecc_check = QCheckBox("ECC")
        ecc_layout.addWidget(self.ecc_check)
        
        ecc_layout.addWidget(QLabel("Curve:"))
        self.ecc_curve_combo = QComboBox()
        self.ecc_curve_combo.addItems(["P-256", "P-384", "P-521", "Curve25519"])
        ecc_layout.addWidget(self.ecc_curve_combo)
        ecc_layout.addStretch()
        methods_layout.addLayout(ecc_layout)
        
        # ML-KEM
        mlkem_layout = QHBoxLayout()
        self.mlkem_check = QCheckBox("ML-KEM")
        mlkem_layout.addWidget(self.mlkem_check)
        
        mlkem_layout.addWidget(QLabel("Parameter Set:"))
        self.mlkem_param_combo = QComboBox()
        self.mlkem_param_combo.addItems(["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
        mlkem_layout.addWidget(self.mlkem_param_combo)
        mlkem_layout.addStretch()
        methods_layout.addLayout(mlkem_layout)
        
        # Set layout for methods group
        methods_group.setLayout(methods_layout)
        
        # Test Parameters group
        test_params_group = QGroupBox("Test Parameters")
        test_params_layout = QFormLayout()
        
        # RAM Usage Limit
        self.ram_limit_combo = QComboBox()
        self.ram_limit_combo.addItems(["500MB", "1GB", "2GB", "4GB", "8GB", "16GB", "32GB", "Uncapped"])
        test_params_layout.addRow("RAM Usage Limit:", self.ram_limit_combo)
        
        # Respect Sentences
        self.respect_sentences_check = QCheckBox()
        test_params_layout.addRow("Respect Sentences:", self.respect_sentences_check)
        
        # Include Standard Library Comparison
        self.include_stdlibs_check = QCheckBox()
        self.include_stdlibs_check.setChecked(True)  # Default to checked
        test_params_layout.addRow("Include Comparison with Standard Libraries:", self.include_stdlibs_check)
        
        # Number of Iterations
        self.iterations_spin = QSpinBox()
        self.iterations_spin.setRange(1, 100)
        self.iterations_spin.setValue(3)  # Default to 3
        test_params_layout.addRow("Number of Iterations:", self.iterations_spin)
        
        # Set layout for test parameters group
        test_params_group.setLayout(test_params_layout)
        
        # Buttons group
        buttons_group = QGroupBox("Configuration Management")
        buttons_layout = QHBoxLayout()
        
        # Save Config button
        self.save_config_button = QPushButton("Save Configuration")
        buttons_layout.addWidget(self.save_config_button)
        
        # Load Config button
        self.load_config_button = QPushButton("Load Configuration")
        buttons_layout.addWidget(self.load_config_button)
        
        # Start Tests button
        self.start_tests_button = QPushButton("START TESTS")
        self.start_tests_button.setStyleSheet("font-weight: bold;")
        buttons_layout.addWidget(self.start_tests_button)
        
        # Set layout for buttons group
        buttons_group.setLayout(buttons_layout)
        
        # Add groups to scroll layout
        scroll_layout.addWidget(languages_group)
        scroll_layout.addWidget(methods_group)
        scroll_layout.addWidget(test_params_group)
        scroll_layout.addWidget(buttons_group)
        
        # Add spacing
        scroll_layout.addStretch()
        
        # Set the scroll content and add to main layout
        scroll_area.setWidget(scroll_content)
        main_layout.addWidget(scroll_area)
        
        # Default selections
        self.lang_python_check.setChecked(True)
        self.aes_check.setChecked(True)
        
        # Connect signals
        self._connect_signals()
    
    def _connect_signals(self):
        """Connect signals to slots."""
        # Button signals
        self.save_config_button.clicked.connect(self._save_config)
        self.load_config_button.clicked.connect(self._load_config)
        self.start_tests_button.clicked.connect(self._start_tests)
        
        # Checkbox signals
        self.aes_check.toggled.connect(lambda checked: self.aes_key_size_combo.setEnabled(checked))
        self.rsa_check.toggled.connect(lambda checked: self.rsa_key_size_combo.setEnabled(checked))
        self.ecc_check.toggled.connect(lambda checked: self.ecc_curve_combo.setEnabled(checked))
        self.mlkem_check.toggled.connect(lambda checked: self.mlkem_param_combo.setEnabled(checked))
        
        # Initial enable/disable
        self.aes_key_size_combo.setEnabled(self.aes_check.isChecked())
        self.rsa_key_size_combo.setEnabled(self.rsa_check.isChecked())
        self.ecc_curve_combo.setEnabled(self.ecc_check.isChecked())
        self.mlkem_param_combo.setEnabled(self.mlkem_check.isChecked())
    
    def _save_config(self):
        """Save configuration to a file."""
        # Create config dictionary
        config = {
            "languages": {
                "python": self.lang_python_check.isChecked(),
                "c": self.lang_c_check.isChecked(),
                "rust": self.lang_rust_check.isChecked(),
                "go": self.lang_go_check.isChecked(),
                "assembly": self.lang_assembly_check.isChecked()
            },
            "encryption_methods": {
                "aes": {
                    "enabled": self.aes_check.isChecked(),
                    "key_size": self.aes_key_size_combo.currentText()
                },
                "chacha20": {
                    "enabled": self.chacha_check.isChecked()
                },
                "rsa": {
                    "enabled": self.rsa_check.isChecked(),
                    "key_size": self.rsa_key_size_combo.currentText()
                },
                "ecc": {
                    "enabled": self.ecc_check.isChecked(),
                    "curve": self.ecc_curve_combo.currentText()
                },
                "mlkem": {
                    "enabled": self.mlkem_check.isChecked(),
                    "param_set": self.mlkem_param_combo.currentText()
                }
            },
            "test_parameters": {
                "ram_limit": self.ram_limit_combo.currentText(),
                "respect_sentences": self.respect_sentences_check.isChecked(),
                "include_stdlibs": self.include_stdlibs_check.isChecked(),
                "iterations": self.iterations_spin.value()
            }
        }
        
        # Open file dialog
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Configuration",
            os.path.join(os.getcwd(), "configs"),
            "JSON Files (*.json)"
        )
        
        if file_path:
            # Ensure directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            # Save config to file
            with open(file_path, "w") as f:
                json.dump(config, f, indent=4)
            
            self.config_path = file_path
            self.status_message.emit(f"Configuration saved to {os.path.basename(file_path)}")
    
    def _load_config(self):
        """Load configuration from a file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Configuration",
            os.path.join(os.getcwd(), "configs"),
            "JSON Files (*.json)"
        )
        
        if file_path:
            try:
                # Load config from file
                with open(file_path, "r") as f:
                    config = json.load(f)
                
                # Update UI with loaded config
                # Languages
                self.lang_python_check.setChecked(config["languages"]["python"])
                self.lang_c_check.setChecked(config["languages"]["c"])
                self.lang_rust_check.setChecked(config["languages"]["rust"])
                self.lang_go_check.setChecked(config["languages"]["go"])
                self.lang_assembly_check.setChecked(config["languages"]["assembly"])
                
                # Encryption methods
                self.aes_check.setChecked(config["encryption_methods"]["aes"]["enabled"])
                self.aes_key_size_combo.setCurrentText(config["encryption_methods"]["aes"]["key_size"])
                
                self.chacha_check.setChecked(config["encryption_methods"]["chacha20"]["enabled"])
                
                self.rsa_check.setChecked(config["encryption_methods"]["rsa"]["enabled"])
                self.rsa_key_size_combo.setCurrentText(config["encryption_methods"]["rsa"]["key_size"])
                
                self.ecc_check.setChecked(config["encryption_methods"]["ecc"]["enabled"])
                self.ecc_curve_combo.setCurrentText(config["encryption_methods"]["ecc"]["curve"])
                
                self.mlkem_check.setChecked(config["encryption_methods"]["mlkem"]["enabled"])
                self.mlkem_param_combo.setCurrentText(config["encryption_methods"]["mlkem"]["param_set"])
                
                # Test parameters
                self.ram_limit_combo.setCurrentText(config["test_parameters"]["ram_limit"])
                self.respect_sentences_check.setChecked(config["test_parameters"]["respect_sentences"])
                self.include_stdlibs_check.setChecked(config["test_parameters"]["include_stdlibs"])
                self.iterations_spin.setValue(config["test_parameters"]["iterations"])
                
                self.config_path = file_path
                self.status_message.emit(f"Configuration loaded from {os.path.basename(file_path)}")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error loading configuration: {str(e)}")
    
    def _start_tests(self):
        """Start the benchmarking tests."""
        # Check if at least one language is selected
        if not any([
            self.lang_python_check.isChecked(),
            self.lang_c_check.isChecked(),
            self.lang_rust_check.isChecked(),
            self.lang_go_check.isChecked(),
            self.lang_assembly_check.isChecked()
        ]):
            QMessageBox.warning(self, "Warning", "Please select at least one programming language.")
            return
        
        # Check if at least one encryption method is selected
        if not any([
            self.aes_check.isChecked(),
            self.chacha_check.isChecked(),
            self.rsa_check.isChecked(),
            self.ecc_check.isChecked(),
            self.mlkem_check.isChecked()
        ]):
            QMessageBox.warning(self, "Warning", "Please select at least one encryption method.")
            return
        
        # Get dataset information - safer approach to find the dataset tab
        dataset_path = None
        dataset_info = {}
        dataset_sample = ""
        
        # Try to find the dataset tab safely
        try:
            # Navigate to the main window
            main_window = None
            parent = self.parent()
            while parent:
                if isinstance(parent, QMainWindow):
                    main_window = parent
                    break
                parent = parent.parent()
            
            # If we found the main window, get the tabs
            if main_window:
                tab_widget = main_window.findChild(QTabWidget)
                if tab_widget and tab_widget.count() > 0:
                    dataset_tab = tab_widget.widget(0)  # Assuming dataset tab is the first tab
                    
                    # Get the selected dataset if available
                    if dataset_tab and hasattr(dataset_tab, 'get_selected_dataset'):
                        dataset_path = dataset_tab.get_selected_dataset()
                        
                        # If a dataset is selected, get information about it
                        if dataset_path:
                            dataset_info = self._get_dataset_info(dataset_path)
                            dataset_sample = self._get_dataset_sample(dataset_path, 200)
        except Exception as e:
            # Log the error but continue without dataset information
            print(f"Error accessing dataset tab: {str(e)}")
        
        # Format timestamp for human readability
        now = datetime.now()
        timestamp = now.strftime("%Y%m%d_%H%M%S")  # Keep original format for internal use
        human_timestamp = now.strftime("%d.%m.%y-%H:%M:%S")  # New human-readable format - Fix month format
        
        # Create session directory with new format
        session_dir = os.path.join(os.getcwd(), f"Session-{human_timestamp}")
        os.makedirs(session_dir, exist_ok=True)
        os.makedirs(os.path.join(session_dir, "results"), exist_ok=True)
        
        # Collect PC specifications
        pc_specs = self._collect_pc_specs()
        
        # Save current configuration to session directory
        config_path = os.path.join(session_dir, "test_config.json")
        with open(config_path, "w") as f:
            # Create config dictionary (enhanced with new fields)
            config = {
                "languages": {
                    "python": self.lang_python_check.isChecked(),
                    "c": self.lang_c_check.isChecked(),
                    "rust": self.lang_rust_check.isChecked(),
                    "go": self.lang_go_check.isChecked(),
                    "assembly": self.lang_assembly_check.isChecked()
                },
                "encryption_methods": {
                    "aes": {
                        "enabled": self.aes_check.isChecked(),
                        "key_size": self.aes_key_size_combo.currentText()
                    },
                    "chacha20": {
                        "enabled": self.chacha_check.isChecked()
                    },
                    "rsa": {
                        "enabled": self.rsa_check.isChecked(),
                        "key_size": self.rsa_key_size_combo.currentText()
                    },
                    "ecc": {
                        "enabled": self.ecc_check.isChecked(),
                        "curve": self.ecc_curve_combo.currentText()
                    },
                    "mlkem": {
                        "enabled": self.mlkem_check.isChecked(),
                        "param_set": self.mlkem_param_combo.currentText()
                    }
                },
                "test_parameters": {
                    "ram_limit": self.ram_limit_combo.currentText(),
                    "respect_sentences": self.respect_sentences_check.isChecked(),
                    "include_stdlibs": self.include_stdlibs_check.isChecked(),
                    "iterations": self.iterations_spin.value(),
                    "dataset_path": dataset_path,
                },
                "session_info": {
                    "timestamp": timestamp,
                    "human_timestamp": human_timestamp,
                    "session_dir": session_dir
                },
                "dataset_info": dataset_info,
                "dataset_sample": dataset_sample,
                "pc_specifications": pc_specs
            }
            json.dump(config, f, indent=4)
        
        # Emit signal to indicate tests are starting
        self.status_message.emit(f"Starting tests with configuration from {config_path}")
        
        # Notify user
        QMessageBox.information(
            self, 
            "Tests Started", 
            f"Tests are being started with the current configuration.\n\n"
            f"Session directory: {session_dir}\n\n"
            f"Results will be available in the Results Viewer tab when complete."
        )

    def _collect_pc_specs(self):
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
                import subprocess
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

    def _get_dataset_info(self, dataset_path):
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

    def _get_dataset_sample(self, dataset_path, sample_size=200):
        """Get a sample from the dataset that's more representative."""
        try:
            # Get file size
            file_size = os.path.getsize(dataset_path)
            
            # Detect dataset type
            dataset_info = self._get_dataset_info(dataset_path)
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