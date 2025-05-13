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
from PyQt6.QtWidgets import QApplication
import subprocess


class OrchestrationThread(QThread):
    """Thread to run the orchestrator without blocking the UI."""
    
    progress_update = pyqtSignal(str)
    orchestration_complete = pyqtSignal(bool, str)  # Success flag and message
    
    def __init__(self, orchestrator_func):
        super().__init__()
        self.orchestrator_func = orchestrator_func
        self.running = False
        self.success = False
        self.error_message = ""
        # Set this as a daemon thread (will be killed when main thread exits)
        self.setTerminationEnabled(True)
    
    def run(self):
        """Execute the orchestrator."""
        try:
            # Set running flag
            self.running = True
            
            # Redirect logging to capture progress
            self._setup_logging()
            
            # Run the orchestrator
            self.progress_update.emit("Starting orchestration process...")
            result = self.orchestrator_func()
            self.success = result is True
            
            if self.success:
                self.progress_update.emit("Orchestration completed successfully!")
                self.orchestration_complete.emit(True, "Orchestration completed successfully")
            else:
                self.progress_update.emit("Orchestration completed with errors")
                self.orchestration_complete.emit(False, "Orchestration completed with errors")
        except Exception as e:
            print(f"Orchestration error in thread: {str(e)}")
            import traceback
            traceback.print_exc()
            self.error_message = str(e)
            self.progress_update.emit(f"Error: {str(e)}")
            self.orchestration_complete.emit(False, f"Error: {str(e)}")
        finally:
            # Always make sure to reset running flag
            self.running = False
    
    def _setup_logging(self):
        """Redirect logging to emit progress updates."""
        import logging
        
        class SignalHandler(logging.Handler):
            def __init__(self, signal):
                super().__init__()
                self.signal = signal
            
            def emit(self, record):
                msg = self.format(record)
                self.signal.emit(msg)
        
        # Get the orchestrator logger
        logger = logging.getLogger("Orchestrator")
        
        # Add our custom handler
        handler = SignalHandler(self.progress_update)
        handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        logger.addHandler(handler)


class ConfigurationTab(QWidget):
    """Test Configuration tab widget."""
    
    status_message = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        
        # Initialize member variables
        self.config_path = None
        self.orchestrator_thread = None  # Store thread reference
        
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
        
        aes_layout.addWidget(QLabel("Mode:"))
        self.aes_mode_combo = QComboBox()
        self.aes_mode_combo.addItems(["CBC", "CTR", "GCM", "ECB"])
        self.aes_mode_combo.setCurrentText("GCM")  # GCM is recommended default
        aes_layout.addWidget(self.aes_mode_combo)
        
        aes_layout.addStretch()
        methods_layout.addLayout(aes_layout)
        
        # ChaCha20
        chacha_layout = QHBoxLayout()
        self.chacha_check = QCheckBox("ChaCha20")
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
        
        rsa_layout.addWidget(QLabel("Padding:"))
        self.rsa_padding_combo = QComboBox()
        self.rsa_padding_combo.addItems(["OAEP", "PKCS#1 v1.5"])
        self.rsa_padding_combo.setCurrentText("OAEP")  # OAEP is recommended default
        rsa_layout.addWidget(self.rsa_padding_combo)
        
        # Add key reuse option for RSA
        self.rsa_reuse_keys_check = QCheckBox("Reuse Keys")
        self.rsa_reuse_keys_check.setToolTip("Generate a specific number of key pairs once and reuse them")
        rsa_layout.addWidget(self.rsa_reuse_keys_check)
        
        rsa_layout.addWidget(QLabel("Key Sets:"))
        self.rsa_key_sets_spin = QSpinBox()
        self.rsa_key_sets_spin.setRange(1, 100)
        self.rsa_key_sets_spin.setValue(10)  # Default to 10 sets
        self.rsa_key_sets_spin.setEnabled(False)  # Disabled by default
        self.rsa_key_sets_spin.setToolTip("Number of key pairs to generate and use")
        rsa_layout.addWidget(self.rsa_key_sets_spin)
        
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
        
        # Twofish (replacing ML-KEM)
        twofish_layout = QHBoxLayout()
        self.twofish_check = QCheckBox("Twofish")
        twofish_layout.addWidget(self.twofish_check)
        
        twofish_layout.addWidget(QLabel("Key Size:"))
        self.twofish_key_size_combo = QComboBox()
        self.twofish_key_size_combo.addItems(["128", "192", "256"])
        twofish_layout.addWidget(self.twofish_key_size_combo)
        
        twofish_layout.addWidget(QLabel("Mode:"))
        self.twofish_mode_combo = QComboBox()
        self.twofish_mode_combo.addItems(["CBC", "CTR", "GCM", "ECB"])
        self.twofish_mode_combo.setCurrentText("GCM")  # GCM is recommended default
        twofish_layout.addWidget(self.twofish_mode_combo)
        
        twofish_layout.addStretch()
        methods_layout.addLayout(twofish_layout)
        
        # Set layout for methods group
        methods_group.setLayout(methods_layout)
        
        # Test Parameters group
        test_params_group = QGroupBox("Test Parameters")
        test_params_layout = QFormLayout()
        
        # Processing Strategy
        strategy_layout = QHBoxLayout()
        self.processing_strategy_combo = QComboBox()
        self.processing_strategy_combo.addItems(["Memory", "Stream"])
        self.processing_strategy_combo.setToolTip("Memory: Process entire dataset in memory\nStream: Process dataset in chunks")
        strategy_layout.addWidget(QLabel("Processing Strategy:"))
        strategy_layout.addWidget(self.processing_strategy_combo)
        
        # Chunk Size (only relevant for Stream processing)
        strategy_layout.addWidget(QLabel("Chunk Size:"))
        self.chunk_size_combo = QComboBox()
        self.chunk_size_combo.addItems(["64KB", "256KB", "1MB", "4MB", "16MB"])
        self.chunk_size_combo.setCurrentText("1MB")
        self.chunk_size_combo.setToolTip("Size of chunks when using Stream processing")
        strategy_layout.addWidget(self.chunk_size_combo)
        test_params_layout.addRow(strategy_layout)
        
        # Replace the single checkbox with two separate ones
        encryption_options_layout = QVBoxLayout()
        
        # Standard Libraries checkbox
        self.use_stdlib_check = QCheckBox("Use Standard Library Implementations")
        self.use_stdlib_check.setChecked(True)  # Default to checked
        encryption_options_layout.addWidget(self.use_stdlib_check)
        
        # Custom Implementation checkbox
        self.use_custom_check = QCheckBox("Use Custom Implementations")
        self.use_custom_check.setChecked(True)  # Default to checked
        encryption_options_layout.addWidget(self.use_custom_check)
        
        # Add the encryption options to the form layout
        test_params_layout.addRow("Implementation Options:", encryption_options_layout)
        
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
        self.aes_check.toggled.connect(lambda checked: self.aes_mode_combo.setEnabled(checked))
        self.rsa_check.toggled.connect(lambda checked: self.rsa_key_size_combo.setEnabled(checked))
        self.rsa_check.toggled.connect(lambda checked: self.rsa_padding_combo.setEnabled(checked))
        self.rsa_check.toggled.connect(lambda checked: self.rsa_reuse_keys_check.setEnabled(checked))
        # Only enable the key sets spinbox if both RSA is enabled and reuse keys is checked
        self.rsa_check.toggled.connect(self._update_rsa_controls)
        self.rsa_reuse_keys_check.toggled.connect(self._update_rsa_controls)
        self.ecc_check.toggled.connect(lambda checked: self.ecc_curve_combo.setEnabled(checked))
        self.twofish_check.toggled.connect(lambda checked: self.twofish_key_size_combo.setEnabled(checked))
        self.twofish_check.toggled.connect(lambda checked: self.twofish_mode_combo.setEnabled(checked))
        
        # Connect implementation options checkboxes to validation method
        self.use_stdlib_check.toggled.connect(self._validate_implementation_options)
        self.use_custom_check.toggled.connect(self._validate_implementation_options)
        
        # Processing strategy signals
        self.processing_strategy_combo.currentTextChanged.connect(self._update_chunk_size_visibility)
        
        # Initial enable/disable
        self.aes_key_size_combo.setEnabled(self.aes_check.isChecked())
        self.aes_mode_combo.setEnabled(self.aes_check.isChecked())
        self.rsa_key_size_combo.setEnabled(self.rsa_check.isChecked())
        self.rsa_padding_combo.setEnabled(self.rsa_check.isChecked())
        self.rsa_reuse_keys_check.setEnabled(self.rsa_check.isChecked())
        self._update_rsa_controls()
        self.ecc_curve_combo.setEnabled(self.ecc_check.isChecked())
        self.twofish_key_size_combo.setEnabled(self.twofish_check.isChecked())
        self.twofish_mode_combo.setEnabled(self.twofish_check.isChecked())
        self._update_chunk_size_visibility(self.processing_strategy_combo.currentText())
    
    def _update_rsa_controls(self):
        """Update RSA controls' enabled state based on checkbox states."""
        rsa_enabled = self.rsa_check.isChecked()
        reuse_keys_enabled = self.rsa_reuse_keys_check.isChecked()
        # Key sets spinbox is only enabled if both RSA is enabled and reuse keys is checked
        self.rsa_key_sets_spin.setEnabled(rsa_enabled and reuse_keys_enabled)
    
    def _update_chunk_size_visibility(self, strategy):
        """Enable/disable chunk size selector based on processing strategy."""
        self.chunk_size_combo.setEnabled(strategy == "Stream")
    
    def _validate_implementation_options(self):
        """Ensure at least one implementation option is selected."""
        if not self.use_stdlib_check.isChecked() and not self.use_custom_check.isChecked():
            # If user tries to uncheck both, force the current one to stay checked
            sender = self.sender()
            sender.setChecked(True)
            QMessageBox.warning(
                self,
                "Invalid Selection",
                "At least one implementation type (Standard Library or Custom) must be selected."
            )
    
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
                    "key_size": self.aes_key_size_combo.currentText(),
                    "mode": self.aes_mode_combo.currentText()
                },
                "chacha20": {
                    "enabled": self.chacha_check.isChecked()
                },
                "rsa": {
                    "enabled": self.rsa_check.isChecked(),
                    "key_size": self.rsa_key_size_combo.currentText(),
                    "padding": self.rsa_padding_combo.currentText(),
                    "reuse_keys": self.rsa_reuse_keys_check.isChecked(),
                    "key_sets": self.rsa_key_sets_spin.value()
                },
                "ecc": {
                    "enabled": self.ecc_check.isChecked(),
                    "curve": self.ecc_curve_combo.currentText()
                },
                "twofish": {
                    "enabled": self.twofish_check.isChecked(),
                    "key_size": self.twofish_key_size_combo.currentText(),
                    "mode": self.twofish_mode_combo.currentText()
                }
            },
            "test_parameters": {
                "processing_strategy": self.processing_strategy_combo.currentText(),
                "chunk_size": self.chunk_size_combo.currentText(),
                "use_stdlib": self.use_stdlib_check.isChecked(),
                "use_custom": self.use_custom_check.isChecked(),
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
                self.aes_mode_combo.setCurrentText(config["encryption_methods"]["aes"]["mode"])
                
                # Handle chacha20 config (and handle old configs with use_poly1305 field)
                self.chacha_check.setChecked(config["encryption_methods"]["chacha20"]["enabled"])
                
                # Handle RSA configuration with backwards compatibility for padding
                self.rsa_check.setChecked(config["encryption_methods"]["rsa"]["enabled"])
                self.rsa_key_size_combo.setCurrentText(config["encryption_methods"]["rsa"]["key_size"])
                if "padding" in config["encryption_methods"]["rsa"]:
                    self.rsa_padding_combo.setCurrentText(config["encryption_methods"]["rsa"]["padding"])
                else:
                    # Default to OAEP for older config files
                    self.rsa_padding_combo.setCurrentText("OAEP")
                
                # Handle RSA key reuse settings with backward compatibility
                if "reuse_keys" in config["encryption_methods"]["rsa"]:
                    self.rsa_reuse_keys_check.setChecked(config["encryption_methods"]["rsa"]["reuse_keys"])
                else:
                    self.rsa_reuse_keys_check.setChecked(False)
                
                if "key_sets" in config["encryption_methods"]["rsa"]:
                    self.rsa_key_sets_spin.setValue(config["encryption_methods"]["rsa"]["key_sets"])
                else:
                    self.rsa_key_sets_spin.setValue(10)  # Default value
                
                self.ecc_check.setChecked(config["encryption_methods"]["ecc"]["enabled"])
                self.ecc_curve_combo.setCurrentText(config["encryption_methods"]["ecc"]["curve"])
                
                self.twofish_check.setChecked(config["encryption_methods"]["twofish"]["enabled"])
                self.twofish_key_size_combo.setCurrentText(config["encryption_methods"]["twofish"]["key_size"])
                self.twofish_mode_combo.setCurrentText(config["encryption_methods"]["twofish"]["mode"])
                
                # Test parameters
                self.processing_strategy_combo.setCurrentText(config["test_parameters"]["processing_strategy"])
                self.chunk_size_combo.setCurrentText(config["test_parameters"]["chunk_size"])
                
                # Handle the implementation options
                if "use_stdlib" in config["test_parameters"] and "use_custom" in config["test_parameters"]:
                    # New format
                    self.use_stdlib_check.setChecked(config["test_parameters"]["use_stdlib"])
                    self.use_custom_check.setChecked(config["test_parameters"]["use_custom"])
                elif "include_stdlibs" in config["test_parameters"]:
                    # Old format - set both checkboxes based on the old value
                    include_stdlibs = config["test_parameters"]["include_stdlibs"]
                    self.use_stdlib_check.setChecked(include_stdlibs)
                    self.use_custom_check.setChecked(True)  # Always enable custom
                else:
                    # Default - enable both
                    self.use_stdlib_check.setChecked(True)
                    self.use_custom_check.setChecked(True)
                
                self.iterations_spin.setValue(config["test_parameters"]["iterations"])
                
                self.config_path = file_path
                self.status_message.emit(f"Configuration loaded from {os.path.basename(file_path)}")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error loading configuration: {str(e)}")
    
    def _start_tests(self):
        """Start the benchmarking tests."""
        # Check if an orchestration is already running
        if self.orchestrator_thread and self.orchestrator_thread.isRunning():
            # Ask the user if they want to stop the current run
            reply = QMessageBox.question(
                self,
                "Orchestration in Progress",
                "An orchestration process is already running. Do you want to stop it and start a new one?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Properly terminate the thread
                self.orchestrator_thread.terminate()
                self.orchestrator_thread.wait(3000)  # Wait up to 3 seconds for clean termination
                
                # Clean up any temporary files
                for file in os.listdir(os.getcwd()):
                    if file.startswith("session-") and file.endswith(".json"):
                        try:
                            os.remove(os.path.join(os.getcwd(), file))
                        except:
                            pass
            else:
                return
        
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
            self.twofish_check.isChecked()
        ]):
            QMessageBox.warning(self, "Warning", "Please select at least one encryption method.")
            return
        
        # Check if at least one implementation option is selected
        if not self.use_stdlib_check.isChecked() and not self.use_custom_check.isChecked():
            QMessageBox.warning(self, "Warning", "Please select at least one implementation option (Standard Library or Custom).")
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
                        
                        # Validate dataset
                        if not dataset_path:
                            QMessageBox.warning(self, "Dataset Required", 
                                "Please select a dataset in the Dataset tab before starting the tests.")
                            self.status_message.emit("Test not started: No dataset selected")
                            print("Test not started: No dataset selected")
                            return
                        
                        # If a dataset is selected, get information about it
                        dataset_info = self._get_dataset_info(dataset_path)
                        dataset_sample = self._get_dataset_sample(dataset_path, 200)
        except Exception as e:
            # Log the error but continue without dataset information
            print(f"Error accessing dataset tab: {str(e)}")
            QMessageBox.warning(self, "Dataset Error", 
                f"Could not access dataset information: {str(e)}\n\nPlease select a dataset in the Dataset tab.")
            self.status_message.emit("Test not started: Dataset error")
            return
        
        # Format timestamp for human readability
        now = datetime.now()
        timestamp = now.strftime("%Y%m%d_%H%M%S")  # Keep original format for internal use
        human_timestamp = now.strftime("%d.%m.%Y-%H:%M:%S")  # Updated format with 4-digit year
        
        # Create sessions directory if it doesn't exist
        # Get project root directory
        project_root = os.getcwd()
        
        # If running from src directory, go up one level to find project root
        if os.path.basename(project_root) == "src":
            project_root = os.path.dirname(project_root)
            
        # Use project root for sessions directory
        sessions_dir = os.path.join(project_root, "sessions")
        os.makedirs(sessions_dir, exist_ok=True)
        
        # Create session directory with new format
        session_dir = os.path.join(sessions_dir, f"Session-{human_timestamp}")
        os.makedirs(session_dir, exist_ok=True)
        os.makedirs(os.path.join(session_dir, "results"), exist_ok=True)
        
        # Collect PC specifications
        pc_specs = self._collect_pc_specs()
        
        # Create config dictionary (enhanced with new fields)
        config = {
            "languages": {
                "python": {
                    "is_enabled": self.lang_python_check.isChecked()
                },
                "c": {
                    "is_enabled": self.lang_c_check.isChecked()
                },
                "rust": {
                    "is_enabled": self.lang_rust_check.isChecked()
                },
                "go": {
                    "is_enabled": self.lang_go_check.isChecked()
                },
                "assembly": {
                    "is_enabled": self.lang_assembly_check.isChecked()
                }
            },
            "encryption_methods": {
                "aes": {
                    "enabled": self.aes_check.isChecked(),
                    "key_size": self.aes_key_size_combo.currentText(),
                    "mode": self.aes_mode_combo.currentText()
                },
                "chacha20": {
                    "enabled": self.chacha_check.isChecked()
                },
                "rsa": {
                    "enabled": self.rsa_check.isChecked(),
                    "key_size": self.rsa_key_size_combo.currentText(),
                    "padding": self.rsa_padding_combo.currentText(),
                    "reuse_keys": self.rsa_reuse_keys_check.isChecked(),
                    "key_sets": self.rsa_key_sets_spin.value()
                },
                "ecc": {
                    "enabled": self.ecc_check.isChecked(),
                    "curve": self.ecc_curve_combo.currentText()
                },
                "twofish": {
                    "enabled": self.twofish_check.isChecked(),
                    "key_size": self.twofish_key_size_combo.currentText(),
                    "mode": self.twofish_mode_combo.currentText()
                }
            },
            "test_parameters": {
                "processing_strategy": self.processing_strategy_combo.currentText(),
                "chunk_size": self.chunk_size_combo.currentText(),
                "use_stdlib": self.use_stdlib_check.isChecked(),
                "use_custom": self.use_custom_check.isChecked(),
                "iterations": self.iterations_spin.value(),
                "dataset_path": dataset_path,
            },
            "session_info": {
                "timestamp": timestamp,
                "human_timestamp": human_timestamp,
                "session_dir": session_dir,
                "session_id": f"Session-{human_timestamp}"
            },
            "dataset_info": dataset_info,
            "dataset_sample": dataset_sample,
            "pc_specifications": pc_specs
        }
        
        # Save configuration as session JSON in the session directory only
        config_path = os.path.join(session_dir, "test_config.json")
        with open(config_path, "w") as f:
            json.dump(config, f, indent=4)
        
        # Emit signal to indicate tests are starting
        message = f"Starting tests with configuration from {config_path}"
        self.status_message.emit(message)
        print(f"\n=== TEST SESSION STARTED ===")
        print(message)
        
        # If Python is selected, run Python tests directly
        if self.lang_python_check.isChecked():
            try:
                # Get the path to the Python test script
                script_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                python_test_script = os.path.join(script_dir, "encryption", "python", "run_python_tests.sh")
                
                # Make sure the script is executable
                os.chmod(python_test_script, 0o755)
                
                # Run the Python test script
                message = "Running Python encryption tests..."
                self.status_message.emit(message)
                print(message)
                
                subprocess.run([python_test_script, config_path], check=True)
                
                # Update progress
                message = "Python tests completed successfully"
                self.status_message.emit(message)
                print(message)
            except subprocess.CalledProcessError as e:
                error_msg = f"Python tests failed: {str(e)}"
                self.status_message.emit(error_msg)
                print(f"ERROR: {error_msg}")
                QMessageBox.warning(self, "Test Error", error_msg)
            except Exception as e:
                error_msg = f"Error running Python tests: {str(e)}"
                self.status_message.emit(error_msg)
                print(f"ERROR: {error_msg}")
                QMessageBox.warning(self, "Test Error", error_msg)
        
        # For other languages, run the orchestrator
        if any([
            self.lang_c_check.isChecked(),
            self.lang_rust_check.isChecked(),
            self.lang_go_check.isChecked(),
            self.lang_assembly_check.isChecked()
        ]):
            try:
                # Import and run the orchestrator
                from src.orchestrator import main as run_orchestrator
                message = "Launching orchestrator..."
                self.status_message.emit(message)
                print(message)
                
                # Run in a separate thread to avoid blocking the UI
                self.orchestrator_thread = OrchestrationThread(run_orchestrator)
                
                # Connect signals
                self.orchestrator_thread.finished.connect(self._orchestration_finished)
                self.orchestrator_thread.orchestration_complete.connect(self._orchestration_completed)
                
                # Connect progress updates
                self.orchestrator_thread.progress_update.connect(self._forward_progress_update)
                
                # Start the thread
                self.orchestrator_thread.start()
            except Exception as e:
                error_msg = f"Failed to start orchestrator: {str(e)}"
                print(f"ERROR: {error_msg}")
                QMessageBox.warning(
                    self,
                    "Orchestration Error",
                    f"{error_msg}\n\n"
                    f"You may need to run it manually with:\n"
                    f"python -m src.orchestrator"
                )
                self.status_message.emit(f"Orchestration error: {str(e)}")
    
    # Add a new method to forward progress updates to both UI and console
    def _forward_progress_update(self, message):
        """Forward progress updates to both UI and console."""
        self.status_message.emit(message)
        print(message)

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

    def _generate_test_params(self):
        """Generate test parameters from current UI state."""
        params = {
            "iterations": self.iterations_spin.value(),
            "processing_strategy": self.processing_strategy_combo.currentText(),
            "chunk_size": self.chunk_size_combo.currentText(),
            "use_stdlib": self.use_stdlib_check.isChecked(),
            "use_custom": self.use_custom_check.isChecked(),
            "ram_limit": ram_limit,
            "dataset_path": self.dataset_combo.currentData(),
            "encryption_settings": {
                "aes": {
                    "key_size": self.aes_key_size_combo.currentText(),
                    "mode": self.aes_mode_combo.currentText()
                },
                "chacha20": {},
                "rsa": {
                    "key_size": self.rsa_key_size_combo.currentText(),
                    "padding": self.rsa_padding_combo.currentText(),
                    "reuse_keys": self.rsa_reuse_keys_check.isChecked(),
                    "key_sets": self.rsa_key_sets_spin.value() if self.rsa_reuse_keys_check.isChecked() else 1
                },
                "ecc": {
                    "curve": self.ecc_curve_combo.currentText()
                },
                "twofish": {
                    "key_size": self.twofish_key_size_combo.currentText(),
                    "mode": self.twofish_mode_combo.currentText()
                }
            }
        }
        return params

    def _orchestration_finished(self):
        """Handle thread finished signal (always called)."""
        # Clean up any temporary files
        for file in os.listdir(os.getcwd()):
            if file.startswith("session-") and file.endswith(".json"):
                try:
                    os.remove(os.path.join(os.getcwd(), file))
                except:
                    pass

    def _orchestration_completed(self, success, message):
        """Handle orchestration completion."""
        if success:
            message = "Orchestration completed successfully. Check results tab."
            self.status_message.emit(message)
            print(f"\n=== TEST SESSION COMPLETED ===")
            print(message)
        else:
            error_message = f"Orchestration error: {message}"
            self.status_message.emit(error_message)
            print(f"\n=== TEST SESSION FAILED ===")
            print(error_message)
            QMessageBox.warning(self, "Orchestration Error", 
                               f"Benchmarking encountered an error:\n\n{message}") 