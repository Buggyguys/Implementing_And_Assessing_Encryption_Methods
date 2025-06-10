"""
CryptoBench Pro - Test Configuration Tab
Allows users to configure benchmarking tests.
"""

import os
import json
from datetime import datetime
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
    QCheckBox, QPushButton, QFileDialog, QLabel,
    QComboBox, QSpinBox, QLineEdit, QProgressBar,
    QFormLayout, QSizePolicy, QScrollArea, QMessageBox,
    QGridLayout, QTabWidget, QMainWindow
)
from PyQt6.QtCore import Qt, pyqtSignal, pyqtSlot

from .orchestration import OrchestrationThread, TestExecutor
from .utils import SystemInfoCollector, DatasetAnalyzer, ConfigurationHelper


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
        self.lang_zig_check = QCheckBox("Zig")
        self.lang_c_check = QCheckBox("C")
        self.lang_rust_check = QCheckBox("Rust")
        self.lang_go_check = QCheckBox("Go")
        self.lang_java_check = QCheckBox("Java")
        
        # Add checkboxes to grid
        languages_layout.addWidget(self.lang_python_check, 0, 0)
        languages_layout.addWidget(self.lang_zig_check, 0, 1)
        languages_layout.addWidget(self.lang_c_check, 0, 2)
        languages_layout.addWidget(self.lang_rust_check, 1, 0)
        languages_layout.addWidget(self.lang_go_check, 1, 1)
        languages_layout.addWidget(self.lang_java_check, 1, 2)
        
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
        
        rsa_layout.addStretch()
        methods_layout.addLayout(rsa_layout)
        
        # ECC
        ecc_layout = QHBoxLayout()
        self.ecc_check = QCheckBox("ECC")
        ecc_layout.addWidget(self.ecc_check)
        
        ecc_layout.addWidget(QLabel("Curve:"))
        self.ecc_curve_combo = QComboBox()
        self.ecc_curve_combo.addItems(["P-256", "P-384", "P-521"])
        ecc_layout.addWidget(self.ecc_curve_combo)
        ecc_layout.addStretch()
        methods_layout.addLayout(ecc_layout)
        
        # Camellia (replacing Twofish)
        camellia_layout = QHBoxLayout()
        self.camellia_check = QCheckBox("Camellia")
        camellia_layout.addWidget(self.camellia_check)
        
        camellia_layout.addWidget(QLabel("Key Size:"))
        self.camellia_key_size_combo = QComboBox()
        self.camellia_key_size_combo.addItems(["128", "192", "256"])
        camellia_layout.addWidget(self.camellia_key_size_combo)
        
        camellia_layout.addWidget(QLabel("Mode:"))
        self.camellia_mode_combo = QComboBox()
        self.camellia_mode_combo.addItems(["CBC", "CTR", "GCM", "ECB"])
        self.camellia_mode_combo.setCurrentText("GCM")  # GCM is recommended default
        camellia_layout.addWidget(self.camellia_mode_combo)
        
        camellia_layout.addStretch()
        methods_layout.addLayout(camellia_layout)
        
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
        self.ecc_check.toggled.connect(lambda checked: self.ecc_curve_combo.setEnabled(checked))
        self.camellia_check.toggled.connect(lambda checked: self.camellia_key_size_combo.setEnabled(checked))
        self.camellia_check.toggled.connect(lambda checked: self.camellia_mode_combo.setEnabled(checked))
        
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
        self.ecc_curve_combo.setEnabled(self.ecc_check.isChecked())
        self.camellia_key_size_combo.setEnabled(self.camellia_check.isChecked())
        self.camellia_mode_combo.setEnabled(self.camellia_check.isChecked())
        self._update_chunk_size_visibility(self.processing_strategy_combo.currentText())
    
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
                "zig": self.lang_zig_check.isChecked(),
                "c": self.lang_c_check.isChecked(),
                "rust": self.lang_rust_check.isChecked(),
                "go": self.lang_go_check.isChecked(),
                "java": self.lang_java_check.isChecked()
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
                    "padding": self.rsa_padding_combo.currentText()
                },
                "ecc": {
                    "enabled": self.ecc_check.isChecked(),
                    "curve": self.ecc_curve_combo.currentText()
                },
                "camellia": {
                    "enabled": self.camellia_check.isChecked(),
                    "key_size": self.camellia_key_size_combo.currentText(),
                    "mode": self.camellia_mode_combo.currentText()
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
                self.lang_python_check.setChecked(config["languages"].get("python", False))
                self.lang_zig_check.setChecked(config["languages"]["zig"])
                self.lang_c_check.setChecked(config["languages"]["c"])
                self.lang_rust_check.setChecked(config["languages"]["rust"])
                self.lang_go_check.setChecked(config["languages"]["go"])
                self.lang_java_check.setChecked(config["languages"]["java"])
                
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
                
                self.ecc_check.setChecked(config["encryption_methods"]["ecc"]["enabled"])
                self.ecc_curve_combo.setCurrentText(config["encryption_methods"]["ecc"]["curve"])
                
                self.camellia_check.setChecked(config["encryption_methods"]["camellia"]["enabled"])
                self.camellia_key_size_combo.setCurrentText(config["encryption_methods"]["camellia"]["key_size"])
                self.camellia_mode_combo.setCurrentText(config["encryption_methods"]["camellia"]["mode"])
                
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
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                # Properly stop and clean up the thread
                self._cleanup_orchestrator_thread()
            else:
                return
        
        # Validation checks
        if not self._validate_selections():
            return
        
        # Get dataset information
        dataset_path, dataset_info, dataset_sample = self._get_dataset_information()
        if not dataset_path:
            return
        
        # Create session and configuration
        config_path = self._create_session_config(dataset_path, dataset_info, dataset_sample)
        
        # Execute tests
        self._execute_tests(config_path)
    
    def _validate_selections(self):
        """Validate user selections."""
        # Check if at least one language is selected
        if not any([
            self.lang_python_check.isChecked(),
            self.lang_zig_check.isChecked(),
            self.lang_c_check.isChecked(),
            self.lang_rust_check.isChecked(),
            self.lang_go_check.isChecked(),
            self.lang_java_check.isChecked()
        ]):
            QMessageBox.warning(self, "Warning", "Please select at least one programming language.")
            return False
        
        # Check if at least one encryption method is selected
        if not any([
            self.aes_check.isChecked(),
            self.chacha_check.isChecked(),
            self.rsa_check.isChecked(),
            self.ecc_check.isChecked(),
            self.camellia_check.isChecked()
        ]):
            QMessageBox.warning(self, "Warning", "Please select at least one encryption method.")
            return False
        
        # Check if at least one implementation option is selected
        if not self.use_stdlib_check.isChecked() and not self.use_custom_check.isChecked():
            QMessageBox.warning(self, "Warning", "Please select at least one implementation option (Standard Library or Custom).")
            return False
        
        return True
    
    def _get_dataset_information(self):
        """Get dataset information from the dataset tab."""
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
                            return None, None, None
                        
                        # If a dataset is selected, get information about it
                        dataset_info = DatasetAnalyzer.get_dataset_info(dataset_path)
                        dataset_sample = DatasetAnalyzer.get_dataset_sample(dataset_path, 200)
        except Exception as e:
            # Log the error but continue without dataset information
            print(f"Error accessing dataset tab: {str(e)}")
            QMessageBox.warning(self, "Dataset Error", 
                f"Could not access dataset information: {str(e)}\n\nPlease select a dataset in the Dataset tab.")
            self.status_message.emit("Test not started: Dataset error")
            return None, None, None
        
        return dataset_path, dataset_info, dataset_sample
    
    def _create_session_config(self, dataset_path, dataset_info, dataset_sample):
        """Create session directory and configuration file."""
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
        pc_specs = SystemInfoCollector.collect_pc_specs()
        
        # Create config dictionary (enhanced with new fields)
        config = {
            "languages": {
                "python": self.lang_python_check.isChecked(),
                "zig": self.lang_zig_check.isChecked(),
                "c": self.lang_c_check.isChecked(),
                "rust": self.lang_rust_check.isChecked(),
                "go": self.lang_go_check.isChecked(),
                "java": self.lang_java_check.isChecked()
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
                    "padding": self.rsa_padding_combo.currentText()
                },
                "ecc": {
                    "enabled": self.ecc_check.isChecked(),
                    "curve": self.ecc_curve_combo.currentText()
                },
                "camellia": {
                    "enabled": self.camellia_check.isChecked(),
                    "key_size": self.camellia_key_size_combo.currentText(),
                    "mode": self.camellia_mode_combo.currentText()
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
        
        return config_path
    
    def _execute_tests(self, config_path):
        """Execute the selected tests."""
        # Emit signal to indicate tests are starting
        message = f"Starting tests with configuration from {config_path}"
        self.status_message.emit(message)
        print(f"\n=== TEST SESSION STARTED ===")
        print(message)
        
        # Create test executor
        executor = TestExecutor(self.status_message.emit)
        
        # Execute tests based on selected languages
        if self.lang_zig_check.isChecked():
            executor.execute_zig_tests(config_path)
        
        if self.lang_c_check.isChecked():
            executor.execute_c_tests(config_path)
        
        # For other languages, run the orchestrator
        if any([
            self.lang_python_check.isChecked(),
            self.lang_rust_check.isChecked(),
            self.lang_go_check.isChecked(),
            self.lang_java_check.isChecked()
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
    
    def _cleanup_orchestrator_thread(self):
        """Safely clean up the orchestrator thread."""
        if self.orchestrator_thread:
            try:
                # First try to quit gracefully
                self.orchestrator_thread.quit()
                if not self.orchestrator_thread.wait(2000):  # Wait 2 seconds
                    # If it doesn't quit gracefully, terminate it
                    self.orchestrator_thread.terminate()
                    self.orchestrator_thread.wait(3000)  # Wait up to 3 seconds for termination
                
                # Disconnect all signals to prevent issues
                try:
                    self.orchestrator_thread.finished.disconnect()
                    self.orchestrator_thread.orchestration_complete.disconnect()
                    self.orchestrator_thread.progress_update.disconnect()
                except:
                    pass
                
                # Clean up the thread reference
                self.orchestrator_thread = None
                
                # Clean up any temporary files
                for file in os.listdir(os.getcwd()):
                    if file.startswith("session-") and file.endswith(".json"):
                        try:
                            os.remove(os.path.join(os.getcwd(), file))
                        except:
                            pass
                
                # Force garbage collection
                import gc
                gc.collect()
                
            except Exception as e:
                print(f"Error during thread cleanup: {e}")


# Export the main class
__all__ = ['ConfigurationTab'] 