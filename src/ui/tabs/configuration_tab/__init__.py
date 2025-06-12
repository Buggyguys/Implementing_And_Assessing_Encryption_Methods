"""
CryptoBench Pro - Test Configuration Tab
Allows users to configure benchmarking tests with separate panels for symmetric and asymmetric encryption.
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
    QGridLayout, QTabWidget, QMainWindow, QSplitter,
    QFrame, QTextEdit
)
from PyQt6.QtCore import Qt, pyqtSignal, pyqtSlot, QThread

from src.ui.tabs.configuration_tab.utils import DatasetAnalyzer, SystemInfoCollector
from src.ui.tabs.configuration_tab.orchestration import OrchestrationThread, TestExecutor


class ConfigurationTab(QWidget):
    """Test Configuration tab widget with separate panels for symmetric and asymmetric encryption."""
    
    status_message = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        
        # Initialize member variables
        self.config_path = None
        self.orchestrator_thread = None  # Store thread reference
        
        # Dataset paths
        self.symmetric_dataset_path = None
        self.asymmetric_dataset_path = None
        
        # Set up the UI
        self._setup_ui()
    
    def _setup_ui(self):
        """Set up the UI components."""
        # Main layout
        main_layout = QVBoxLayout(self)
        
        # Programming Languages group (global)
        languages_group = self._create_programming_languages_group()
        main_layout.addWidget(languages_group)
        
        # Create a horizontal splitter for the two encryption panels
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)  # Prevent collapsing
        
        # Left Panel: Symmetric Encryption
        symmetric_panel = self._create_symmetric_panel()
        symmetric_panel.setFixedHeight(250)  # Set fixed height like bottom panels
        splitter.addWidget(symmetric_panel)
        
        # Right Panel: Asymmetric Encryption
        asymmetric_panel = self._create_asymmetric_panel()
        asymmetric_panel.setFixedHeight(250)  # Set fixed height like bottom panels
        splitter.addWidget(asymmetric_panel)
        
        # Set equal sizes for both panels and disable handle
        splitter.setSizes([400, 400])
        splitter.setHandleWidth(10)  # Increase handle width to match bottom spacing
        splitter.setStyleSheet("QSplitter::handle { background-color: transparent; }")  # Make handle invisible but preserve spacing
        main_layout.addWidget(splitter)
        
        # Add spacing after encryption panels
        main_layout.addSpacing(15)
        
        # Create horizontal layout for algorithm info (left) and test parameters (right)
        bottom_layout = QHBoxLayout()
        algo_info_group = self._create_algorithm_info_group()
        algo_info_group.setFixedHeight(300)  # Set fixed height to match top panels
        test_params_group = self._create_test_parameters_group()
        test_params_group.setFixedHeight(300)  # Set fixed height to match top panels
        bottom_layout.addWidget(algo_info_group)
        bottom_layout.addWidget(test_params_group)
        main_layout.addLayout(bottom_layout)
        
        # Add spacing before control buttons
        main_layout.addSpacing(15)
        
        # Control buttons
        control_buttons = self._create_control_buttons()
        main_layout.addLayout(control_buttons)
        
        # Add spacing before progress bar
        main_layout.addSpacing(10)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)
        
        # Connect signals
        self._connect_signals()
    
    def _create_programming_languages_group(self):
        """Create the global programming languages group."""
        group = QGroupBox("Programming Languages")
        layout = QGridLayout()
        
        self.lang_python_check = QCheckBox("Python")
        self.lang_c_check = QCheckBox("C")
        self.lang_rust_check = QCheckBox("Rust")
        self.lang_go_check = QCheckBox("Go")
        self.lang_java_check = QCheckBox("Java")
        self.lang_zig_check = QCheckBox("Zig")
        
        layout.addWidget(self.lang_python_check, 0, 0)
        layout.addWidget(self.lang_c_check, 0, 1)
        layout.addWidget(self.lang_rust_check, 0, 2)
        layout.addWidget(self.lang_go_check, 1, 0)
        layout.addWidget(self.lang_java_check, 1, 1)
        layout.addWidget(self.lang_zig_check, 1, 2)
        
        group.setLayout(layout)
        return group
    
    def _create_symmetric_panel(self):
        """Create the symmetric encryption panel."""
        panel = QGroupBox("Symmetric Encryption")
        layout = QVBoxLayout(panel)
        
        # Dataset Selection for Symmetric
        dataset_group = QGroupBox("Dataset Selection")
        dataset_layout = QVBoxLayout()
        
        # Dataset selection with dropdown
        dataset_select_layout = QHBoxLayout()
        dataset_select_layout.addWidget(QLabel("Select Dataset:"))
        
        self.symmetric_dataset_combo = QComboBox()
        self.symmetric_dataset_combo.addItem("No dataset selected")
        self.symmetric_dataset_combo.currentTextChanged.connect(self._on_symmetric_dataset_changed)
        dataset_select_layout.addWidget(self.symmetric_dataset_combo)
        
        # Refresh button
        self.symmetric_refresh_btn = QPushButton("Refresh")
        self.symmetric_refresh_btn.clicked.connect(self._refresh_symmetric_datasets)
        dataset_select_layout.addWidget(self.symmetric_refresh_btn)
        
        dataset_layout.addLayout(dataset_select_layout)
        
        dataset_group.setLayout(dataset_layout)
        layout.addWidget(dataset_group)
        
        # Symmetric Algorithms
        algo_group = QGroupBox("Symmetric Algorithms")
        algo_layout = QVBoxLayout()
        
        # AES
        aes_layout = QHBoxLayout()
        self.sym_aes_check = QCheckBox("AES")
        aes_layout.addWidget(self.sym_aes_check)
        
        aes_layout.addWidget(QLabel("Key Size:"))
        self.sym_aes_key_size_combo = QComboBox()
        self.sym_aes_key_size_combo.addItems(["128", "192", "256"])
        self.sym_aes_key_size_combo.setCurrentText("256")
        aes_layout.addWidget(self.sym_aes_key_size_combo)
        
        aes_layout.addWidget(QLabel("Mode:"))
        self.sym_aes_mode_combo = QComboBox()
        self.sym_aes_mode_combo.addItems(["CBC", "CFB", "OFB", "GCM"])
        self.sym_aes_mode_combo.setCurrentText("GCM")
        aes_layout.addWidget(self.sym_aes_mode_combo)
        
        aes_layout.addStretch()
        algo_layout.addLayout(aes_layout)
        
        # ChaCha20
        chacha_layout = QHBoxLayout()
        self.sym_chacha_check = QCheckBox("ChaCha20")
        chacha_layout.addWidget(self.sym_chacha_check)
        chacha_layout.addStretch()
        algo_layout.addLayout(chacha_layout)
        
        # Camellia
        camellia_layout = QHBoxLayout()
        self.sym_camellia_check = QCheckBox("Camellia")
        camellia_layout.addWidget(self.sym_camellia_check)
        
        camellia_layout.addWidget(QLabel("Key Size:"))
        self.sym_camellia_key_size_combo = QComboBox()
        self.sym_camellia_key_size_combo.addItems(["128", "192", "256"])
        self.sym_camellia_key_size_combo.setCurrentText("256")
        camellia_layout.addWidget(self.sym_camellia_key_size_combo)
        
        camellia_layout.addWidget(QLabel("Mode:"))
        self.sym_camellia_mode_combo = QComboBox()
        self.sym_camellia_mode_combo.addItems(["CBC", "ECB", "CFB", "OFB"])
        self.sym_camellia_mode_combo.setCurrentText("CBC")
        camellia_layout.addWidget(self.sym_camellia_mode_combo)
        
        camellia_layout.addStretch()
        algo_layout.addLayout(camellia_layout)
        
        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)
        
        # Initialize dataset list
        self._refresh_symmetric_datasets()
        
        return panel
    
    def _create_asymmetric_panel(self):
        """Create the asymmetric encryption panel."""
        panel = QGroupBox("Asymmetric Encryption")
        layout = QVBoxLayout(panel)
        
        # Dataset Selection for Asymmetric
        dataset_group = QGroupBox("Dataset Selection")
        dataset_layout = QVBoxLayout()
        
        # Dataset selection with dropdown
        dataset_select_layout = QHBoxLayout()
        dataset_select_layout.addWidget(QLabel("Select Dataset:"))
        
        self.asymmetric_dataset_combo = QComboBox()
        self.asymmetric_dataset_combo.addItem("No dataset selected")
        self.asymmetric_dataset_combo.currentTextChanged.connect(self._on_asymmetric_dataset_changed)
        dataset_select_layout.addWidget(self.asymmetric_dataset_combo)
        
        # Refresh button
        self.asymmetric_refresh_btn = QPushButton("Refresh")
        self.asymmetric_refresh_btn.clicked.connect(self._refresh_asymmetric_datasets)
        dataset_select_layout.addWidget(self.asymmetric_refresh_btn)
        
        dataset_layout.addLayout(dataset_select_layout)
        
        dataset_group.setLayout(dataset_layout)
        layout.addWidget(dataset_group)
        
        # Asymmetric Algorithms
        algo_group = QGroupBox("Asymmetric Algorithms (Pure/Chunked)")
        algo_layout = QVBoxLayout()
        
        # RSA
        rsa_layout = QHBoxLayout()
        self.asym_rsa_check = QCheckBox("RSA")
        rsa_layout.addWidget(self.asym_rsa_check)
        
        rsa_layout.addWidget(QLabel("Key Size:"))
        self.asym_rsa_key_size_combo = QComboBox()
        self.asym_rsa_key_size_combo.addItems(["1024", "2048", "3072", "4096"])
        self.asym_rsa_key_size_combo.setCurrentText("2048")
        rsa_layout.addWidget(self.asym_rsa_key_size_combo)
        
        rsa_layout.addWidget(QLabel("Padding:"))
        self.asym_rsa_padding_combo = QComboBox()
        self.asym_rsa_padding_combo.addItems(["OAEP", "PKCS#1 v1.5"])
        self.asym_rsa_padding_combo.setCurrentText("OAEP")
        rsa_layout.addWidget(self.asym_rsa_padding_combo)
        
        rsa_layout.addStretch()
        algo_layout.addLayout(rsa_layout)
        
        # ECC
        ecc_layout = QHBoxLayout()
        self.asym_ecc_check = QCheckBox("ECC")
        ecc_layout.addWidget(self.asym_ecc_check)
        
        ecc_layout.addWidget(QLabel("Curve:"))
        self.asym_ecc_curve_combo = QComboBox()
        self.asym_ecc_curve_combo.addItems(["P-256", "P-384", "P-521"])
        self.asym_ecc_curve_combo.setCurrentText("P-256")
        ecc_layout.addWidget(self.asym_ecc_curve_combo)
        ecc_layout.addStretch()
        algo_layout.addLayout(ecc_layout)
        
        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)
        
        # Initialize dataset list
        self._refresh_asymmetric_datasets()
        
        return panel
    
    def _create_test_parameters_group(self):
        """Create the test parameters group (now includes implementation options)."""
        group = QGroupBox("Test Parameters")
        layout = QVBoxLayout()
        
        # Implementation Options Section
        impl_group = QGroupBox("Implementation Options")
        impl_layout = QVBoxLayout()
        
        self.use_stdlib_check = QCheckBox("Use Standard Library Implementations")
        self.use_stdlib_check.setChecked(True)
        impl_layout.addWidget(self.use_stdlib_check)
        
        self.use_custom_check = QCheckBox("Use Custom Implementations")
        self.use_custom_check.setChecked(True)
        impl_layout.addWidget(self.use_custom_check)
        
        impl_group.setLayout(impl_layout)
        layout.addWidget(impl_group)
        
        # Processing Strategy Section
        strategy_group = QGroupBox("Processing Strategy")
        strategy_layout = QVBoxLayout()
        strategy_layout.setSpacing(10)  # Add more spacing between elements
        
        # Processing Strategy
        strategy_select_layout = QHBoxLayout()
        strategy_select_layout.addWidget(QLabel("Processing Strategy:"))
        self.processing_strategy_combo = QComboBox()
        self.processing_strategy_combo.addItems(["Memory", "Stream"])
        self.processing_strategy_combo.setToolTip("Memory: Process entire dataset in memory\nStream: Process dataset in chunks")
        strategy_select_layout.addWidget(self.processing_strategy_combo)
        strategy_select_layout.addStretch()
        strategy_layout.addLayout(strategy_select_layout)
        
        # Chunk Size
        chunk_layout = QHBoxLayout()
        chunk_layout.addWidget(QLabel("Chunk Size:"))
        self.chunk_size_combo = QComboBox()
        self.chunk_size_combo.addItems(["64KB", "256KB", "1MB", "4MB", "16MB"])
        self.chunk_size_combo.setCurrentText("1MB")
        self.chunk_size_combo.setToolTip("Size of chunks when using Stream processing")
        chunk_layout.addWidget(self.chunk_size_combo)
        chunk_layout.addStretch()
        strategy_layout.addLayout(chunk_layout)
        
        strategy_group.setLayout(strategy_layout)
        strategy_group.setMinimumHeight(100)  # Ensure enough height for content
        layout.addWidget(strategy_group)
        
        # Other Parameters Section
        other_group = QGroupBox("Other Parameters")
        other_layout = QFormLayout()
        
        # Number of Iterations
        self.iterations_spin = QSpinBox()
        self.iterations_spin.setRange(1, 100)
        self.iterations_spin.setValue(3)
        other_layout.addRow("Number of Iterations:", self.iterations_spin)
        
        other_group.setLayout(other_layout)
        layout.addWidget(other_group)
        
        group.setLayout(layout)
        return group
    
    def _create_algorithm_info_group(self):
        """Create the algorithm information group."""
        group = QGroupBox("Algorithm Information & Messages")
        layout = QVBoxLayout()
        
        # Algorithm info text area with scroll - resizable
        self.algorithm_info_text = QTextEdit()
        self.algorithm_info_text.setStyleSheet("color: #adb5bd; font-size: 10px; padding: 8px; border: 1px solid #404040; border-radius: 4px; background-color: #2b2b2b;")
        self.algorithm_info_text.setPlainText("Select algorithms to see detailed information...")
        self.algorithm_info_text.setReadOnly(True)
        self.algorithm_info_text.setMinimumHeight(250)  # Adjust to fit in fixed height group
        layout.addWidget(self.algorithm_info_text)
        
        group.setLayout(layout)
        return group
    
    def _create_control_buttons(self):
        """Create the control buttons layout."""
        layout = QHBoxLayout()
        
        # Save/Load Configuration buttons
        self.save_config_btn = QPushButton("Save Configuration")
        self.save_config_btn.clicked.connect(self._save_config)
        layout.addWidget(self.save_config_btn)
        
        self.load_config_btn = QPushButton("Load Configuration")
        self.load_config_btn.clicked.connect(self._load_config)
        layout.addWidget(self.load_config_btn)
        
        layout.addStretch()
        
        # Start Tests button (removed green styling)
        self.start_tests_btn = QPushButton("Start Tests")
        self.start_tests_btn.setStyleSheet("font-weight: bold;")
        self.start_tests_btn.clicked.connect(self._start_tests)
        layout.addWidget(self.start_tests_btn)
        
        return layout
    
    def _connect_signals(self):
        """Connect signals to slots."""
        # Button signals
        self.save_config_btn.clicked.connect(self._save_config)
        self.load_config_btn.clicked.connect(self._load_config)
        self.start_tests_btn.clicked.connect(self._start_tests)
        
        # Checkbox signals
        self.sym_aes_check.toggled.connect(lambda checked: self.sym_aes_key_size_combo.setEnabled(checked))
        self.sym_aes_check.toggled.connect(lambda checked: self.sym_aes_mode_combo.setEnabled(checked))
        self.sym_camellia_check.toggled.connect(lambda checked: self.sym_camellia_key_size_combo.setEnabled(checked))
        self.sym_camellia_check.toggled.connect(lambda checked: self.sym_camellia_mode_combo.setEnabled(checked))
        self.asym_rsa_check.toggled.connect(lambda checked: self.asym_rsa_key_size_combo.setEnabled(checked))
        self.asym_rsa_check.toggled.connect(lambda checked: self.asym_rsa_padding_combo.setEnabled(checked))
        self.asym_ecc_check.toggled.connect(lambda checked: self.asym_ecc_curve_combo.setEnabled(checked))
        
        # Connect implementation options checkboxes to validation method
        self.use_stdlib_check.toggled.connect(self._validate_implementation_options)
        self.use_custom_check.toggled.connect(self._validate_implementation_options)
        
        # Connect signals for dynamic message updates
        self.lang_python_check.toggled.connect(self._update_dynamic_messages)
        self.use_custom_check.toggled.connect(self._update_dynamic_messages)
        self.sym_aes_check.toggled.connect(self._update_algorithm_info)
        self.sym_aes_key_size_combo.currentTextChanged.connect(self._update_algorithm_info)
        self.sym_aes_mode_combo.currentTextChanged.connect(self._update_algorithm_info)
        self.sym_chacha_check.toggled.connect(self._update_dynamic_messages)
        self.sym_chacha_check.toggled.connect(self._update_algorithm_info)
        self.sym_camellia_check.toggled.connect(self._update_dynamic_messages)
        self.sym_camellia_check.toggled.connect(self._update_algorithm_info)
        self.sym_camellia_key_size_combo.currentTextChanged.connect(self._update_algorithm_info)
        self.sym_camellia_mode_combo.currentTextChanged.connect(self._update_algorithm_info)
        self.asym_rsa_check.toggled.connect(self._update_dynamic_messages)
        self.asym_rsa_check.toggled.connect(self._update_algorithm_info)
        self.asym_rsa_key_size_combo.currentTextChanged.connect(self._update_algorithm_info)
        self.asym_rsa_padding_combo.currentTextChanged.connect(self._update_algorithm_info)
        self.asym_ecc_check.toggled.connect(self._update_dynamic_messages)
        self.asym_ecc_check.toggled.connect(self._update_algorithm_info)
        self.asym_ecc_curve_combo.currentTextChanged.connect(self._update_algorithm_info)
        
        # Processing strategy signals
        self.processing_strategy_combo.currentTextChanged.connect(self._update_chunk_size_visibility)
        self.processing_strategy_combo.currentTextChanged.connect(self._update_algorithm_info)
        self.chunk_size_combo.currentTextChanged.connect(self._update_algorithm_info)
        
        # Dataset selection signals
        self.symmetric_dataset_combo.currentTextChanged.connect(self._on_symmetric_dataset_changed)
        self.asymmetric_dataset_combo.currentTextChanged.connect(self._on_asymmetric_dataset_changed)
        self.symmetric_dataset_combo.currentTextChanged.connect(self._update_algorithm_info)
        self.asymmetric_dataset_combo.currentTextChanged.connect(self._update_algorithm_info)
        
        # Initial enable/disable
        self.sym_aes_key_size_combo.setEnabled(self.sym_aes_check.isChecked())
        self.sym_aes_mode_combo.setEnabled(self.sym_aes_check.isChecked())
        self.sym_camellia_key_size_combo.setEnabled(self.sym_camellia_check.isChecked())
        self.sym_camellia_mode_combo.setEnabled(self.sym_camellia_check.isChecked())
        self.asym_rsa_key_size_combo.setEnabled(self.asym_rsa_check.isChecked())
        self.asym_rsa_padding_combo.setEnabled(self.asym_rsa_check.isChecked())
        self.asym_ecc_curve_combo.setEnabled(self.asym_ecc_check.isChecked())
        self._update_chunk_size_visibility(self.processing_strategy_combo.currentText())
        
        # Initialize algorithm messages
        self._update_algorithm_info()
        
        # Ensure all language checkboxes start unchecked for consistency
        self.lang_python_check.setChecked(False)
        self.lang_c_check.setChecked(False)
        self.lang_rust_check.setChecked(False)
        self.lang_go_check.setChecked(False)
        self.lang_java_check.setChecked(False)
        self.lang_zig_check.setChecked(False)
    
    def _update_chunk_size_visibility(self, strategy):
        """Enable/disable chunk size selector based on processing strategy."""
        self.chunk_size_combo.setEnabled(strategy == "Stream")
    
    def _update_algorithm_info(self):
        """Update the central algorithm information section with details about selected algorithms."""
        if not hasattr(self, 'algorithm_info_text'):
            return
            
        content_sections = []
        
        # === ALGORITHM INFORMATION ===
        algo_sections = []
        
        # Check symmetric algorithms
        if hasattr(self, 'sym_aes_check') and self.sym_aes_check.isChecked():
            key_size = self.sym_aes_key_size_combo.currentText()
            mode = self.sym_aes_mode_combo.currentText()
            
            key_info = {
                "128": "128-bit key: Fast, good security for most applications",
                "192": "192-bit key: Balanced performance and enhanced security", 
                "256": "256-bit key: Maximum security, slightly slower"
            }
            
            mode_info = {
                "CBC": "CBC mode: Sequential processing, requires initialization vector",
                "CTR": "CTR mode: Parallel processing, good for streaming",
                "GCM": "GCM mode: Authenticated encryption, built-in integrity check",
                "ECB": "ECB mode: Fastest but less secure, not recommended for production"
            }
            
            aes_info = f"AES: {key_info.get(key_size, '')} | {mode_info.get(mode, '')}"
            algo_sections.append(aes_info)
        
        if hasattr(self, 'sym_chacha_check') and self.sym_chacha_check.isChecked():
            chacha_info = "ChaCha20: 256-bit key, designed for high performance and security, resistant to timing attacks"
            algo_sections.append(chacha_info)
        
        if hasattr(self, 'sym_camellia_check') and self.sym_camellia_check.isChecked():
            key_size = self.sym_camellia_key_size_combo.currentText()
            mode = self.sym_camellia_mode_combo.currentText()
            
            key_info = {
                "128": "128-bit key: Good performance, suitable for general use",
                "192": "192-bit key: Enhanced security with moderate performance impact",
                "256": "256-bit key: Maximum security, compatible with AES-256 applications"
            }
            
            mode_info = {
                "CBC": "CBC mode: Standard block cipher mode, sequential processing",
                "CTR": "CTR mode: Counter mode, enables parallel processing", 
                "GCM": "GCM mode: Galois/Counter mode with authentication",
                "ECB": "ECB mode: Electronic codebook, simplest but least secure"
            }
            
            camellia_info = f"Camellia: {key_info.get(key_size, '')} | {mode_info.get(mode, '')}"
            algo_sections.append(camellia_info)
        
        # Check asymmetric algorithms
        if hasattr(self, 'asym_rsa_check') and self.asym_rsa_check.isChecked():
            key_size = self.asym_rsa_key_size_combo.currentText()
            padding = self.asym_rsa_padding_combo.currentText()
            
            key_info = {
                "1024": "1024-bit: Fast but deprecated, not secure for new applications",
                "2048": "2048-bit: Current standard, good balance of security and performance",
                "3072": "3072-bit: Enhanced security, slower key generation and operations",
                "4096": "4096-bit: Maximum security, significantly slower operations"
            }
            
            padding_info = {
                "OAEP": "OAEP padding: Optimal Asymmetric Encryption Padding, more secure",
                "PKCS#1 v1.5": "PKCS#1 v1.5: Classic padding, faster but potentially vulnerable to attacks"
            }
            
            rsa_info = f"RSA: {key_info.get(key_size, '')} | {padding_info.get(padding, '')}"
            algo_sections.append(rsa_info)
        
        if hasattr(self, 'asym_ecc_check') and self.asym_ecc_check.isChecked():
            curve = self.asym_ecc_curve_combo.currentText()
            
            curve_info = {
                "P-256": "P-256: 256-bit curve, equivalent to RSA-3072 security, fast operations",
                "P-384": "P-384: 384-bit curve, equivalent to RSA-7680 security, moderate performance",
                "P-521": "P-521: 521-bit curve, equivalent to RSA-15360 security, slower but maximum security"
            }
            
            ecc_info = curve_info.get(curve, "")
            if ecc_info:
                algo_sections.append(f"ECC: {ecc_info}")
        
        if algo_sections:
            content_sections.append("=== ALGORITHM INFORMATION ===")
            content_sections.extend(algo_sections)
        
        # === WARNINGS & RECOMMENDATIONS ===
        warning_sections = []
        
        # Get processing strategy information
        strategy = self.processing_strategy_combo.currentText()
        if strategy == "Memory":
            warning_sections.append("PROCESSING: Memory mode - Fast but memory intensive")
        elif strategy == "Stream":
            chunk_size = self.chunk_size_combo.currentText()
            if chunk_size in ["1MB", "4MB", "16MB"]:
                warning_sections.append(f"PROCESSING: Stream mode with {chunk_size} chunks - Memory efficient, similar performance to memory mode")
            else:
                warning_sections.append(f"PROCESSING: Stream mode with {chunk_size} chunks - Memory efficient but slower, uses less RAM")
        
        # Get symmetric dataset warnings
        sym_messages = self._get_symmetric_messages()
        if sym_messages:
            warning_sections.extend(sym_messages)
        
        # Get asymmetric dataset warnings  
        asym_messages = self._get_asymmetric_messages()
        if asym_messages:
            warning_sections.extend(asym_messages)
        
        if warning_sections:
            content_sections.append("")
            content_sections.append("=== WARNINGS & RECOMMENDATIONS ===")
            content_sections.extend(warning_sections)
        
        # Update the display
        if content_sections:
            self.algorithm_info_text.setPlainText("\n\n".join(content_sections))
        else:
            self.algorithm_info_text.setPlainText("Select algorithms to see detailed information...")
    
    def _get_symmetric_messages(self):
        """Get symmetric encryption warnings and recommendations."""
        messages = []
        
        # Add dataset size information first
        if hasattr(self, 'symmetric_dataset_path') and self.symmetric_dataset_path:
            try:
                size_bytes = Path(self.symmetric_dataset_path).stat().st_size
                size_mb = size_bytes / (1024 * 1024)
                dataset_name = Path(self.symmetric_dataset_path).name
                messages.append(f"DATASET: Symmetric '{dataset_name}' - {size_mb:.2f} MB")
            except Exception:
                messages.append("DATASET: Symmetric dataset size unknown")
        
        # Check for Python + Custom implementation warning
        if (hasattr(self, 'lang_python_check') and hasattr(self, 'use_custom_check') and 
            self.lang_python_check.isChecked() and self.use_custom_check.isChecked()):
            if any([
                hasattr(self, 'sym_aes_check') and self.sym_aes_check.isChecked(),
                hasattr(self, 'sym_chacha_check') and self.sym_chacha_check.isChecked(),
                hasattr(self, 'sym_camellia_check') and self.sym_camellia_check.isChecked()
            ]):
                if hasattr(self, 'symmetric_dataset_path') and self.symmetric_dataset_path:
                    try:
                        size_mb = Path(self.symmetric_dataset_path).stat().st_size / (1024 * 1024)
                        if size_mb > 1:
                            messages.append(f"WARNING: Custom Python implementation is significantly slower. "
                                          f"Dataset '{Path(self.symmetric_dataset_path).name}' ({size_mb:.1f} MB) may take considerable time. "
                                          f"Consider datasets < 1 MB for custom Python.")
                        else:
                            messages.append(f"GOOD: Dataset size ({size_mb:.1f} MB) is suitable for custom Python implementations.")
                    except Exception:
                        messages.append("WARNING: Custom Python implementation is significantly slower. Consider datasets < 1 MB.")
                else:
                    messages.append("WARNING: Custom Python implementation is significantly slower. Consider datasets < 1 MB.")
        
        return messages
    
    def _get_asymmetric_messages(self):
        """Get asymmetric encryption warnings and recommendations.""" 
        messages = []
        
        # Add dataset size information first
        if hasattr(self, 'asymmetric_dataset_path') and self.asymmetric_dataset_path:
            try:
                size_bytes = Path(self.asymmetric_dataset_path).stat().st_size
                size_kb = size_bytes / 1024
                size_mb = size_bytes / (1024 * 1024)
                dataset_name = Path(self.asymmetric_dataset_path).name
                messages.append(f"DATASET: Asymmetric '{dataset_name}' - {size_mb:.2f} MB ({size_kb:.1f} KB)")
            except Exception:
                messages.append("DATASET: Asymmetric dataset size unknown")
        
        # Check dataset size warnings for asymmetric algorithms
        if (hasattr(self, 'asymmetric_dataset_path') and self.asymmetric_dataset_path and 
            any([
                hasattr(self, 'asym_rsa_check') and self.asym_rsa_check.isChecked(),
                hasattr(self, 'asym_ecc_check') and self.asym_ecc_check.isChecked()
            ])):
            try:
                size_bytes = Path(self.asymmetric_dataset_path).stat().st_size
                size_kb = size_bytes / 1024
                size_mb = size_bytes / (1024 * 1024)
                dataset_name = Path(self.asymmetric_dataset_path).name
                
                if size_kb > 50:
                    messages.append(f"WARNING: Dataset '{dataset_name}' ({size_mb:.2f} MB) is too large for efficient asymmetric encryption. "
                                  f"Will be chunked automatically. Recommend < 50 KB for optimal performance.")
                else:
                    messages.append(f"GOOD: Dataset '{dataset_name}' ({size_kb:.1f} KB) is suitable for asymmetric encryption.")
            except Exception:
                pass
        
        # Check for Python + Custom + Asymmetric combination
        if (hasattr(self, 'lang_python_check') and hasattr(self, 'use_custom_check') and
            self.lang_python_check.isChecked() and self.use_custom_check.isChecked()):
            if any([
                hasattr(self, 'asym_rsa_check') and self.asym_rsa_check.isChecked(),
                hasattr(self, 'asym_ecc_check') and self.asym_ecc_check.isChecked()
            ]):
                if messages:
                    messages.append("SLOW: Custom Python asymmetric implementations are extremely slow. Consider < 10 KB datasets for testing only.")
                else:
                    messages.append("SLOW: Custom Python asymmetric implementations are extremely slow. Consider < 10 KB datasets for testing only.")
        
        return messages
    
    def _update_dynamic_messages(self):
        """Update dynamic messages based on current selections."""
        # All messages now go to the algorithm info section
        if hasattr(self, 'algorithm_info_text'):
            self._update_algorithm_info()
    
    def _update_symmetric_messages(self):
        """Deprecated - messages now handled in algorithm info section."""
        pass
    
    def _update_asymmetric_messages(self):
        """Deprecated - messages now handled in algorithm info section."""
        pass
    
    def _refresh_symmetric_datasets(self):
        """Refresh the list of available datasets for symmetric encryption."""
        self.symmetric_dataset_combo.clear()
        self.symmetric_dataset_combo.addItem("No dataset selected")
        
        dataset_dir = Path("src/datasets")
        if dataset_dir.exists():
            for file_path in dataset_dir.iterdir():
                if file_path.is_file():
                    self.symmetric_dataset_combo.addItem(file_path.name)
    
    def _refresh_asymmetric_datasets(self):
        """Refresh the list of available datasets for asymmetric encryption."""
        self.asymmetric_dataset_combo.clear()
        self.asymmetric_dataset_combo.addItem("No dataset selected")
        
        dataset_dir = Path("src/datasets")
        if dataset_dir.exists():
            for file_path in dataset_dir.iterdir():
                if file_path.is_file():
                    self.asymmetric_dataset_combo.addItem(file_path.name)
    
    def _on_symmetric_dataset_changed(self, dataset_name):
        """Handle symmetric dataset selection change."""
        if dataset_name == "No dataset selected":
            self.symmetric_dataset_path = None
        else:
            dataset_path = Path("src/datasets") / dataset_name
            if dataset_path.exists():
                self.symmetric_dataset_path = str(dataset_path)
                try:
                    size_bytes = dataset_path.stat().st_size
                    size_mb = size_bytes / (1024 * 1024)
                    self.status_message.emit(f"Selected symmetric dataset: {dataset_name}")
                except Exception:
                    self.status_message.emit("Size: Unknown")
                    
                self._update_dynamic_messages()
            else:
                self.symmetric_dataset_path = None
                self.status_message.emit("Dataset not found")
        
        self._update_dynamic_messages()
        self._update_algorithm_info()
    
    def _on_asymmetric_dataset_changed(self, dataset_name):
        """Handle asymmetric dataset selection change."""
        if dataset_name == "No dataset selected":
            self.asymmetric_dataset_path = None
        else:
            dataset_path = Path("src/datasets") / dataset_name
            if dataset_path.exists():
                self.asymmetric_dataset_path = str(dataset_path)
                
                # Show dataset info with size warning
                try:
                    size_bytes = dataset_path.stat().st_size
                    size_kb = size_bytes / 1024
                    size_mb = size_bytes / (1024 * 1024)
                    
                    if size_kb > 50:
                        self.status_message.emit(f"WARNING: Dataset '{dataset_name}' ({size_mb:.2f} MB) is too large for efficient asymmetric encryption. Will be chunked automatically. Recommend < 50 KB for optimal performance.")
                    else:
                        self.status_message.emit(f"GOOD: Dataset '{dataset_name}' ({size_kb:.1f} KB) is suitable for asymmetric encryption.")
                except Exception:
                    self.status_message.emit("Size: Unknown")
                    
                self.status_message.emit(f"Selected asymmetric dataset: {dataset_name}")
            else:
                self.asymmetric_dataset_path = None
                self.status_message.emit("Dataset not found")
        
        self._update_dynamic_messages()
        self._update_algorithm_info()
    
    def _validate_implementation_options(self):
        """Ensure at least one implementation option is selected."""
        if not self.use_stdlib_check.isChecked() and not self.use_custom_check.isChecked():
            sender = self.sender()
            if sender in [self.use_stdlib_check, self.use_custom_check]:
                sender.setChecked(True)
    
    def _save_config(self):
        """Save configuration to a file."""
        # Create config dictionary
        config = {
            "languages": {
                "python": self.lang_python_check.isChecked(),
                "c": self.lang_c_check.isChecked(),
                "rust": self.lang_rust_check.isChecked(),
                "go": self.lang_go_check.isChecked(),
                "java": self.lang_java_check.isChecked(),
                "zig": self.lang_zig_check.isChecked()
            },
            "encryption_methods": {
                "aes": {
                    "enabled": self.sym_aes_check.isChecked(),
                    "key_size": self.sym_aes_key_size_combo.currentText(),
                    "mode": self.sym_aes_mode_combo.currentText()
                },
                "chacha20": {
                    "enabled": self.sym_chacha_check.isChecked()
                },
                "camellia": {
                    "enabled": self.sym_camellia_check.isChecked(),
                    "key_size": self.sym_camellia_key_size_combo.currentText(),
                    "mode": self.sym_camellia_mode_combo.currentText()
                },
                "rsa": {
                    "enabled": self.asym_rsa_check.isChecked(),
                    "key_size": self.asym_rsa_key_size_combo.currentText(),
                    "padding": self.asym_rsa_padding_combo.currentText()
                },
                "ecc": {
                    "enabled": self.asym_ecc_check.isChecked(),
                    "curve": self.asym_ecc_curve_combo.currentText()
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
                self.lang_c_check.setChecked(config["languages"]["c"])
                self.lang_rust_check.setChecked(config["languages"]["rust"])
                self.lang_go_check.setChecked(config["languages"]["go"])
                self.lang_java_check.setChecked(config["languages"]["java"])
                self.lang_zig_check.setChecked(config["languages"]["zig"])
                
                # Encryption methods
                self.sym_aes_check.setChecked(config["encryption_methods"]["aes"]["enabled"])
                self.sym_aes_key_size_combo.setCurrentText(config["encryption_methods"]["aes"]["key_size"])
                self.sym_aes_mode_combo.setCurrentText(config["encryption_methods"]["aes"]["mode"])
                
                self.sym_chacha_check.setChecked(config["encryption_methods"]["chacha20"]["enabled"])
                
                self.sym_camellia_check.setChecked(config["encryption_methods"]["camellia"]["enabled"])
                self.sym_camellia_key_size_combo.setCurrentText(config["encryption_methods"]["camellia"]["key_size"])
                self.sym_camellia_mode_combo.setCurrentText(config["encryption_methods"]["camellia"]["mode"])
                
                # Asymmetric algorithms (if available in config)
                if "rsa" in config["encryption_methods"]:
                    self.asym_rsa_check.setChecked(config["encryption_methods"]["rsa"]["enabled"])
                    self.asym_rsa_key_size_combo.setCurrentText(config["encryption_methods"]["rsa"]["key_size"])
                    self.asym_rsa_padding_combo.setCurrentText(config["encryption_methods"]["rsa"]["padding"])
                
                if "ecc" in config["encryption_methods"]:
                    self.asym_ecc_check.setChecked(config["encryption_methods"]["ecc"]["enabled"])
                    self.asym_ecc_curve_combo.setCurrentText(config["encryption_methods"]["ecc"]["curve"])
                
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
        dataset_info = self._get_dataset_information()
        if not dataset_info:
            return
        
        # Create session and configuration
        config_path = self._create_session_config(dataset_info)
        
        # Execute tests
        self._execute_tests(config_path)
    
    def _validate_selections(self):
        """Validate user selections."""
        # Check if at least one language is selected
        if not any([
            self.lang_python_check.isChecked(),
            self.lang_c_check.isChecked(),
            self.lang_rust_check.isChecked(),
            self.lang_go_check.isChecked(),
            self.lang_java_check.isChecked(),
            self.lang_zig_check.isChecked()
        ]):
            QMessageBox.warning(self, "Warning", "Please select at least one programming language.")
            return False
        
        # Check if at least one encryption method is selected (symmetric or asymmetric)
        symmetric_selected = any([
            self.sym_aes_check.isChecked(),
            self.sym_chacha_check.isChecked(),
            self.sym_camellia_check.isChecked()
        ])
        
        asymmetric_selected = any([
            self.asym_rsa_check.isChecked(),
            self.asym_ecc_check.isChecked()
        ])
        
        if not symmetric_selected and not asymmetric_selected:
            QMessageBox.warning(self, "Warning", "Please select at least one encryption method (symmetric or asymmetric).")
            return False
        
        # Check if datasets are selected for enabled algorithm types
        if symmetric_selected and not self.symmetric_dataset_path:
            QMessageBox.warning(self, "Warning", "Please select a dataset for symmetric encryption algorithms.")
            return False
            
        if asymmetric_selected and not self.asymmetric_dataset_path:
            QMessageBox.warning(self, "Warning", "Please select a dataset for asymmetric encryption algorithms.")
            return False
        
        # Check if at least one implementation option is selected
        if not self.use_stdlib_check.isChecked() and not self.use_custom_check.isChecked():
            QMessageBox.warning(self, "Warning", "Please select at least one implementation option (Standard Library or Custom).")
            return False
        
        return True
    
    def _get_dataset_information(self):
        """Get dataset information from both symmetric and asymmetric panels."""
        # Get symmetric dataset info
        symmetric_info = {}
        symmetric_sample = ""
        if hasattr(self, 'symmetric_dataset_path') and self.symmetric_dataset_path:
            try:
                symmetric_info = DatasetAnalyzer.get_dataset_info(self.symmetric_dataset_path)
                symmetric_sample = DatasetAnalyzer.get_dataset_sample(self.symmetric_dataset_path, 200)
            except Exception as e:
                print(f"Error analyzing symmetric dataset: {e}")
                symmetric_info = {"error": str(e)}
                
        # Get asymmetric dataset info  
        asymmetric_info = {}
        asymmetric_sample = ""
        if hasattr(self, 'asymmetric_dataset_path') and self.asymmetric_dataset_path:
            try:
                asymmetric_info = DatasetAnalyzer.get_dataset_info(self.asymmetric_dataset_path)
                asymmetric_sample = DatasetAnalyzer.get_dataset_sample(self.asymmetric_dataset_path, 200)
            except Exception as e:
                print(f"Error analyzing asymmetric dataset: {e}")
                asymmetric_info = {"error": str(e)}
        
        # Check if at least one dataset is selected
        if not self.symmetric_dataset_path and not self.asymmetric_dataset_path:
            QMessageBox.warning(self, "Dataset Required", 
                "Please select at least one dataset (symmetric or asymmetric) before starting the tests.")
            self.status_message.emit("Test not started: No datasets selected")
            print("Test not started: No datasets selected")
            return None
        
        return {
            "symmetric": {
                "path": self.symmetric_dataset_path,
                "info": symmetric_info,
                "sample": symmetric_sample
            },
            "asymmetric": {
                "path": self.asymmetric_dataset_path,
                "info": asymmetric_info,
                "sample": asymmetric_sample
            }
        }
    
    def _create_session_config(self, dataset_info):
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
                "c": self.lang_c_check.isChecked(),
                "rust": self.lang_rust_check.isChecked(),
                "go": self.lang_go_check.isChecked(),
                "java": self.lang_java_check.isChecked(),
                "zig": self.lang_zig_check.isChecked()
            },
            "encryption_methods": {
                "aes": {
                    "enabled": self.sym_aes_check.isChecked(),
                    "key_size": self.sym_aes_key_size_combo.currentText(),
                    "mode": self.sym_aes_mode_combo.currentText()
                },
                "chacha20": {
                    "enabled": self.sym_chacha_check.isChecked()
                },
                "camellia": {
                    "enabled": self.sym_camellia_check.isChecked(),
                    "key_size": self.sym_camellia_key_size_combo.currentText(),
                    "mode": self.sym_camellia_mode_combo.currentText()
                },
                "rsa": {
                    "enabled": self.asym_rsa_check.isChecked(),
                    "key_size": self.asym_rsa_key_size_combo.currentText(),
                    "padding": self.asym_rsa_padding_combo.currentText()
                },
                "ecc": {
                    "enabled": self.asym_ecc_check.isChecked(),
                    "curve": self.asym_ecc_curve_combo.currentText()
                }
            },
            "test_parameters": {
                "processing_strategy": self.processing_strategy_combo.currentText(),
                "chunk_size": self.chunk_size_combo.currentText(),
                "use_stdlib": self.use_stdlib_check.isChecked(),
                "use_custom": self.use_custom_check.isChecked(),
                "iterations": self.iterations_spin.value(),
                "dataset_info": dataset_info
            },
            "session_info": {
                "timestamp": timestamp,
                "human_timestamp": human_timestamp,
                "session_dir": session_dir,
                "session_id": f"Session-{human_timestamp}"
            },
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
        if self.lang_c_check.isChecked():
            executor.execute_c_tests(config_path)
        
        if self.lang_rust_check.isChecked():
            executor.execute_rust_tests(config_path)
        
        if self.lang_go_check.isChecked():
            executor.execute_go_tests(config_path)
        
        if self.lang_java_check.isChecked():
            executor.execute_java_tests(config_path)
        
        # For other languages, run the orchestrator
        if any([
            self.lang_python_check.isChecked(),
            self.lang_zig_check.isChecked()
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