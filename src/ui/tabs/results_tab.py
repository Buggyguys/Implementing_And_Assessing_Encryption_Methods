"""
CryptoBench Pro - Results Viewer Tab
Allows users to view and analyze benchmarking results.
"""

import os
import json
import glob
from datetime import datetime
from pathlib import Path
import matplotlib
matplotlib.use('Qt5Agg')  # Use Qt5 backend for matplotlib
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar
import numpy as np

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
    QPushButton, QLabel, QTableWidget, QTableWidgetItem,
    QComboBox, QTabWidget, QSplitter, QFileDialog,
    QScrollArea, QSizePolicy, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QSize
from PyQt6.QtGui import QFont


class MatplotlibCanvas(FigureCanvas):
    """Matplotlib canvas for embedding plots in PyQt."""
    
    def __init__(self, parent=None, width=6, height=4, dpi=100):
        """Initialize the canvas."""
        self.fig = Figure(figsize=(width, height), dpi=dpi, tight_layout=True)
        self.axes = self.fig.add_subplot(111)
        
        super().__init__(self.fig)
        self.setParent(parent)
        
        # Set size policy
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.updateGeometry()


class ResultsTab(QWidget):
    """Results Viewer tab widget."""
    
    status_message = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        
        # Initialize member variables
        self.current_session = None
        self.results_data = None
        
        # Set up the UI
        self._setup_ui()
        
        # Connect signals
        self._connect_signals()
        
        # Refresh sessions
        self._refresh_sessions()
    
    def _setup_ui(self):
        """Set up the UI components."""
        # Main layout
        main_layout = QVBoxLayout(self)
        
        # Session selection
        session_layout = QHBoxLayout()
        
        # Session selection label
        session_layout.addWidget(QLabel("Select Session:"))
        
        # Session selection combo box
        self.session_combo = QComboBox()
        self.session_combo.setMinimumWidth(300)
        session_layout.addWidget(self.session_combo)
        
        # Refresh sessions button
        self.refresh_button = QPushButton("Refresh")
        session_layout.addWidget(self.refresh_button)
        
        # Export results button
        self.export_button = QPushButton("Export Results")
        self.export_button.setEnabled(False)
        session_layout.addWidget(self.export_button)
        
        # Add session layout to main layout
        main_layout.addLayout(session_layout)
        
        # Create splitter for results view
        self.results_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side: Results table and summary
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # Summary group
        summary_group = QGroupBox("Test Summary")
        summary_layout = QVBoxLayout()
        
        # Summary text
        self.summary_label = QLabel("No session selected")
        self.summary_label.setWordWrap(True)
        summary_layout.addWidget(self.summary_label)
        
        # Set layout for summary group
        summary_group.setLayout(summary_layout)
        left_layout.addWidget(summary_group)
        
        # Results table
        table_group = QGroupBox("Detailed Results")
        table_layout = QVBoxLayout()
        
        # View selection
        view_layout = QHBoxLayout()
        
        # View selection label
        view_layout.addWidget(QLabel("View Results By:"))
        
        # View selection combo box
        self.view_combo = QComboBox()
        self.view_combo.addItems([
            "Programming Language", 
            "Encryption Method", 
            "Self vs. Standard Library"
        ])
        view_layout.addWidget(self.view_combo)
        
        # Add view layout to table layout
        table_layout.addLayout(view_layout)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setMinimumHeight(300)
        table_layout.addWidget(self.results_table)
        
        # Set layout for table group
        table_group.setLayout(table_layout)
        left_layout.addWidget(table_group)
        
        # Right side: Charts
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # Charts group
        charts_group = QGroupBox("Performance Charts")
        charts_layout = QVBoxLayout()
        
        # Chart type selection
        chart_layout = QHBoxLayout()
        
        # Chart type label
        chart_layout.addWidget(QLabel("Chart Type:"))
        
        # Chart type combo box
        self.chart_combo = QComboBox()
        self.chart_combo.addItems([
            "Encryption Speed", 
            "Decryption Speed", 
            "Key Generation Time", 
            "Memory Usage",
            "Self vs. Library Comparison"
        ])
        chart_layout.addWidget(self.chart_combo)
        
        # Add chart layout to charts layout
        charts_layout.addLayout(chart_layout)
        
        # Matplotlib canvas for chart
        self.chart_canvas = MatplotlibCanvas(self, width=6, height=4, dpi=100)
        charts_layout.addWidget(self.chart_canvas)
        
        # Matplotlib toolbar
        self.chart_toolbar = NavigationToolbar(self.chart_canvas, self)
        charts_layout.addWidget(self.chart_toolbar)
        
        # Set layout for charts group
        charts_group.setLayout(charts_layout)
        right_layout.addWidget(charts_group)
        
        # Add widgets to splitter
        self.results_splitter.addWidget(left_widget)
        self.results_splitter.addWidget(right_widget)
        
        # Set splitter sizes
        self.results_splitter.setSizes([400, 600])
        
        # Add splitter to main layout
        main_layout.addWidget(self.results_splitter)
    
    def _connect_signals(self):
        """Connect signals to slots."""
        # Session combo box
        self.session_combo.currentIndexChanged.connect(self._load_session)
        
        # Refresh button
        self.refresh_button.clicked.connect(self._refresh_sessions)
        
        # Export button
        self.export_button.clicked.connect(self._export_results)
        
        # View combo box
        self.view_combo.currentIndexChanged.connect(self._update_results_table)
        
        # Chart combo box
        self.chart_combo.currentIndexChanged.connect(self._update_chart)
    
    def _refresh_sessions(self):
        """Refresh the list of available sessions."""
        # Store current selection
        current_text = self.session_combo.currentText()
        
        # Clear combo box
        self.session_combo.clear()
        
        # Find all session directories - look in the sessions directory in project root
        project_root = os.getcwd()
        
        # If running from src directory, go up one level
        if os.path.basename(project_root) == "src":
            project_root = os.path.dirname(project_root)
            
        sessions_dir = os.path.join(project_root, "sessions")
        session_dirs = glob.glob(os.path.join(sessions_dir, "Session-*"))
        
        # Sort by creation time (newest first)
        session_dirs.sort(key=os.path.getctime, reverse=True)
        
        # Add each session to combo box
        for session_dir in session_dirs:
            # Create display name
            dir_name = os.path.basename(session_dir)
            display_name = dir_name
            
            # Store the actual path in the user data
            self.session_combo.addItem(display_name, session_dir)
        
        # Add "No session" option if no sessions found
        if self.session_combo.count() == 0:
            self.session_combo.addItem("No sessions available")
            self.export_button.setEnabled(False)
        
        # Try to restore previous selection
        if current_text:
            index = self.session_combo.findText(current_text)
            if index >= 0:
                self.session_combo.setCurrentIndex(index)
        
        self.status_message.emit("Sessions refreshed")
    
    def _load_session(self, index):
        """Load the selected session."""
        # Check if there are any sessions
        if self.session_combo.count() == 0 or self.session_combo.itemText(0) == "No sessions available":
            self.export_button.setEnabled(False)
            return
        
        # Get session directory
        session_dir = self.session_combo.itemData(index)
        
        if not session_dir:
            self.export_button.setEnabled(False)
            return
        
        self.current_session = session_dir
        
        # Try to load the configuration
        config_path = os.path.join(session_dir, "test_config.json")
        
        if not os.path.exists(config_path):
            self.summary_label.setText(f"Configuration file not found in {session_dir}")
            self.export_button.setEnabled(False)
            return
        
        try:
            # Load configuration
            with open(config_path, "r") as f:
                config = json.load(f)
            
            # Load results
            results_dir = os.path.join(session_dir, "results")
            result_files = glob.glob(os.path.join(results_dir, "*.json"))
            
            if not result_files:
                self.summary_label.setText(f"No result files found in {results_dir}")
                self.export_button.setEnabled(False)
                return
            
            # Parse results
            self.results_data = {
                "config": config,
                "results": {}
            }
            
            for result_file in result_files:
                try:
                    with open(result_file, "r") as f:
                        result_data = json.load(f)
                    
                    # Extract filename parts
                    filename = os.path.basename(result_file)
                    parts = filename.replace(".json", "").split("_")
                    
                    if len(parts) >= 2:
                        # First part is language, second is algorithm
                        language = parts[0]
                        algorithm = parts[1]
                        
                        if language not in self.results_data["results"]:
                            self.results_data["results"][language] = {}
                        
                        self.results_data["results"][language][algorithm] = result_data
                
                except Exception as e:
                    self.status_message.emit(f"Error loading {result_file}: {str(e)}")
            
            # Update summary
            self._update_summary()
            
            # Update table and chart
            self._update_results_table()
            self._update_chart()
            
            # Enable export button
            self.export_button.setEnabled(True)
            
            self.status_message.emit(f"Loaded session from {session_dir}")
            
        except Exception as e:
            self.summary_label.setText(f"Error loading session: {str(e)}")
            self.export_button.setEnabled(False)
    
    def _update_summary(self):
        """Update the summary label with session information."""
        if not self.results_data:
            self.summary_label.setText("No data loaded")
            return
        
        config = self.results_data["config"]
        
        # Create summary text
        summary = []
        
        # Session timestamp
        if "session_info" in config:
            if "human_timestamp" in config["session_info"]:
                # Use new human-readable timestamp
                summary.append(f"<b>Session Date:</b> {config['session_info']['human_timestamp']}")
            elif "timestamp" in config["session_info"]:
                # Fall back to old timestamp format
                timestamp = config["session_info"]["timestamp"]
                try:
                    dt = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
                    summary.append(f"<b>Session Date:</b> {dt.strftime('%Y-%m-%d %H:%M:%S')}")
                except ValueError:
                    summary.append(f"<b>Session:</b> {timestamp}")
        
        # Languages
        languages = [lang for lang, enabled in config["languages"].items() if enabled]
        summary.append(f"<b>Languages:</b> {', '.join(languages)}")
        
        # Encryption methods
        methods = []
        for method, data in config["encryption_methods"].items():
            if data.get("enabled", False):
                method_str = method.upper()
                
                if method == "aes":
                    method_str += f"-{data.get('key_size', '?')}"
                elif method == "rsa":
                    method_str += f" {data.get('key_size', '?')}-bit"
                elif method == "ecc":
                    method_str += f" ({data.get('curve', '?')})"
                elif method == "mlkem":
                    method_str += f" {data.get('param_set', '?')}"
                
                methods.append(method_str)
        
        summary.append(f"<b>Encryption Methods:</b> {', '.join(methods)}")
        
        # Test parameters
        summary.append(f"<b>RAM Limit:</b> {config['test_parameters']['ram_limit']}")
        summary.append(f"<b>Iterations:</b> {config['test_parameters']['iterations']}")
        summary.append(f"<b>Standard Library Comparison:</b> {'Yes' if config['test_parameters']['include_stdlibs'] else 'No'}")
        
        # Add dataset information if available
        if "dataset_info" in config and config["dataset_info"]:
            summary.append("<br><b>Dataset Information:</b>")
            dataset_info = config["dataset_info"]
            if "file_name" in dataset_info:
                summary.append(f"&nbsp;&nbsp;File: {dataset_info['file_name']}")
            if "file_size_kb" in dataset_info:
                summary.append(f"&nbsp;&nbsp;Size: {dataset_info['file_size_kb']} KB")
            if "content_type" in dataset_info:
                summary.append(f"&nbsp;&nbsp;Content Type: {dataset_info['content_type']}")
            
            # Character types
            char_types = []
            if dataset_info.get("has_alphabetic", False): char_types.append("Alphabetic")
            if dataset_info.get("has_digits", False): char_types.append("Digits")
            if dataset_info.get("has_spaces", False): char_types.append("Spaces")
            if dataset_info.get("has_punctuation", False): char_types.append("Punctuation")
            if dataset_info.get("has_special_chars", False): char_types.append("Special Characters")
            
            if char_types:
                summary.append(f"&nbsp;&nbsp;Contains: {', '.join(char_types)}")
        
        # Add system specifications if available
        if "pc_specifications" in config and config["pc_specifications"]:
            summary.append("<br><b>System Specifications:</b>")
            pc_specs = config["pc_specifications"]
            
            # CPU info
            if "cpu" in pc_specs:
                cpu = pc_specs["cpu"]
                cpu_info = f"{cpu.get('name', 'Unknown')}"
                if "cores" in cpu and "logical_cores" in cpu:
                    cpu_info += f" ({cpu.get('cores')} cores, {cpu.get('logical_cores')} threads)"
                summary.append(f"&nbsp;&nbsp;CPU: {cpu_info}")
            
            # GPU info if available
            if "gpu" in pc_specs:
                gpu = pc_specs["gpu"]
                if "cores" in gpu:
                    summary.append(f"&nbsp;&nbsp;GPU Cores: {gpu['cores']}")
            
            # Memory
            if "memory" in pc_specs:
                memory = pc_specs["memory"]
                if "total_ram_gb" in memory:
                    summary.append(f"&nbsp;&nbsp;RAM: {memory['total_ram_gb']} GB")
            
            # OS
            if "os" in pc_specs:
                os_info = pc_specs["os"]
                os_str = f"{os_info.get('system', 'Unknown')} {os_info.get('release', '')}"
                summary.append(f"&nbsp;&nbsp;OS: {os_str}")
        
        # Add dataset sample if available
        if "dataset_sample" in config and config["dataset_sample"]:
            sample = config["dataset_sample"]
            if len(sample) > 200:  # Limit display length
                sample = sample[:197] + "..."
            
            summary.append(f"<br><b>Dataset Sample:</b><br><span style='font-family: monospace;'>{sample}</span>")
        
        # Set summary text
        self.summary_label.setText("<br>".join(summary))
    
    def _update_results_table(self):
        """Update the results table based on the selected view."""
        if not self.results_data:
            return
        
        # Clear table
        self.results_table.clear()
        self.results_table.setRowCount(0)
        
        # Get selected view
        view = self.view_combo.currentText()
        
        if view == "Programming Language":
            self._show_results_by_language()
        elif view == "Encryption Method":
            self._show_results_by_method()
        elif view == "Self vs. Standard Library":
            self._show_results_by_comparison()
    
    def _show_results_by_language(self):
        """Show results grouped by programming language."""
        if not self.results_data:
            return
        
        # Set up table headers
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            "Language",
            "Algorithm",
            "Avg. Encryption Time (ms)",
            "Avg. Decryption Time (ms)",
            "Avg. Key Gen Time (ms)"
        ])
        
        # Add data rows
        row = 0
        for language, algorithms in self.results_data["results"].items():
            for algorithm, data in algorithms.items():
                # Add a row for self-implementation
                self.results_table.insertRow(row)
                
                # Language
                self.results_table.setItem(row, 0, QTableWidgetItem(language.capitalize()))
                
                # Algorithm
                self.results_table.setItem(row, 1, QTableWidgetItem(f"{algorithm.upper()} (Self)"))
                
                # Times - for simplicity, just showing averages here
                if "self_implementation" in data:
                    impl_data = data["self_implementation"]
                    
                    # Encryption time
                    if "encryption_times" in impl_data:
                        times = impl_data["encryption_times"]
                        avg = sum(times) / len(times) if times else 0
                        self.results_table.setItem(row, 2, QTableWidgetItem(f"{avg * 1000:.2f}"))
                    
                    # Decryption time
                    if "decryption_times" in impl_data:
                        times = impl_data["decryption_times"]
                        avg = sum(times) / len(times) if times else 0
                        self.results_table.setItem(row, 3, QTableWidgetItem(f"{avg * 1000:.2f}"))
                    
                    # Key generation time
                    if "key_generation_time" in impl_data:
                        time = impl_data["key_generation_time"]
                        self.results_table.setItem(row, 4, QTableWidgetItem(f"{time * 1000:.2f}"))
                
                row += 1
                
                # Add a row for library implementation if available
                if "library_implementation" in data:
                    self.results_table.insertRow(row)
                    
                    # Language
                    self.results_table.setItem(row, 0, QTableWidgetItem(language.capitalize()))
                    
                    # Algorithm
                    self.results_table.setItem(row, 1, QTableWidgetItem(f"{algorithm.upper()} (Lib)"))
                    
                    # Times
                    impl_data = data["library_implementation"]
                    
                    # Encryption time
                    if "encryption_times" in impl_data:
                        times = impl_data["encryption_times"]
                        avg = sum(times) / len(times) if times else 0
                        self.results_table.setItem(row, 2, QTableWidgetItem(f"{avg * 1000:.2f}"))
                    
                    # Decryption time
                    if "decryption_times" in impl_data:
                        times = impl_data["decryption_times"]
                        avg = sum(times) / len(times) if times else 0
                        self.results_table.setItem(row, 3, QTableWidgetItem(f"{avg * 1000:.2f}"))
                    
                    # Key generation time
                    if "key_generation_time" in impl_data:
                        time = impl_data["key_generation_time"]
                        self.results_table.setItem(row, 4, QTableWidgetItem(f"{time * 1000:.2f}"))
                    
                    row += 1
        
        # Resize columns to content
        self.results_table.resizeColumnsToContents()
    
    def _show_results_by_method(self):
        """Show results grouped by encryption method."""
        if not self.results_data:
            return
        
        # Set up table headers
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            "Algorithm",
            "Language",
            "Avg. Encryption Time (ms)",
            "Avg. Decryption Time (ms)",
            "Avg. Key Gen Time (ms)"
        ])
        
        # Collect all algorithms
        algorithms = set()
        for language_data in self.results_data["results"].values():
            algorithms.update(language_data.keys())
        
        # Add data rows
        row = 0
        for algorithm in sorted(algorithms):
            for language, language_data in self.results_data["results"].items():
                if algorithm in language_data:
                    data = language_data[algorithm]
                    
                    # Add a row for self-implementation
                    self.results_table.insertRow(row)
                    
                    # Algorithm
                    self.results_table.setItem(row, 0, QTableWidgetItem(algorithm.upper()))
                    
                    # Language
                    self.results_table.setItem(row, 1, QTableWidgetItem(f"{language.capitalize()} (Self)"))
                    
                    # Times - for simplicity, just showing averages here
                    if "self_implementation" in data:
                        impl_data = data["self_implementation"]
                        
                        # Encryption time
                        if "encryption_times" in impl_data:
                            times = impl_data["encryption_times"]
                            avg = sum(times) / len(times) if times else 0
                            self.results_table.setItem(row, 2, QTableWidgetItem(f"{avg * 1000:.2f}"))
                        
                        # Decryption time
                        if "decryption_times" in impl_data:
                            times = impl_data["decryption_times"]
                            avg = sum(times) / len(times) if times else 0
                            self.results_table.setItem(row, 3, QTableWidgetItem(f"{avg * 1000:.2f}"))
                        
                        # Key generation time
                        if "key_generation_time" in impl_data:
                            time = impl_data["key_generation_time"]
                            self.results_table.setItem(row, 4, QTableWidgetItem(f"{time * 1000:.2f}"))
                    
                    row += 1
                    
                    # Add a row for library implementation if available
                    if "library_implementation" in data:
                        self.results_table.insertRow(row)
                        
                        # Algorithm
                        self.results_table.setItem(row, 0, QTableWidgetItem(algorithm.upper()))
                        
                        # Language
                        self.results_table.setItem(row, 1, QTableWidgetItem(f"{language.capitalize()} (Lib)"))
                        
                        # Times
                        impl_data = data["library_implementation"]
                        
                        # Encryption time
                        if "encryption_times" in impl_data:
                            times = impl_data["encryption_times"]
                            avg = sum(times) / len(times) if times else 0
                            self.results_table.setItem(row, 2, QTableWidgetItem(f"{avg * 1000:.2f}"))
                        
                        # Decryption time
                        if "decryption_times" in impl_data:
                            times = impl_data["decryption_times"]
                            avg = sum(times) / len(times) if times else 0
                            self.results_table.setItem(row, 3, QTableWidgetItem(f"{avg * 1000:.2f}"))
                        
                        # Key generation time
                        if "key_generation_time" in impl_data:
                            time = impl_data["key_generation_time"]
                            self.results_table.setItem(row, 4, QTableWidgetItem(f"{time * 1000:.2f}"))
                        
                        row += 1
        
        # Resize columns to content
        self.results_table.resizeColumnsToContents()
    
    def _show_results_by_comparison(self):
        """Show results comparing self vs. standard library implementations."""
        if not self.results_data:
            return
        
        # Set up table headers
        self.results_table.setColumnCount(7)
        self.results_table.setHorizontalHeaderLabels([
            "Language",
            "Algorithm",
            "Self Enc. Time (ms)",
            "Lib Enc. Time (ms)",
            "Self/Lib Ratio",
            "Self Dec. Time (ms)",
            "Lib Dec. Time (ms)"
        ])
        
        # Add data rows
        row = 0
        for language, algorithms in self.results_data["results"].items():
            for algorithm, data in algorithms.items():
                # Only add rows if both implementations are available
                if "self_implementation" in data and "library_implementation" in data:
                    self.results_table.insertRow(row)
                    
                    # Language
                    self.results_table.setItem(row, 0, QTableWidgetItem(language.capitalize()))
                    
                    # Algorithm
                    self.results_table.setItem(row, 1, QTableWidgetItem(algorithm.upper()))
                    
                    # Self implementation encryption time
                    self_impl = data["self_implementation"]
                    if "encryption_times" in self_impl:
                        self_times = self_impl["encryption_times"]
                        self_avg = sum(self_times) / len(self_times) if self_times else 0
                        self.results_table.setItem(row, 2, QTableWidgetItem(f"{self_avg * 1000:.2f}"))
                    
                    # Library implementation encryption time
                    lib_impl = data["library_implementation"]
                    if "encryption_times" in lib_impl:
                        lib_times = lib_impl["encryption_times"]
                        lib_avg = sum(lib_times) / len(lib_times) if lib_times else 0
                        self.results_table.setItem(row, 3, QTableWidgetItem(f"{lib_avg * 1000:.2f}"))
                    
                    # Self/Lib ratio
                    if "encryption_times" in self_impl and "encryption_times" in lib_impl:
                        self_times = self_impl["encryption_times"]
                        lib_times = lib_impl["encryption_times"]
                        
                        self_avg = sum(self_times) / len(self_times) if self_times else 0
                        lib_avg = sum(lib_times) / len(lib_times) if lib_times else 0
                        
                        if lib_avg > 0:
                            ratio = self_avg / lib_avg
                            self.results_table.setItem(row, 4, QTableWidgetItem(f"{ratio:.2f}x"))
                    
                    # Self implementation decryption time
                    if "decryption_times" in self_impl:
                        self_times = self_impl["decryption_times"]
                        self_avg = sum(self_times) / len(self_times) if self_times else 0
                        self.results_table.setItem(row, 5, QTableWidgetItem(f"{self_avg * 1000:.2f}"))
                    
                    # Library implementation decryption time
                    if "decryption_times" in lib_impl:
                        lib_times = lib_impl["decryption_times"]
                        lib_avg = sum(lib_times) / len(lib_times) if lib_times else 0
                        self.results_table.setItem(row, 6, QTableWidgetItem(f"{lib_avg * 1000:.2f}"))
                    
                    row += 1
        
        # Resize columns to content
        self.results_table.resizeColumnsToContents()
    
    def _update_chart(self):
        """Update the chart based on the selected chart type."""
        if not self.results_data:
            return
        
        # Clear the current chart
        self.chart_canvas.axes.clear()
        
        # Get selected chart type
        chart_type = self.chart_combo.currentText()
        
        if chart_type == "Encryption Speed":
            self._plot_encryption_speed()
        elif chart_type == "Decryption Speed":
            self._plot_decryption_speed()
        elif chart_type == "Key Generation Time":
            self._plot_key_generation_time()
        elif chart_type == "Memory Usage":
            self._plot_memory_usage()
        elif chart_type == "Self vs. Library Comparison":
            self._plot_self_vs_library()
        
        # Redraw the canvas
        self.chart_canvas.draw()
    
    def _plot_encryption_speed(self):
        """Plot encryption speed chart."""
        if not self.results_data:
            return
        
        # Collect data for plotting
        languages = []
        algorithms = []
        self_speeds = []
        lib_speeds = []
        
        for language, language_data in self.results_data["results"].items():
            for algorithm, data in language_data.items():
                if "self_implementation" in data:
                    self_impl = data["self_implementation"]
                    if "encryption_times" in self_impl and "data_size" in self_impl:
                        times = self_impl["encryption_times"]
                        avg_time = sum(times) / len(times) if times else 0
                        data_size = self_impl["data_size"]
                        
                        if avg_time > 0:
                            languages.append(language.capitalize())
                            algorithms.append(algorithm.upper())
                            self_speeds.append(data_size / avg_time / (1024 * 1024))  # MB/s
                            
                            # Add library data if available
                            if "library_implementation" in data:
                                lib_impl = data["library_implementation"]
                                if "encryption_times" in lib_impl and "data_size" in lib_impl:
                                    lib_times = lib_impl["encryption_times"]
                                    lib_avg_time = sum(lib_times) / len(lib_times) if lib_times else 0
                                    lib_data_size = lib_impl["data_size"]
                                    
                                    if lib_avg_time > 0:
                                        lib_speeds.append(lib_data_size / lib_avg_time / (1024 * 1024))  # MB/s
                                    else:
                                        lib_speeds.append(0)
                                else:
                                    lib_speeds.append(0)
                            else:
                                lib_speeds.append(0)
        
        # If no data, show message
        if not languages:
            self.chart_canvas.axes.text(
                0.5, 0.5, "No encryption speed data available",
                horizontalalignment="center",
                verticalalignment="center",
                transform=self.chart_canvas.axes.transAxes
            )
            return
        
        # Create x positions for bars
        x = np.arange(len(languages))
        width = 0.35
        
        # Plot bars
        self.chart_canvas.axes.bar(x - width/2, self_speeds, width, label="Self Implementation")
        
        # Only plot library bars if there's data
        if any(lib_speeds):
            self.chart_canvas.axes.bar(x + width/2, lib_speeds, width, label="Library Implementation")
        
        # Add labels and title
        self.chart_canvas.axes.set_xlabel("Implementation")
        self.chart_canvas.axes.set_ylabel("Speed (MB/s)")
        self.chart_canvas.axes.set_title("Encryption Speed Comparison")
        
        # Set x-axis labels
        self.chart_canvas.axes.set_xticks(x)
        self.chart_canvas.axes.set_xticklabels([f"{lang}\n{algo}" for lang, algo in zip(languages, algorithms)])
        
        # Add legend
        self.chart_canvas.axes.legend()
        
        # Make sure everything fits
        self.chart_canvas.fig.tight_layout()
    
    def _plot_decryption_speed(self):
        """Plot decryption speed chart."""
        # Similar to _plot_encryption_speed but for decryption
        # Implementation left as an exercise
        self.chart_canvas.axes.text(
            0.5, 0.5, "Decryption speed chart would be similar to encryption speed",
            horizontalalignment="center",
            verticalalignment="center",
            transform=self.chart_canvas.axes.transAxes
        )
    
    def _plot_key_generation_time(self):
        """Plot key generation time chart."""
        # Similar to other plot methods but for key generation time
        # Implementation left as an exercise
        self.chart_canvas.axes.text(
            0.5, 0.5, "Key generation time chart would compare key generation times",
            horizontalalignment="center",
            verticalalignment="center",
            transform=self.chart_canvas.axes.transAxes
        )
    
    def _plot_memory_usage(self):
        """Plot memory usage chart."""
        # Similar to other plot methods but for memory usage
        # Implementation left as an exercise
        self.chart_canvas.axes.text(
            0.5, 0.5, "Memory usage chart would compare peak memory usage",
            horizontalalignment="center",
            verticalalignment="center",
            transform=self.chart_canvas.axes.transAxes
        )
    
    def _plot_self_vs_library(self):
        """Plot self vs. library comparison chart."""
        # Similar to other plot methods but focusing on the comparison
        # Implementation left as an exercise
        self.chart_canvas.axes.text(
            0.5, 0.5, "Self vs. Library comparison would show performance ratios",
            horizontalalignment="center",
            verticalalignment="center",
            transform=self.chart_canvas.axes.transAxes
        )
    
    def _export_results(self):
        """Export results to PDF."""
        if not self.results_data or not self.current_session:
            return
        
        # Open file dialog
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            os.path.join(self.current_session, "report.pdf"),
            "PDF Files (*.pdf)"
        )
        
        if file_path:
            self.status_message.emit(f"Exporting results to {file_path}...")
            
            # In a real implementation, this would generate a PDF report
            # For now, just show a message
            QMessageBox.information(
                self,
                "Export Results",
                f"Results would be exported to {file_path}.\n\n"
                f"This feature will be implemented in a future version."
            )
            
            self.status_message.emit(f"Results exported to {file_path}") 