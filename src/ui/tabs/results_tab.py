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
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import matplotlib.pyplot as plt
from io import BytesIO

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
    QPushButton, QLabel, QTableWidget, QTableWidgetItem,
    QComboBox, QTabWidget, QSplitter, QFileDialog,
    QScrollArea, QSizePolicy, QMessageBox, QCheckBox
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
        
        # Top section: Session selection and export options
        top_layout = QHBoxLayout()
        
        # Session selection
        session_group = QGroupBox("Session Selection")
        session_layout = QVBoxLayout()
        
        # Session selection combo box
        self.session_combo = QComboBox()
        self.session_combo.setMinimumWidth(300)
        session_layout.addWidget(self.session_combo)
        
        # Refresh sessions button
        self.refresh_button = QPushButton("Refresh")
        session_layout.addWidget(self.refresh_button)
        
        session_group.setLayout(session_layout)
        top_layout.addWidget(session_group)
        
        # Export options
        export_group = QGroupBox("Export Options")
        export_layout = QVBoxLayout()
        
        # Export options
        options_layout = QHBoxLayout()
        
        # Include charts in PDF checkbox
        self.include_charts_checkbox = QCheckBox("Include charts in PDF")
        self.include_charts_checkbox.setChecked(True)
        options_layout.addWidget(self.include_charts_checkbox)
        
        # Export charts separately checkbox
        self.export_charts_checkbox = QCheckBox("Export charts separately")
        self.export_charts_checkbox.setChecked(False)
        options_layout.addWidget(self.export_charts_checkbox)
        
        # Add options to export layout
        export_layout.addLayout(options_layout)
        
        # Export button
        self.export_button = QPushButton("Export Results")
        self.export_button.setEnabled(False)
        export_layout.addWidget(self.export_button)
        
        export_group.setLayout(export_layout)
        top_layout.addWidget(export_group)
        
        main_layout.addLayout(top_layout)
        
        # Main content area
        content_layout = QHBoxLayout()
        
        # Left side: Results table
        table_group = QGroupBox("Results")
        table_layout = QVBoxLayout()
        
        # View selection
        view_layout = QHBoxLayout()
        view_layout.addWidget(QLabel("View:"))
        
        self.view_combo = QComboBox()
        self.view_combo.addItems([
            "By Programming Language", 
            "By Encryption Method", 
            "Self vs. Library Comparison"
        ])
        view_layout.addWidget(self.view_combo)
        table_layout.addLayout(view_layout)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setMinimumHeight(400)
        table_layout.addWidget(self.results_table)
        
        table_group.setLayout(table_layout)
        content_layout.addWidget(table_group)
        
        # Right side: Charts
        chart_group = QGroupBox("Charts")
        chart_layout = QVBoxLayout()
        
        # Chart type selection
        chart_type_layout = QHBoxLayout()
        chart_type_layout.addWidget(QLabel("Chart Type:"))
        
        self.chart_combo = QComboBox()
        self.chart_combo.addItems([
            "Encryption Speed", 
            "Decryption Speed", 
            "Key Generation Time", 
            "Memory Usage",
            "CPU Usage",
            "Ciphertext Overhead",
            "Context Switches",
            "Self vs. Library Comparison"
        ])
        chart_type_layout.addWidget(self.chart_combo)
        chart_layout.addLayout(chart_type_layout)
        
        # Matplotlib canvas for chart
        self.chart_canvas = MatplotlibCanvas(self, width=6, height=4, dpi=100)
        chart_layout.addWidget(self.chart_canvas)
        
        # Matplotlib toolbar
        self.chart_toolbar = NavigationToolbar(self.chart_canvas, self)
        chart_layout.addWidget(self.chart_toolbar)
        
        chart_group.setLayout(chart_layout)
        content_layout.addWidget(chart_group)
        
        main_layout.addLayout(content_layout)
    
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
            self.results_table.clear()
            self.results_table.setRowCount(0)
            self.results_table.setColumnCount(1)
            self.results_table.setHorizontalHeaderLabels(["Status"])
            self.results_table.setItem(0, 0, QTableWidgetItem("No sessions available to load."))
            self.chart_canvas.axes.clear()
            self.chart_canvas.axes.text(0.5, 0.5, "No session loaded", horizontalalignment='center', verticalalignment='center', transform=self.chart_canvas.axes.transAxes)
            self.chart_canvas.draw()
            return
        
        # Get session directory
        session_dir = self.session_combo.itemData(index)
        
        if not session_dir:
            self.export_button.setEnabled(False)
            self.results_table.clear()
            self.results_table.setRowCount(1) # Adjusted to 1 for the message
            self.results_table.setColumnCount(1)
            self.results_table.setHorizontalHeaderLabels(["Status"])
            item = QTableWidgetItem("Invalid session selected.")
            self.results_table.setItem(0, 0, item)
            self.chart_canvas.axes.clear()
            self.chart_canvas.axes.text(0.5, 0.5, "Invalid session", horizontalalignment='center', verticalalignment='center', transform=self.chart_canvas.axes.transAxes)
            self.chart_canvas.draw()
            return
        
        self.current_session = session_dir
        
        # Try to load the configuration
        config_path = os.path.join(session_dir, "test_config.json")
        
        if not os.path.exists(config_path):
            # self.summary_label.setText(f"Configuration file not found in {session_dir}") # summary_label removed
            self.results_table.clear()
            self.results_table.setRowCount(1)
            self.results_table.setColumnCount(1)
            self.results_table.setHorizontalHeaderLabels(["Status"])
            self.results_table.setItem(0, 0, QTableWidgetItem(f"Configuration file not found in {session_dir}"))
            self.export_button.setEnabled(False)
            self.chart_canvas.axes.clear()
            self.chart_canvas.axes.text(0.5, 0.5, "Config not found", horizontalalignment='center', verticalalignment='center', transform=self.chart_canvas.axes.transAxes)
            self.chart_canvas.draw()
            return
        
        try:
            # Load configuration
            with open(config_path, "r") as f:
                config = json.load(f)
            
            # Load results
            results_dir = os.path.join(session_dir, "results")
            result_files = glob.glob(os.path.join(results_dir, "*.json")) # e.g., c_results.json, python_results.json
            
            if not result_files:
                # self.summary_label.setText(f"No result files found in {results_dir}") # summary_label removed
                self.results_table.clear()
                self.results_table.setRowCount(1)
                self.results_table.setColumnCount(1)
                self.results_table.setHorizontalHeaderLabels(["Status"])
                self.results_table.setItem(0, 0, QTableWidgetItem(f"No result files found in {results_dir}"))
                self.export_button.setEnabled(False)
                self.chart_canvas.axes.clear()
                self.chart_canvas.axes.text(0.5, 0.5, "Results not found", horizontalalignment='center', verticalalignment='center', transform=self.chart_canvas.axes.transAxes)
                self.chart_canvas.draw()
                return
            
            # Parse results
            self.results_data = {
                "config": config, # This is from test_config.json
                "results": {} # This will store results: {"c": c_encryption_results, "python": python_encryption_results}
            }
            
            for result_file_path in result_files:
                try:
                    with open(result_file_path, "r") as f:
                        # result_data_full is the content of one of the *_results.json files
                        result_data_full = json.load(f) 
                    
                    language_name = result_data_full.get("language")
                    if language_name:
                        # Store all encryption_results for that language
                        # Each key under encryption_results is an algorithm (e.g., "aes", "aes_custom")
                        self.results_data["results"][language_name] = result_data_full.get("encryption_results", {})
                    else:
                        self.status_message.emit(f"Warning: 'language' key not found in {result_file_path}. Skipping file.")
                
                except json.JSONDecodeError as je:
                    self.status_message.emit(f"Error decoding JSON from {result_file_path}: {str(je)}")
                except Exception as e:
                    self.status_message.emit(f"Error processing file {result_file_path}: {str(e)}")

            if not self.results_data["results"]:
                self.results_table.clear()
                self.results_table.setRowCount(1)
                self.results_table.setColumnCount(1)
                self.results_table.setHorizontalHeaderLabels(["Status"])
                self.results_table.setItem(0, 0, QTableWidgetItem("No valid result data loaded from JSON files."))
                self.export_button.setEnabled(False)
                self.chart_canvas.axes.clear()
                self.chart_canvas.axes.text(0.5, 0.5, "No valid result data", horizontalalignment='center', verticalalignment='center', transform=self.chart_canvas.axes.transAxes)
                self.chart_canvas.draw()
                return

            # Update table and chart
            self._update_results_table() # This will need to be aware of the new data structure
            self._update_chart()         # This will also need to be aware
            
            # Enable export button
            self.export_button.setEnabled(True)
            
            self.status_message.emit(f"Loaded session from {session_dir}")
            
        except json.JSONDecodeError as je:
            # self.summary_label.setText(f"Error decoding config JSON: {str(je)}") # summary_label removed
            self.results_table.clear()
            self.results_table.setRowCount(1)
            self.results_table.setColumnCount(1)
            self.results_table.setHorizontalHeaderLabels(["Status"])
            self.results_table.setItem(0, 0, QTableWidgetItem(f"Error decoding config JSON: {str(je)}"))
            self.export_button.setEnabled(False)
        except Exception as e:
            # self.summary_label.setText(f"Error loading session: {str(e)}") # summary_label removed
            self.results_table.clear()
            self.results_table.setRowCount(1)
            self.results_table.setColumnCount(1)
            self.results_table.setHorizontalHeaderLabels(["Status"])
            self.results_table.setItem(0, 0, QTableWidgetItem(f"Error loading session: {str(e)}"))
            self.export_button.setEnabled(False)
    
    def _update_results_table(self):
        """Update the results table based on the selected view."""
        if not self.results_data:
            return
        
        # Clear table
        self.results_table.clear()
        self.results_table.setRowCount(0)
        
        # Get selected view
        view = self.view_combo.currentText()
        
        if view == "By Programming Language":
            self._show_results_by_language()
        elif view == "By Encryption Method":
            self._show_results_by_method()
        elif view == "Self vs. Library Comparison":
            self._show_results_by_comparison()
    
    def _show_results_by_language(self):
        """Show results grouped by programming language."""
        if not self.results_data or not self.results_data.get("results"):
            self.results_table.setItem(0, 0, QTableWidgetItem("No results data to display."))
            return
        
        self.results_table.setColumnCount(7) # Increased columns
        self.results_table.setHorizontalHeaderLabels([
            "Language", "Algorithm", "Implementation",
            "Avg. Encrypt Time (ms)", "Avg. Decrypt Time (ms)", 
            "Avg. KeyGen Time (ms)", "Avg. Encrypt Throughput (MB/s)"
        ])
        
        row = 0
        for language, algorithms_data in self.results_data["results"].items():
            if not algorithms_data: continue
            for algo_key, algo_perf_data in algorithms_data.items():
                metrics = algo_perf_data.get("aggregated_metrics", {})
                config = algo_perf_data.get("configuration", {})
                impl_type = algo_perf_data.get("implementation_type", "N/A").capitalize()
                
                display_algo_name = algo_key.replace("_custom", "").upper()
                if "aes" in algo_key.lower() or "camellia" in algo_key.lower():
                     display_algo_name += f"-{config.get('key_size', '?')}"
                elif "rsa" in algo_key.lower():
                     display_algo_name += f" {config.get('key_size', '?')}-bit"
                elif "ecc" in algo_key.lower(): # P-256
                     display_algo_name += f" ({config.get('mode', '?')})" # mode used for curve


                self.results_table.insertRow(row)
                self.results_table.setItem(row, 0, QTableWidgetItem(language.capitalize()))
                self.results_table.setItem(row, 1, QTableWidgetItem(display_algo_name))
                self.results_table.setItem(row, 2, QTableWidgetItem(impl_type))
                
                enc_time = metrics.get("avg_encrypt_wall_time_ms", 0)
                dec_time = metrics.get("avg_decrypt_wall_time_ms", 0)
                keygen_time = metrics.get("avg_keygen_wall_time_ms", 0)
                
                # Throughput: Prefer MB/s, convert from BPS if necessary
                throughput_mb_s = metrics.get("avg_throughput_encrypt_mb_per_s")
                if throughput_mb_s is None:
                    throughput_bps = metrics.get("avg_encrypt_throughput_bps")
                    if throughput_bps is not None:
                        throughput_mb_s = throughput_bps / (8 * 1024 * 1024)
                    else:
                        throughput_mb_s = 0

                self.results_table.setItem(row, 3, QTableWidgetItem(f"{enc_time:.2f}"))
                self.results_table.setItem(row, 4, QTableWidgetItem(f"{dec_time:.2f}"))
                self.results_table.setItem(row, 5, QTableWidgetItem(f"{keygen_time:.3f}")) # More precision for keygen
                self.results_table.setItem(row, 6, QTableWidgetItem(f"{throughput_mb_s:.2f}"))
                row += 1
        
        if row == 0:
            self.results_table.setRowCount(1)
            self.results_table.setItem(0, 0, QTableWidgetItem("No algorithm data found in results."))
        
        self.results_table.resizeColumnsToContents()
    
    def _show_results_by_method(self):
        """Show results grouped by encryption method."""
        if not self.results_data or not self.results_data.get("results"):
            self.results_table.setItem(0, 0, QTableWidgetItem("No results data to display."))
            return

        self.results_table.setColumnCount(7) # Increased columns
        self.results_table.setHorizontalHeaderLabels([
            "Algorithm", "Implementation", "Language",
            "Avg. Encrypt Time (ms)", "Avg. Decrypt Time (ms)",
            "Avg. KeyGen Time (ms)", "Avg. Encrypt Throughput (MB/s)"
        ])

        all_algos_flat = []
        for lang, algos_data in self.results_data["results"].items():
            for algo_key, algo_perf_data in algos_data.items():
                all_algos_flat.append({
                    "lang": lang,
                    "algo_key": algo_key,
                    "perf_data": algo_perf_data
                })
        
        # Sort by algorithm key then by language
        all_algos_flat.sort(key=lambda x: (x["algo_key"], x["lang"]))

        row = 0
        for item in all_algos_flat:
            lang = item["lang"]
            algo_key = item["algo_key"]
            algo_perf_data = item["perf_data"]
            
            metrics = algo_perf_data.get("aggregated_metrics", {})
            config = algo_perf_data.get("configuration", {})
            impl_type = algo_perf_data.get("implementation_type", "N/A").capitalize()

            display_algo_name = algo_key.replace("_custom", "").upper()
            if "aes" in algo_key.lower() or "camellia" in algo_key.lower():
                 display_algo_name += f"-{config.get('key_size', '?')}"
            elif "rsa" in algo_key.lower():
                 display_algo_name += f" {config.get('key_size', '?')}-bit"
            elif "ecc" in algo_key.lower():
                 display_algo_name += f" ({config.get('mode', '?')})"


            self.results_table.insertRow(row)
            self.results_table.setItem(row, 0, QTableWidgetItem(display_algo_name))
            self.results_table.setItem(row, 1, QTableWidgetItem(impl_type))
            self.results_table.setItem(row, 2, QTableWidgetItem(lang.capitalize()))

            enc_time = metrics.get("avg_encrypt_wall_time_ms", 0)
            dec_time = metrics.get("avg_decrypt_wall_time_ms", 0)
            keygen_time = metrics.get("avg_keygen_wall_time_ms", 0)
            
            throughput_mb_s = metrics.get("avg_throughput_encrypt_mb_per_s")
            if throughput_mb_s is None:
                throughput_bps = metrics.get("avg_encrypt_throughput_bps")
                if throughput_bps is not None:
                    throughput_mb_s = throughput_bps / (8 * 1024 * 1024)
                else:
                    throughput_mb_s = 0
            
            self.results_table.setItem(row, 3, QTableWidgetItem(f"{enc_time:.2f}"))
            self.results_table.setItem(row, 4, QTableWidgetItem(f"{dec_time:.2f}"))
            self.results_table.setItem(row, 5, QTableWidgetItem(f"{keygen_time:.3f}"))
            self.results_table.setItem(row, 6, QTableWidgetItem(f"{throughput_mb_s:.2f}"))
            row += 1
            
        if row == 0:
            self.results_table.setRowCount(1)
            self.results_table.setItem(0, 0, QTableWidgetItem("No algorithm data found in results."))

        self.results_table.resizeColumnsToContents()
    
    def _show_results_by_comparison(self):
        """Show results comparing self vs. standard library implementations."""
        if not self.results_data or not self.results_data.get("results"):
            self.results_table.setItem(0, 0, QTableWidgetItem("No results data to display."))
            return

        self.results_table.setColumnCount(9) # Language, Algorithm, Self Enc Time, Lib Enc Time, Enc Ratio, Self Dec Time, Lib Dec Time, Dec Ratio, KeyGen Ratio
        self.results_table.setHorizontalHeaderLabels([
            "Language", "Algorithm", 
            "Self Enc (ms)", "Lib Enc (ms)", "Enc Ratio",
            "Self Dec (ms)", "Lib Dec (ms)", "Dec Ratio",
            "KeyGen Ratio (S/L)"
        ])

        row = 0
        for language, algorithms_data in self.results_data["results"].items():
            # Group algorithms by base name (e.g., "aes" from "aes" and "aes_custom")
            grouped_algos = {}
            for algo_key, perf_data in algorithms_data.items():
                base_algo_name = algo_key.replace("_custom", "")
                if base_algo_name not in grouped_algos:
                    grouped_algos[base_algo_name] = {}
                
                impl_type = perf_data.get("implementation_type")
                if impl_type == "custom":
                    grouped_algos[base_algo_name]["custom"] = perf_data
                elif impl_type == "stdlib":
                    grouped_algos[base_algo_name]["stdlib"] = perf_data

            for base_algo_name, impls in grouped_algos.items():
                if "custom" in impls and "stdlib" in impls:
                    custom_metrics = impls["custom"].get("aggregated_metrics", {})
                    stdlib_metrics = impls["stdlib"].get("aggregated_metrics", {})
                    
                    config = impls["stdlib"].get("configuration", {}) # Use stdlib's config for display name
                    display_algo_name = base_algo_name.upper()
                    if "aes" in base_algo_name.lower() or "camellia" in base_algo_name.lower():
                         display_algo_name += f"-{config.get('key_size', '?')}"
                    elif "rsa" in base_algo_name.lower():
                         display_algo_name += f" {config.get('key_size', '?')}-bit"
                    elif "ecc" in base_algo_name.lower():
                         display_algo_name += f" ({config.get('mode', '?')})"


                    self.results_table.insertRow(row)
                    self.results_table.setItem(row, 0, QTableWidgetItem(language.capitalize()))
                    self.results_table.setItem(row, 1, QTableWidgetItem(display_algo_name))

                    self_enc_time = custom_metrics.get("avg_encrypt_wall_time_ms", 0)
                    lib_enc_time = stdlib_metrics.get("avg_encrypt_wall_time_ms", 0)
                    self_dec_time = custom_metrics.get("avg_decrypt_wall_time_ms", 0)
                    lib_dec_time = stdlib_metrics.get("avg_decrypt_wall_time_ms", 0)
                    self_keygen_time = custom_metrics.get("avg_keygen_wall_time_ms", 0)
                    lib_keygen_time = stdlib_metrics.get("avg_keygen_wall_time_ms", 0)

                    enc_ratio = f"{self_enc_time / lib_enc_time:.2f}x" if lib_enc_time else "N/A"
                    dec_ratio = f"{self_dec_time / lib_dec_time:.2f}x" if lib_dec_time else "N/A"
                    keygen_ratio = f"{self_keygen_time / lib_keygen_time:.2f}x" if lib_keygen_time else "N/A"

                    self.results_table.setItem(row, 2, QTableWidgetItem(f"{self_enc_time:.2f}"))
                    self.results_table.setItem(row, 3, QTableWidgetItem(f"{lib_enc_time:.2f}"))
                    self.results_table.setItem(row, 4, QTableWidgetItem(enc_ratio))
                    self.results_table.setItem(row, 5, QTableWidgetItem(f"{self_dec_time:.2f}"))
                    self.results_table.setItem(row, 6, QTableWidgetItem(f"{lib_dec_time:.2f}"))
                    self.results_table.setItem(row, 7, QTableWidgetItem(dec_ratio))
                    self.results_table.setItem(row, 8, QTableWidgetItem(keygen_ratio))
                    row += 1
        
        if row == 0:
            self.results_table.setRowCount(1)
            self.results_table.setItem(0, 0, QTableWidgetItem("No suitable custom vs. stdlib pairs found for comparison."))

        self.results_table.resizeColumnsToContents()
    
    def _update_chart(self):
        """Update the chart based on the selected chart type."""
        if not self.results_data:
            self.chart_canvas.axes.clear()
            self.chart_canvas.axes.text(0.5, 0.5, "No session data loaded to draw chart.", 
                                        horizontalalignment='center', verticalalignment='center', 
                                        transform=self.chart_canvas.axes.transAxes)
            self.chart_canvas.draw()
            return
        
        self.chart_canvas.axes.clear() # Clear previous chart
        
        chart_type = self.chart_combo.currentText()
        
        if chart_type == "Encryption Speed":
            self._plot_encryption_speed()
        elif chart_type == "Decryption Speed":
            self._plot_decryption_speed()
        elif chart_type == "Key Generation Time":
            self._plot_key_generation_time()
        elif chart_type == "Memory Usage":
            self._plot_memory_usage()
        elif chart_type == "CPU Usage":
            self._plot_cpu_usage()
        elif chart_type == "Ciphertext Overhead":
            self._plot_ciphertext_overhead()
        elif chart_type == "Context Switches":
            self._plot_context_switches()
        elif chart_type == "Self vs. Library Comparison":
            self._plot_self_vs_library()
        else:
            self.chart_canvas.axes.text(0.5, 0.5, f"Chart type '{chart_type}' not yet implemented.",
                                        horizontalalignment='center', verticalalignment='center',
                                        transform=self.chart_canvas.axes.transAxes)
            self.chart_canvas.draw()
    
    def _plot_encryption_speed(self):
        """Plot encryption speed chart with a logarithmic scale if data varies widely."""
        if not self.results_data:
            self.chart_canvas.axes.clear()
            self.chart_canvas.axes.text(0.5, 0.5, "No results data loaded", horizontalalignment='center', verticalalignment='center', transform=self.chart_canvas.axes.transAxes)
            self.chart_canvas.draw()
            return
        
        plot_data = []
        for lang_name, lang_results in self.results_data.get("results", {}).items():
            grouped_algos = {}
            for algo_key, algo_data in lang_results.items():
                base_algo = algo_key.replace("_custom", "")
                if base_algo not in grouped_algos: grouped_algos[base_algo] = {}
                metrics = algo_data.get("aggregated_metrics", {})
                speed_mb_s = metrics.get("avg_throughput_encrypt_mb_per_s")
                if speed_mb_s is None:
                    speed_bps = metrics.get("avg_encrypt_throughput_bps")
                    speed_mb_s = speed_bps / (8 * 1024 * 1024) if speed_bps is not None else 0
                if "_custom" in algo_key: grouped_algos[base_algo]["custom"] = speed_mb_s
                else: grouped_algos[base_algo]["stdlib"] = speed_mb_s
                grouped_algos[base_algo]["config"] = algo_data.get("configuration", {}) # Store for display name

            for base_algo, speeds in grouped_algos.items():
                config = speeds.get("config", {})
                display_algo_name = base_algo.upper()
                if "aes" in base_algo.lower() or "camellia" in base_algo.lower(): display_algo_name += f"-{config.get('key_size', '?')}"
                elif "rsa" in base_algo.lower(): display_algo_name += f" {config.get('key_size', '?')}-bit"
                elif "ecc" in base_algo.lower(): display_algo_name += f" ({config.get('mode', '?')})"
                label = f"{lang_name.capitalize()}\\n{display_algo_name}"
                plot_data.append({"label": label, "self": speeds.get("custom", 0), "lib": speeds.get("stdlib", 0)})
        
        self.chart_canvas.axes.clear()
        if not plot_data:
            self.chart_canvas.axes.text(0.5, 0.5, "No encryption speed data for plotting", horizontalalignment='center', verticalalignment='center', transform=self.chart_canvas.axes.transAxes)
            self.chart_canvas.draw()
            return
            
        labels = [p["label"] for p in plot_data]
        self_speeds = np.array([p["self"] for p in plot_data])
        lib_speeds = np.array([p["lib"] for p in plot_data])

        x = np.arange(len(labels))
        width = 0.35
        
        rects1 = self.chart_canvas.axes.bar(x - width/2, self_speeds, width, label="Self Implementation")
        rects2 = None
        if any(s > 0 for s in lib_speeds):
            rects2 = self.chart_canvas.axes.bar(x + width/2, lib_speeds, width, label="Library Implementation")
        
        self.chart_canvas.axes.set_ylabel("Encryption Speed (MB/s)")
        self.chart_canvas.axes.set_title("Encryption Speed Comparison")
        self.chart_canvas.axes.set_xticks(x)
        self.chart_canvas.axes.set_xticklabels(labels, rotation=45, ha="right")

        # Apply log scale if data range is large
        all_speeds_for_scale_check = np.concatenate((self_speeds[self_speeds > 0], lib_speeds[lib_speeds > 0]))
        is_log_scale = False
        if len(all_speeds_for_scale_check) > 1 and (np.max(all_speeds_for_scale_check) / np.min(all_speeds_for_scale_check) > 100):
             self.chart_canvas.axes.set_yscale('log')
             self.chart_canvas.axes.set_ylabel("Encryption Speed (MB/s) - Log Scale")
             is_log_scale = True
        else:
            self.chart_canvas.axes.set_yscale('linear') # Ensure linear if not log
            # Adjust y-axis limit for linear scale to make space for labels
            max_val = 0
            if len(self_speeds) > 0: max_val = max(max_val, np.max(self_speeds))
            if len(lib_speeds) > 0: max_val = max(max_val, np.max(lib_speeds))
            if max_val > 0: # Avoid issues if all values are zero
                self.chart_canvas.axes.set_ylim(0, max_val * 1.15) # Add 15% padding at the top


        # Add value labels
        def autolabel(rects, data_values, is_log):
            if rects is None: return
            for i, rect in enumerate(rects):
                height = rect.get_height()
                value_to_display = data_values[i]
                
                # For log scale, position text above the bar carefully if height is small.
                # For linear scale, a small vertical offset is usually fine.
                # Annotation text will be the actual value.
                
                # Adjust y_pos for log scale to avoid labels inside tiny bars
                y_pos = height
                if is_log and height > 0: # Ensure not attempting log of 0 if height is actually 0
                    # Heuristic: if bar is very small on log, put label slightly above its actual height.
                    # This might need tweaking depending on typical data ranges.
                     y_pos = height # For log, annotate at bar top
                elif not is_log:
                     y_pos = height # For linear, annotate at bar top

                # Do not annotate if value is effectively zero, to avoid clutter
                if value_to_display < 0.001 and value_to_display !=0 : # very small non-zero
                     formatted_value = f'{value_to_display:.2e}' # scientific notation for very small
                elif value_to_display == 0 :
                     formatted_value = '0'
                else:
                     formatted_value = f'{value_to_display:.2f}'


                if value_to_display > 0 or (not is_log and value_to_display == 0): # Plot '0' if linear scale
                    self.chart_canvas.axes.annotate(formatted_value,
                                                    xy=(rect.get_x() + rect.get_width() / 2, y_pos),
                                                    xytext=(0, 3),  # 3 points vertical offset
                                                    textcoords="offset points",
                                                    ha='center', va='bottom', fontsize=8,
                                                    rotation=0) # Ensure rotation is 0 for readability

        autolabel(rects1, self_speeds, is_log_scale)
        if rects2:
            autolabel(rects2, lib_speeds, is_log_scale)

        self.chart_canvas.axes.legend()
        self.chart_canvas.fig.tight_layout()
        self.chart_canvas.draw()

    def _plot_decryption_speed(self):
        """Plot decryption speed chart with a logarithmic scale if data varies widely."""
        # TODO: Add value annotations to bars similar to _plot_encryption_speed
        if not self.results_data:
            self.chart_canvas.axes.clear()
            self.chart_canvas.axes.text(0.5, 0.5, "No results data loaded", horizontalalignment='center', verticalalignment='center', transform=self.chart_canvas.axes.transAxes)
            self.chart_canvas.draw()
            return

        plot_data = []
        for lang_name, lang_results in self.results_data.get("results", {}).items():
            grouped_algos = {}
            for algo_key, algo_data in lang_results.items():
                base_algo = algo_key.replace("_custom", "")
                if base_algo not in grouped_algos: grouped_algos[base_algo] = {}
                metrics = algo_data.get("aggregated_metrics", {})
                speed_mb_s = metrics.get("avg_throughput_decrypt_mb_per_s")
                if speed_mb_s is None:
                    speed_bps = metrics.get("avg_decrypt_throughput_bps")
                    speed_mb_s = speed_bps / (8 * 1024 * 1024) if speed_bps is not None else 0
                if "_custom" in algo_key: grouped_algos[base_algo]["custom"] = speed_mb_s
                else: grouped_algos[base_algo]["stdlib"] = speed_mb_s
                grouped_algos[base_algo]["config"] = algo_data.get("configuration", {})
            
            for base_algo, speeds in grouped_algos.items():
                config = speeds.get("config", {})
                display_algo_name = base_algo.upper()
                if "aes" in base_algo.lower() or "camellia" in base_algo.lower(): display_algo_name += f"-{config.get('key_size', '?')}"
                elif "rsa" in base_algo.lower(): display_algo_name += f" {config.get('key_size', '?')}-bit"
                elif "ecc" in base_algo.lower(): display_algo_name += f" ({config.get('mode', '?')})"
                label = f"{lang_name.capitalize()}\\n{display_algo_name}"
                plot_data.append({"label": label, "self": speeds.get("custom", 0), "lib": speeds.get("stdlib", 0)})

        self.chart_canvas.axes.clear()
        if not plot_data:
            self.chart_canvas.axes.text(0.5, 0.5, "No decryption speed data for plotting", horizontalalignment='center', verticalalignment='center', transform=self.chart_canvas.axes.transAxes)
            self.chart_canvas.draw()
            return
            
        labels = [p["label"] for p in plot_data]
        self_speeds = np.array([p["self"] for p in plot_data])
        lib_speeds = np.array([p["lib"] for p in plot_data])

        x = np.arange(len(labels))
        width = 0.35
        
        rects1 = self.chart_canvas.axes.bar(x - width/2, self_speeds, width, label="Self Implementation")
        rects2 = None
        if any(s > 0 for s in lib_speeds):
            rects2 = self.chart_canvas.axes.bar(x + width/2, lib_speeds, width, label="Library Implementation")
        
        self.chart_canvas.axes.set_ylabel("Decryption Speed (MB/s)")
        self.chart_canvas.axes.set_title("Decryption Speed Comparison")
        self.chart_canvas.axes.set_xticks(x)
        self.chart_canvas.axes.set_xticklabels(labels, rotation=45, ha="right")

        all_speeds = np.concatenate((self_speeds[self_speeds > 0], lib_speeds[lib_speeds > 0]))
        if len(all_speeds) > 1 and (np.max(all_speeds) / np.min(all_speeds) > 100):
             self.chart_canvas.axes.set_yscale('log')
             self.chart_canvas.axes.set_ylabel("Decryption Speed (MB/s) - Log Scale")
        else:
            self.chart_canvas.axes.set_yscale('linear')

        # Add value labels
        def autolabel(rects, data_values):
            if rects is None: return
            for i, rect in enumerate(rects):
                height = rect.get_height()
                value_to_display = data_values[i]
                
                # For linear scale, a small vertical offset is usually fine.
                # Annotation text will be the actual value.
                
                # Adjust y_pos for linear scale to avoid labels inside tiny bars
                y_pos = height
                if height > 0: # Avoid issues if all values are zero
                    y_pos = height # For linear, annotate at bar top

                # Do not annotate if value is effectively zero, to avoid clutter
                if value_to_display < 0.001 and value_to_display !=0 : # very small non-zero
                     formatted_value = f'{value_to_display:.2e}' # scientific notation for very small
                elif value_to_display == 0 :
                     formatted_value = '0'
                else:
                     formatted_value = f'{value_to_display:.2f}'


                if value_to_display > 0 or value_to_display == 0: # Plot '0' if linear scale
                    self.chart_canvas.axes.annotate(formatted_value,
                                                    xy=(rect.get_x() + rect.get_width() / 2, y_pos),
                                                    xytext=(0, 3),  # 3 points vertical offset
                                                    textcoords="offset points",
                                                    ha='center', va='bottom', fontsize=8,
                                                    rotation=0) # Ensure rotation is 0 for readability

        autolabel(rects1, self_speeds)
        if rects2:
            autolabel(rects2, lib_speeds)

        self.chart_canvas.axes.legend()
        self.chart_canvas.fig.tight_layout()
        self.chart_canvas.draw()
    
    def _plot_key_generation_time(self):
        """Plot key generation time chart."""
        # TODO: Add value annotations to bars similar to _plot_encryption_speed
        if not self.results_data:
            self.chart_canvas.axes.clear()
            self.chart_canvas.axes.text(0.5, 0.5, "No results data loaded", horizontalalignment='center', verticalalignment='center', transform=self.chart_canvas.axes.transAxes)
            self.chart_canvas.draw()
            return
        
        plot_data = []
        all_positive_times_for_scale_check = []

        for lang_name, lang_results in self.results_data.get("results", {}).items():
            grouped_algos = {}
            for algo_key, algo_data in lang_results.items():
                base_algo = algo_key.replace("_custom", "")
                if base_algo not in grouped_algos:
                    grouped_algos[base_algo] = {}

                metrics = algo_data.get("aggregated_metrics", {})
                time_ms = metrics.get("avg_keygen_wall_time_ms", 0)

                if "_custom" in algo_key:
                    grouped_algos[base_algo]["custom"] = time_ms
                    grouped_algos[base_algo]["config"] = algo_data.get("configuration", {})
                else: # stdlib
                    grouped_algos[base_algo]["stdlib"] = time_ms
                    if "config" not in grouped_algos[base_algo]:
                         grouped_algos[base_algo]["config"] = algo_data.get("configuration", {})
            
            for base_algo, times in grouped_algos.items():
                config = times.get("config", {})
                display_algo_name = base_algo.upper()
                if "aes" in base_algo.lower() or "camellia" in base_algo.lower():
                     display_algo_name += f"-{config.get('key_size', '?')}"
                elif "rsa" in base_algo.lower():
                     display_algo_name += f" {config.get('key_size', '?')}-bit"
                elif "ecc" in base_algo.lower():
                     display_algo_name += f" ({config.get('mode', '?')})"

                label = f"{lang_name.capitalize()}\\n{display_algo_name}"
                
                self_time = times.get("custom", 0)
                lib_time = times.get("stdlib", 0)
                if self_time > 0: all_positive_times_for_scale_check.append(self_time)
                if lib_time > 0: all_positive_times_for_scale_check.append(lib_time)
                
                plot_data.append({
                    "label": label,
                    "self": self_time,
                    "lib": lib_time
                })

        self.chart_canvas.axes.clear()
        if not plot_data:
            self.chart_canvas.axes.text(0.5, 0.5, "No keygen time data for plotting", horizontalalignment='center', verticalalignment='center', transform=self.chart_canvas.axes.transAxes)
            self.chart_canvas.draw()
            return

        labels = [p["label"] for p in plot_data]
        self_times = np.array([p["self"] for p in plot_data])
        lib_times = np.array([p["lib"] for p in plot_data])

        x = np.arange(len(labels))
        width = 0.35
        
        rects1 = self.chart_canvas.axes.bar(x - width/2, self_times, width, label="Self Implementation")
        rects2 = None
        if any(t > 0 for t in lib_times) or any("stdlib" in grouped_algos[base_algo] for lang_res in self.results_data.get("results", {}).values() for base_algo in grouped_algos):
             rects2 = self.chart_canvas.axes.bar(x + width/2, lib_times, width, label="Library Implementation", hatch='//')
        
        self.chart_canvas.axes.set_ylabel("Key Generation Time (ms)")
        self.chart_canvas.axes.set_title("Key Generation Time Comparison")
        self.chart_canvas.axes.set_xticks(x)
        self.chart_canvas.axes.set_xticklabels(labels, rotation=45, ha="right")
        
        is_log_scale = False
        y_axis_label = "Key Generation Time (ms)"
        if len(all_positive_times_for_scale_check) > 1 and (np.max(all_positive_times_for_scale_check) / np.min(all_positive_times_for_scale_check) > 50): # Heuristic for log scale
            self.chart_canvas.axes.set_yscale('log')
            y_axis_label = "Key Generation Time (ms) - Log Scale"
            is_log_scale = True
        else:
            self.chart_canvas.axes.set_yscale('linear')
            max_val = 0
            if len(self_times) > 0: max_val = max(max_val, np.max(self_times))
            if len(lib_times) > 0 and rects2: max_val = max(max_val, np.max(lib_times))
            if max_val > 0:
                self.chart_canvas.axes.set_ylim(0, max_val * 1.15) # Add 15% padding
            else:
                self.chart_canvas.axes.set_ylim(0, 1) # Default if all zero
        self.chart_canvas.axes.set_ylabel(y_axis_label)

        # Add value labels (adapted from _plot_encryption_speed's autolabel)
        def autolabel(rects, data_values, is_log):
            if rects is None: return
            for i, rect in enumerate(rects):
                height = rect.get_height()
                value_to_display = data_values[i]
                
                y_pos = height 
                formatted_value = ""
                if value_to_display < 0.001 and value_to_display !=0:
                     formatted_value = f'{value_to_display:.2e}' 
                elif value_to_display == 0:
                     formatted_value = '0'
                else:
                     # Keygen times can be small, so use more precision
                     formatted_value = f'{value_to_display:.3f}'

                # For log scale, if height is effectively 0 (due to log of small number), 
                # place label near baseline, but this is tricky if actual value isn't 0.
                # The current y_pos = height should work for visible bars.
                # Annotation for 0 on log scale won't show if value is truly 0, which is fine.

                if value_to_display > 0 or (not is_log and value_to_display == 0):
                    self.chart_canvas.axes.annotate(formatted_value,
                                                    xy=(rect.get_x() + rect.get_width() / 2, y_pos),
                                                    xytext=(0, 3),  # 3 points vertical offset
                                                    textcoords="offset points",
                                                    ha='center', va='bottom', fontsize=8,
                                                    rotation=0)

        autolabel(rects1, self_times, is_log_scale)
        if rects2:
            autolabel(rects2, lib_times, is_log_scale)

        self.chart_canvas.axes.legend()
        self.chart_canvas.fig.tight_layout()
        self.chart_canvas.draw()
    
    def _plot_memory_usage(self):
        """Plot memory usage as a radar/polar chart for each algorithm."""
        if not self.results_data:
            self.chart_canvas.axes.clear()
            self.chart_canvas.axes.text(0.5, 0.5, "No results data loaded", transform=self.chart_canvas.axes.transAxes, ha='center', va='center')
            self.chart_canvas.draw()
            return

        plot_data_points = [] 

        for lang_name, lang_results in self.results_data.get("results", {}).items():
            grouped_algos = {}
            for algo_key, algo_data in lang_results.items():
                base_algo = algo_key.replace("_custom", "")
                if base_algo not in grouped_algos: grouped_algos[base_algo] = {}
                metrics = algo_data.get("aggregated_metrics", {})
                mem_info = {
                    "keygen": metrics.get("avg_keygen_peak_rss_mb", 0),
                    "encrypt": metrics.get("avg_encrypt_peak_rss_mb", 0),
                    "decrypt": metrics.get("avg_decrypt_peak_rss_mb", 0)
                }
                if "_custom" in algo_key:
                    grouped_algos[base_algo]["custom"] = mem_info
                else:
                    grouped_algos[base_algo]["stdlib"] = mem_info
                grouped_algos[base_algo]["config"] = algo_data.get("configuration", {})

            for base_algo, mem_values in grouped_algos.items():
                config = mem_values.get("config", {})
                display_algo_name = base_algo.upper()
                if "aes" in base_algo.lower() or "camellia" in base_algo.lower(): display_algo_name += f"-{config.get('key_size', '?')}"
                elif "rsa" in base_algo.lower(): display_algo_name += f" {config.get('key_size', '?')}-bit"
                elif "ecc" in base_algo.lower(): display_algo_name += f" ({config.get('mode', '?')})"
                label = f"{lang_name.capitalize()} {display_algo_name}"
                
                custom_mem = mem_values.get("custom", {"keygen":0, "encrypt":0, "decrypt":0})
                stdlib_mem = mem_values.get("stdlib", {"keygen":0, "encrypt":0, "decrypt":0})
                
                if any(v > 0 for v in custom_mem.values()) or any(v > 0 for v in stdlib_mem.values()):
                    plot_data_points.append({
                        "label": label,
                        "self_keygen": custom_mem["keygen"], "lib_keygen": stdlib_mem["keygen"],
                        "self_encrypt": custom_mem["encrypt"], "lib_encrypt": stdlib_mem["encrypt"],
                        "self_decrypt": custom_mem["decrypt"], "lib_decrypt": stdlib_mem["decrypt"]
                    })
        
        self.chart_canvas.axes.clear()
        if not plot_data_points:
            self.chart_canvas.axes.text(0.5, 0.5, "No memory usage data for plotting", transform=self.chart_canvas.axes.transAxes, ha='center', va='center')
            self.chart_canvas.draw()
            return

        # Reset the axes to use a polar projection
        self.chart_canvas.fig.clear()
        self.chart_canvas.axes = self.chart_canvas.fig.add_subplot(111, polar=True)
        
        # Prepare data for radar chart
        labels = [p["label"] for p in plot_data_points]
        num_vars = len(labels)
        
        # If no data points, handle gracefully
        if num_vars == 0:
            self.chart_canvas.axes.text(0, 0, "No memory usage data for plotting", ha='center', va='center')
            self.chart_canvas.draw()
            return
            
        # Compute angles for each category (algorithm)
        angles = np.linspace(0, 2*np.pi, num_vars, endpoint=False).tolist()
        # Make the plot a full circle
        angles += angles[:1]
        
        # Calculate a reasonable scale for the radar chart
        # Get max memory usage across all categories
        max_memory = 0
        for p in plot_data_points:
            max_memory = max(max_memory, p["self_keygen"], p["self_encrypt"], p["self_decrypt"], 
                             p["lib_keygen"], p["lib_encrypt"], p["lib_decrypt"])
        
        # Cap at 100MB for better visibility
        display_cap = 100
        if max_memory > display_cap:
            max_memory = display_cap
            title = "Memory Usage (MB) - Values > 100MB Capped"
        else:
            title = "Memory Usage (MB)"
            
        # Set minimum reasonable maximum value
        if max_memory < 1:
            max_memory = 1  # At least 1MB to avoid empty chart
        
        # Extract data for each phase
        self_keygen_data = [min(display_cap, p["self_keygen"]) for p in plot_data_points]
        self_encrypt_data = [min(display_cap, p["self_encrypt"]) for p in plot_data_points]
        self_decrypt_data = [min(display_cap, p["self_decrypt"]) for p in plot_data_points]
        
        lib_keygen_data = [min(display_cap, p["lib_keygen"]) for p in plot_data_points]
        lib_encrypt_data = [min(display_cap, p["lib_encrypt"]) for p in plot_data_points]
        lib_decrypt_data = [min(display_cap, p["lib_decrypt"]) for p in plot_data_points]
        
        # Close the loop for each dataset
        self_keygen_data += self_keygen_data[:1]
        self_encrypt_data += self_encrypt_data[:1]
        self_decrypt_data += self_decrypt_data[:1]
        lib_keygen_data += lib_keygen_data[:1]
        lib_encrypt_data += lib_encrypt_data[:1]
        lib_decrypt_data += lib_decrypt_data[:1]
        
        # Create extended labels list that closes the loop
        labels_for_plot = labels + [labels[0]]
        
        # Set up the radar chart
        self.chart_canvas.axes.set_theta_offset(np.pi / 2)  # Start at top
        self.chart_canvas.axes.set_theta_direction(-1)  # Go clockwise
        
        # Plot each phase as a line on the radar
        # Custom implementation lines
        self.chart_canvas.axes.plot(angles, self_keygen_data, 'o-', linewidth=2, label='Self KeyGen', color='#1f77b4')
        self.chart_canvas.axes.plot(angles, self_encrypt_data, 'o-', linewidth=2, label='Self Encrypt', color='#ff7f0e')
        self.chart_canvas.axes.plot(angles, self_decrypt_data, 'o-', linewidth=2, label='Self Decrypt', color='#2ca02c')
        
        # Check if we have any non-zero library data
        has_lib_data = any(v > 0 for v in lib_keygen_data + lib_encrypt_data + lib_decrypt_data)
        if has_lib_data:
            self.chart_canvas.axes.plot(angles, lib_keygen_data, 'o--', linewidth=2, label='Lib KeyGen', color='#d62728')
            self.chart_canvas.axes.plot(angles, lib_encrypt_data, 'o--', linewidth=2, label='Lib Encrypt', color='#9467bd')
            self.chart_canvas.axes.plot(angles, lib_decrypt_data, 'o--', linewidth=2, label='Lib Decrypt', color='#8c564b')
        
        # Fill the area for visibility (with light transparency)
        self.chart_canvas.axes.fill(angles, self_keygen_data, alpha=0.1, color='#1f77b4')
        self.chart_canvas.axes.fill(angles, self_encrypt_data, alpha=0.1, color='#ff7f0e')
        self.chart_canvas.axes.fill(angles, self_decrypt_data, alpha=0.1, color='#2ca02c')
        
        # Set labels at the correct angles
        self.chart_canvas.axes.set_xticks(angles[:-1])  # Exclude the last angle (which is just for closing the loop)
        self.chart_canvas.axes.set_xticklabels(labels, fontsize=8)
        
        # Add legend
        self.chart_canvas.axes.legend(loc='upper right', fontsize='small')
        
        # Adjust the radial ticks for better readability
        yticks = [0, max_memory/4, max_memory/2, 3*max_memory/4, max_memory]
        self.chart_canvas.axes.set_yticks(yticks)
        self.chart_canvas.axes.set_yticklabels([f"{int(tick)}" for tick in yticks], fontsize=8)
        
        # Set limits to ensure proper display
        self.chart_canvas.axes.set_ylim(0, max_memory * 1.1)  # Add a small buffer
        
        # Add gridlines
        self.chart_canvas.axes.grid(True)
        
        # Add title
        self.chart_canvas.fig.suptitle(title, fontsize=12)
        
        # Add annotations for values > display_cap
        for i, p in enumerate(plot_data_points):
            angle = angles[i]
            # Check each phase and add annotation if needed
            phases = [
                ("self_keygen", self_keygen_data[i], '#1f77b4'),
                ("self_encrypt", self_encrypt_data[i], '#ff7f0e'),
                ("self_decrypt", self_decrypt_data[i], '#2ca02c'),
                ("lib_keygen", lib_keygen_data[i] if has_lib_data else 0, '#d62728'),
                ("lib_encrypt", lib_encrypt_data[i] if has_lib_data else 0, '#9467bd'),
                ("lib_decrypt", lib_decrypt_data[i] if has_lib_data else 0, '#8c564b')
            ]
            
            for phase_name, visual_val, color in phases:
                actual_val = p[phase_name]
                if actual_val > display_cap:
                    # Convert polar to cartesian coordinates for text placement
                    x = (visual_val - 10) * np.cos(angle)  # Add small offset inward for visibility
                    y = (visual_val - 10) * np.sin(angle)
                    self.chart_canvas.axes.annotate(f"{int(actual_val)}",
                                                   (x, y), color=color, fontsize=7,
                                                   ha='center', va='center')
        
        self.chart_canvas.fig.tight_layout()
        self.chart_canvas.draw()

    def _plot_cpu_usage(self):
        """Plot CPU usage as a heatmap."""
        if not self.results_data:
            self.chart_canvas.axes.clear()
            self.chart_canvas.axes.text(0.5, 0.5, "No results data loaded", transform=self.chart_canvas.axes.transAxes, ha='center', va='center')
            self.chart_canvas.draw()
            return

        # Prepare data for heatmap
        algorithms = []  # Will contain labels like "C AES-128", "Python RSA 2048-bit", etc.
        cpu_data = []    # Will contain rows of [self_encrypt, self_decrypt, lib_encrypt, lib_decrypt]
        
        for lang_name, lang_results in self.results_data.get("results", {}).items():
            grouped_algos = {}
            for algo_key, algo_data in lang_results.items():
                base_algo = algo_key.replace("_custom", "")
                if base_algo not in grouped_algos: grouped_algos[base_algo] = {}
                metrics = algo_data.get("aggregated_metrics", {})
                impl_type = algo_data.get("implementation_type", "")
                config = algo_data.get("configuration", {})
                
                # Format algorithm display name
                display_algo_name = base_algo.upper()
                if "aes" in base_algo.lower() or "camellia" in base_algo.lower():
                    display_algo_name += f"-{config.get('key_size', '?')}"
                elif "rsa" in base_algo.lower():
                    display_algo_name += f" {config.get('key_size', '?')}-bit"
                elif "ecc" in base_algo.lower():
                    display_algo_name += f" ({config.get('mode', '?')})"
                
                label = f"{lang_name.capitalize()} {display_algo_name} ({impl_type.capitalize()})"
                
                # Get CPU usage data for this algorithm
                encrypt_cpu = metrics.get("avg_encrypt_cpu_percentage", 0)
                decrypt_cpu = metrics.get("avg_decrypt_cpu_percentage", 0)
                
                algorithms.append(label)
                cpu_data.append([encrypt_cpu, decrypt_cpu])
        
        # Reset canvas
        self.chart_canvas.fig.clear()
        self.chart_canvas.axes = self.chart_canvas.fig.add_subplot(111)
        self.chart_canvas.axes.clear()
        
        if not cpu_data:
            self.chart_canvas.axes.text(0.5, 0.5, "No CPU usage data for plotting", transform=self.chart_canvas.axes.transAxes, ha='center', va='center')
            self.chart_canvas.draw()
            return
        
        # Convert data to numpy array for heatmap
        cpu_array = np.array(cpu_data)
        
        # Define column labels
        columns = ["Encrypt", "Decrypt"]
        
        # Create the heatmap
        im = self.chart_canvas.axes.imshow(cpu_array, cmap="YlOrRd", aspect='auto', vmin=0, vmax=100)
        
        # We want to show all ticks and label them
        self.chart_canvas.axes.set_yticks(np.arange(len(algorithms)))
        self.chart_canvas.axes.set_yticklabels(algorithms, fontsize=7)
        self.chart_canvas.axes.set_xticks(np.arange(len(columns)))
        self.chart_canvas.axes.set_xticklabels(columns)
        
        # Add title and labels
        self.chart_canvas.fig.suptitle("CPU Usage Percentage", fontsize=12)
        
        # Add a colorbar
        cbar = self.chart_canvas.fig.colorbar(im, ax=self.chart_canvas.axes, format='%.0f%%')
        
        # Loop over data dimensions and create text annotations with values
        for i in range(len(algorithms)):
            for j in range(len(columns)):
                cpu_value = cpu_array[i, j]
                # Choose text color based on background darkness for readability
                text_color = "white" if cpu_value > 60 else "black"
                self.chart_canvas.axes.text(j, i, f"{cpu_value:.1f}%",
                                          ha="center", va="center", color=text_color, fontsize=8)
        
        # Rotate x-axis labels slightly if needed
        plt.setp(self.chart_canvas.axes.get_xticklabels(), rotation=0)
        
        # Adjust layout
        self.chart_canvas.fig.tight_layout()
        self.chart_canvas.draw()

    def _plot_ciphertext_overhead(self):
        """Plot ciphertext overhead percentage."""
        if not self.results_data: 
            self.chart_canvas.axes.text(0.5, 0.5, "No results data loaded", transform=self.chart_canvas.axes.transAxes, ha='center', va='center')
            self.chart_canvas.draw()
            return

        plot_data = []
        all_positive_overheads_for_scale_check = [] # For log scale heuristic

        for lang_name, lang_results in self.results_data.get("results", {}).items():
            grouped_algos = {}
            for algo_key, algo_data in lang_results.items():
                base_algo = algo_key.replace("_custom", "")
                if base_algo not in grouped_algos: grouped_algos[base_algo] = {}
                metrics = algo_data.get("aggregated_metrics", {})
                # Use absolute value for overhead, as negative overhead is confusing here
                overhead = abs(metrics.get("avg_ciphertext_overhead_percent", 0)) 
                
                if "_custom" in algo_key:
                    grouped_algos[base_algo]["custom"] = overhead
                else:
                    grouped_algos[base_algo]["stdlib"] = overhead
                grouped_algos[base_algo]["config"] = algo_data.get("configuration", {})

            for base_algo, overhead_values in grouped_algos.items():
                config = overhead_values.get("config", {})
                display_algo_name = base_algo.upper()
                if "aes" in base_algo.lower() or "camellia" in base_algo.lower(): display_algo_name += f"-{config.get('key_size', '?')}"
                elif "rsa" in base_algo.lower(): display_algo_name += f" {config.get('key_size', '?')}-bit"
                elif "ecc" in base_algo.lower(): display_algo_name += f" ({config.get('mode', '?')})"
                label = f"{lang_name.capitalize()}\\n{display_algo_name}"
                
                custom_overhead_val = overhead_values.get("custom", 0)
                stdlib_overhead_val = overhead_values.get("stdlib", 0)

                if custom_overhead_val > 0: all_positive_overheads_for_scale_check.append(custom_overhead_val)
                if stdlib_overhead_val > 0: all_positive_overheads_for_scale_check.append(stdlib_overhead_val)

                # Only plot if there is some overhead data (can be zero, but not if both missing)
                # Original condition: if custom_overhead != 0 or stdlib_overhead != 0 or ("custom" in overhead_values) or ("stdlib" in overhead_values):
                # Simpler: always add, let autolabel decide to show '0' if value is 0
                plot_data.append({
                    "label": label,
                    "self": custom_overhead_val,
                    "lib": stdlib_overhead_val
                })
        
        self.chart_canvas.axes.clear() # Clear before checking plot_data
        if not plot_data:
            self.chart_canvas.axes.text(0.5, 0.5, "No ciphertext overhead data available", transform=self.chart_canvas.axes.transAxes, ha='center', va='center')
            self.chart_canvas.draw()
            return

        labels = [p["label"] for p in plot_data]
        self_overhead_abs = np.array([p["self"] for p in plot_data]) # Already abs
        lib_overhead_abs = np.array([p["lib"] for p in plot_data])   # Already abs
        
        x = np.arange(len(labels))
        width = 0.35

        rects1 = self.chart_canvas.axes.bar(x - width/2, self_overhead_abs, width, label='Self Impl. Overhead')
        rects2 = None
        # Plot lib bars if any lib has non-zero overhead OR if there's a "stdlib" entry (even if value is 0)
        # This ensures a bar is plotted for lib if data exists, and autolabel can show '0'.
        if any(algo_key.endswith("stdlib") for lang_res in self.results_data.get("results", {}).values() for algo_key in lang_res):
             rects2 = self.chart_canvas.axes.bar(x + width/2, lib_overhead_abs, width, label='Library Impl. Overhead', hatch='//')

        self.chart_canvas.axes.set_ylabel("Ciphertext Overhead (%)")
        self.chart_canvas.axes.set_title("Average Ciphertext Overhead Percentage (Absolute Values)")
        self.chart_canvas.axes.set_xticks(x)
        self.chart_canvas.axes.set_xticklabels(labels, rotation=45, ha="right")
        
        is_log_scale = False
        if len(all_positive_overheads_for_scale_check) > 1 and (np.max(all_positive_overheads_for_scale_check) / np.min(all_positive_overheads_for_scale_check) > 100):
            self.chart_canvas.axes.set_yscale('log')
            self.chart_canvas.axes.set_ylabel("Ciphertext Overhead (%) - Log Scale (Absolute Values)")
            is_log_scale = True
        else:
            self.chart_canvas.axes.set_yscale('linear')
            max_val = 0
            if len(self_overhead_abs) > 0: max_val = max(max_val, np.max(self_overhead_abs))
            if len(lib_overhead_abs) > 0 and rects2 : max_val = max(max_val, np.max(lib_overhead_abs))
            if max_val > 0:
                 self.chart_canvas.axes.set_ylim(0, max_val * 1.25) # More padding for potential inside labels
            else: # All zeros
                 self.chart_canvas.axes.set_ylim(0, 1) # Avoid empty chart if all are zero


        # Add value labels
        def autolabel(rects, data_values, is_log_s, axis_max_val_for_linear_check):
            if rects is None: return
            font_size = 8
            # Estimate text height in data coordinates (very approximate)
            # This is tricky because figure/axis size isn't fixed in data units here.
            # Use a heuristic: if bar height is less than X times max_val, label outside.
            # Or, more simply, if bar height is very small in absolute terms (e.g. < 1% of y-axis range)
            # For now, use a simpler threshold relative to bar's own height.

            for i, rect in enumerate(rects):
                height = rect.get_height()
                value_to_display = data_values[i]
                
                formatted_value = ""
                if value_to_display < 0.001 and value_to_display !=0:
                     formatted_value = f'{value_to_display:.1e}' # 1 decimal for scientific
                elif value_to_display == 0:
                     formatted_value = '0'
                else:
                     # For larger numbers, fewer decimals might be okay if space is an issue.
                     # For percentages, 1 or 2 decimals usually good.
                     if value_to_display > 10:
                         formatted_value = f'{value_to_display:.1f}' 
                     else:
                         formatted_value = f'{value_to_display:.2f}'
                
                formatted_value += "%" # Add percent sign

                if is_log_s:
                    # For log scale, always label above the bar
                    y_pos = height
                    va = 'bottom'
                    xytext_offset = (0, 3)
                else:
                    # For linear scale, try to label inside if bar is tall enough
                    # Heuristic: if bar height is less than ~10% of axis height, label outside.
                    # axis_max_val_for_linear_check can be 0 if all data is 0
                    min_height_for_internal_label = 0
                    if axis_max_val_for_linear_check > 0 : # Avoid division by zero
                        min_height_for_internal_label = axis_max_val_for_linear_check * 0.07 # 7% of y-axis range

                    if height > min_height_for_internal_label and height > 0: # If bar is reasonably tall
                        y_pos = height / 2 
                        va = 'center'
                        xytext_offset = (0, 0)
                    else: # Bar is too short or zero height
                        y_pos = height
                        va = 'bottom'
                        xytext_offset = (0, 3)
                
                # Only annotate if there's something to show (value > 0, or it's 0 on linear scale)
                if value_to_display > 0 or (not is_log_s and value_to_display == 0):
                    self.chart_canvas.axes.annotate(formatted_value,
                                                    xy=(rect.get_x() + rect.get_width() / 2, y_pos),
                                                    xytext=xytext_offset,
                                                    textcoords="offset points",
                                                    ha='center', va=va, fontsize=font_size,
                                                    rotation=0)

        current_max_val_on_axis = self.chart_canvas.axes.get_ylim()[1]
        autolabel(rects1, self_overhead_abs, is_log_scale, current_max_val_on_axis)
        if rects2: # rects2 might exist even if all lib_overhead_abs are 0
            autolabel(rects2, lib_overhead_abs, is_log_scale, current_max_val_on_axis)

        self.chart_canvas.axes.legend(fontsize='small')
        self.chart_canvas.fig.tight_layout()
        self.chart_canvas.draw()

    def _plot_context_switches(self):
        """Plot context switches for keygen, encryption and decryption phases."""
        # TODO: Add value annotations to bars similar to _plot_encryption_speed (for each bar in the group)
        if not self.results_data:
            self.chart_canvas.axes.text(0.5, 0.5, "No results data loaded", transform=self.chart_canvas.axes.transAxes, ha='center', va='center')
            self.chart_canvas.draw()
            return

        plot_data_points = []
        for lang_name, lang_results in self.results_data.get("results", {}).items():
            grouped_algos = {}
            for algo_key, algo_data in lang_results.items():
                base_algo = algo_key.replace("_custom", "")
                if base_algo not in grouped_algos: grouped_algos[base_algo] = {}
                metrics = algo_data.get("aggregated_metrics", {})
                cs_info = {
                    "keygen": metrics.get("avg_keygen_ctx_switches_total", 0),
                    "encrypt": metrics.get("avg_encrypt_ctx_switches_total", 0),
                    "decrypt": metrics.get("avg_decrypt_ctx_switches_total", 0)
                }
                if "_custom" in algo_key:
                    grouped_algos[base_algo]["custom"] = cs_info
                else:
                    grouped_algos[base_algo]["stdlib"] = cs_info
                grouped_algos[base_algo]["config"] = algo_data.get("configuration", {})

            for base_algo, cs_values in grouped_algos.items():
                config = cs_values.get("config", {})
                display_algo_name = base_algo.upper()
                if "aes" in base_algo.lower() or "camellia" in base_algo.lower(): display_algo_name += f"-{config.get('key_size', '?')}"
                elif "rsa" in base_algo.lower(): display_algo_name += f" {config.get('key_size', '?')}-bit"
                elif "ecc" in base_algo.lower(): display_algo_name += f" ({config.get('mode', '?')})"
                label = f"{lang_name.capitalize()}\\n{display_algo_name}"
                
                custom_cs = cs_values.get("custom", {"keygen":0, "encrypt":0, "decrypt":0})
                stdlib_cs = cs_values.get("stdlib", {"keygen":0, "encrypt":0, "decrypt":0})

                if any(v > 0 for v in custom_cs.values()) or any(v > 0 for v in stdlib_cs.values()):
                    plot_data_points.append({
                        "label": label,
                        "self_keygen": custom_cs["keygen"], "lib_keygen": stdlib_cs["keygen"],
                        "self_encrypt": custom_cs["encrypt"], "lib_encrypt": stdlib_cs["encrypt"],
                        "self_decrypt": custom_cs["decrypt"], "lib_decrypt": stdlib_cs["decrypt"]
                    })
        
        if not plot_data_points:
            self.chart_canvas.axes.text(0.5, 0.5, "No context switch data available", transform=self.chart_canvas.axes.transAxes, ha='center', va='center')
            self.chart_canvas.draw()
            return

        labels = [p["label"] for p in plot_data_points]
        n_groups = len(labels)
        x = np.arange(n_groups)
        bar_width = 0.15

        self_keygen_cs = np.array([p["self_keygen"] for p in plot_data_points])
        self_encrypt_cs = np.array([p["self_encrypt"] for p in plot_data_points])
        self_decrypt_cs = np.array([p["self_decrypt"] for p in plot_data_points])
        lib_keygen_cs = np.array([p["lib_keygen"] for p in plot_data_points])
        lib_encrypt_cs = np.array([p["lib_encrypt"] for p in plot_data_points])
        lib_decrypt_cs = np.array([p["lib_decrypt"] for p in plot_data_points])

        rects1 = self.chart_canvas.axes.bar(x - 2*bar_width, self_keygen_cs, bar_width, label='Self KeyGen CS')
        rects2 = self.chart_canvas.axes.bar(x - bar_width, self_encrypt_cs, bar_width, label='Self Encrypt CS')
        rects3 = self.chart_canvas.axes.bar(x, self_decrypt_cs, bar_width, label='Self Decrypt CS')
        
        has_lib_data = any(val > 0 for val_list in [lib_keygen_cs, lib_encrypt_cs, lib_decrypt_cs] for val in val_list)
        if has_lib_data:
            rects4 = self.chart_canvas.axes.bar(x + bar_width, lib_keygen_cs, bar_width, label='Lib KeyGen CS', hatch='//')
            rects5 = self.chart_canvas.axes.bar(x + 2*bar_width, lib_encrypt_cs, bar_width, label='Lib Encrypt CS', hatch='//')
            rects6 = self.chart_canvas.axes.bar(x + 3*bar_width, lib_decrypt_cs, bar_width, label='Lib Decrypt CS', hatch='//')

        self.chart_canvas.axes.set_ylabel("Avg. Total Context Switches")
        self.chart_canvas.axes.set_title("Average Context Switches by Phase")
        self.chart_canvas.axes.set_xticks(x + bar_width / 2 if has_lib_data else x)
        self.chart_canvas.axes.set_xticklabels(labels, rotation=45, ha="right")
        
        all_cs = np.concatenate([
            self_keygen_cs[self_keygen_cs > 0], self_encrypt_cs[self_encrypt_cs > 0], self_decrypt_cs[self_decrypt_cs > 0],
            lib_keygen_cs[lib_keygen_cs > 0], lib_encrypt_cs[lib_encrypt_cs > 0], lib_decrypt_cs[lib_decrypt_cs > 0]
        ])
        if len(all_cs) > 1 and (np.max(all_cs) / np.min(all_cs) > 50): # Heuristic for context switches
             self.chart_canvas.axes.set_yscale('log')
             self.chart_canvas.axes.set_ylabel("Avg. Total Context Switches - Log Scale")
        else:
            self.chart_canvas.axes.set_yscale('linear')

        # Add value labels
        def autolabel(rects, data_values):
            if rects is None: return
            for i, rect in enumerate(rects):
                height = rect.get_height()
                value_to_display = data_values[i]
                
                # For linear scale, a small vertical offset is usually fine.
                # Annotation text will be the actual value.
                
                # Adjust y_pos for linear scale to avoid labels inside tiny bars
                y_pos = height
                if height > 0: # Avoid issues if all values are zero
                    y_pos = height # For linear, annotate at bar top

                # Do not annotate if value is effectively zero, to avoid clutter
                if value_to_display < 0.001 and value_to_display !=0 : # very small non-zero
                     formatted_value = f'{value_to_display:.2e}' # scientific notation for very small
                elif value_to_display == 0 :
                     formatted_value = '0'
                else:
                     formatted_value = f'{value_to_display:.2f}'


                if value_to_display > 0 or value_to_display == 0: # Plot '0' if linear scale
                    self.chart_canvas.axes.annotate(formatted_value,
                                                    xy=(rect.get_x() + rect.get_width() / 2, y_pos),
                                                    xytext=(0, 3),  # 3 points vertical offset
                                                    textcoords="offset points",
                                                    ha='center', va='bottom', fontsize=8,
                                                    rotation=0) # Ensure rotation is 0 for readability

        autolabel(rects1, self_keygen_cs)
        autolabel(rects2, self_encrypt_cs)
        autolabel(rects3, self_decrypt_cs)
        if has_lib_data:
            autolabel(rects4, lib_keygen_cs)
            autolabel(rects5, lib_encrypt_cs)
            autolabel(rects6, lib_decrypt_cs)

        self.chart_canvas.axes.legend()
        self.chart_canvas.fig.tight_layout()
        self.chart_canvas.draw()

    def _plot_self_vs_library(self):
        """Plot self vs. library comparison chart for encryption and decryption time ratios."""
        # TODO: Add value annotations to bars similar to _plot_encryption_speed
        if not self.results_data:
            self.chart_canvas.axes.clear()
            self.chart_canvas.axes.text(0.5, 0.5, "No results data loaded", horizontalalignment='center', verticalalignment='center', transform=self.chart_canvas.axes.transAxes)
            self.chart_canvas.draw()
            return

        plot_data = [] # List of dicts {"label": "Lang\\nAlgo", "enc_ratio": X, "dec_ratio": Y}

        for lang_name, lang_results in self.results_data.get("results", {}).items():
            grouped_algos = {}
            for algo_key, algo_data in lang_results.items():
                base_algo = algo_key.replace("_custom", "")
                if base_algo not in grouped_algos:
                    grouped_algos[base_algo] = {}
                
                impl_type = algo_data.get("implementation_type")
                metrics = algo_data.get("aggregated_metrics", {})
                if impl_type == "custom":
                    grouped_algos[base_algo]["custom_metrics"] = metrics
                    grouped_algos[base_algo]["config"] = algo_data.get("configuration", {})
                elif impl_type == "stdlib":
                    grouped_algos[base_algo]["stdlib_metrics"] = metrics
                    if "config" not in grouped_algos[base_algo]: # Prefer custom config if available for display
                         grouped_algos[base_algo]["config"] = algo_data.get("configuration", {})
            
            for base_algo, data in grouped_algos.items():
                if "custom_metrics" in data and "stdlib_metrics" in data:
                    custom_m = data["custom_metrics"]
                    stdlib_m = data["stdlib_metrics"]
                    config = data.get("config", {})
                    
                    display_algo_name = base_algo.upper()
                    if "aes" in base_algo.lower() or "camellia" in base_algo.lower():
                         display_algo_name += f"-{config.get('key_size', '?')}"
                    elif "rsa" in base_algo.lower():
                         display_algo_name += f" {config.get('key_size', '?')}-bit"
                    elif "ecc" in base_algo.lower():
                         display_algo_name += f" ({config.get('mode', '?')})"

                    label = f"{lang_name.capitalize()}\\n{display_algo_name}"
                    
                    self_enc_time = custom_m.get("avg_encrypt_wall_time_ms", 0)
                    lib_enc_time = stdlib_m.get("avg_encrypt_wall_time_ms", 0)
                    self_dec_time = custom_m.get("avg_decrypt_wall_time_ms", 0)
                    lib_dec_time = stdlib_m.get("avg_decrypt_wall_time_ms", 0)

                    enc_ratio = (self_enc_time / lib_enc_time) if lib_enc_time and self_enc_time else 0
                    dec_ratio = (self_dec_time / lib_dec_time) if lib_dec_time and self_dec_time else 0
                    
                    plot_data.append({
                        "label": label,
                        "enc_ratio": enc_ratio,
                        "dec_ratio": dec_ratio
                    })

        self.chart_canvas.axes.clear()
        if not plot_data:
            self.chart_canvas.axes.text(0.5, 0.5, "No comparison data (custom vs stdlib)", horizontalalignment='center', verticalalignment='center', transform=self.chart_canvas.axes.transAxes)
            self.chart_canvas.draw()
            return

        labels = [p["label"] for p in plot_data]
        enc_ratios = [p["enc_ratio"] for p in plot_data]
        dec_ratios = [p["dec_ratio"] for p in plot_data]
        
        x = np.arange(len(labels))
        width = 0.35
        
        rects1 = self.chart_canvas.axes.bar(x - width/2, enc_ratios, width, label="Encryption Time (Self/Lib)")
        rects2 = self.chart_canvas.axes.bar(x + width/2, dec_ratios, width, label="Decryption Time (Self/Lib)")
        
        self.chart_canvas.axes.set_ylabel("Performance Ratio (Self Time / Library Time)")
        self.chart_canvas.axes.set_title("Self vs. Library Performance Ratio")
        self.chart_canvas.axes.set_xticks(x)
        self.chart_canvas.axes.set_xticklabels(labels, rotation=45, ha="right")
        self.chart_canvas.axes.axhline(y=1, color='r', linestyle='--', label="Library Baseline (Ratio=1)")
        self.chart_canvas.axes.legend()

        # Add value labels
        def autolabel(rects, data_values):
            if rects is None: return
            for i, rect in enumerate(rects):
                height = rect.get_height()
                value_to_display = data_values[i]
                
                # For linear scale, a small vertical offset is usually fine.
                # Annotation text will be the actual value.
                
                # Adjust y_pos for linear scale to avoid labels inside tiny bars
                y_pos = height
                if height > 0: # Avoid issues if all values are zero
                    y_pos = height # For linear, annotate at bar top

                # Do not annotate if value is effectively zero, to avoid clutter
                if value_to_display < 0.001 and value_to_display !=0 : # very small non-zero
                     formatted_value = f'{value_to_display:.2e}' # scientific notation for very small
                elif value_to_display == 0 :
                     formatted_value = '0'
                else:
                     formatted_value = f'{value_to_display:.2f}'


                if value_to_display > 0 or value_to_display == 0: # Plot '0' if linear scale
                    self.chart_canvas.axes.annotate(formatted_value,
                                                    xy=(rect.get_x() + rect.get_width() / 2, y_pos),
                                                    xytext=(0, 3),  # 3 points vertical offset
                                                    textcoords="offset points",
                                                    ha='center', va='bottom', fontsize=8,
                                                    rotation=0) # Ensure rotation is 0 for readability

        autolabel(rects1, enc_ratios)
        autolabel(rects2, dec_ratios)

        self.chart_canvas.axes.legend()
        self.chart_canvas.fig.tight_layout()
        self.chart_canvas.draw()
    
    def _export_results(self):
        """Export results to PDF and optionally charts as separate files."""
        if not self.results_data or not self.current_session:
            return
        
        # Get export options from UI
        include_charts_in_pdf = self.include_charts_checkbox.isChecked()
        export_charts_separately = self.export_charts_checkbox.isChecked()
        
        # Open file dialog for PDF
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            os.path.join(self.current_session, "report.pdf"),
            "PDF Files (*.pdf)"
        )
        
        if not file_path:
            return
        
        # Create PDF document
        doc = SimpleDocTemplate(
            file_path,
            pagesize=landscape(letter),
            rightMargin=30,
            leftMargin=30,
            topMargin=30,
            bottomMargin=30
        )
        
        # Create styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            alignment=TA_CENTER
        )
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=8,
            alignment=TA_LEFT
        )
        
        # Create content
        content = []
        
        # Add title
        content.append(Paragraph("CryptoBench Pro - Benchmark Results", title_style))
        content.append(Spacer(1, 0.2 * inch))
        
        # Add session information
        content.append(Paragraph("Session Information", heading_style))
        content.append(Spacer(1, 0.1 * inch))
        
        # Get session info from config
        config = self.results_data["config"]
        session_info = []
        
        # Session timestamp
        if "session_info" in config:
            if "human_timestamp" in config["session_info"]:
                session_info.append(["Session Date:", config["session_info"]["human_timestamp"]])
            elif "timestamp" in config["session_info"]:
                timestamp = config["session_info"]["timestamp"]
                try:
                    dt = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
                    session_info.append(["Session Date:", dt.strftime("%Y-%m-%d %H:%M:%S")])
                except ValueError:
                    session_info.append(["Session:", timestamp])
        
        # Languages
        if "languages" in config:
            languages = [lang for lang, enabled in config["languages"].items() if enabled]
            session_info.append(["Languages:", ", ".join(languages)])
        
        # Encryption methods
        if "encryption_methods" in config:
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
            
            session_info.append(["Encryption Methods:", ", ".join(methods)])
        
        # Test parameters
        if "test_parameters" in config:
            test_params = config["test_parameters"]
            if "ram_limit" in test_params:
                session_info.append(["RAM Limit:", test_params["ram_limit"]])
            if "iterations" in test_params:
                session_info.append(["Iterations:", test_params["iterations"]])
            if "processing_strategy" in test_params:
                session_info.append(["Processing Strategy:", test_params["processing_strategy"]])
                if test_params["processing_strategy"] == "Stream" and "chunk_size" in test_params:
                    session_info.append(["Chunk Size:", test_params["chunk_size"]])
        
        # Add session info table
        session_table = Table(session_info, colWidths=[2*inch, 4*inch])
        session_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        content.append(session_table)
        content.append(Spacer(1, 0.2 * inch))
        
        # Add results by programming language
        content.append(Paragraph("Results by Programming Language", heading_style))
        content.append(Spacer(1, 0.1 * inch))
        
        # Process results by language
        for language, language_data in self.results_data["results"].items():
            content.append(Paragraph(f"{language.capitalize()} Results", heading_style))
            content.append(Spacer(1, 0.1 * inch))
            
            # Create table data
            table_data = [["Algorithm", "Encryption Time (ms)", "Decryption Time (ms)", "Key Gen Time (ms)"]]
            
            # Track best values for highlighting
            best_encryption = float('inf')
            best_decryption = float('inf')
            best_keygen = float('inf')
            best_encryption_idx = -1
            best_decryption_idx = -1
            best_keygen_idx = -1
            
            # Add data rows
            row_idx = 1
            for algorithm, data in language_data.items():
                if "self_implementation" in data:
                    impl_data = data["self_implementation"]
                    
                    # Get average times
                    enc_time = 0
                    dec_time = 0
                    keygen_time = 0
                    
                    if "encryption_times" in impl_data:
                        times = impl_data["encryption_times"]
                        enc_time = sum(times) / len(times) * 1000 if times else 0
                    
                    if "decryption_times" in impl_data:
                        times = impl_data["decryption_times"]
                        dec_time = sum(times) / len(times) * 1000 if times else 0
                    
                    if "key_generation_time" in impl_data:
                        keygen_time = impl_data["key_generation_time"] * 1000
                    
                    # Add row
                    table_data.append([algorithm.upper(), f"{enc_time:.2f}", f"{dec_time:.2f}", f"{keygen_time:.2f}"])
                    
                    # Check if this is the best
                    if enc_time > 0 and enc_time < best_encryption:
                        best_encryption = enc_time
                        best_encryption_idx = row_idx
                    
                    if dec_time > 0 and dec_time < best_decryption:
                        best_decryption = dec_time
                        best_decryption_idx = row_idx
                    
                    if keygen_time > 0 and keygen_time < best_keygen:
                        best_keygen = keygen_time
                        best_keygen_idx = row_idx
                    
                    row_idx += 1
            
            # Create table
            table = Table(table_data, colWidths=[2*inch, 1.5*inch, 1.5*inch, 1.5*inch])
            
            # Create table style
            table_style = [
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('ALIGN', (1, 1), (-1, -1), 'RIGHT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]
            
            # Highlight best values
            if best_encryption_idx > 0:
                table_style.append(('BACKGROUND', (1, best_encryption_idx), (1, best_encryption_idx), colors.lightgreen))
            
            if best_decryption_idx > 0:
                table_style.append(('BACKGROUND', (2, best_decryption_idx), (2, best_decryption_idx), colors.lightgreen))
            
            if best_keygen_idx > 0:
                table_style.append(('BACKGROUND', (3, best_keygen_idx), (3, best_keygen_idx), colors.lightgreen))
            
            table.setStyle(TableStyle(table_style))
            content.append(table)
            content.append(Spacer(1, 0.2 * inch))
        
        # Add results by encryption method
        content.append(Paragraph("Results by Encryption Method", heading_style))
        content.append(Spacer(1, 0.1 * inch))
        
        # Collect all algorithms
        algorithms = set()
        for language_data in self.results_data["results"].values():
            algorithms.update(language_data.keys())
        
        # Process results by algorithm
        for algorithm in sorted(algorithms):
            content.append(Paragraph(f"{algorithm.upper()} Results", heading_style))
            content.append(Spacer(1, 0.1 * inch))
            
            # Create table data
            table_data = [["Language", "Encryption Time (ms)", "Decryption Time (ms)", "Key Gen Time (ms)"]]
            
            # Track best values for highlighting
            best_encryption = float('inf')
            best_decryption = float('inf')
            best_keygen = float('inf')
            best_encryption_idx = -1
            best_decryption_idx = -1
            best_keygen_idx = -1
            
            # Add data rows
            row_idx = 1
            for language, language_data in self.results_data["results"].items():
                if algorithm in language_data and "self_implementation" in language_data[algorithm]:
                    data = language_data[algorithm]
                    impl_data = data["self_implementation"]
                    
                    # Get average times
                    enc_time = 0
                    dec_time = 0
                    keygen_time = 0
                    
                    if "encryption_times" in impl_data:
                        times = impl_data["encryption_times"]
                        enc_time = sum(times) / len(times) * 1000 if times else 0
                    
                    if "decryption_times" in impl_data:
                        times = impl_data["decryption_times"]
                        dec_time = sum(times) / len(times) * 1000 if times else 0
                    
                    if "key_generation_time" in impl_data:
                        keygen_time = impl_data["key_generation_time"] * 1000
                    
                    # Add row
                    table_data.append([language.capitalize(), f"{enc_time:.2f}", f"{dec_time:.2f}", f"{keygen_time:.2f}"])
                    
                    # Check if this is the best
                    if enc_time > 0 and enc_time < best_encryption:
                        best_encryption = enc_time
                        best_encryption_idx = row_idx
                    
                    if dec_time > 0 and dec_time < best_decryption:
                        best_decryption = dec_time
                        best_decryption_idx = row_idx
                    
                    if keygen_time > 0 and keygen_time < best_keygen:
                        best_keygen = keygen_time
                        best_keygen_idx = row_idx
                    
                    row_idx += 1
            
            # Create table
            table = Table(table_data, colWidths=[2*inch, 1.5*inch, 1.5*inch, 1.5*inch])
            
            # Create table style
            table_style = [
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('ALIGN', (1, 1), (-1, -1), 'RIGHT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]
            
            # Highlight best values
            if best_encryption_idx > 0:
                table_style.append(('BACKGROUND', (1, best_encryption_idx), (1, best_encryption_idx), colors.lightgreen))
            
            if best_decryption_idx > 0:
                table_style.append(('BACKGROUND', (2, best_decryption_idx), (2, best_decryption_idx), colors.lightgreen))
            
            if best_keygen_idx > 0:
                table_style.append(('BACKGROUND', (3, best_keygen_idx), (3, best_keygen_idx), colors.lightgreen))
            
            table.setStyle(TableStyle(table_style))
            content.append(table)
            content.append(Spacer(1, 0.2 * inch))
        
        # Add self vs. library comparison
        content.append(Paragraph("Self vs. Library Implementation Comparison", heading_style))
        content.append(Spacer(1, 0.1 * inch))
        
        # Create table data
        table_data = [["Language", "Algorithm", "Self Enc. Time (ms)", "Lib Enc. Time (ms)", "Self/Lib Ratio", "Self Dec. Time (ms)", "Lib Dec. Time (ms)"]]
        
        # Add data rows
        for language, algorithms in self.results_data["results"].items():
            for algorithm, data in algorithms.items():
                # Only add rows if both implementations are available
                if "self_implementation" in data and "library_implementation" in data:
                    self_impl = data["self_implementation"]
                    lib_impl = data["library_implementation"]
                    
                    # Get average times
                    self_enc_time = 0
                    lib_enc_time = 0
                    self_dec_time = 0
                    lib_dec_time = 0
                    
                    if "encryption_times" in self_impl:
                        times = self_impl["encryption_times"]
                        self_enc_time = sum(times) / len(times) * 1000 if times else 0
                    
                    if "encryption_times" in lib_impl:
                        times = lib_impl["encryption_times"]
                        lib_enc_time = sum(times) / len(times) * 1000 if times else 0
                    
                    if "decryption_times" in self_impl:
                        times = self_impl["decryption_times"]
                        self_dec_time = sum(times) / len(times) * 1000 if times else 0
                    
                    if "decryption_times" in lib_impl:
                        times = lib_impl["decryption_times"]
                        lib_dec_time = sum(times) / len(times) * 1000 if times else 0
                    
                    # Calculate ratio
                    ratio = "N/A"
                    if lib_enc_time > 0:
                        ratio = f"{self_enc_time / lib_enc_time:.2f}x"
                    
                    # Add row
                    table_data.append([
                        language.capitalize(),
                        algorithm.upper(),
                        f"{self_enc_time:.2f}",
                        f"{lib_enc_time:.2f}",
                        ratio,
                        f"{self_dec_time:.2f}",
                        f"{lib_dec_time:.2f}"
                    ])
        
        # Create table
        table = Table(table_data, colWidths=[1.2*inch, 1.2*inch, 1.2*inch, 1.2*inch, 1.2*inch, 1.2*inch, 1.2*inch])
        
        # Create table style
        table_style = [
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('ALIGN', (1, 1), (-1, -1), 'RIGHT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]
        
        table.setStyle(TableStyle(table_style))
        content.append(table)
        content.append(Spacer(1, 0.2 * inch))
        
        # Add charts if requested
        if include_charts_in_pdf:
            content.append(Paragraph("Performance Charts", heading_style))
            content.append(Spacer(1, 0.1 * inch))
            
            # Generate and add charts
            chart_types = [
                "Encryption Speed",
                "Decryption Speed",
                "Key Generation Time",
                "Memory Usage",
                "Self vs. Library Comparison"
            ]
            
            for chart_type in chart_types:
                # Save current chart type
                current_chart = self.chart_combo.currentText()
                
                # Set chart type
                self.chart_combo.setCurrentText(chart_type)
                
                # Update chart
                self._update_chart()
                
                # Save chart to buffer
                buf = BytesIO()
                self.chart_canvas.fig.savefig(buf, format='png', dpi=300, bbox_inches='tight')
                buf.seek(0)
                
                # Add chart to PDF
                content.append(Paragraph(chart_type, heading_style))
                content.append(Spacer(1, 0.1 * inch))
                
                img = Image(buf, width=7*inch, height=4*inch)
                content.append(img)
                content.append(Spacer(1, 0.2 * inch))
                
                # Restore original chart
                self.chart_combo.setCurrentText(current_chart)
                self._update_chart()
        
        # Build PDF
        doc.build(content)
        
        # Export charts separately if requested
        if export_charts_separately:
            # Create charts directory
            charts_dir = os.path.join(os.path.dirname(file_path), "charts")
            os.makedirs(charts_dir, exist_ok=True)
            
            # Save current chart type
            current_chart = self.chart_combo.currentText()
            
            # Export each chart
            for chart_type in [
                "Encryption Speed",
                "Decryption Speed",
                "Key Generation Time",
                "Memory Usage",
                "Self vs. Library Comparison"
            ]:
                # Set chart type
                self.chart_combo.setCurrentText(chart_type)
                
                # Update chart
                self._update_chart()
                
                # Save chart
                chart_path = os.path.join(charts_dir, f"{chart_type.lower().replace(' ', '_')}.png")
                self.chart_canvas.fig.savefig(chart_path, format='png', dpi=300, bbox_inches='tight')
            
            # Restore original chart
            self.chart_combo.setCurrentText(current_chart)
            self._update_chart()
        
            self.status_message.emit(f"Results exported to {file_path}") 