"""
CryptoBench Pro - Environment Check Tab
Allows users to check if their system has the necessary tools and libraries.
"""

import os
import sys
import platform
import shutil
import subprocess
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
    QPushButton, QLabel, QProgressBar, QTextEdit,
    QScrollArea, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, pyqtSlot
from PyQt6.QtGui import QColor, QTextCharFormat, QFont


class EnvironmentCheckWorker(QThread):
    """Worker thread for environment checking."""
    
    progress_updated = pyqtSignal(int, str)
    item_result = pyqtSignal(str, bool, str)
    finished = pyqtSignal()
    
    def __init__(self):
        super().__init__()
        self.is_canceled = False
    
    def run(self):
        """Run the environment checks."""
        try:
            # Set up environment checks (total number of checks)
            total_checks = 9  # Updated to include PyPy and Python packages checks
            current_check = 1
            
            # Check Python
            self._check_python(current_check, total_checks)
            if self.is_canceled:
                return
            current_check += 1
            
            # Check PyPy
            self._check_pypy(current_check, total_checks)
            if self.is_canceled:
                return
            current_check += 1
            
            # Check Python packages
            self._check_python_packages(current_check, total_checks)
            if self.is_canceled:
                return
            current_check += 1
            
            # Check C compiler
            self._check_c_compiler(current_check, total_checks)
            if self.is_canceled:
                return
            current_check += 1
            
            # Check Rust
            self._check_rust(current_check, total_checks)
            if self.is_canceled:
                return
            current_check += 1
            
            # Check Go
            self._check_go(current_check, total_checks)
            if self.is_canceled:
                return
            current_check += 1
            
            # Check Java tools
            self._check_java_tools(current_check, total_checks)
            if self.is_canceled:
                return
            current_check += 1
            
            # Check Zig tools
            self._check_zig_tools(current_check, total_checks)
            if self.is_canceled:
                return
            current_check += 1
            
            # Check CPU information
            self._check_cpu_info(current_check, total_checks)
            if self.is_canceled:
                return
            current_check += 1
            
            # Emit finished signal
            self.finished.emit()
            
        except Exception as e:
            self.item_result.emit("Error running checks", False, str(e))
            self.finished.emit()
    
    def cancel(self):
        """Cancel the checking process."""
        self.is_canceled = True
    
    def _check_python(self, current_check, total_checks):
        """Check Python version and details."""
        item_name = "Python Version"
        self.progress_updated.emit(
            int((current_check / total_checks) * 100),
            f"Checking {item_name}..."
        )
        
        # Get Python version and implementation
        version = sys.version.split()[0]
        implementation = platform.python_implementation()
        major, minor, _ = version.split(".")
        
        # Get Python executable path
        python_path = sys.executable
        
        # Check if version is at least 3.9
        if int(major) >= 3 and int(minor) >= 9:
            self.item_result.emit(
                item_name,
                True,
                f"{implementation} {version} at {python_path} (recommended: 3.9+)"
            )
        else:
            self.item_result.emit(
                item_name,
                False,
                f"{implementation} {version} at {python_path} - Version 3.9+ is recommended for optimal performance"
            )
    
    def _check_pypy(self, current_check, total_checks):
        """Check PyPy version."""
        item_name = "PyPy Version"
        self.progress_updated.emit(
            int((current_check / total_checks) * 100),
            f"Checking {item_name}..."
        )
        
        # Check if pypy is available
        pypy_path = shutil.which("pypy")
        pypy3_path = shutil.which("pypy3")
        
        if pypy_path or pypy3_path:
            try:
                # Try pypy3 first, then pypy
                cmd = "pypy3" if pypy3_path else "pypy"
                result = subprocess.run(
                    [cmd, "--version"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                version_info = result.stderr.strip() if result.stderr else result.stdout.strip()
                self.item_result.emit(
                    item_name,
                    True,
                    f"PyPy is installed: {version_info} (recommended for Python encryption performance)"
                )
            except subprocess.SubprocessError:
                self.item_result.emit(
                    item_name,
                    False,
                    "PyPy is installed but failed to get version"
                )
        else:
            self.item_result.emit(
                item_name,
                False,
                "PyPy not found (optional, recommended for faster Python encryption implementations)"
            )
    
    def _check_python_packages(self, current_check, total_checks):
        """Check Python encryption packages."""
        item_name = "Python Crypto Packages"
        self.progress_updated.emit(
            int((current_check / total_checks) * 100),
            f"Checking {item_name}..."
        )
        
        # Check for encryption-related packages
        crypto_packages = {
            "cryptography": "Modern cryptographic library",
            "pycryptodome": "Cryptographic library (alternative to PyCrypto)",
            "pynacl": "Python binding to NaCl library",
            "pyopenssl": "Python wrapper for OpenSSL"
        }
        
        installed_packages = []
        missing_packages = []
        
        for package, description in crypto_packages.items():
            try:
                __import__(package)
                installed_packages.append(f"{package} ({description})")
            except ImportError:
                missing_packages.append(package)
        
        if installed_packages:
            status_msg = f"Installed: {'; '.join(installed_packages)}"
            if missing_packages:
                status_msg += f" | Missing: {', '.join(missing_packages)}"
            
            # Consider it successful if at least cryptography is installed
            has_cryptography = any("cryptography" in pkg for pkg in installed_packages)
            self.item_result.emit(
                item_name,
                has_cryptography,
                status_msg
            )
        else:
            self.item_result.emit(
                item_name,
                False,
                f"No crypto packages found. Install: {', '.join(crypto_packages.keys())}"
            )
    
    def _check_c_compiler(self, current_check, total_checks):
        """Check C compiler."""
        item_name = "C Compiler"
        self.progress_updated.emit(
            int((current_check / total_checks) * 100),
            f"Checking {item_name}..."
        )
        
        # Check if gcc or clang is available
        gcc_path = shutil.which("gcc")
        clang_path = shutil.which("clang")
        
        if gcc_path:
            try:
                # Get gcc version
                result = subprocess.run(
                    ["gcc", "--version"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                version = result.stdout.split("\n")[0]
                self.item_result.emit(
                    item_name,
                    True,
                    f"GCC is installed: {version}"
                )
            except subprocess.SubprocessError:
                self.item_result.emit(
                    item_name,
                    False,
                    "GCC is installed but failed to get version"
                )
        elif clang_path:
            try:
                # Get clang version
                result = subprocess.run(
                    ["clang", "--version"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                version = result.stdout.split("\n")[0]
                self.item_result.emit(
                    item_name,
                    True,
                    f"Clang is installed: {version}"
                )
            except subprocess.SubprocessError:
                self.item_result.emit(
                    item_name,
                    False,
                    "Clang is installed but failed to get version"
                )
        else:
            self.item_result.emit(
                item_name,
                False,
                "No C compiler found (gcc or clang required)"
            )
    
    def _check_rust(self, current_check, total_checks):
        """Check Rust compiler."""
        item_name = "Rust Compiler"
        self.progress_updated.emit(
            int((current_check / total_checks) * 100),
            f"Checking {item_name}..."
        )
        
        # Check if rustc is available
        rustc_path = shutil.which("rustc")
        
        if rustc_path:
            try:
                # Get rustc version
                result = subprocess.run(
                    ["rustc", "--version"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                version = result.stdout.strip()
                self.item_result.emit(
                    item_name,
                    True,
                    f"Rust is installed: {version}"
                )
            except subprocess.SubprocessError:
                self.item_result.emit(
                    item_name,
                    False,
                    "Rust is installed but failed to get version"
                )
        else:
            self.item_result.emit(
                item_name,
                False,
                "Rust compiler not found (optional, required for Rust implementations)"
            )
    
    def _check_go(self, current_check, total_checks):
        """Check Go compiler."""
        item_name = "Go Compiler"
        self.progress_updated.emit(
            int((current_check / total_checks) * 100),
            f"Checking {item_name}..."
        )
        
        # Check if go is available
        go_path = shutil.which("go")
        
        if go_path:
            try:
                # Get go version
                result = subprocess.run(
                    ["go", "version"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                version = result.stdout.strip()
                self.item_result.emit(
                    item_name,
                    True,
                    f"Go is installed: {version}"
                )
            except subprocess.SubprocessError:
                self.item_result.emit(
                    item_name,
                    False,
                    "Go is installed but failed to get version"
                )
        else:
            self.item_result.emit(
                item_name,
                False,
                "Go compiler not found (optional, required for Go implementations)"
            )
    
    def _check_java_tools(self, current_check, total_checks):
        """Check Java tools."""
        item_name = "Java Tools"
        self.progress_updated.emit(
            int((current_check / total_checks) * 100),
            f"Checking {item_name}..."
        )
        
        # Check for Java
        java_path = shutil.which("java")
        javac_path = shutil.which("javac")
        
        if java_path and javac_path:
            try:
                # Get Java version
                result = subprocess.run(
                    ["java", "--version"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                version = result.stdout.split("\n")[0]
                self.item_result.emit(
                    item_name,
                    True,
                    f"Java is installed: {version}"
                )
            except subprocess.SubprocessError:
                self.item_result.emit(
                    item_name,
                    False,
                    "Java is installed but failed to get version"
                )
        else:
            self.item_result.emit(
                item_name,
                False,
                "Java tools not found (required for Java implementations)"
            )
    
    def _check_zig_tools(self, current_check, total_checks):
        """Check Zig tools."""
        item_name = "Zig Compiler"
        self.progress_updated.emit(
            int((current_check / total_checks) * 100),
            f"Checking {item_name}..."
        )
        
        # Check for Zig compiler
        zig_path = shutil.which("zig")
        
        if zig_path:
            try:
                # Get Zig version
                result = subprocess.run(
                    ["zig", "version"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                version = result.stdout.strip()
                self.item_result.emit(
                    item_name,
                    True,
                    f"Zig is installed: {version}"
                )
            except subprocess.SubprocessError:
                self.item_result.emit(
                    item_name,
                    False,
                    "Zig is installed but failed to get version"
                )
        else:
            self.item_result.emit(
                item_name,
                False,
                "Zig compiler not found (required for Zig implementations)"
            )
    
    def _check_cpu_info(self, current_check, total_checks):
        """Check CPU capabilities."""
        item_name = "CPU Capabilities"
        self.progress_updated.emit(
            int((current_check / total_checks) * 100),
            f"Checking {item_name}..."
        )
        
        try:
            import cpuinfo
            info = cpuinfo.get_cpu_info()
            
            cpu_name = info.get('brand_raw', info.get('brand', 'Unknown CPU'))
            flags = info.get('flags', [])
            
            # Check for crypto-relevant CPU features
            crypto_features = []
            
            if 'aes' in flags:
                crypto_features.append('AES-NI')
            if 'pclmulqdq' in flags:
                crypto_features.append('PCLMULQDQ')
            if 'sha' in flags:
                crypto_features.append('SHA')
            if 'sse4_1' in flags and 'sse4_2' in flags:
                crypto_features.append('SSE4')
            if 'avx' in flags:
                crypto_features.append('AVX')
            if 'avx2' in flags:
                crypto_features.append('AVX2')
            
            if crypto_features:
                self.item_result.emit(
                    item_name,
                    True,
                    f"{cpu_name} with hardware crypto acceleration: {', '.join(crypto_features)}"
                )
            else:
                self.item_result.emit(
                    item_name,
                    True,
                    f"{cpu_name} (no specific crypto acceleration detected)"
                )
            
        except ImportError:
            # Fallback if cpuinfo is not available
            cpu_info = platform.processor()
            if not cpu_info:
                cpu_info = "Unknown CPU"
            
            self.item_result.emit(
                item_name,
                True,
                f"{cpu_info} (detailed capabilities check requires py-cpuinfo package)"
            )


class EnvironmentTab(QWidget):
    """Environment Check tab widget."""
    
    status_message = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        
        # Initialize member variables
        self.worker = None
        
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
        
        # Environment check group
        check_group = QGroupBox("Environment Check")
        check_layout = QVBoxLayout()
        
        # Instructions label
        instructions_label = QLabel(
            "Check if your system has the necessary tools and libraries for CryptoBench Pro. "
            "Items marked with ✓ are ready. Items marked with ⚠️ may need attention."
        )
        instructions_label.setWordWrap(True)
        check_layout.addWidget(instructions_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        check_layout.addWidget(self.progress_bar)
        
        # Current check label
        self.current_check_label = QLabel("Ready to check environment")
        check_layout.addWidget(self.current_check_label)
        
        # Results text area
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setMinimumHeight(300)
        check_layout.addWidget(self.results_text)
        
        # Check button
        self.check_button = QPushButton("Check Environment")
        check_layout.addWidget(self.check_button)
        
        # Set layout for check group
        check_group.setLayout(check_layout)
        
        # Add groups to scroll layout
        scroll_layout.addWidget(check_group)
        
        # Add spacing
        scroll_layout.addStretch()
        
        # Set the scroll content and add to main layout
        scroll_area.setWidget(scroll_content)
        main_layout.addWidget(scroll_area)
        
        # Connect signals
        self._connect_signals()
    
    def _connect_signals(self):
        """Connect signals to slots."""
        # Button signals
        self.check_button.clicked.connect(self._check_environment)
    
    def _check_environment(self):
        """Check environment for required tools and libraries."""
        # Check if a worker is already running
        if self.worker and self.worker.isRunning():
            # Stop the current worker
            self.worker.cancel()
            self.worker.wait()
            self.progress_bar.setValue(0)
            self.current_check_label.setText("Environment check canceled")
            self.check_button.setText("Check Environment")
            self.status_message.emit("Environment check canceled")
            return
        
        # Clear results
        self.results_text.clear()
        
        # Create worker thread
        self.worker = EnvironmentCheckWorker()
        
        # Connect signals
        self.worker.progress_updated.connect(self._update_progress)
        self.worker.item_result.connect(self._add_item_result)
        self.worker.finished.connect(self._check_finished)
        
        # Update UI
        self.progress_bar.setValue(0)
        self.current_check_label.setText("Starting environment check...")
        self.check_button.setText("Cancel Check")
        self.status_message.emit("Checking environment...")
        
        # Start worker
        self.worker.start()
    
    @pyqtSlot(int, str)
    def _update_progress(self, value, message):
        """Update progress bar value and message."""
        self.progress_bar.setValue(value)
        self.current_check_label.setText(message)
    
    @pyqtSlot(str, bool, str)
    def _add_item_result(self, item_name, status, message):
        """Add result for an item to the results text."""
        cursor = self.results_text.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        
        # Create a character format for the item name
        name_format = QTextCharFormat()
        name_format.setFontWeight(QFont.Weight.Bold)
        
        # Create a character format for the status
        status_format = QTextCharFormat()
        status_format.setFontWeight(QFont.Weight.Bold)
        
        if status:
            status_text = "✓"
            status_format.setForeground(QColor("green"))
        else:
            status_text = "⚠️"
            status_format.setForeground(QColor("orange"))
        
        # Set cursor and formats
        self.results_text.setTextCursor(cursor)
        
        # Insert item name
        cursor.insertText(f"{item_name}: ", name_format)
        
        # Insert status
        cursor.insertText(f"{status_text} ", status_format)
        
        # Insert message
        cursor.insertText(f"{message}\n\n")
    
    @pyqtSlot()
    def _check_finished(self):
        """Handle environment check finished."""
        # Update UI
        self.progress_bar.setValue(100)
        self.current_check_label.setText("Environment check completed")
        self.check_button.setText("Check Environment")
        
        # Add summary
        cursor = self.results_text.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        
        # Set cursor
        self.results_text.setTextCursor(cursor)
        
        # Add separator
        cursor.insertText("---------------------------------------------\n")
        
        # Add summary heading
        summary_format = QTextCharFormat()
        summary_format.setFontWeight(QFont.Weight.Bold)
        cursor.insertText("Summary: ", summary_format)
        
        # Count successful and warning results
        text = self.results_text.toPlainText()
        success_count = text.count("✓")
        warning_count = text.count("⚠️")
        
        if warning_count == 0:
            cursor.insertText("All checks passed! Your system is ready for CryptoBench Pro.")
            self.status_message.emit("Environment check completed: All checks passed!")
        else:
            cursor.insertText(f"{success_count} checks passed, {warning_count} warnings. "
                             f"Some features may be limited or require additional setup.")
            self.status_message.emit(f"Environment check completed: {success_count} passed, {warning_count} warnings")
            
            # Add note about requirement vs. optional
            cursor.insertText("\n\nNote: Some warnings are for optional features and may not affect "
                              "your ability to run specific configurations of CryptoBench Pro.") 