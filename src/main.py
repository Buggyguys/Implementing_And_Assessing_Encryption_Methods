#!/usr/bin/env python3
"""
CryptoBench Pro - Main Entry Point
A comprehensive benchmarking tool for cryptographic algorithms.
"""

import sys
import os
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import after path adjustment
from src.ui.main_window import MainWindow
from PyQt6.QtWidgets import QApplication


def main():
    """Main entry point for the application"""
    # Create the application
    app = QApplication(sys.argv)
    app.setApplicationName("CryptoBench Pro")
    
    # Create and show the main window
    main_window = MainWindow()
    main_window.show()
    
    # Run the application event loop
    sys.exit(app.exec())


if __name__ == "__main__":
    main() 