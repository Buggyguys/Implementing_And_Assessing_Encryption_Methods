"""
CryptoBench Pro - Main Window
Contains the main application window with tabs for different functionality.
"""

from PyQt6.QtWidgets import (
    QMainWindow, QTabWidget, QVBoxLayout, QWidget, 
    QStatusBar, QLabel, QSplitter, QApplication
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QIcon, QFont

from src.ui.tabs.dataset_tab import DatasetTab
from src.ui.tabs.configuration_tab import ConfigurationTab
from src.ui.tabs.environment_tab import EnvironmentTab
from src.ui.tabs.results_tab import ResultsTab


class MainWindow(QMainWindow):
    """Main application window with tabs for different functionality."""
    
    def __init__(self):
        super().__init__()
        
        # Set window properties
        self.setWindowTitle("CryptoBench Pro")
        self.setMinimumSize(1024, 768)
        
        # Create central widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabPosition(QTabWidget.TabPosition.North)
        self.tab_widget.setMovable(False)
        
        # Create tabs
        self.dataset_tab = DatasetTab()
        self.configuration_tab = ConfigurationTab()
        self.environment_tab = EnvironmentTab()
        self.results_tab = ResultsTab()
        
        # Add tabs to tab widget
        self.tab_widget.addTab(self.dataset_tab, "Dataset Management")
        self.tab_widget.addTab(self.configuration_tab, "Test Configuration")
        self.tab_widget.addTab(self.environment_tab, "Environment Check")
        self.tab_widget.addTab(self.results_tab, "Results Viewer")
        
        # Add tab widget to main layout
        self.main_layout.addWidget(self.tab_widget)
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Add status message
        self.status_message = QLabel("Ready")
        self.status_bar.addWidget(self.status_message)
        
        # Connect signals
        self._connect_signals()
    
    def _connect_signals(self):
        """Connect signals between tabs and components."""
        # Connect tab changed signal
        self.tab_widget.currentChanged.connect(self._handle_tab_changed)
        
        # Connect signals from tabs
        self.dataset_tab.status_message.connect(self._update_status)
        self.configuration_tab.status_message.connect(self._update_status)
        self.environment_tab.status_message.connect(self._update_status)
        self.results_tab.status_message.connect(self._update_status)
    
    def _handle_tab_changed(self, index):
        """Handle tab changed event."""
        tab_name = self.tab_widget.tabText(index)
        self._update_status(f"Switched to {tab_name} tab")
    
    def _update_status(self, message):
        """Update status bar message."""
        self.status_message.setText(message) 
        
    def closeEvent(self, event):
        """Handle application close event."""
        # Check if any orchestration threads are running
        if hasattr(self.configuration_tab, 'orchestrator_thread') and self.configuration_tab.orchestrator_thread and self.configuration_tab.orchestrator_thread.isRunning():
            # Wait for thread to finish with a timeout
            self.status_message.setText("Waiting for orchestration to complete...")
            self.configuration_tab.orchestrator_thread.quit()
            finished = self.configuration_tab.orchestrator_thread.wait(3000)  # 3 second timeout
            
            if not finished:
                # If not finished, force termination
                self.configuration_tab.orchestrator_thread.terminate()
                self.configuration_tab.orchestrator_thread.wait()
        
        # Accept the close event
        event.accept() 