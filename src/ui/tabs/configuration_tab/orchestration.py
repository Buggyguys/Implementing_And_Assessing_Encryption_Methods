"""
CryptoBench Pro - Configuration Tab Orchestration Module
Handles test execution and orchestration threading.
"""

import os
import json
import subprocess
import logging
from datetime import datetime
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import QMessageBox


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
        self.custom_handler = None
        # Ensure proper cleanup
        self.finished.connect(self._cleanup)
    
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
            # Clean up logging
            self._cleanup_logging()
    
    def _setup_logging(self):
        """Redirect logging to emit progress updates."""
        class SignalHandler(logging.Handler):
            def __init__(self, signal):
                super().__init__()
                self.signal = signal
            
            def emit(self, record):
                try:
                    msg = self.format(record)
                    self.signal.emit(msg)
                except:
                    # Ignore errors in logging to prevent crashes
                    pass
        
        # Get the orchestrator logger
        logger = logging.getLogger("Orchestrator")
        
        # Add our custom handler
        self.custom_handler = SignalHandler(self.progress_update)
        self.custom_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        logger.addHandler(self.custom_handler)
    
    def _cleanup_logging(self):
        """Clean up logging handlers."""
        try:
            if self.custom_handler:
                logger = logging.getLogger("Orchestrator")
                logger.removeHandler(self.custom_handler)
                self.custom_handler = None
        except:
            # Ignore cleanup errors
            pass
    
    def _cleanup(self):
        """Clean up resources when thread finishes."""
        try:
            self._cleanup_logging()
            self.running = False
            # Force garbage collection to clean up any remaining objects
            import gc
            gc.collect()
        except:
            # Ignore cleanup errors to prevent crashes
            pass


class TestExecutor:
    """Handles execution of different language tests."""
    
    def __init__(self, status_callback=None):
        self.status_callback = status_callback or (lambda x: None)
    
    def execute_zig_tests(self, config_path):
        """Execute Zig tests."""
        try:
            # Get the path to the Zig test script
            script_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            zig_test_script = os.path.join(script_dir, "encryption", "zig", "run_zig_tests.sh")
            
            # Make sure the script is executable
            os.chmod(zig_test_script, 0o755)
            
            # Run the Zig test script
            message = "Running Zig encryption tests..."
            self.status_callback(message)
            print(message)
            
            subprocess.run([zig_test_script, config_path], check=True)
            
            # Update progress
            message = "Zig tests completed successfully"
            self.status_callback(message)
            print(message)
            return True
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Zig tests failed: {str(e)}"
            self.status_callback(error_msg)
            print(f"ERROR: {error_msg}")
            return False
        except Exception as e:
            error_msg = f"Error running Zig tests: {str(e)}"
            self.status_callback(error_msg)
            print(f"ERROR: {error_msg}")
            return False
    
    def execute_c_tests(self, config_path):
        """Execute C tests."""
        try:
            # Get the path to the C test script
            script_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            c_test_script = os.path.join(script_dir, "encryption", "c", "run_c_tests.sh")
            
            # Make sure the script is executable
            os.chmod(c_test_script, 0o755)
            
            # Run the C test script
            message = "Running C encryption tests..."
            self.status_callback(message)
            
            subprocess.run([c_test_script, config_path], check=True)
            
            # Update progress
            message = "C tests completed successfully"
            self.status_callback(message)
            return True
            
        except subprocess.CalledProcessError as e:
            error_msg = f"C tests failed: {str(e)}"
            self.status_callback(error_msg)
            print(f"ERROR: {error_msg}")
            return False
        except Exception as e:
            error_msg = f"Error running C tests: {str(e)}"
            self.status_callback(error_msg)
            print(f"ERROR: {error_msg}")
            return False
    
    def execute_orchestrator(self, selected_languages):
        """Execute the orchestrator for other languages."""
        try:
            # Import and run the orchestrator
            from src.orchestrator import main as run_orchestrator
            message = "Launching orchestrator..."
            self.status_callback(message)
            print(message)
            
            return run_orchestrator()
            
        except Exception as e:
            error_msg = f"Failed to start orchestrator: {str(e)}"
            print(f"ERROR: {error_msg}")
            self.status_callback(f"Orchestration error: {str(e)}")
            return False 