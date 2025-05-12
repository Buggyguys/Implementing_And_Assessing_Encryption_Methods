"""
CryptoBench Pro - Master Orchestrator

This module serves as the main entry point for benchmark execution.
It discovers the latest session configuration, prepares output directories,
and sequentially invokes language-specific core runners.
"""

import os
import json
import subprocess
import logging
import glob
import sys
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("Orchestrator")

def find_latest_session_json():
    """Find the most recent session JSON file in the project root."""
    session_files = glob.glob("session-*.json")
    if not session_files:
        raise FileNotFoundError("No session configuration files found. Please generate a session first.")
    
    # Sort by timestamp in filename (most recent first)
    session_files.sort(key=lambda x: datetime.strptime(
        x.replace("session-", "").replace(".json", ""), 
        "%Y%m%d_%H%M%S"
    ), reverse=True)
    
    return session_files[0]

def prepare_output_directory(session_dir):
    """Create the results directory for the current session."""
    results_dir = os.path.join(session_dir, "results")
    os.makedirs(results_dir, exist_ok=True)
    return results_dir

def run_language_core(lang_name, session_json_path):
    """Run the core runner for a specific language."""
    logger.info(f"Invoking {lang_name} core runner...")
    
    # Construct command based on language
    if lang_name == "python":
        cmd = ["python3", "src/runners/python_core_runner.py", "--config", session_json_path]
        timeout_seconds = 600  # 10 minutes for Python
    elif lang_name == "c":
        cmd = ["./src/runners/c_runner/c_core_runner", "--session-json-path", session_json_path]
        timeout_seconds = 180  # 3 minutes for others
    elif lang_name == "rust":
        cmd = ["./src/runners/rust_runner/rust_core_runner", "--session-json-path", session_json_path]
        timeout_seconds = 180
    elif lang_name == "go":
        cmd = ["./src/runners/go_runner/go_core_runner", "--session-json-path", session_json_path]
        timeout_seconds = 180
    elif lang_name == "assembly":
        cmd = ["./src/runners/assembly_runner/assembly_core_runner", "--session-json-path", session_json_path]
        timeout_seconds = 180
    else:
        logger.error(f"Unsupported language: {lang_name}")
        return False
    
    # Execute the command with a timeout
    try:
        # Create a progress indicator that prints a dot every 5 seconds
        import threading
        import time
        
        stop_progress = False
        
        def progress_indicator():
            count = 0
            while not stop_progress:
                logger.info(f"{lang_name} runner still working... ({count*5} seconds)")
                time.sleep(5)
                count += 1
        
        # Start progress thread
        progress_thread = threading.Thread(target=progress_indicator)
        progress_thread.daemon = True
        progress_thread.start()
        
        try:
            result = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                check=True,
                timeout=timeout_seconds
            )
            
            # Stop progress indicator
            stop_progress = True
            progress_thread.join(1)  # Wait at most 1 second for it to stop
            
            logger.info(f"{lang_name} stdout: {result.stdout}")
            if result.stderr:
                logger.warning(f"{lang_name} stderr: {result.stderr}")
            logger.info(f"{lang_name} core runner finished")
            return True
            
        except subprocess.TimeoutExpired as e:
            # Stop progress indicator
            stop_progress = True
            progress_thread.join(1)
            
            logger.error(f"{lang_name} core runner timed out after {timeout_seconds} seconds")
            return False
            
        except subprocess.CalledProcessError as e:
            # Stop progress indicator
            stop_progress = True
            progress_thread.join(1)
            
            logger.error(f"{lang_name} core runner failed with exit code {e.returncode}")
            logger.error(f"Error output: {e.stderr}")
            return False
            
    except Exception as e:
        logger.error(f"Error running {lang_name} core runner: {str(e)}")
        return False

def main():
    """Main orchestrator function."""
    try:
        # Find the latest session JSON
        session_json_path = find_latest_session_json()
        logger.info(f"Found session configuration: {session_json_path}")
        
        # Load session configuration
        with open(session_json_path, 'r') as f:
            session_config = json.load(f)
        
        # Prepare output directory
        session_dir = session_config["session_info"]["session_dir"]
        results_dir = prepare_output_directory(session_dir)
        logger.info(f"Orchestrator: Starting session defined in {session_json_path}. Output will be in {results_dir}")
        
        # Run core runners for each enabled language
        success_count = 0
        total_runs = 0
        
        for lang_name, lang_config in session_config["languages"].items():
            if lang_config.get("is_enabled", False):
                total_runs += 1
                if run_language_core(lang_name, session_json_path):
                    success_count += 1
            else:
                logger.info(f"{lang_name} core runner skipped (not enabled)")
        
        logger.info(f"All selected test executions completed. Individual results should be in {results_dir}.")
        
        # Return success only if all enabled languages completed successfully
        if total_runs > 0 and success_count == total_runs:
            logger.info("Orchestration completed successfully!")
            return True
        elif total_runs > 0:
            logger.warning(f"Orchestration completed with some failures: {success_count}/{total_runs} successful.")
            return False
        else:
            logger.warning("No language runners were enabled. Nothing to run.")
            return False
        
    except Exception as e:
        logger.error(f"Orchestration failed: {str(e)}")
        return False

if __name__ == "__main__":
    main() 