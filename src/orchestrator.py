"""
CryptoBench Pro - Orchestrator Module
Coordinates execution of benchmark tests across different programming languages.
"""

import os
import sys
import json
import time
import logging
import subprocess
from datetime import datetime
from pathlib import Path
import shutil

# Set up logging
logger = logging.getLogger("Orchestrator")
logger.setLevel(logging.INFO)

if not logger.handlers:
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

def find_latest_session_file():
    """Find the most recent session directory in the sessions folder."""
    # Try to find the sessions directory
    project_root = os.getcwd()
    
    # If running from src directory, go up one level
    if os.path.basename(project_root) == "src":
        project_root = os.path.dirname(project_root)
        
    sessions_dir = os.path.join(project_root, "sessions")
    
    if not os.path.exists(sessions_dir):
        logger.error(f"Sessions directory not found at {sessions_dir}")
        return None
    
    # Find Session-* directories
    session_dirs = [os.path.join(sessions_dir, d) for d in os.listdir(sessions_dir) 
                   if os.path.isdir(os.path.join(sessions_dir, d)) and d.startswith("Session-")]
    
    if not session_dirs:
        logger.error("No session directories found")
        return None
    
    # Sort by creation time (most recent first)
    session_dirs.sort(key=lambda x: os.path.getctime(x), reverse=True)
    
    # Get the config file from the most recent session
    config_file = os.path.join(session_dirs[0], "test_config.json")
    
    if not os.path.exists(config_file):
        logger.error(f"Config file not found in {session_dirs[0]}")
        return None
        
    return config_file

def load_session_config(session_file):
    """Load and parse the session configuration file."""
    try:
        with open(session_file, 'r') as f:
            config = json.load(f)
        return config
    except Exception as e:
        logger.error(f"Error loading session config: {str(e)}")
        return None

def run_language_benchmark(language, config):
    """Run benchmarks for the specified language."""
    session_dir = config["session_info"]["session_dir"]
    session_id = config["session_info"]["session_id"]
    
    logger.info(f"Starting {language} benchmarks for session {session_id}")
    
    try:
        # Path to the language-specific runner
        script_dir = os.path.dirname(os.path.abspath(__file__))
        lang_script_path = os.path.join(script_dir, "encryption", language, f"{language}_core.py")
        
        # If the language is not Zig, we need to ensure it's compiled/built first
        if language != "zig":
            build_script_path = os.path.join(script_dir, "encryption", language, f"build_{language}.sh")
            if os.path.exists(build_script_path):
                logger.info(f"Building {language} implementation...")
                os.chmod(build_script_path, 0o755)  # Make executable
                subprocess.run([build_script_path], check=True)
        
        # Run the language-specific benchmark
        if language == "zig":
            # For Zig, we can import and run directly
            sys.path.insert(0, os.path.dirname(script_dir))
            
            # Check if the script exists
            if not os.path.exists(lang_script_path):
                logger.error(f"{language} core script not found at {lang_script_path}")
                return False
                
            # Dynamic import and run
            import importlib.util
            spec = importlib.util.spec_from_file_location(f"{language}_core", lang_script_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Call the main function
            module.main(config)
        elif language == "java":
            # For Java, use Java specific execution
            java_main_class = os.path.join(script_dir, "encryption", language, "JavaCore")
            if os.path.exists(os.path.join(script_dir, "encryption", language, "JavaCore.class")):
                os.chmod(os.path.join(script_dir, "encryption", language), 0o755)  # Make directory executable
                # Pass JSON config path to the Java program
                session_json_path = os.path.join(session_dir, "test_config.json")
                subprocess.run(["java", "-cp", os.path.join(script_dir, "encryption", language), "JavaCore", session_json_path], check=True)
            else:
                logger.error(f"Java core class not found at {java_main_class}")
                return False
        else:
            # For other languages, execute the script as a subprocess
            if not os.path.exists(lang_script_path):
                # For compiled languages, look for an executable
                executable_path = os.path.join(script_dir, "encryption", language, f"{language}_core")
                if os.path.exists(executable_path):
                    os.chmod(executable_path, 0o755)  # Make executable
                    # Pass JSON config path to the executable
                    session_json_path = os.path.join(session_dir, "test_config.json")
                    subprocess.run([executable_path, session_json_path], check=True)
                else:
                    logger.error(f"{language} core executable not found at {executable_path}")
                    return False
            else:
                # It's a script - determine interpreter
                interpreter = "python3"  # Default for Python scripts
                
                if language == "go":
                    interpreter = "go run"
                
                # Make the script executable
                os.chmod(lang_script_path, 0o755)
                
                # Pass JSON config path to the script
                session_json_path = os.path.join(session_dir, "test_config.json")
                subprocess.run(f"{interpreter} {lang_script_path} {session_json_path}", shell=True, check=True)
        
        # For C language, clean up placeholder implementations
        if language == "c":
            clean_script_path = os.path.join(script_dir, "encryption", language, "clean.sh")
            if os.path.exists(clean_script_path):
                os.chmod(clean_script_path, 0o755)  # Make executable
                subprocess.run([clean_script_path], check=True)
        
        return True
    
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing {language} benchmark: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error in {language} benchmark: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def update_ui_status(config, message):
    """Update the UI with the current status."""
    # Write to a status file that can be polled by the UI
    session_dir = config["session_info"]["session_dir"]
    status_file = os.path.join(session_dir, "status.json")
    
    status_data = {
        "timestamp": datetime.now().isoformat(),
        "message": message,
        "status": "running"
    }
    
    with open(status_file, 'w') as f:
        json.dump(status_data, f, indent=4)
    
    # Also log to console
    logger.info(message)

def finalize_results(config, success=True):
    """Finalize the benchmark results."""
    session_dir = config["session_info"]["session_dir"]
    
    # Update status file
    status_file = os.path.join(session_dir, "status.json")
    
    status_data = {
        "timestamp": datetime.now().isoformat(),
        "message": "Benchmarks completed" if success else "Benchmarks completed with errors",
        "status": "completed" if success else "error"
    }
    
    with open(status_file, 'w') as f:
        json.dump(status_data, f, indent=4)
    
    logger.info("Orchestration completed")

def main():
    """Main entry point for the orchestrator."""
    try:
        logger.info("Starting benchmark orchestration")
        
        # Find and load the latest session configuration
        session_file = find_latest_session_file()
        if not session_file:
            logger.error("No session file found. Aborting.")
            return False
        
        logger.info(f"Found session file: {session_file}")
        config = load_session_config(session_file)
        if not config:
            logger.error("Failed to load session configuration. Aborting.")
            return False
        
        # Extract enabled languages
        enabled_languages = []
        for lang, settings in config["languages"].items():
            if settings.get("is_enabled", False):
                enabled_languages.append(lang)
        
        if not enabled_languages:
            logger.error("No languages enabled in configuration. Aborting.")
            return False
        
        logger.info(f"Enabled languages: {', '.join(enabled_languages)}")
        
        # Run benchmarks for each enabled language
        success = True
        for lang in enabled_languages:
            update_ui_status(config, f"Running {lang.capitalize()} benchmarks...")
            if run_language_benchmark(lang, config):
                update_ui_status(config, f"{lang.capitalize()} benchmarks completed successfully")
            else:
                update_ui_status(config, f"{lang.capitalize()} benchmarks failed")
                success = False
                logger.warning(f"Benchmark failed for {lang}")
        
        # Finalize results
        finalize_results(config, success)
        return success
    
    except Exception as e:
        logger.error(f"Orchestration error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 