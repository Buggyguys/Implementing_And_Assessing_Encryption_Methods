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
            # For Zig, we need to build first and then run the executable
            build_script_path = os.path.join(script_dir, "encryption", language, f"build_{language}.sh")
            if os.path.exists(build_script_path):
                logger.info(f"Building {language} implementation...")
                os.chmod(build_script_path, 0o755)  # Make executable
                subprocess.run([build_script_path], check=True)
            
            # Look for the compiled executable
            executable_path = os.path.join(script_dir, "encryption", language, "build", f"{language}_core")
            if os.path.exists(executable_path):
                os.chmod(executable_path, 0o755)  # Make executable
                # Pass JSON config path to the executable
                session_json_path = os.path.join(session_dir, "test_config.json")
                subprocess.run([executable_path, session_json_path], check=True)
            else:
                logger.error(f"{language} core executable not found at {executable_path}")
                return False
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
                    
                    # Run with proper process management for Go
                    if language == "go":
                        # Use Popen for better process control
                        process = subprocess.Popen([executable_path, session_json_path], 
                                                 stdout=subprocess.PIPE, 
                                                 stderr=subprocess.PIPE,
                                                 text=True)
                        stdout, stderr = process.communicate()
                        
                        if process.returncode != 0:
                            logger.error(f"Go process failed with return code {process.returncode}")
                            if stderr:
                                logger.error(f"Go stderr: {stderr}")
                            return False
                        
                        # Log output if needed
                        if stdout:
                            logger.info(f"Go stdout: {stdout}")
                    else:
                        subprocess.run([executable_path, session_json_path], check=True)
                else:
                    logger.error(f"{language} core executable not found at {executable_path}")
                    return False
            else:
                # It's a script - handle each language appropriately
                session_json_path = os.path.join(session_dir, "test_config.json")
                
                if language == "python":
                    # For Python, use better process isolation to prevent segfaults
                    os.chmod(lang_script_path, 0o755)
                    
                    # Use Popen for better process control and isolation
                    env = os.environ.copy()
                    # Ensure clean Python environment
                    env['PYTHONDONTWRITEBYTECODE'] = '1'  # Don't create .pyc files
                    env['PYTHONUNBUFFERED'] = '1'  # Unbuffered output
                    
                    process = subprocess.Popen(
                        ["python3", lang_script_path, session_json_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        env=env,
                        # Add process isolation
                        preexec_fn=os.setsid if hasattr(os, 'setsid') else None
                    )
                    stdout, stderr = process.communicate()
                    
                    if process.returncode != 0:
                        logger.error(f"Python process failed with return code {process.returncode}")
                        if stderr:
                            logger.error(f"Python stderr: {stderr}")
                        return False
                    
                    # Log output if needed
                    if stdout:
                        logger.info(f"Python stdout: {stdout}")
                        
                elif language == "go":
                    # For Go, use go run
                    os.chmod(lang_script_path, 0o755)
                    subprocess.run(f"go run {lang_script_path} {session_json_path}", shell=True, check=True)
                else:
                    # For other interpreted languages
                    interpreter = "python3"  # Default fallback
                    os.chmod(lang_script_path, 0o755)
                    subprocess.run(f"{interpreter} {lang_script_path} {session_json_path}", shell=True, check=True)
        
        # For C and Zig languages, clean up placeholder implementations
        if language in ["c", "zig"]:
            clean_script_path = os.path.join(script_dir, "encryption", language, "clean.sh")
            if os.path.exists(clean_script_path):
                os.chmod(clean_script_path, 0o755)  # Make executable
                subprocess.run([clean_script_path], check=True)
        
        # For Python language, clean up any residual files to prevent segmentation faults
        if language == "python":
            logger.info(f"Cleaning up {language} artifacts...")
            python_dir = os.path.join(script_dir, "encryption", language)
            try:
                # Remove Python cache directories
                import shutil
                for root, dirs, files in os.walk(python_dir):
                    for dir_name in dirs:
                        if dir_name == "__pycache__":
                            cache_dir = os.path.join(root, dir_name)
                            shutil.rmtree(cache_dir, ignore_errors=True)
                
                # Remove .pyc files
                for root, dirs, files in os.walk(python_dir):
                    for file in files:
                        if file.endswith('.pyc'):
                            pyc_file = os.path.join(root, file)
                            try:
                                os.remove(pyc_file)
                            except:
                                pass
                                
                logger.info(f"{language} cleanup completed")
            except Exception as e:
                logger.warning(f"Error during {language} cleanup: {e}")
        
        # For Go language, clean up build artifacts to prevent segmentation faults
        if language == "go":
            logger.info(f"Cleaning up {language} build artifacts...")
            go_dir = os.path.join(script_dir, "encryption", language)
            try:
                # Remove the compiled binary
                go_binary = os.path.join(go_dir, "go_core")
                if os.path.exists(go_binary):
                    os.remove(go_binary)
                
                # Clean Go module cache and build cache
                subprocess.run(["go", "clean", "-cache", "-modcache"], cwd=go_dir, check=False)
                subprocess.run(["go", "clean", "-testcache"], cwd=go_dir, check=False)
                
                # Remove go.mod and go.sum to force fresh module initialization
                go_mod = os.path.join(go_dir, "go.mod")
                go_sum = os.path.join(go_dir, "go.sum")
                if os.path.exists(go_mod):
                    os.remove(go_mod)
                if os.path.exists(go_sum):
                    os.remove(go_sum)
                    
                logger.info(f"{language} cleanup completed")
            except Exception as e:
                logger.warning(f"Error during {language} cleanup: {e}")
        
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
            # Handle both boolean values and objects with is_enabled field
            if isinstance(settings, bool):
                if settings:
                    enabled_languages.append(lang)
            elif isinstance(settings, dict):
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