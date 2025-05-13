#!/bin/bash
# Build script for Rust encryption implementations

# Exit on error
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "Building Rust encryption implementations..."

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "Rust not found. Please install Rust to build this implementation."
    exit 1
fi

# Check if Cargo.toml exists, if not create it
if [ ! -f "Cargo.toml" ]; then
    echo "Creating Cargo.toml..."
    cat > Cargo.toml << EOF
[package]
name = "rust_crypto_bench"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
aes = "0.8"
aes-gcm = "0.10"
rand = "0.8"
rsa = "0.9"
sha2 = "0.10"
p256 = "0.13"
chacha20poly1305 = "0.10"
EOF
fi

# Check if src directory exists, if not create it with main.rs
if [ ! -d "src" ]; then
    echo "Creating Rust source directory..."
    mkdir -p src
    
    # Create a placeholder main.rs
    cat > src/main.rs << EOF
use std::env;
use std::fs;
use std::time::{Duration, Instant};
use std::process::exit;
use serde_json::{Value, json};

fn main() {
    println!("Rust Crypto Benchmarking Tool starting...");
    
    // Get config file path from command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <config_file>", args[0]);
        exit(1);
    }
    
    let config_file = &args[1];
    println!("Loading configuration from: {}", config_file);
    
    // Load and parse configuration
    let config_data = match fs::read_to_string(config_file) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to read config file: {}", e);
            exit(1);
        }
    };
    
    let config: Value = match serde_json::from_str(&config_data) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Failed to parse JSON config: {}", e);
            exit(1);
        }
    };
    
    // Extract session info
    let session_dir = config["session_info"]["session_dir"].as_str().unwrap_or("");
    let session_id = config["session_info"]["session_id"].as_str().unwrap_or("");
    
    println!("Session ID: {}", session_id);
    println!("Session directory: {}", session_dir);
    
    // Create results structure
    let results = json!({
        "language": "rust",
        "session_id": session_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "dataset": {
            "path": config["test_parameters"]["dataset_path"],
            "size_bytes": 0  // Will be updated when dataset is loaded
        },
        "encryption_results": {}
    });
    
    // Save placeholder results for now
    let results_dir = format!("{}/results", session_dir);
    
    // Create results directory if it doesn't exist
    match fs::create_dir_all(&results_dir) {
        Ok(_) => {},
        Err(e) => {
            eprintln!("Failed to create results directory: {}", e);
            exit(1);
        }
    };
    
    let results_file = format!("{}/rust_results.json", results_dir);
    match fs::write(&results_file, results.to_string()) {
        Ok(_) => println!("Results saved to: {}", results_file),
        Err(e) => eprintln!("Failed to write results: {}", e)
    };
    
    println!("Rust Crypto Benchmarking completed");
}
EOF
fi

# Build the Rust implementation
echo "Building with cargo..."
cargo build --release

# Copy the built executable to the current directory for easier access
echo "Copying executable..."
cp target/release/rust_crypto_bench rust_core

echo "Rust implementation built successfully" 