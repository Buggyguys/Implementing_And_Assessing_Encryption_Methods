# CryptoBench Pro

A comprehensive benchmarking tool for cryptographic algorithms across multiple programming languages.

## Overview

CryptoBench Pro allows you to benchmark various encryption algorithms implemented in different programming languages. The tool tracks detailed performance metrics including CPU usage, memory consumption, and disk I/O, providing a comprehensive analysis of encryption performance.

## Features

- Benchmark multiple encryption algorithms: AES, RSA, ECC, ChaCha20, ML-KEM
- Compare implementations across programming languages: Python, C, Rust, Go
- Track detailed performance metrics during key generation, encryption, and decryption
- Generate comprehensive reports with comparative analysis
- Configurable test parameters including dataset size and number of iterations

## System Requirements

- Python 3.8 or higher
- For C implementations: GCC compiler
- For Rust implementations: Rust and Cargo
- For Go implementations: Go compiler
- PyQt6 for the GUI
- Required Python packages (see requirements.txt)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/cryptobench-pro.git
   cd cryptobench-pro
   ```

2. Create and activate a virtual environment (recommended):
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Launch the application:
   ```
   python src/main.py
   ```

2. Configure your benchmark:
   - Select programming languages to benchmark
   - Choose encryption algorithms and their parameters
   - Set the number of iterations
   - Select a dataset (or generate a new one)

3. Start the benchmark and wait for results

4. View detailed performance metrics in the Results tab

## Architecture

The system is comprised of the following components:

1. **UI**: PyQt6-based user interface for configuration and results display
2. **Orchestrator**: Coordinates benchmarking across different languages
3. **Language Cores**: Implementation-specific code for each language
4. **Session Management**: Handles test configurations and results storage

When a test is started, the following happens:

1. A unique session folder is created with the timestamp
2. Test configuration is stored as JSON
3. The orchestrator launches language-specific benchmarks
4. Each language core benchmarks the selected encryption methods
5. Results are saved in the session folder for analysis

## Adding New Implementations

See the [Encryption README](src/encryption/README.md) for instructions on adding new encryption implementations or languages.

## Metrics Tracked

The system tracks the following metrics:

### Key Generation
- Wall clock time
- CPU time (user and system)
- Memory usage
- Context switches

### Encryption
- Wall clock time
- CPU time (user and system)
- Memory usage
- Disk I/O
- Context switches
- Ciphertext size

### Decryption
- Wall clock time
- CPU time (user and system)
- Memory usage
- Disk I/O
- Context switches
- Correctness verification

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.