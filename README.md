# CryptoBench Pro

A comprehensive benchmarking tool for cryptographic algorithms implemented from scratch across multiple programming languages.

## Overview

CryptoBench Pro allows you to:
- Implement and benchmark standard cryptographic algorithms (AES, ChaCha20, ECC, RSA, ML-KEM)
- Compare implementations across multiple languages (Python, C, Rust, Go, Assembly)
- Compare self-implemented algorithms against standard library versions
- Generate detailed reports with security analysis and performance metrics

## Features

- **Deep Dive Implementation & Benchmarking**: Implement and test cryptographic algorithms from scratch
- **Comprehensive Parameterization**: Control input data, algorithm parameters, test execution, and resource constraints
- **Multi-faceted Comparative Analysis**: Compare across algorithms, languages, and against standard libraries
- **User-Friendly Interface**: PyQt6-based GUI for configuration, execution, and results visualization
- **Detailed Reporting**: Generate PDF transcripts with security analysis and performance charts

## Getting Started

### Prerequisites

- Python 3.9+
- C/C++ compiler (gcc/clang)
- Rust compiler (if using Rust implementations)
- Go compiler (if using Go implementations)
- Assembly tools (if using Assembly implementations)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/CryptoBench-Pro.git
cd CryptoBench-Pro
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Build language-specific runners (optional, will be built on demand):
```bash
cd src/runners
make all
```

### Usage

1. Launch the application:
```bash
python src/main.py
```

2. Use the GUI to:
   - Configure test parameters
   - Generate or select datasets
   - Run benchmarks
   - View and export results

## Project Structure

```
.
├── src/
│   ├── ui/                  # PyQt6 user interface components
│   ├── runners/             # Language-specific implementation runners
│   │   ├── python_runner/   # Python implementations
│   │   ├── c_runner/        # C implementations
│   │   ├── rust_runner/     # Rust implementations
│   │   ├── go_runner/       # Go implementations
│   │   └── assembly_runner/ # Assembly implementations
│   ├── datasets/            # Dataset generation and management
│   ├── utils/               # Utility functions
│   ├── results/             # Results processing and visualization
│   └── tests/               # Unit tests
├── docs/                    # Documentation
└── requirements.txt         # Python dependencies
```