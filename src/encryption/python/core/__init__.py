#!/usr/bin/env python3
"""
CryptoBench Pro - Python Core Module
Provides core functionality for benchmarking encryption implementations.
"""

import logging

# Configure logging
logger = logging.getLogger("PythonCore")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Import key components
from .metrics import BenchmarkMetrics
from .utils import MemoryMappedDataset, RotatingKeySet, load_dataset
from .results import calculate_aggregated_metrics, save_results
from .measurement import measure_encryption_metrics
from .registry import register_implementation, list_implementations, register_all_implementations
from .benchmark_runner import run_benchmarks

# Expose core functionality
__all__ = [
    'BenchmarkMetrics',
    'MemoryMappedDataset',
    'RotatingKeySet',
    'load_dataset',
    'calculate_aggregated_metrics',
    'save_results',
    'measure_encryption_metrics',
    'register_implementation',
    'list_implementations',
    'register_all_implementations',
    'run_benchmarks',
] 