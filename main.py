#!/usr/bin/env python3
"""
Main entry point for pyRanoid CLI.

This script allows running pyRanoid CLI directly from the repository.
Usage: 
    uv run python main.py [arguments]
    or
    python main.py [arguments] (if dependencies are installed)
"""

import sys
import os
from pathlib import Path

src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

os.environ['PYTHONPATH'] = str(src_path) + os.pathsep + os.environ.get('PYTHONPATH', '')

try:
    from pyRanoid.cli import main
    
    if __name__ == "__main__":
        main()
except ModuleNotFoundError as e:
    print(f"Error: Missing dependency - {e}")
    print("\nPlease run with uv:")
    print("  uv run python main.py [arguments]")
    print("\nOr install dependencies:")
    print("  uv sync")
    print("  python main.py [arguments]")
    sys.exit(1)

