# pyRanoid 🔒

![Tests](https://github.com/omnone/pyRanoid/workflows/Tests/badge.svg) ![Python](https://img.shields.io/badge/python-3.11+-blue.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg)

**pyRanoid** is a Python application that combines advanced encryption and steganography to securely hide your files within images. Using AES-256-CBC or RSA encryption and LSB (Least Significant Bit) steganography, pyRanoid ensures your sensitive data remains both encrypted and concealed.

<img src="screenshot.png" width="650" height="410">

## Features

### Security
- **AES-256-CBC Encryption**: Military-grade encryption using the Advanced Encryption Standard with 256-bit keys
- **PBKDF2 Key Derivation**: Secure password-based key derivation with 100,000 iterations using HMAC-SHA256
- **Random Salt & IV**: Each encryption uses unique randomly generated salt and initialization vectors
- **Cryptographic Integrity**: Built on the industry-standard `cryptography` library

### Steganography
- **LSB Technique**: Hides encrypted data in the least significant bits of image pixels
- **Lossless Format**: Works with PNG images to preserve data integrity
- **Dimension Preservation**: Maintains original image dimensions and visual quality
- **Capacity Calculation**: Automatically checks if the carrier image can hold the encrypted data

### User Interface
- **Dual Interface**: Choose between a modern GTK3 GUI or an interactive CLI
- **GUI Features**:
  - Drag-and-drop file selection
  - Real-time password strength indicator
  - Progress tracking for encryption/decryption operations
  - Visual feedback and error handling
- **CLI Features**:
  - Rich terminal formatting with colors and spinners
  - Interactive password input with verification
  - Command-line arguments for automation
  - Detailed error messages

## Requirements
- Python 3.11 or higher
- Dependencies (automatically managed via uv)
- GTK3 libraries (for GUI mode)

## Installation & Usage

```bash
# Install dependencies
make install

# Run GUI
make run-gui

# Run CLI
make run-cli
```

For more commands, run `make help`

## Development

### Setting Up Development Environment

1. **Clone the repository**
   ```bash
   git clone https://github.com/omnone/pyRanoid.git
   cd pyRanoid
   ```

2. **Install dependencies**
   
   pyRanoid uses [uv](https://github.com/astral-sh/uv) for fast, reliable dependency management:
   ```bash
   make install
   ```
   
   This will:
   - Install all project dependencies
   - Install development dependencies (pytest, pytest-mock, pytest-cov, ruff)
   - Install the package in editable mode

### Project Structure

```
pyRanoid/
├── src/
│   ├── pyRanoid/          # Main package
│   │   ├── __init__.py
│   │   ├── cli.py         # CLI interface
│   │   ├── gui.py         # GTK3 GUI interface
│   │   └── utils.py       # Core encryption/steganography logic
│   └── tests/
│       ├── unit/          # Unit tests
│       └── integration/   # Integration tests
├── pyproject.toml         # Project configuration and dependencies
├── Makefile              # Development commands
└── README.md
```

### Running Tests

pyRanoid has comprehensive test coverage with both unit and integration tests:

```bash
# Run all tests
make test

# Run only unit tests
make test-unit

# Run only integration tests
make test-integration

# Run tests with coverage report
make test-cov

# Generate HTML coverage report
make test-cov-html
```

The HTML coverage report will be generated in `htmlcov/index.html`.

### Code Quality

**Linting:**
```bash
make lint
```

**Formatting:**
```bash
make format
```

The project uses [Ruff](https://github.com/astral-sh/ruff) for both linting and formatting, ensuring consistent code style.

### Building Distribution Packages

To build wheel and source distribution packages:

```bash
make build
```

Packages will be created in the `dist/` directory.

### Development Workflow

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write code following the existing style
   - Add tests for new functionality
   - Update documentation as needed

3. **Run tests and linting**
   ```bash
   make test
   make lint
   make format
   ```

4. **Test both interfaces**
   ```bash
   make run-cli    # Test CLI interface
   make run-gui    # Test GUI interface
   ```

5. **Commit and push**
   ```bash
   git add .
   git commit -m "Description of changes"
   git push origin feature/your-feature-name
   ```

### Debugging

For development and debugging, you can run the application directly:

```bash
# CLI mode
uv run python main.py

# GUI mode
uv run python -m pyRanoid.gui
```

### Dependencies

- **Runtime dependencies**: Pillow, cryptography, pygobject, numpy, rich
- **Development dependencies**: pytest, pytest-mock, pytest-cov, ruff

All dependencies are managed in `pyproject.toml` and locked in `uv.lock`.

## Contributing
Contributions to pyRanoid are welcome! If you encounter any issues or have ideas for enhancements, please feel free to submit a pull request or create an issue in the project's repository.

Please ensure:
- All tests pass (`make test`)
- Code is properly formatted (`make format`)
- Linting passes (`make lint`)
- New features include appropriate tests

## ⭐ Support
If you find pyRanoid useful, please consider giving it a star on GitHub!
