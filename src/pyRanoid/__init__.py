"""
PyRanoid - A steganography tool for hiding files in images.

This package provides both GUI and CLI interfaces for encrypting files into
images and decrypting files from images using LSB (Least Significant Bit)
steganography combined with AES-256-CBC encryption.

Modules:
    - gui: GTK3-based graphical user interface
    - cli: Interactive command-line interface
    - utils: Core steganography and encryption functions

Example:
    To run the GUI::

        $ python -m pyRanoid.gui

    To run the CLI::

        $ python -m pyRanoid.cli
"""

__version__ = "2.0.0"
__author__ = "Konstantinos Bourantas"
__license__ = "MIT"
