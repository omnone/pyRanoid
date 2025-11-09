# ============================================================================================
# MIT License
# Copyright (c) 2025 Konstantinos Bourantas

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# Part of the code was taken from:
# https://itnext.io/steganography-101-lsb-introduction-with-python-4c4803e08041
# ============================================================================================

"""
Utility functions for steganography operations.

This module provides functions for encrypting files into images and decrypting
files from images using steganography techniques (LSB - Least Significant Bit).
It also handles file compression, encryption, and logging.
"""

import tarfile
from PIL import Image
import os
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import numpy as np
import secrets
import struct
import logging

logging.basicConfig(level=logging.DEBUG)

try:
    import gi

    gi.require_version("GLib", "2.0")
    from gi.repository import GLib
except ImportError:
    GLib = None

CHUNK_SIZE = 64 * 1024
HEADER_SIZE = 32
SALT_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4

TAR_FILE_PATH = "output.tar.gz"
FINAL_PNG_PATH = "output.png"
ENCR_FILE_PATH = "output.prnd"

MAGIC_BYTES = b"PRND"
VERSION = 1

RSA_KEY_SIZE = 4096
PASSWORD_LENGTH = 32

# --------------------------------------------------------------------------------------------


def generate_rsa_keypair(key_size=RSA_KEY_SIZE):
    """
    Generate an RSA key pair for encrypting/decrypting passwords.

    :param key_size: Size of the RSA key in bits (default: 4096).
    :type key_size: int
    :return: Tuple of (private_key, public_key).
    :rtype: tuple
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


# --------------------------------------------------------------------------------------------


def save_private_key(private_key, filepath, password=None):
    """
    Save an RSA private key to a file.

    :param private_key: The RSA private key to save.
    :type private_key: rsa.RSAPrivateKey
    :param filepath: Path where the private key will be saved.
    :type filepath: str
    :param password: Optional password to encrypt the private key (recommended).
    :type password: str or None
    """
    if password:
        encryption_algorithm = serialization.BestAvailableEncryption(
            password.encode("utf-8")
        )
    else:
        encryption_algorithm = serialization.NoEncryption()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )

    with open(filepath, "wb") as f:
        f.write(pem)


# --------------------------------------------------------------------------------------------


def save_public_key(public_key, filepath):
    """
    Save an RSA public key to a file.

    :param public_key: The RSA public key to save.
    :type public_key: rsa.RSAPublicKey
    :param filepath: Path where the public key will be saved.
    :type filepath: str
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(filepath, "wb") as f:
        f.write(pem)


# --------------------------------------------------------------------------------------------


def is_private_key_encrypted(filepath):
    """
    Check if an RSA private key file is encrypted (password-protected).

    This function examines the PEM file headers to determine if the key
    is encrypted without attempting to load it.

    :param filepath: Path to the private key file.
    :type filepath: str
    :return: True if the key is encrypted, False otherwise.
    :rtype: bool
    """
    with open(filepath, "rb") as f:
        pem_data = f.read()

    try:
        pem_str = pem_data.decode("utf-8")
    except UnicodeDecodeError:
        return True

    if "BEGIN ENCRYPTED PRIVATE KEY" in pem_str:
        return True

    if "Proc-Type: 4,ENCRYPTED" in pem_str:
        return True

    if "BEGIN PRIVATE KEY" in pem_str or "BEGIN RSA PRIVATE KEY" in pem_str:
        return False

    return True


# --------------------------------------------------------------------------------------------


def load_private_key(filepath, password=None):
    """
    Load an RSA private key from a file.

    :param filepath: Path to the private key file.
    :type filepath: str
    :param password: Password to decrypt the private key (if encrypted).
    :type password: str or None
    :return: The loaded RSA private key.
    :rtype: rsa.RSAPrivateKey
    :raises ValueError: If the key is encrypted but no password provided, or password is incorrect.
    """
    with open(filepath, "rb") as f:
        pem_data = f.read()

    password_bytes = password.encode("utf-8") if password else None

    try:
        private_key = serialization.load_pem_private_key(
            pem_data, password=password_bytes, backend=default_backend()
        )
    except TypeError as e:
        raise ValueError(
            "The private key is encrypted but no password was provided. "
        ) from e
    except ValueError as e:
        error_msg = str(e).lower()
        if "bad decrypt" in error_msg or "incorrect password" in error_msg:
            raise ValueError("Incorrect password for the private key.") from e
        raise

    return private_key


# --------------------------------------------------------------------------------------------


def load_public_key(filepath):
    """
    Load an RSA public key from a file.

    :param filepath: Path to the public key file.
    :type filepath: str
    :return: The loaded RSA public key.
    :rtype: rsa.RSAPublicKey
    """
    with open(filepath, "rb") as f:
        pem_data = f.read()

    public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())

    return public_key


# --------------------------------------------------------------------------------------------


def generate_random_password(length=PASSWORD_LENGTH):
    """
    Generate a cryptographically secure random password.

    :param length: Length of the password in bytes (default: 32 bytes = 256 bits).
    :type length: int
    :return: Random password as a hex string.
    :rtype: str
    """
    return secrets.token_hex(length)


# --------------------------------------------------------------------------------------------


def encrypt_password_with_rsa(password, public_key):
    """
    Encrypt a password using RSA public key.

    :param password: The password to encrypt.
    :type password: str
    :param public_key: RSA public key for encryption.
    :type public_key: rsa.RSAPublicKey
    :return: Encrypted password as bytes.
    :rtype: bytes
    """
    encrypted = public_key.encrypt(
        password.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted


# --------------------------------------------------------------------------------------------


def decrypt_password_with_rsa(encrypted_password, private_key):
    """
    Decrypt a password using RSA private key.

    :param encrypted_password: The encrypted password bytes.
    :type encrypted_password: bytes
    :param private_key: RSA private key for decryption.
    :type private_key: rsa.RSAPrivateKey
    :return: Decrypted password as a string.
    :rtype: str
    """
    decrypted = private_key.decrypt(
        encrypted_password,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return decrypted.decode("utf-8")


# --------------------------------------------------------------------------------------------


def file_to_bin(file_path):
    """
    Convert a file to its binary string representation.

    :param file_path: Path to the file to convert.
    :type file_path: str
    :return: Binary string representation of the file contents.
    :rtype: str
    """
    with open(file_path, "rb") as file:
        file_data = file.read()
    return "".join(format(byte, "08b") for byte in file_data)


# --------------------------------------------------------------------------------------------


def str_to_bin(input):
    """
    Convert a string to its binary representation.

    :param input: String to convert.
    :type input: str
    :return: Binary string representation of the input.
    :rtype: str
    """
    return "".join(format(ord(char), "08b") for char in input)


# --------------------------------------------------------------------------------------------


def int_to_bin(x):
    """
    Convert an integer to its binary string representation.

    :param x: Integer to convert.
    :type x: int
    :return: Binary string representation of the integer.
    :rtype: str
    """
    return "{0:b}".format(x)


# --------------------------------------------------------------------------------------------


def encrypt_image(
    image_path, target_paths, output_path, password=None, rsa_public_key_path=None
):
    """
    Encrypt one or more files into an image using steganography (LSB method).

    This function supports two modes:
    1. Password mode: Uses a user-provided password directly
    2. RSA mode: Generates a random password and encrypts it with RSA public key

    :param image_path: Path to the source image file (PNG, JPG, JPEG).
    :type image_path: str
    :param target_paths: Path(s) to file(s) to encrypt and hide. Can be a string or list.
    :type target_paths: str or list[str]
    :param output_path: Path where the output image will be saved.
    :type output_path: str
    :param password: Password for encryption (password mode). Mutually exclusive with rsa_public_key_path.
    :type password: str or None
    :param rsa_public_key_path: Path to RSA public key file (RSA mode). Mutually exclusive with password.
    :type rsa_public_key_path: str or None
    :raises Exception: If encryption fails or image is too small for the files.
    :raises ValueError: If neither or both password and rsa_public_key_path are provided.
    """
    if (password is None and rsa_public_key_path is None) or (
        password is not None and rsa_public_key_path is not None
    ):
        raise ValueError(
            "Must provide either 'password' or 'rsa_public_key_path', but not both"
        )

    if rsa_public_key_path:
        public_key = load_public_key(rsa_public_key_path)
        random_password = generate_random_password()
        encrypted_password = encrypt_password_with_rsa(random_password, public_key)
        enc_path = encryption_handler(
            target_paths, random_password, encrypted_password=encrypted_password
        )
    else:
        enc_path = encryption_handler(target_paths, password, encrypted_password=None)

    enc_len = os.path.getsize(enc_path)

    img = Image.open(image_path).convert("RGB")

    temp_png_path = None
    if not image_path.lower().endswith(".png"):
        import tempfile

        temp_png_fd, temp_png_path = tempfile.mkstemp(suffix=".png")
        os.close(temp_png_fd)
        img.save(temp_png_path, "PNG")
        img = Image.open(temp_png_path).convert("RGB")

    arr = np.array(img)
    flat = arr.flatten()
    capacity = flat.size

    bits_needed = (enc_len + 4) * 8
    if bits_needed > capacity:
        if temp_png_path and os.path.exists(temp_png_path):
            os.remove(temp_png_path)
        raise Exception("Image too small for data")

    header = struct.pack(">I", enc_len)
    header_bits = np.unpackbits(np.frombuffer(header, dtype=np.uint8))
    flat[: len(header_bits)] = (flat[: len(header_bits)] & 0xFE) | header_bits

    bit_offset = HEADER_SIZE
    with open(enc_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            chunk_bits = np.unpackbits(np.frombuffer(chunk, dtype=np.uint8))
            chunk_size = len(chunk_bits)
            flat[bit_offset : bit_offset + chunk_size] = (
                flat[bit_offset : bit_offset + chunk_size] & 0xFE
            ) | chunk_bits
            bit_offset += chunk_size

    final_img = Image.fromarray(flat.reshape(arr.shape), "RGB")
    final_img.save(output_path, "PNG")

    if temp_png_path and os.path.exists(temp_png_path):
        os.remove(temp_png_path)

    os.remove(enc_path)


# --------------------------------------------------------------------------------------------


def decrypt_image(
    image_path, output_dir, password=None, rsa_private_key_path=None, key_password=None
):
    """
    Decrypt and extract a hidden file from an image.

    This function supports two modes:
    1. Password mode: Uses a user-provided password directly
    2. RSA mode: Decrypts the password using RSA private key

    :param image_path: Path to the image containing hidden data.
    :type image_path: str
    :param output_dir: Directory where extracted files will be saved.
    :type output_dir: str
    :param password: Password for decryption (password mode). Mutually exclusive with rsa_private_key_path.
    :type password: str or None
    :param rsa_private_key_path: Path to RSA private key file (RSA mode). Mutually exclusive with password.
    :type rsa_private_key_path: str or None
    :param key_password: Password to decrypt the RSA private key (if encrypted).
    :type key_password: str or None
    :raises Exception: If decryption fails or image doesn't contain valid hidden data.
    :raises ValueError: If neither or both password and rsa_private_key_path are provided.
    """
    if (password is None and rsa_private_key_path is None) or (
        password is not None and rsa_private_key_path is not None
    ):
        raise ValueError(
            "Must provide either 'password' or 'rsa_private_key_path', but not both"
        )

    img = Image.open(image_path).convert("RGB")
    arr = np.array(img)
    flat = arr.flatten()

    header_bits = flat[:HEADER_SIZE] & 1
    header_bytes = np.packbits(header_bits)
    enc_len = struct.unpack(">I", header_bytes)[0]

    bit_offset = HEADER_SIZE
    bytes_remaining = enc_len

    with open(ENCR_FILE_PATH, "wb") as f:
        while bytes_remaining > 0:
            chunk_bytes = min(CHUNK_SIZE, bytes_remaining)
            chunk_bits_count = chunk_bytes * 8

            chunk_bits = flat[bit_offset : bit_offset + chunk_bits_count] & 1

            chunk_data = np.packbits(chunk_bits).tobytes()

            f.write(chunk_data[:chunk_bytes])

            bit_offset += chunk_bits_count
            bytes_remaining -= chunk_bytes

    if rsa_private_key_path:
        private_key = load_private_key(rsa_private_key_path, key_password)
        output_path = encryption_handler(
            ENCR_FILE_PATH, None, private_key=private_key, decrypt=True
        )
    else:
        output_path = encryption_handler(ENCR_FILE_PATH, password, decrypt=True)

    extract_tar_archive(output_path, output_dir)

    files_extracted = get_tar_archive_files(output_path)

    os.remove(ENCR_FILE_PATH)
    os.remove(output_path)

    return files_extracted


# --------------------------------------------------------------------------------------------


def create_tar_archive(source_files, tar_filename=TAR_FILE_PATH):
    """
    Create a tar archive containing one or more files.

    :param source_files: List of file paths to archive, or a single file path string.
    :type source_files: list[str] or str
    :param tar_filename: Name for the tar archive file.
    :type tar_filename: str
    :return: Path to the created tar archive.
    :rtype: str
    """
    if isinstance(source_files, str):
        source_files = [source_files]

    if tar_filename.endswith(".tar.gz"):
        tar_path = tar_filename[:-7] + ".tar"
    elif tar_filename.endswith(".tar"):
        tar_path = tar_filename
    else:
        tar_path = tar_filename + ".tar"

    with tarfile.open(tar_path, "w") as tar:
        for source_file in source_files:
            arcname = os.path.basename(source_file)
            tar.add(source_file, arcname=arcname)

    return tar_path


# --------------------------------------------------------------------------------------------


def get_tar_archive_files(archive_file):
    """
    Get all files from a tar archive.

    :param archive_file: Path to the tar archive file.
    :type archive_file: str
    :return: List of files in the archive.
    :rtype: list
    """
    with tarfile.open(archive_file, "r") as tar:
        return tar.getnames()


# --------------------------------------------------------------------------------------------


def extract_tar_archive(archive_file, output_directory):
    """
    Extract all files from a tar archive to the specified directory.

    :param archive_file: Path to the tar archive file.
    :type archive_file: str
    :param output_directory: Directory where files will be extracted.
    :type output_directory: str
    """
    with tarfile.open(archive_file, "r") as tar:
        tar.extractall(output_directory, filter="data")


# --------------------------------------------------------------------------------------------


def derive_key(password, salt):
    """
    Derive a cryptographic key from a password using Argon2id.

    Argon2id is a memory-hard key derivation function that is resistant to
    GPU cracking attacks and side-channel attacks. It's the winner of the
    Password Hashing Competition and is recommended for password-based key derivation.

    :param password: Password to derive key from.
    :type password: str
    :param salt: Cryptographic salt (should be SALT_SIZE bytes).
    :type salt: bytes
    :return: Derived key of KEY_SIZE bytes.
    :rtype: bytes
    """
    password_bytes = password.encode("utf-8")

    kdf = Argon2id(
        salt=salt,
        length=KEY_SIZE,
        iterations=ARGON2_TIME_COST,
        lanes=ARGON2_PARALLELISM,
        memory_cost=ARGON2_MEMORY_COST,
    )

    key = kdf.derive(password_bytes)

    password_bytes = b"\x00" * len(password_bytes)

    return key


# --------------------------------------------------------------------------------------------


def encryption_handler(
    target_filepaths, password, encrypted_password=None, private_key=None, decrypt=False
):
    """
    Handle encryption or decryption of files using AES-256-GCM with Argon2id.

    This function uses modern cryptographic best practices:
    - AES-256-GCM for authenticated encryption
    - Argon2id for password-based key derivation
    - Optional RSA for password encryption/decryption
    - Cryptographically secure random salts and nonces
    - Authentication tags to prevent tampering

    Supports two modes:
    1. Password mode: encrypted_password is None, uses password directly
    2. RSA mode: encrypted_password is provided (encryption) or private_key is provided (decryption)

    :param target_filepaths: Path(s) to file(s) to encrypt or decrypt. Can be a string or list.
    :type target_filepaths: str or list[str]
    :param password: Password for encryption/decryption.
    :type password: str or None
    :param encrypted_password: RSA-encrypted password bytes (for RSA encryption mode).
    :type encrypted_password: bytes or None
    :param private_key: RSA private key for decrypting password (for RSA decryption mode).
    :type private_key: rsa.RSAPrivateKey or None
    :param decrypt: If True, decrypt the file; if False, encrypt it.
    :type decrypt: bool
    :return: Path to the output file.
    :rtype: str
    """
    if decrypt:
        if isinstance(target_filepaths, list):
            target_filepath = target_filepaths[0]
        else:
            target_filepath = target_filepaths

        target_filename = os.path.basename(target_filepath)
        final_path = target_filename.split(".prnd")[0] + ".tar.gz"

        if private_key:
            decrypt_file(target_filepath, final_path, private_key=private_key)
        else:
            decrypt_file(target_filepath, final_path, password=password)
    else:
        tar_filename = create_tar_archive(target_filepaths)
        final_path = tar_filename + ".prnd"
        encrypt_file(tar_filename, final_path, password, encrypted_password)
        os.remove(tar_filename)

    return final_path


# --------------------------------------------------------------------------------------------


def encrypt_file(input_path, output_path, password, encrypted_password):
    """
    Encrypt a file using AES-256-GCM with Argon2id.

    File format (RSA mode):
    - Encrypted password length (4 bytes) - non-zero value
    - Encrypted password (variable length)
    - Salt (32 bytes)
    - Nonce (12 bytes)
    - Encrypted data
    - Authentication tag (16 bytes)

    File format (Password mode):
    - Encrypted password length (4 bytes) - zero value (indicates password mode)
    - Salt (32 bytes)
    - Nonce (12 bytes)
    - Encrypted data
    - Authentication tag (16 bytes)

    :param input_path: Path to the file to encrypt.
    :type input_path: str
    :param output_path: Path to the file to write the encrypted data.
    :type output_path: str
    :param password: Password for encryption.
    :type password: str
    :param encrypted_password: RSA-encrypted password bytes (None for password mode).
    :type encrypted_password: bytes or None
    """
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_path, "rb") as input_file, open(output_path, "wb") as output_file:
        if encrypted_password:
            encrypted_password_len = len(encrypted_password)
            output_file.write(struct.pack(">I", encrypted_password_len))
            output_file.write(encrypted_password)
        else:
            output_file.write(struct.pack(">I", 0))

        output_file.write(salt)
        output_file.write(nonce)

        while chunk := input_file.read(CHUNK_SIZE):
            output_file.write(encryptor.update(chunk))

        output_file.write(encryptor.finalize())
        output_file.write(encryptor.tag)


# --------------------------------------------------------------------------------------------


def decrypt_file(input_path, output_path, password=None, private_key=None):
    """
    Decrypt a file using AES-256-GCM with Argon2id.

    Supports two modes:
    1. Password mode: Uses provided password directly
    2. RSA mode: Decrypts password using RSA private key

    File format (RSA mode):
    - Encrypted password length (4 bytes) - non-zero value
    - Encrypted password (variable length)
    - Salt (32 bytes)
    - Nonce (12 bytes)
    - Encrypted data
    - Authentication tag (16 bytes)

    File format (Password mode):
    - Encrypted password length (4 bytes) - zero value
    - Salt (32 bytes)
    - Nonce (12 bytes)
    - Encrypted data
    - Authentication tag (16 bytes)

    :param input_path: Path to the file to decrypt.
    :type input_path: str
    :param output_path: Path to the file to write the decrypted data.
    :type output_path: str
    :param password: Password for decryption (password mode).
    :type password: str or None
    :param private_key: RSA private key for decrypting the password (RSA mode).
    :type private_key: rsa.RSAPrivateKey or None
    """
    with open(input_path, "rb") as input_file:
        encrypted_password_len_bytes = input_file.read(4)
        encrypted_password_len = struct.unpack(">I", encrypted_password_len_bytes)[0]

        if encrypted_password_len > 0:
            if not private_key:
                raise ValueError(
                    "File was encrypted with RSA mode but no private key provided"
                )
            encrypted_password = input_file.read(encrypted_password_len)
            password = decrypt_password_with_rsa(encrypted_password, private_key)
        else:
            if not password:
                raise ValueError(
                    "File was encrypted with password mode but no password provided"
                )

        salt = input_file.read(SALT_SIZE)
        nonce = input_file.read(NONCE_SIZE)

        input_file.seek(0, os.SEEK_END)
        file_size = input_file.tell()
        tag_pos = file_size - TAG_SIZE

        input_file.seek(tag_pos)
        tag = input_file.read(TAG_SIZE)

        key = derive_key(password, salt)
        cipher = Cipher(
            algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
        )
        decryptor = cipher.decryptor()

        data_start = 4 + encrypted_password_len + SALT_SIZE + NONCE_SIZE
        input_file.seek(data_start)
        remaining = tag_pos - data_start

        with open(output_path, "wb") as output_file:
            while remaining > 0:
                chunk = input_file.read(min(CHUNK_SIZE, remaining))
                remaining -= len(chunk)
                output_file.write(decryptor.update(chunk))

            output_file.write(decryptor.finalize())
