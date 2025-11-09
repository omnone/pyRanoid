"""
Unit tests for pyRanoid utils module.

Tests all utility functions including:
- Binary conversion functions
- Cryptographic functions
- Tar archive operations
"""

import os
import sys
import tarfile
from unittest.mock import MagicMock

import pytest

test_dir = os.path.dirname(__file__)
src_dir = "../../"
sys.path.insert(0, os.path.abspath(os.path.join(test_dir, src_dir)))

import pyRanoid.utils as utils  # noqa: E402


class TestConversionFunctions:
    """Test binary conversion functions."""

    def test_file_to_bin(self, test_text_file):
        """Test converting a file to binary string."""
        result = utils.file_to_bin(test_text_file)

        assert isinstance(result, str)
        assert all(c in "01" for c in result)

        with open(test_text_file, "rb") as f:
            file_size = len(f.read())
        assert len(result) == file_size * 8

    def test_str_to_bin(self):
        """Test converting a string to binary."""
        test_str = "Hello"
        result = utils.str_to_bin(test_str)

        assert isinstance(result, str)
        assert all(c in "01" for c in result)
        assert len(result) == len(test_str) * 8
        assert utils.str_to_bin("A") == "01000001"

    def test_int_to_bin(self):
        """Test converting an integer to binary."""
        assert utils.int_to_bin(0) == "0"
        assert utils.int_to_bin(1) == "1"
        assert utils.int_to_bin(5) == "101"
        assert utils.int_to_bin(255) == "11111111"


class TestTarArchiveFunctions:
    """Test tar archive creation and extraction."""

    def test_create_tar_archive(self, test_text_file, temp_dir):
        """Test creating a tar archive."""
        original_dir = os.getcwd()
        os.chdir(temp_dir)

        try:
            tar_filename = "test_archive.tar.gz"
            archive_path = utils.create_tar_archive(test_text_file, tar_filename)

            assert os.path.exists(archive_path)

            with tarfile.open(archive_path, "r") as tar:
                members = tar.getnames()
                assert os.path.basename(test_text_file) in members
        finally:
            os.chdir(original_dir)

    def test_get_tar_archive_files(self, test_text_file, temp_dir):
        """Test getting files from a tar archive."""
        original_dir = os.getcwd()
        os.chdir(temp_dir)

        try:
            tar_filename = "test_file.tar.gz"
            archive_path = utils.create_tar_archive(test_text_file, tar_filename)

            files = utils.get_tar_archive_files(archive_path)

            assert isinstance(files, list)
            assert os.path.basename(test_text_file) in files
        finally:
            os.chdir(original_dir)

    def test_extract_tar_archive(self, test_text_file, temp_dir):
        """Test extracting a tar archive."""
        original_dir = os.getcwd()
        os.chdir(temp_dir)

        try:
            tar_filename = "extracted_file.tar.gz"
            archive_path = utils.create_tar_archive(test_text_file, tar_filename)

            output_dir = os.path.join(temp_dir, "extracted")
            os.makedirs(output_dir, exist_ok=True)

            utils.extract_tar_archive(archive_path, output_dir)

            extracted_file = os.path.join(output_dir, os.path.basename(test_text_file))
            assert os.path.exists(extracted_file)

            with open(test_text_file, "r") as original:
                with open(extracted_file, "r") as extracted:
                    assert original.read() == extracted.read()
        finally:
            os.chdir(original_dir)


class TestRSAFunctions:
    """Test RSA key generation and encryption/decryption functions."""

    def test_generate_rsa_keypair(self):
        """Test RSA key pair generation."""
        private_key, public_key = utils.generate_rsa_keypair()

        assert private_key is not None
        assert public_key is not None
        assert private_key.key_size == utils.RSA_KEY_SIZE

    def test_save_and_load_private_key(self, temp_dir):
        """Test saving and loading RSA private key without password."""
        private_key, _ = utils.generate_rsa_keypair()
        key_path = os.path.join(temp_dir, "private_key.pem")

        utils.save_private_key(private_key, key_path)
        assert os.path.exists(key_path)

        loaded_key = utils.load_private_key(key_path)
        assert loaded_key is not None
        assert loaded_key.key_size == private_key.key_size

    def test_save_and_load_private_key_with_password(self, temp_dir):
        """Test saving and loading RSA private key with password."""
        private_key, _ = utils.generate_rsa_keypair()
        key_path = os.path.join(temp_dir, "private_key_encrypted.pem")
        password = "SecureKeyPassword123!"

        utils.save_private_key(private_key, key_path, password)
        assert os.path.exists(key_path)

        loaded_key = utils.load_private_key(key_path, password)
        assert loaded_key is not None
        assert loaded_key.key_size == private_key.key_size

    def test_save_and_load_public_key(self, temp_dir):
        """Test saving and loading RSA public key."""
        _, public_key = utils.generate_rsa_keypair()
        key_path = os.path.join(temp_dir, "public_key.pem")

        utils.save_public_key(public_key, key_path)
        assert os.path.exists(key_path)

        loaded_key = utils.load_public_key(key_path)
        assert loaded_key is not None
        assert loaded_key.key_size == public_key.key_size

    def test_generate_random_password(self):
        """Test random password generation."""
        password1 = utils.generate_random_password()
        password2 = utils.generate_random_password()

        assert isinstance(password1, str)
        assert isinstance(password2, str)
        assert (
            len(password1) == utils.PASSWORD_LENGTH * 2
        )  # Hex encoding doubles length
        assert password1 != password2

    def test_encrypt_decrypt_password_with_rsa(self):
        """Test RSA password encryption and decryption."""
        private_key, public_key = utils.generate_rsa_keypair()
        original_password = "TestPassword123!"

        encrypted_password = utils.encrypt_password_with_rsa(
            original_password, public_key
        )
        assert isinstance(encrypted_password, bytes)
        assert len(encrypted_password) > 0

        decrypted_password = utils.decrypt_password_with_rsa(
            encrypted_password, private_key
        )
        assert decrypted_password == original_password


class TestCryptographicFunctions:
    """Test encryption and key derivation functions."""

    def test_derive_key(self):
        """Test key derivation with Argon2id."""
        password = "TestPassword123"
        salt = os.urandom(utils.SALT_SIZE)

        key = utils.derive_key(password, salt)

        assert isinstance(key, bytes)
        assert len(key) == utils.KEY_SIZE

        key2 = utils.derive_key(password, salt)
        assert key == key2

        salt2 = os.urandom(utils.SALT_SIZE)
        key3 = utils.derive_key(password, salt2)
        assert key != key3

    def test_encrypt_decrypt_file_rsa_mode(self, test_text_file, temp_dir):
        """Test file encryption and decryption with RSA mode."""
        private_key, public_key = utils.generate_rsa_keypair()
        password = "SecurePassword123!"
        encrypted_password = utils.encrypt_password_with_rsa(password, public_key)

        encrypted_path = os.path.join(temp_dir, "encrypted.bin")
        decrypted_path = os.path.join(temp_dir, "decrypted.txt")

        utils.encrypt_file(test_text_file, encrypted_path, password, encrypted_password)
        assert os.path.exists(encrypted_path)

        original_size = os.path.getsize(test_text_file)
        encrypted_size = os.path.getsize(encrypted_path)
        assert encrypted_size > original_size

        utils.decrypt_file(encrypted_path, decrypted_path, private_key=private_key)
        assert os.path.exists(decrypted_path)

        with open(test_text_file, "rb") as original:
            with open(decrypted_path, "rb") as decrypted:
                assert original.read() == decrypted.read()

    def test_encrypt_decrypt_file_password_mode(self, test_text_file, temp_dir):
        """Test file encryption and decryption with password mode."""
        password = "SecurePassword123!"

        encrypted_path = os.path.join(temp_dir, "encrypted_pwd.bin")
        decrypted_path = os.path.join(temp_dir, "decrypted_pwd.txt")

        utils.encrypt_file(
            test_text_file, encrypted_path, password, encrypted_password=None
        )
        assert os.path.exists(encrypted_path)

        original_size = os.path.getsize(test_text_file)
        encrypted_size = os.path.getsize(encrypted_path)
        assert encrypted_size > original_size

        utils.decrypt_file(encrypted_path, decrypted_path, password=password)
        assert os.path.exists(decrypted_path)

        with open(test_text_file, "rb") as original:
            with open(decrypted_path, "rb") as decrypted:
                assert original.read() == decrypted.read()

    def test_decrypt_with_wrong_password(self, test_text_file, temp_dir):
        """Test that decryption fails with wrong password."""
        password = "CorrectPassword123!"
        wrong_password = "WrongPassword456!"

        encrypted_path = os.path.join(temp_dir, "encrypted.bin")
        decrypted_path = os.path.join(temp_dir, "decrypted.txt")

        utils.encrypt_file(
            test_text_file, encrypted_path, password, encrypted_password=None
        )

        with pytest.raises(Exception):
            utils.decrypt_file(encrypted_path, decrypted_path, password=wrong_password)

    def test_decrypt_with_wrong_key(self, test_text_file, temp_dir):
        """Test that decryption fails with wrong RSA key."""
        private_key1, public_key1 = utils.generate_rsa_keypair()
        private_key2, _ = utils.generate_rsa_keypair()

        password = "CorrectPassword123!"
        encrypted_password = utils.encrypt_password_with_rsa(password, public_key1)

        encrypted_path = os.path.join(temp_dir, "encrypted.bin")
        decrypted_path = os.path.join(temp_dir, "decrypted.txt")

        utils.encrypt_file(test_text_file, encrypted_path, password, encrypted_password)

        with pytest.raises(Exception):
            utils.decrypt_file(encrypted_path, decrypted_path, private_key=private_key2)

    def test_encryption_handler_encrypt(self, test_text_file, temp_dir):
        """Test encryption handler in encrypt mode with RSA."""
        private_key, public_key = utils.generate_rsa_keypair()
        password = "TestPass123!"
        encrypted_password = utils.encrypt_password_with_rsa(password, public_key)

        original_dir = os.getcwd()
        os.chdir(temp_dir)

        try:
            result_path = utils.encryption_handler(
                test_text_file,
                password,
                encrypted_password=encrypted_password,
                decrypt=False,
            )

            assert os.path.exists(result_path)
            assert result_path.endswith(".prnd")
        finally:
            os.chdir(original_dir)

    def test_encryption_handler_decrypt(self, test_text_file, temp_dir):
        """Test encryption handler in decrypt mode with RSA."""
        private_key, public_key = utils.generate_rsa_keypair()
        password = "TestPass123!"
        encrypted_password = utils.encrypt_password_with_rsa(password, public_key)

        original_dir = os.getcwd()
        os.chdir(temp_dir)

        try:
            encrypted_path = utils.encryption_handler(
                test_text_file,
                password,
                encrypted_password=encrypted_password,
                decrypt=False,
            )
            assert os.path.exists(encrypted_path)

            decrypted_path = utils.encryption_handler(
                encrypted_path, None, private_key=private_key, decrypt=True
            )
            assert os.path.exists(decrypted_path)
            assert decrypted_path.endswith(".tar.gz")
        finally:
            os.chdir(original_dir)


class TestConstants:
    """Test that constants are properly defined."""

    def test_constants_defined(self):
        """Test that all required constants are defined."""
        assert hasattr(utils, "CHUNK_SIZE")
        assert hasattr(utils, "HEADER_SIZE")
        assert hasattr(utils, "SALT_SIZE")
        assert hasattr(utils, "NONCE_SIZE")
        assert hasattr(utils, "TAG_SIZE")
        assert hasattr(utils, "KEY_SIZE")
        assert hasattr(utils, "ARGON2_TIME_COST")
        assert hasattr(utils, "ARGON2_MEMORY_COST")
        assert hasattr(utils, "ARGON2_PARALLELISM")
        assert hasattr(utils, "MAGIC_BYTES")
        assert hasattr(utils, "VERSION")

    def test_constants_values(self):
        """Test that constants have sensible values."""
        assert utils.CHUNK_SIZE > 0
        assert utils.HEADER_SIZE == 32
        assert utils.SALT_SIZE == 32
        assert utils.NONCE_SIZE == 12
        assert utils.TAG_SIZE == 16
        assert utils.KEY_SIZE == 32
        assert utils.ARGON2_TIME_COST > 0
        assert utils.ARGON2_MEMORY_COST > 0
        assert utils.ARGON2_PARALLELISM > 0
        assert utils.MAGIC_BYTES == b"PRND"
        assert utils.VERSION == 1

    def test_file_path_constants(self):
        """Test file path constants."""
        assert utils.TAR_FILE_PATH == "output.tar.gz"
        assert utils.FINAL_PNG_PATH == "output.png"
        assert utils.ENCR_FILE_PATH == "output.prnd"


class TestImageEncryptionDecryption:
    """Test end-to-end image encryption and decryption."""

    def test_encrypt_decrypt_image_password_mode(
        self, test_image, test_text_file, temp_dir
    ):
        """Test encrypting and decrypting with password mode."""
        password = "StrongPassword123!"
        output_image = os.path.join(temp_dir, "encrypted_image.png")

        utils.encrypt_image(
            test_image, [test_text_file], output_image, password=password
        )
        assert os.path.exists(output_image)

        output_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(output_dir, exist_ok=True)

        extracted_files = utils.decrypt_image(
            output_image, output_dir=output_dir, password=password
        )
        assert len(extracted_files) > 0
        assert os.path.basename(test_text_file) in extracted_files

        extracted_file_path = os.path.join(output_dir, os.path.basename(test_text_file))
        assert os.path.exists(extracted_file_path)

        with open(test_text_file, "r") as original:
            with open(extracted_file_path, "r") as extracted:
                assert original.read() == extracted.read()

    def test_encrypt_decrypt_image_rsa_mode(self, test_image, test_text_file, temp_dir):
        """Test encrypting and decrypting with RSA mode."""
        private_key, public_key = utils.generate_rsa_keypair()
        private_key_path = os.path.join(temp_dir, "private.pem")
        public_key_path = os.path.join(temp_dir, "public.pem")

        utils.save_private_key(private_key, private_key_path)
        utils.save_public_key(public_key, public_key_path)

        output_image = os.path.join(temp_dir, "encrypted_image_rsa.png")

        utils.encrypt_image(
            test_image,
            [test_text_file],
            output_image,
            rsa_public_key_path=public_key_path,
        )
        assert os.path.exists(output_image)

        output_dir = os.path.join(temp_dir, "extracted_rsa")
        os.makedirs(output_dir, exist_ok=True)

        extracted_files = utils.decrypt_image(
            output_image, output_dir=output_dir, rsa_private_key_path=private_key_path
        )
        assert len(extracted_files) > 0
        assert os.path.basename(test_text_file) in extracted_files

        extracted_file_path = os.path.join(output_dir, os.path.basename(test_text_file))
        assert os.path.exists(extracted_file_path)

        with open(test_text_file, "r") as original:
            with open(extracted_file_path, "r") as extracted:
                assert original.read() == extracted.read()

    def test_encrypt_decrypt_multiple_files_password_mode(
        self, test_image, test_text_file, test_binary_file, temp_dir
    ):
        """Test encrypting and decrypting multiple files with password mode."""
        password = "MultiFilePassword123!"
        output_image = os.path.join(temp_dir, "multi_encrypted.png")

        utils.encrypt_image(
            test_image,
            [test_text_file, test_binary_file],
            output_image,
            password=password,
        )
        assert os.path.exists(output_image)

        output_dir = os.path.join(temp_dir, "multi_extracted")
        os.makedirs(output_dir, exist_ok=True)

        extracted_files = utils.decrypt_image(
            output_image, output_dir=output_dir, password=password
        )
        assert len(extracted_files) == 2
        assert os.path.basename(test_text_file) in extracted_files
        assert os.path.basename(test_binary_file) in extracted_files

    def test_encrypt_decrypt_multiple_files_rsa_mode(
        self, test_image, test_text_file, test_binary_file, temp_dir
    ):
        """Test encrypting and decrypting multiple files with RSA mode."""
        private_key, public_key = utils.generate_rsa_keypair()
        private_key_path = os.path.join(temp_dir, "private_multi.pem")
        public_key_path = os.path.join(temp_dir, "public_multi.pem")

        utils.save_private_key(private_key, private_key_path)
        utils.save_public_key(public_key, public_key_path)

        output_image = os.path.join(temp_dir, "multi_encrypted_rsa.png")

        utils.encrypt_image(
            test_image,
            [test_text_file, test_binary_file],
            output_image,
            rsa_public_key_path=public_key_path,
        )
        assert os.path.exists(output_image)

        output_dir = os.path.join(temp_dir, "multi_extracted_rsa")
        os.makedirs(output_dir, exist_ok=True)

        extracted_files = utils.decrypt_image(
            output_image, output_dir=output_dir, rsa_private_key_path=private_key_path
        )
        assert len(extracted_files) == 2
        assert os.path.basename(test_text_file) in extracted_files
        assert os.path.basename(test_binary_file) in extracted_files

    def test_encrypt_image_requires_auth(self, test_image, test_text_file, temp_dir):
        """Test that encrypt_image requires either password or RSA key."""
        output_image = os.path.join(temp_dir, "output.png")

        with pytest.raises(ValueError):
            utils.encrypt_image(test_image, [test_text_file], output_image)

    def test_decrypt_image_requires_auth(self, test_image, temp_dir):
        """Test that decrypt_image requires either password or RSA key."""
        output_dir = os.path.join(temp_dir, "output")
        os.makedirs(output_dir, exist_ok=True)

        with pytest.raises(ValueError):
            utils.decrypt_image(test_image, output_dir=output_dir)
