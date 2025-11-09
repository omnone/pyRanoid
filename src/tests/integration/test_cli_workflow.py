"""
Integration tests for pyRanoid CLI workflows.

Tests complete command-line interface workflows from start to finish for both
password mode and RSA mode.
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

test_dir = os.path.dirname(__file__)
src_dir = "../../"
sys.path.insert(0, os.path.abspath(os.path.join(test_dir, src_dir)))

import pyRanoid.utils as utils
from pyRanoid import cli


@pytest.mark.integration
class TestCLIIntegrationPasswordMode:
    """Integration tests for CLI commands with password mode."""

    def test_full_encrypt_workflow_password(self, test_image, test_text_file, temp_dir):
        """Test full encryption workflow through CLI with password mode."""
        output_path = os.path.join(temp_dir, "encrypted.png")

        args = MagicMock()
        args.image = test_image
        args.target = test_text_file
        args.output = output_path
        args.password = "TestPass123!"
        args.public_key = None

        cli.encrypt_command(args)

        assert os.path.exists(output_path)

    def test_full_decrypt_workflow_password(self, test_image, test_text_file, temp_dir):
        """Test full decryption workflow through CLI with password mode."""
        encrypted_path = os.path.join(temp_dir, "encrypted.png")
        output_dir = os.path.join(temp_dir, "decrypted")
        os.makedirs(output_dir, exist_ok=True)

        password = "TestPass123!"

        utils.encrypt_image(
            test_image, [test_text_file], encrypted_path, password=password
        )

        args = MagicMock()
        args.image = encrypted_path
        args.output_dir = output_dir
        args.password = password
        args.private_key = None

        cli.decrypt_command(args)

        extracted_file = os.path.join(output_dir, os.path.basename(test_text_file))
        assert os.path.exists(extracted_file)

    def test_encrypt_with_provided_password(self, test_image, test_text_file, temp_dir):
        """Test encryption with password provided as argument."""
        output_path = os.path.join(temp_dir, "encrypted.png")

        args = MagicMock()
        args.image = test_image
        args.target = test_text_file
        args.output = output_path
        args.password = "DirectPassword123!"
        args.public_key = None

        cli.encrypt_command(args)

        assert os.path.exists(output_path)

    def test_decrypt_with_provided_password(self, test_image, test_text_file, temp_dir):
        """Test decryption with password provided as argument."""
        encrypted_path = os.path.join(temp_dir, "encrypted.png")
        output_dir = os.path.join(temp_dir, "decrypted")
        os.makedirs(output_dir, exist_ok=True)

        password = "DirectPassword123!"

        utils.encrypt_image(
            test_image, [test_text_file], encrypted_path, password=password
        )

        args = MagicMock()
        args.image = encrypted_path
        args.output_dir = output_dir
        args.password = password
        args.private_key = None

        cli.decrypt_command(args)

        extracted_file = os.path.join(output_dir, os.path.basename(test_text_file))
        assert os.path.exists(extracted_file)

    def test_encrypt_decrypt_roundtrip_via_cli_password(
        self, test_image, test_text_file, temp_dir
    ):
        """Test complete encrypt and decrypt roundtrip via CLI with password mode."""
        password = "RoundtripPass123!"

        encrypted_path = os.path.join(temp_dir, "encrypted.png")
        output_dir = os.path.join(temp_dir, "decrypted")
        os.makedirs(output_dir, exist_ok=True)

        encrypt_args = MagicMock()
        encrypt_args.image = test_image
        encrypt_args.target = test_text_file
        encrypt_args.output = encrypted_path
        encrypt_args.password = password
        encrypt_args.public_key = None

        cli.encrypt_command(encrypt_args)
        assert os.path.exists(encrypted_path)

        decrypt_args = MagicMock()
        decrypt_args.image = encrypted_path
        decrypt_args.output_dir = output_dir
        decrypt_args.password = password
        decrypt_args.private_key = None

        cli.decrypt_command(decrypt_args)

        extracted_file = os.path.join(output_dir, os.path.basename(test_text_file))
        assert os.path.exists(extracted_file)

        with open(test_text_file, "r") as original:
            with open(extracted_file, "r") as extracted:
                assert original.read() == extracted.read()

    def test_cli_with_binary_file_password(
        self, test_image, test_binary_file, temp_dir
    ):
        """Test CLI with binary file encryption using password mode."""
        encrypted_path = os.path.join(temp_dir, "encrypted.png")
        output_dir = os.path.join(temp_dir, "decrypted")
        os.makedirs(output_dir, exist_ok=True)

        password = "BinaryPass123!"

        encrypt_args = MagicMock()
        encrypt_args.image = test_image
        encrypt_args.target = test_binary_file
        encrypt_args.output = encrypted_path
        encrypt_args.password = password
        encrypt_args.public_key = None

        cli.encrypt_command(encrypt_args)

        decrypt_args = MagicMock()
        decrypt_args.image = encrypted_path
        decrypt_args.output_dir = output_dir
        decrypt_args.password = password
        decrypt_args.private_key = None

        cli.decrypt_command(decrypt_args)

        extracted_file = os.path.join(output_dir, os.path.basename(test_binary_file))
        assert os.path.exists(extracted_file)

        with open(test_binary_file, "rb") as original:
            with open(extracted_file, "rb") as extracted:
                assert original.read() == extracted.read()

    def test_cli_error_handling_wrong_password(
        self, test_image, test_text_file, temp_dir
    ):
        """Test CLI error handling with wrong password."""
        encrypted_path = os.path.join(temp_dir, "encrypted.png")
        output_dir = os.path.join(temp_dir, "decrypted")
        os.makedirs(output_dir, exist_ok=True)

        utils.encrypt_image(
            test_image, [test_text_file], encrypted_path, password="CorrectPass123!"
        )

        decrypt_args = MagicMock()
        decrypt_args.image = encrypted_path
        decrypt_args.output_dir = output_dir
        decrypt_args.password = "WrongPass123!"
        decrypt_args.private_key = None

        with pytest.raises(SystemExit):
            cli.decrypt_command(decrypt_args)


@pytest.mark.integration
class TestCLIIntegrationRSAMode:
    """Integration tests for CLI commands with RSA mode."""

    def test_full_encrypt_workflow_rsa(
        self, test_image, test_text_file, temp_dir, rsa_keypair
    ):
        """Test full encryption workflow through CLI with RSA mode."""
        output_path = os.path.join(temp_dir, "encrypted_rsa.png")

        args = MagicMock()
        args.image = test_image
        args.target = test_text_file
        args.output = output_path
        args.password = None
        args.public_key = rsa_keypair["public_key_path"]

        cli.encrypt_command(args)

        assert os.path.exists(output_path)

    @patch("getpass.getpass", return_value="")
    def test_full_decrypt_workflow_rsa(
        self, mock_getpass, test_image, test_text_file, temp_dir, rsa_keypair
    ):
        """Test full decryption workflow through CLI with RSA mode."""
        encrypted_path = os.path.join(temp_dir, "encrypted_rsa.png")
        output_dir = os.path.join(temp_dir, "decrypted_rsa")
        os.makedirs(output_dir, exist_ok=True)

        utils.encrypt_image(
            test_image,
            [test_text_file],
            encrypted_path,
            rsa_public_key_path=rsa_keypair["public_key_path"],
        )

        assert os.path.exists(encrypted_path), (
            f"Encrypted image not created at {encrypted_path}"
        )

        args = MagicMock()
        args.image = encrypted_path
        args.output_dir = output_dir
        args.password = None
        args.private_key = rsa_keypair["private_key_path"]
        args.key_password = None

        cli.decrypt_command(args)

        extracted_file = os.path.join(output_dir, os.path.basename(test_text_file))
        assert os.path.exists(extracted_file)

    @patch("getpass.getpass", return_value="")
    def test_encrypt_decrypt_roundtrip_via_cli_rsa(
        self, mock_getpass, test_image, test_text_file, temp_dir, rsa_keypair
    ):
        """Test complete encrypt and decrypt roundtrip via CLI with RSA mode."""
        encrypted_path = os.path.join(temp_dir, "encrypted_roundtrip_rsa.png")
        output_dir = os.path.join(temp_dir, "decrypted_roundtrip_rsa")
        os.makedirs(output_dir, exist_ok=True)

        encrypt_args = MagicMock()
        encrypt_args.image = test_image
        encrypt_args.target = test_text_file
        encrypt_args.output = encrypted_path
        encrypt_args.password = None
        encrypt_args.public_key = rsa_keypair["public_key_path"]

        cli.encrypt_command(encrypt_args)
        assert os.path.exists(encrypted_path)

        decrypt_args = MagicMock()
        decrypt_args.image = encrypted_path
        decrypt_args.output_dir = output_dir
        decrypt_args.password = None
        decrypt_args.private_key = rsa_keypair["private_key_path"]
        decrypt_args.key_password = None

        cli.decrypt_command(decrypt_args)

        extracted_file = os.path.join(output_dir, os.path.basename(test_text_file))
        assert os.path.exists(extracted_file)

        with open(test_text_file, "r") as original:
            with open(extracted_file, "r") as extracted:
                assert original.read() == extracted.read()
