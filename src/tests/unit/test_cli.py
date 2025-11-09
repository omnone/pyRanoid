"""
Unit tests for pyRanoid CLI module.

Tests all CLI functions including:
- Banner printing
- Path validation
- Password input
- Command parsing
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

test_dir = os.path.dirname(__file__)
src_dir = "../../"
sys.path.insert(0, os.path.abspath(os.path.join(test_dir, src_dir)))

from pyRanoid import cli  # noqa: E402


class TestBanner:
    """Test banner printing."""

    def test_print_banner(self, capsys):
        """Test that banner prints without errors."""
        cli.print_banner()
        captured = capsys.readouterr()
        assert "pyRanoid" in captured.out
        assert "github.com/omnone/pyRanoid" in captured.out


class TestValidation:
    """Test path validation functions."""

    def test_validate_path_exists(self, test_text_file):
        """Test validating an existing path."""
        result = cli.validate_path(test_text_file, must_exist=True)
        assert result == test_text_file

    def test_validate_path_not_exists(self, temp_dir):
        """Test validating a non-existent path with must_exist=True."""
        non_existent = os.path.join(temp_dir, "does_not_exist.txt")

        with pytest.raises(SystemExit):
            cli.validate_path(non_existent, must_exist=True)

    def test_validate_path_not_exists_optional(self, temp_dir):
        """Test validating a non-existent path with must_exist=False."""
        non_existent = os.path.join(temp_dir, "does_not_exist.txt")
        result = cli.validate_path(non_existent, must_exist=False)
        assert result == non_existent


class TestPasswordInput:
    """Test password input functions."""

    @patch("getpass.getpass")
    def test_get_password_no_verify(self, mock_getpass):
        """Test getting password without verification."""
        mock_getpass.return_value = "TestPassword123"

        password = cli.get_password(verify=False)

        assert password == "TestPassword123"
        assert mock_getpass.call_count == 1

    @patch("getpass.getpass")
    def test_get_password_with_verify_match(self, mock_getpass):
        """Test getting password with verification when passwords match."""
        mock_getpass.side_effect = ["TestPassword123", "TestPassword123"]

        password = cli.get_password(verify=True)

        assert password == "TestPassword123"
        assert mock_getpass.call_count == 2

    @patch("getpass.getpass")
    def test_get_password_with_verify_mismatch(self, mock_getpass):
        """Test getting password with verification when passwords don't match."""
        mock_getpass.side_effect = ["TestPassword123", "DifferentPassword"]

        with pytest.raises(SystemExit):
            cli.get_password(verify=True)


class TestEncryptCommand:
    """Test the encrypt command."""

    @patch("pyRanoid.cli.encrypt_image")
    def test_encrypt_command_success_password_mode(
        self, mock_encrypt, test_image, test_text_file, temp_dir
    ):
        """Test successful encryption command with password mode."""
        mock_encrypt.return_value = None

        output_path = os.path.join(temp_dir, "output.png")

        args = MagicMock()
        args.image = test_image
        args.target = test_text_file
        args.output = output_path
        args.password = "TestPassword123!"
        args.public_key = None

        cli.encrypt_command(args)

        mock_encrypt.assert_called_once()

    @patch("pyRanoid.cli.encrypt_image")
    def test_encrypt_command_success_rsa_mode(
        self, mock_encrypt, test_image, test_text_file, temp_dir, rsa_keypair
    ):
        """Test successful encryption command with RSA mode."""
        mock_encrypt.return_value = None

        output_path = os.path.join(temp_dir, "output.png")

        args = MagicMock()
        args.image = test_image
        args.target = test_text_file
        args.output = output_path
        args.password = None
        args.public_key = rsa_keypair["public_key_path"]

        cli.encrypt_command(args)

        mock_encrypt.assert_called_once()

    @patch("pyRanoid.cli.get_password")
    def test_encrypt_command_invalid_image(self, mock_get_password, temp_dir):
        """Test encrypt command with invalid image path."""
        args = MagicMock()
        args.image = os.path.join(temp_dir, "nonexistent.png")
        args.target = "somefile.txt"
        args.password = "test"
        args.public_key = None

        with pytest.raises(SystemExit):
            cli.encrypt_command(args)

    @patch("pyRanoid.cli.get_password")
    def test_encrypt_command_invalid_target(
        self, mock_get_password, test_image, temp_dir
    ):
        """Test encrypt command with invalid target file."""
        args = MagicMock()
        args.image = test_image
        args.target = os.path.join(temp_dir, "nonexistent.txt")
        args.password = "test"
        args.public_key = None

        with pytest.raises(SystemExit):
            cli.encrypt_command(args)

    @patch("pyRanoid.cli.encrypt_image")
    def test_encrypt_command_with_password_arg(
        self, mock_encrypt, test_image, test_text_file, temp_dir
    ):
        """Test encrypt command with password provided as argument."""
        mock_encrypt.return_value = None

        output_path = os.path.join(temp_dir, "output.png")

        args = MagicMock()
        args.image = test_image
        args.target = test_text_file
        args.output = output_path
        args.password = "ProvidedPassword123!"
        args.public_key = None

        cli.encrypt_command(args)

        mock_encrypt.assert_called_once()

    @patch("pyRanoid.cli.get_password")
    @patch("pyRanoid.cli.encrypt_image")
    def test_encrypt_command_exception_handling(
        self, mock_encrypt, mock_get_password, test_image, test_text_file, temp_dir
    ):
        """Test encrypt command handles exceptions properly."""
        mock_get_password.return_value = "TestPassword123!"
        mock_encrypt.side_effect = Exception("Encryption failed")

        output_path = os.path.join(temp_dir, "output.png")

        args = MagicMock()
        args.image = test_image
        args.target = test_text_file
        args.output = output_path
        args.password = None

        with pytest.raises(SystemExit):
            cli.encrypt_command(args)


class TestDecryptCommand:
    """Test the decrypt command."""

    @patch("pyRanoid.cli.decrypt_image")
    def test_decrypt_command_success_password_mode(
        self, mock_decrypt, test_image, temp_dir
    ):
        """Test successful decryption command with password mode."""
        mock_decrypt.return_value = ["extracted_file.txt"]

        output_dir = os.path.join(temp_dir, "output")
        os.makedirs(output_dir, exist_ok=True)

        args = MagicMock()
        args.image = test_image
        args.output_dir = output_dir
        args.password = "TestPassword123!"
        args.private_key = None

        cli.decrypt_command(args)

        mock_decrypt.assert_called_once()

    @patch("pyRanoid.cli.decrypt_image")
    def test_decrypt_command_success_rsa_mode(
        self, mock_decrypt, test_image, temp_dir, rsa_keypair
    ):
        """Test successful decryption command with RSA mode."""
        mock_decrypt.return_value = ["extracted_file.txt"]

        output_dir = os.path.join(temp_dir, "output")
        os.makedirs(output_dir, exist_ok=True)

        args = MagicMock()
        args.image = test_image
        args.output_dir = output_dir
        args.password = None
        args.private_key = rsa_keypair["private_key_path"]

        cli.decrypt_command(args)

        mock_decrypt.assert_called_once()

    @patch("pyRanoid.cli.get_password")
    def test_decrypt_command_invalid_image(self, mock_get_password, temp_dir):
        """Test decrypt command with invalid image path."""
        args = MagicMock()
        args.image = os.path.join(temp_dir, "nonexistent.png")
        args.output_dir = temp_dir
        args.password = "test"
        args.private_key = None

        with pytest.raises(SystemExit):
            cli.decrypt_command(args)

    @patch("pyRanoid.cli.decrypt_image")
    def test_decrypt_command_creates_output_dir(
        self, mock_decrypt, test_image, temp_dir
    ):
        """Test decrypt command creates output directory if it doesn't exist."""
        mock_decrypt.return_value = ["file.txt"]

        output_dir = os.path.join(temp_dir, "new_output_dir")

        args = MagicMock()
        args.image = test_image
        args.output_dir = output_dir
        args.password = "TestPassword123!"
        args.private_key = None

        cli.decrypt_command(args)

        assert os.path.exists(output_dir)

    @patch("pyRanoid.cli.decrypt_image")
    def test_decrypt_command_with_password_arg(
        self, mock_decrypt, test_image, temp_dir
    ):
        """Test decrypt command with password provided as argument."""
        mock_decrypt.return_value = ["file.txt"]

        args = MagicMock()
        args.image = test_image
        args.output_dir = temp_dir
        args.password = "ProvidedPassword123!"
        args.private_key = None

        cli.decrypt_command(args)

        mock_decrypt.assert_called_once()

    @patch("pyRanoid.cli.get_password")
    @patch("pyRanoid.cli.decrypt_image")
    def test_decrypt_command_exception_handling(
        self, mock_decrypt, mock_get_password, test_image, temp_dir
    ):
        """Test decrypt command handles exceptions properly."""
        mock_get_password.return_value = "TestPassword123!"
        mock_decrypt.side_effect = Exception("Decryption failed")

        args = MagicMock()
        args.image = test_image
        args.output_dir = temp_dir
        args.password = None

        with pytest.raises(SystemExit):
            cli.decrypt_command(args)

    @patch("pyRanoid.cli.is_private_key_encrypted")
    @patch("pyRanoid.cli.decrypt_image")
    def test_decrypt_command_unencrypted_key_no_prompt(
        self, mock_decrypt, mock_is_encrypted, test_image, temp_dir, rsa_keypair
    ):
        """Test that unencrypted key doesn't prompt for password."""
        mock_decrypt.return_value = ["file.txt"]
        mock_is_encrypted.return_value = False  # Key is not encrypted

        output_dir = os.path.join(temp_dir, "output")
        os.makedirs(output_dir, exist_ok=True)

        args = MagicMock()
        args.image = test_image
        args.output_dir = output_dir
        args.password = None
        args.private_key = rsa_keypair["private_key_path"]
        args.key_password = None

        cli.decrypt_command(args)

        # Verify decrypt_image was called with None password
        mock_decrypt.assert_called_once()
        call_kwargs = mock_decrypt.call_args[1]
        assert call_kwargs["key_password"] is None

    @patch("pyRanoid.cli.is_private_key_encrypted")
    @patch("pyRanoid.cli.get_key_password")
    @patch("pyRanoid.cli.decrypt_image")
    def test_decrypt_command_encrypted_key_prompts(
        self,
        mock_decrypt,
        mock_get_key_password,
        mock_is_encrypted,
        test_image,
        temp_dir,
        rsa_keypair_with_password,
    ):
        """Test that encrypted key prompts for password when not provided."""
        mock_decrypt.return_value = ["file.txt"]
        mock_is_encrypted.return_value = True  # Key is encrypted
        mock_get_key_password.return_value = "TestKeyPassword"

        output_dir = os.path.join(temp_dir, "output")
        os.makedirs(output_dir, exist_ok=True)

        args = MagicMock()
        args.image = test_image
        args.output_dir = output_dir
        args.password = None
        args.private_key = rsa_keypair_with_password["private_key_path"]
        args.key_password = None

        cli.decrypt_command(args)

        # Verify get_key_password was called
        mock_get_key_password.assert_called_once()
        # Verify decrypt_image was called with the password
        mock_decrypt.assert_called_once()
        call_kwargs = mock_decrypt.call_args[1]
        assert call_kwargs["key_password"] == "TestKeyPassword"

    @patch("pyRanoid.cli.is_private_key_encrypted")
    @patch("pyRanoid.cli.get_key_password")
    @patch("pyRanoid.cli.decrypt_image")
    def test_decrypt_command_encrypted_key_with_cli_password(
        self,
        mock_decrypt,
        mock_get_key_password,
        mock_is_encrypted,
        test_image,
        temp_dir,
        rsa_keypair_with_password,
    ):
        """Test that CLI password is used when provided, no prompt."""
        mock_decrypt.return_value = ["file.txt"]
        mock_is_encrypted.return_value = True  # Key is encrypted

        output_dir = os.path.join(temp_dir, "output")
        os.makedirs(output_dir, exist_ok=True)

        args = MagicMock()
        args.image = test_image
        args.output_dir = output_dir
        args.password = None
        args.private_key = rsa_keypair_with_password["private_key_path"]
        args.key_password = "ProvidedPassword"  # Password provided via CLI

        cli.decrypt_command(args)

        # Verify get_key_password was NOT called
        mock_get_key_password.assert_not_called()
        # Verify decrypt_image was called with the CLI password
        mock_decrypt.assert_called_once()
        call_kwargs = mock_decrypt.call_args[1]
        assert call_kwargs["key_password"] == "ProvidedPassword"


class TestMainFunction:
    """Test the main CLI entry point."""

    @patch("sys.argv", ["pyranoid"])
    def test_main_no_command(self, capsys):
        """Test main function with no command shows help."""
        with pytest.raises(SystemExit) as exc_info:
            cli.main()

        assert exc_info.value.code == 0

    @patch(
        "sys.argv", ["pyranoid", "encrypt", "image.png", "file.txt", "-p", "password"]
    )
    @patch("pyRanoid.cli.encrypt_command")
    def test_main_encrypt_command(self, mock_encrypt_cmd):
        """Test main function with encrypt command."""
        mock_encrypt_cmd.return_value = None

        cli.main()

        mock_encrypt_cmd.assert_called_once()

    @patch("sys.argv", ["pyranoid", "decrypt", "image.png", "-p", "password"])
    @patch("pyRanoid.cli.decrypt_command")
    def test_main_decrypt_command(self, mock_decrypt_cmd):
        """Test main function with decrypt command."""
        mock_decrypt_cmd.return_value = None

        cli.main()

        mock_decrypt_cmd.assert_called_once()

    @patch(
        "sys.argv",
        [
            "pyranoid",
            "encrypt",
            "image.png",
            "file.txt",
            "-o",
            "custom_output.png",
            "-p",
            "password",
        ],
    )
    @patch("pyRanoid.cli.encrypt_command")
    def test_main_encrypt_with_custom_output(self, mock_encrypt_cmd):
        """Test main function with custom output path."""
        mock_encrypt_cmd.return_value = None

        cli.main()

        call_args = mock_encrypt_cmd.call_args[0][0]
        assert call_args.output == "custom_output.png"

    @patch(
        "sys.argv",
        ["pyranoid", "decrypt", "image.png", "-d", "/custom/dir", "-p", "password"],
    )
    @patch("pyRanoid.cli.decrypt_command")
    def test_main_decrypt_with_custom_output_dir(self, mock_decrypt_cmd):
        """Test main function with custom output directory."""
        mock_decrypt_cmd.return_value = None

        cli.main()

        call_args = mock_decrypt_cmd.call_args[0][0]
        assert call_args.output_dir == "/custom/dir"

    def test_main_entry_point(self):
        """Test that main can be called as entry point."""
        assert callable(cli.main)


class TestKeygenCommand:
    """Test the keygen command."""

    @patch("builtins.input", return_value="no")
    @patch("pyRanoid.cli.generate_rsa_keypair")
    @patch("pyRanoid.cli.save_private_key")
    @patch("pyRanoid.cli.save_public_key")
    def test_keygen_command_without_password(
        self, mock_save_public, mock_save_private, mock_generate, mock_input, temp_dir
    ):
        """Test keygen command without password protection."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()
        mock_generate.return_value = (private_key, public_key)

        private_key_path = os.path.join(temp_dir, "private.pem")
        public_key_path = os.path.join(temp_dir, "public.pem")

        args = MagicMock()
        args.private_key = private_key_path
        args.public_key = public_key_path

        cli.keygen_command(args)

        mock_generate.assert_called_once()
        mock_save_private.assert_called_once_with(private_key, private_key_path, None)
        mock_save_public.assert_called_once_with(public_key, public_key_path)

    @patch("getpass.getpass", return_value="KeyPassword123!")
    @patch("builtins.input", return_value="yes")
    @patch("pyRanoid.cli.generate_rsa_keypair")
    @patch("pyRanoid.cli.save_private_key")
    @patch("pyRanoid.cli.save_public_key")
    def test_keygen_command_with_password(
        self,
        mock_save_public,
        mock_save_private,
        mock_generate,
        mock_input,
        mock_getpass,
        temp_dir,
    ):
        """Test keygen command with password protection."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()
        mock_generate.return_value = (private_key, public_key)

        private_key_path = os.path.join(temp_dir, "private.pem")
        public_key_path = os.path.join(temp_dir, "public.pem")

        args = MagicMock()
        args.private_key = private_key_path
        args.public_key = public_key_path

        cli.keygen_command(args)

        mock_generate.assert_called_once()
        mock_save_private.assert_called_once_with(
            private_key, private_key_path, "KeyPassword123!"
        )
        mock_save_public.assert_called_once_with(public_key, public_key_path)
