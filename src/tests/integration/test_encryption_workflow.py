"""
Integration tests for pyRanoid encryption/decryption workflows.

Tests the complete end-to-end encryption and decryption processes
for both password mode and RSA mode.
"""

import os
import sys

import pytest
from PIL import Image
import pyRanoid.utils as utils

test_dir = os.path.dirname(__file__)
src_dir = "../../"
sys.path.insert(0, os.path.abspath(os.path.join(test_dir, src_dir)))


@pytest.mark.integration
class TestEncryptDecryptImagePasswordMode:
    """Integration tests for image encryption and decryption with password mode."""

    def test_encrypt_decrypt_roundtrip_password(
        self, test_image, test_text_file, temp_dir, test_password
    ):
        """Test full encryption and decryption cycle with password mode."""
        encrypted_image = os.path.join(temp_dir, "encrypted_pwd.png")
        output_dir = os.path.join(temp_dir, "decrypted_pwd")
        os.makedirs(output_dir, exist_ok=True)

        utils.encrypt_image(
            test_image, [test_text_file], encrypted_image, password=test_password
        )
        assert os.path.exists(encrypted_image)

        files_extracted = utils.decrypt_image(
            encrypted_image, output_dir=output_dir, password=test_password
        )

        assert isinstance(files_extracted, list)
        assert len(files_extracted) > 0

        extracted_file = os.path.join(output_dir, os.path.basename(test_text_file))
        assert os.path.exists(extracted_file)

        with open(test_text_file, "r") as original:
            with open(extracted_file, "r") as extracted:
                assert original.read() == extracted.read()

    def test_encrypt_binary_file_password(
        self, test_image, test_binary_file, temp_dir, test_password
    ):
        """Test encrypting a binary file with password mode."""
        encrypted_image = os.path.join(temp_dir, "encrypted_bin_pwd.png")
        output_dir = os.path.join(temp_dir, "decrypted_bin_pwd")
        os.makedirs(output_dir, exist_ok=True)

        utils.encrypt_image(
            test_image, [test_binary_file], encrypted_image, password=test_password
        )
        utils.decrypt_image(
            encrypted_image, output_dir=output_dir, password=test_password
        )

        extracted_file = os.path.join(output_dir, os.path.basename(test_binary_file))
        with open(test_binary_file, "rb") as original:
            with open(extracted_file, "rb") as extracted:
                assert original.read() == extracted.read()

    def test_decrypt_with_wrong_password(self, test_image, test_text_file, temp_dir):
        """Test that decryption fails with wrong password."""
        encrypted_image = os.path.join(temp_dir, "encrypted_wrong_pwd.png")
        output_dir = os.path.join(temp_dir, "decrypted_wrong_pwd")
        os.makedirs(output_dir, exist_ok=True)

        correct_password = "CorrectPassword123!"
        wrong_password = "WrongPassword456!"

        utils.encrypt_image(
            test_image, [test_text_file], encrypted_image, password=correct_password
        )

        with pytest.raises(Exception):
            utils.decrypt_image(
                encrypted_image, output_dir=output_dir, password=wrong_password
            )


@pytest.mark.integration
class TestEncryptDecryptImageRSAMode:
    """Integration tests for image encryption and decryption with RSA mode."""

    def test_encrypt_decrypt_roundtrip_rsa(self, test_image, test_text_file, temp_dir):
        """Test full encryption and decryption cycle with RSA mode."""
        encrypted_image = os.path.join(temp_dir, "encrypted_rsa.png")
        output_dir = os.path.join(temp_dir, "decrypted_rsa")
        os.makedirs(output_dir, exist_ok=True)

        private_key, public_key = utils.generate_rsa_keypair()
        public_key_path = os.path.join(temp_dir, "public_key.pem")
        private_key_path = os.path.join(temp_dir, "private_key.pem")
        utils.save_public_key(public_key, public_key_path)
        utils.save_private_key(private_key, private_key_path)

        utils.encrypt_image(
            test_image,
            [test_text_file],
            encrypted_image,
            rsa_public_key_path=public_key_path,
        )
        assert os.path.exists(encrypted_image)

        files_extracted = utils.decrypt_image(
            encrypted_image,
            output_dir=output_dir,
            rsa_private_key_path=private_key_path,
        )

        assert isinstance(files_extracted, list)
        assert len(files_extracted) > 0

        extracted_file = os.path.join(output_dir, os.path.basename(test_text_file))
        assert os.path.exists(extracted_file)

        with open(test_text_file, "r") as original:
            with open(extracted_file, "r") as extracted:
                assert original.read() == extracted.read()

    def test_encrypt_binary_file_rsa(self, test_image, test_binary_file, temp_dir):
        """Test encrypting a binary file with RSA mode."""
        encrypted_image = os.path.join(temp_dir, "encrypted_bin_rsa.png")
        output_dir = os.path.join(temp_dir, "decrypted_bin_rsa")
        os.makedirs(output_dir, exist_ok=True)

        private_key, public_key = utils.generate_rsa_keypair()
        public_key_path = os.path.join(temp_dir, "public_key_bin.pem")
        private_key_path = os.path.join(temp_dir, "private_key_bin.pem")
        utils.save_public_key(public_key, public_key_path)
        utils.save_private_key(private_key, private_key_path)

        utils.encrypt_image(
            test_image,
            [test_binary_file],
            encrypted_image,
            rsa_public_key_path=public_key_path,
        )
        utils.decrypt_image(
            encrypted_image,
            output_dir=output_dir,
            rsa_private_key_path=private_key_path,
        )

        extracted_file = os.path.join(output_dir, os.path.basename(test_binary_file))
        with open(test_binary_file, "rb") as original:
            with open(extracted_file, "rb") as extracted:
                assert original.read() == extracted.read()

    def test_decrypt_with_wrong_key(self, test_image, test_text_file, temp_dir):
        """Test that decryption fails with wrong RSA key."""
        encrypted_image = os.path.join(temp_dir, "encrypted_wrong_key.png")
        output_dir = os.path.join(temp_dir, "decrypted_wrong_key")
        os.makedirs(output_dir, exist_ok=True)

        private_key1, public_key1 = utils.generate_rsa_keypair()
        private_key2, _ = utils.generate_rsa_keypair()

        public_key_path = os.path.join(temp_dir, "public_key_correct.pem")
        private_key_path = os.path.join(temp_dir, "private_key_wrong.pem")
        utils.save_public_key(public_key1, public_key_path)
        utils.save_private_key(private_key2, private_key_path)

        utils.encrypt_image(
            test_image,
            [test_text_file],
            encrypted_image,
            rsa_public_key_path=public_key_path,
        )

        with pytest.raises(Exception):
            utils.decrypt_image(
                encrypted_image,
                output_dir=output_dir,
                rsa_private_key_path=private_key_path,
            )

    def test_encrypted_private_key(self, test_image, test_text_file, temp_dir):
        """Test using password-protected RSA private key."""
        encrypted_image = os.path.join(temp_dir, "encrypted_protected.png")
        output_dir = os.path.join(temp_dir, "decrypted_protected")
        os.makedirs(output_dir, exist_ok=True)

        private_key, public_key = utils.generate_rsa_keypair()
        public_key_path = os.path.join(temp_dir, "public_key_protected.pem")
        private_key_path = os.path.join(temp_dir, "private_key_protected.pem")
        key_password = "SecureKeyPassword123!"

        utils.save_public_key(public_key, public_key_path)
        utils.save_private_key(private_key, private_key_path, key_password)

        utils.encrypt_image(
            test_image,
            [test_text_file],
            encrypted_image,
            rsa_public_key_path=public_key_path,
        )
        utils.decrypt_image(
            encrypted_image,
            output_dir=output_dir,
            rsa_private_key_path=private_key_path,
            key_password=key_password,
        )

        extracted_file = os.path.join(output_dir, os.path.basename(test_text_file))
        assert os.path.exists(extracted_file)


@pytest.mark.integration
class TestMultipleFiles:
    """Test encryption/decryption of multiple files."""

    def test_multiple_files_password_mode(
        self, test_image, test_text_file, test_binary_file, temp_dir, test_password
    ):
        """Test encrypting multiple files with password mode."""
        encrypted_image = os.path.join(temp_dir, "multi_pwd.png")
        output_dir = os.path.join(temp_dir, "multi_decrypted_pwd")
        os.makedirs(output_dir, exist_ok=True)

        utils.encrypt_image(
            test_image,
            [test_text_file, test_binary_file],
            encrypted_image,
            password=test_password,
        )

        files_extracted = utils.decrypt_image(
            encrypted_image, output_dir=output_dir, password=test_password
        )

        assert len(files_extracted) == 2
        assert os.path.basename(test_text_file) in files_extracted
        assert os.path.basename(test_binary_file) in files_extracted

    def test_multiple_files_rsa_mode(
        self, test_image, test_text_file, test_binary_file, temp_dir
    ):
        """Test encrypting multiple files with RSA mode."""
        encrypted_image = os.path.join(temp_dir, "multi_rsa.png")
        output_dir = os.path.join(temp_dir, "multi_decrypted_rsa")
        os.makedirs(output_dir, exist_ok=True)

        private_key, public_key = utils.generate_rsa_keypair()
        public_key_path = os.path.join(temp_dir, "public_key_multi.pem")
        private_key_path = os.path.join(temp_dir, "private_key_multi.pem")
        utils.save_public_key(public_key, public_key_path)
        utils.save_private_key(private_key, private_key_path)

        utils.encrypt_image(
            test_image,
            [test_text_file, test_binary_file],
            encrypted_image,
            rsa_public_key_path=public_key_path,
        )

        files_extracted = utils.decrypt_image(
            encrypted_image,
            output_dir=output_dir,
            rsa_private_key_path=private_key_path,
        )

        assert len(files_extracted) == 2
        assert os.path.basename(test_text_file) in files_extracted
        assert os.path.basename(test_binary_file) in files_extracted


@pytest.mark.integration
class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_image_too_small_for_data_password(
        self, small_test_image, large_test_file, temp_dir, test_password
    ):
        """Test that encryption fails when image is too small (password mode)."""
        output_path = os.path.join(temp_dir, "encrypted_small_pwd.png")

        with pytest.raises(Exception, match="Image too small for data"):
            utils.encrypt_image(
                small_test_image, [large_test_file], output_path, password=test_password
            )

    def test_image_too_small_for_data_rsa(
        self, small_test_image, large_test_file, temp_dir
    ):
        """Test that encryption fails when image is too small (RSA mode)."""
        output_path = os.path.join(temp_dir, "encrypted_small_rsa.png")

        _, public_key = utils.generate_rsa_keypair()
        public_key_path = os.path.join(temp_dir, "public_key_small.pem")
        utils.save_public_key(public_key, public_key_path)

        with pytest.raises(Exception, match="Image too small for data"):
            utils.encrypt_image(
                small_test_image,
                [large_test_file],
                output_path,
                rsa_public_key_path=public_key_path,
            )

    def test_empty_file_encryption_password(self, test_image, temp_dir, test_password):
        """Test encrypting an empty file with password mode."""
        empty_file = os.path.join(temp_dir, "empty_pwd.txt")
        with open(empty_file, "w"):
            pass

        encrypted_image = os.path.join(temp_dir, "encrypted_empty_pwd.png")
        output_dir = os.path.join(temp_dir, "decrypted_empty_pwd")
        os.makedirs(output_dir, exist_ok=True)

        utils.encrypt_image(
            test_image, [empty_file], encrypted_image, password=test_password
        )
        utils.decrypt_image(
            encrypted_image, output_dir=output_dir, password=test_password
        )

        extracted_file = os.path.join(output_dir, os.path.basename(empty_file))
        assert os.path.exists(extracted_file)
        assert os.path.getsize(extracted_file) == 0

    def test_empty_file_encryption_rsa(self, test_image, temp_dir):
        """Test encrypting an empty file with RSA mode."""
        empty_file = os.path.join(temp_dir, "empty_rsa.txt")
        with open(empty_file, "w"):
            pass

        encrypted_image = os.path.join(temp_dir, "encrypted_empty_rsa.png")
        output_dir = os.path.join(temp_dir, "decrypted_empty_rsa")
        os.makedirs(output_dir, exist_ok=True)

        private_key, public_key = utils.generate_rsa_keypair()
        public_key_path = os.path.join(temp_dir, "public_key_empty.pem")
        private_key_path = os.path.join(temp_dir, "private_key_empty.pem")
        utils.save_public_key(public_key, public_key_path)
        utils.save_private_key(private_key, private_key_path)

        utils.encrypt_image(
            test_image,
            [empty_file],
            encrypted_image,
            rsa_public_key_path=public_key_path,
        )
        utils.decrypt_image(
            encrypted_image,
            output_dir=output_dir,
            rsa_private_key_path=private_key_path,
        )

        extracted_file = os.path.join(output_dir, os.path.basename(empty_file))
        assert os.path.exists(extracted_file)
        assert os.path.getsize(extracted_file) == 0

    def test_encrypted_image_dimensions_preserved(
        self, test_image, test_text_file, temp_dir, test_password
    ):
        """Test that image dimensions are preserved after encryption."""
        encrypted_image = os.path.join(temp_dir, "encrypted_dims.png")

        original_img = Image.open(test_image)
        original_size = original_img.size

        utils.encrypt_image(
            test_image, [test_text_file], encrypted_image, password=test_password
        )

        encrypted_img = Image.open(encrypted_image)
        assert encrypted_img.size == original_size

    def test_large_file_encryption_password(
        self, large_test_image, large_test_file, temp_dir, test_password
    ):
        """Test encrypting a large file with password mode."""
        encrypted_image = os.path.join(temp_dir, "encrypted_large_pwd.png")
        output_dir = os.path.join(temp_dir, "decrypted_large_pwd")
        os.makedirs(output_dir, exist_ok=True)

        utils.encrypt_image(
            large_test_image, [large_test_file], encrypted_image, password=test_password
        )
        assert os.path.exists(encrypted_image)

        utils.decrypt_image(
            encrypted_image, output_dir=output_dir, password=test_password
        )

        extracted_file = os.path.join(output_dir, os.path.basename(large_test_file))
        assert os.path.getsize(extracted_file) == os.path.getsize(large_test_file)

    def test_large_file_encryption_rsa(
        self, large_test_image, large_test_file, temp_dir
    ):
        """Test encrypting a large file with RSA mode."""
        encrypted_image = os.path.join(temp_dir, "encrypted_large_rsa.png")
        output_dir = os.path.join(temp_dir, "decrypted_large_rsa")
        os.makedirs(output_dir, exist_ok=True)

        private_key, public_key = utils.generate_rsa_keypair()
        public_key_path = os.path.join(temp_dir, "public_key_large.pem")
        private_key_path = os.path.join(temp_dir, "private_key_large.pem")
        utils.save_public_key(public_key, public_key_path)
        utils.save_private_key(private_key, private_key_path)

        utils.encrypt_image(
            large_test_image,
            [large_test_file],
            encrypted_image,
            rsa_public_key_path=public_key_path,
        )
        assert os.path.exists(encrypted_image)

        utils.decrypt_image(
            encrypted_image,
            output_dir=output_dir,
            rsa_private_key_path=private_key_path,
        )

        extracted_file = os.path.join(output_dir, os.path.basename(large_test_file))
        assert os.path.getsize(extracted_file) == os.path.getsize(large_test_file)
