"""
Pytest configuration and fixtures for pyRanoid tests.
"""

import pytest
import os
import tempfile
from PIL import Image
import shutil


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp_path = tempfile.mkdtemp()
    yield temp_path
    # Cleanup
    if os.path.exists(temp_path):
        shutil.rmtree(temp_path)


@pytest.fixture
def test_image(temp_dir):
    """Create a test image file."""
    image_path = os.path.join(temp_dir, "test_image.png")
    image = Image.new("RGB", (1000, 1000), color=(255, 255, 255))
    image.save(image_path)
    return image_path


@pytest.fixture
def large_test_image(temp_dir):
    """Create a large test image file for capacity tests."""
    image_path = os.path.join(temp_dir, "large_test_image.png")
    image = Image.new("RGB", (2000, 2000), color=(128, 128, 255))
    image.save(image_path)
    return image_path


@pytest.fixture
def small_test_image(temp_dir):
    """Create a small test image file for capacity tests."""
    image_path = os.path.join(temp_dir, "small_test_image.png")
    image = Image.new("RGB", (100, 100), color=(255, 128, 128))
    image.save(image_path)
    return image_path


@pytest.fixture
def test_text_file(temp_dir):
    """Create a test text file."""
    file_path = os.path.join(temp_dir, "test_file.txt")
    with open(file_path, "w") as f:
        f.write("This is a test file for pyRanoid encryption.")
    return file_path


@pytest.fixture
def test_binary_file(temp_dir):
    """Create a test binary file."""
    file_path = os.path.join(temp_dir, "test_binary.bin")
    with open(file_path, "wb") as f:
        f.write(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09" * 100)
    return file_path


@pytest.fixture
def large_test_file(temp_dir):
    """Create a large test file."""
    file_path = os.path.join(temp_dir, "large_file.txt")
    with open(file_path, "w") as f:
        # Create a ~1MB file
        for i in range(10000):
            f.write(f"Line {i}: This is a test line with some content.\n")
    return file_path


@pytest.fixture
def test_password():
    """Standard test password."""
    return "TestPassword123!"


@pytest.fixture
def weak_password():
    """Weak test password."""
    return "weak"


@pytest.fixture
def strong_password():
    """Strong test password."""
    return "Str0ng!P@ssw0rd#2024$WithManyChars"


@pytest.fixture
def rsa_keypair(temp_dir):
    """Generate RSA key pair and save to temp directory."""
    import sys
    import os

    test_dir = os.path.dirname(__file__)
    src_dir = "../../"
    sys.path.insert(0, os.path.abspath(os.path.join(test_dir, src_dir)))

    from pyRanoid.utils import generate_rsa_keypair, save_private_key, save_public_key

    private_key, public_key = generate_rsa_keypair()
    private_key_path = os.path.join(temp_dir, "test_private.pem")
    public_key_path = os.path.join(temp_dir, "test_public.pem")

    save_private_key(private_key, private_key_path)
    save_public_key(public_key, public_key_path)

    return {
        "private_key": private_key,
        "public_key": public_key,
        "private_key_path": private_key_path,
        "public_key_path": public_key_path,
    }


@pytest.fixture
def rsa_keypair_with_password(temp_dir):
    """Generate password-protected RSA key pair."""
    import sys
    import os

    test_dir = os.path.dirname(__file__)
    src_dir = "../../"
    sys.path.insert(0, os.path.abspath(os.path.join(test_dir, src_dir)))

    from pyRanoid.utils import generate_rsa_keypair, save_private_key, save_public_key

    private_key, public_key = generate_rsa_keypair()
    private_key_path = os.path.join(temp_dir, "test_private_encrypted.pem")
    public_key_path = os.path.join(temp_dir, "test_public_encrypted.pem")
    password = "KeyPassword123!"

    save_private_key(private_key, private_key_path, password)
    save_public_key(public_key, public_key_path)

    return {
        "private_key": private_key,
        "public_key": public_key,
        "private_key_path": private_key_path,
        "public_key_path": public_key_path,
        "password": password,
    }
