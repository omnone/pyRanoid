import unittest
import sys
import os
from PIL import Image

test_dir = os.path.dirname(__file__)
src_dir = "../"
sys.path.insert(0, os.path.abspath(os.path.join(test_dir, src_dir)))

# fmt: off
import pyRanoid.utils as utils
# fmt: on


class Testutils(unittest.TestCase):

    @classmethod
    def tearDownClass(self):
        try:
            os.remove("output.png")
        except FileNotFoundError:
            pass

    def tearDown(self):
        if os.path.exists("test_file.txt"):
            os.remove("test_file.txt")

        if os.path.exists("test_image.png"):
            os.remove("test_image.png")

        if os.path.exists("output.tar.gz"):
            os.remove("output.tar.gz")

    def setUp(self):
        # Create a test file
        self.file_path = "test_file.txt"
        with open(self.file_path, "w") as file:
            file.write("This is a test file.")

        # Create a test image
        self.image_path = "test_image.png"
        image = Image.new("RGB", (1000, 1000), color=(255, 255, 255))
        image.save(self.image_path)

    def test_utils1(self):
        """
        Test that image encrypt works.
        """
        utils.encrypt_image(
            self.image_path, self.file_path, password="test")

        self.assertTrue(os.path.exists("output.png"))

    def test_utils2(self):
        """
        Test that image decrypt works and hidden file is exported
        """
        utils.decrypt_image("output.png", password="test")

        with open(self.file_path, "r") as f:
            self.assertEqual(f.read(), "This is a test file.")


if __name__ == "__main__":
    unittest.main()
