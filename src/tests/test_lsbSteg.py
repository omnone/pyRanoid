import lsbSteg
import unittest
import sys
import os

testDir = os.path.dirname(__file__)
srcDir = '../pyHide'
sys.path.insert(0, os.path.abspath(os.path.join(testDir, srcDir)))


class TestLsbSteg(unittest.TestCase):
    @classmethod
    def tearDownClass(self):
        try:
            os.remove('secret.png')
        except FileNotFoundError as e:
            pass

    def test_lsbSteg1(self):
        """
        Test that image encoding works.
        """
        message = 'test'
        lsbSteg.encodeImage(
            '../../screenshot.png', message, password='test')

        self.assertTrue(os.path.exists('secret.png'))

    def test_lsbSteg2(self):
        """
        Test decoding works and gives back the write message
        """
        message = 'test'
        result = lsbSteg.decodeImage('secret.png', password='test')

        self.assertEqual(result, message)


if __name__ == '__main__':
    unittest.main()
