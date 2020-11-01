import unittest
import sys
import os

testDir = os.path.dirname(__file__)
srcDir = '../pyHide'
sys.path.insert(0, os.path.abspath(os.path.join(testDir, srcDir)))

import lsbSteg


class TestLsbSteg(unittest.TestCase):
    @classmethod
    def tearDownClass(self):
        try:
            os.remove('secret.png')
            os.remove('test.txt')
        except FileNotFoundError as e:
            pass

    def test_lsbSteg1(self):
        """
        Test that image encoding works for encoding text.
        """
        message = 'test'
        lsbSteg.encodeImage(
            'screenshot.png', message, password='test')

        self.assertTrue(os.path.exists('secret.png'))

    def test_lsbSteg2(self):
        """
        Test decoding works and gives back the right text message
        """
        message = 'test'
        result = lsbSteg.decodeImage('secret.png', password='test')

        os.remove('secret.png')

        self.assertEqual(result, message)

    def test_lsbSteg3(self):
        """
        Test that image encoding works for encoding a file.
        """
        f = open("test.txt", "w+")
        f.write("test")
        f.close()
        
        filePath = os.path.abspath("test.txt")

        lsbSteg.encodeImage('screenshot.png', filePath, password='test')
        self.assertTrue(os.path.exists('secret.png'))

    def test_lsbSteg4(self):
        """
        Test decoding works and gives back the right file
        """
        message = 'test'
        
        result = lsbSteg.decodeImage('secret.png', password='test')
        
        f = open(result, "r")
        result = f.read()
        f.close()
        
        self.assertEqual(result, message)



if __name__ == '__main__':
    unittest.main()
