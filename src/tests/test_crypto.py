import unittest
import sys
import os
testDir = os.path.dirname(__file__)
srcDir = '../pyRanoid'
sys.path.insert(0, os.path.abspath(os.path.join(testDir, srcDir)))

import encryption


class TestCrypto(unittest.TestCase):
    def test_encryptText(self):
        """
        Test that text get encrypted based on AES
        """
        message = 'test'
        result = encryption.encryptText(message, password='test')

        self.assertNotEqual(result, message)

    def test_decryptText(self):
        """
        Test that text get decrypted based on AES
        """
        expectedResult = 'test'
        message = str(b'AES\x02\x00\x00\x1bCREATED_BY\x00pyAesCrypt 0.4.3\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe\xd4\xe2\xcc\x8b\x81pq\x98\xf6W&\xf5\xfcP\x90\xcc\xfd\xa6\xeb\xc0\xa8|4\x0b\x8a\x1a\x0c\x18\x92\xa1\xde[Pd\xed\x85\xa0!\xce\x02W#?\xf2&"\xd9W\xd9\x0e\xdc_\xd7\xc7\xc4`\xa8\xd1\xf0\x08\xc22\xc6\xa6\x9b\xdf^)Mj\x02z0\xc9\xca\xb9[\x7f\xeb\xfcMi\xb8ZD~^\xa3\x93\xb7\xfe\x13\x07q\xa1\xd3"\xf3_\x83\xea\xccbu\xad\xc7\x1b\xd4\xdb\xf1O\x04\x84\x8fK\xb2\xf3\x94H\xabTi\xa0\xda\xd4:n/\xd9\xc3(\xff(gZ\xc9\xe0u}Z\xcb\xb6\xa1\x10')
        result = encryption.decryptText(message,password='test')

        self.assertEqual(result,expectedResult)

if __name__ == '__main__':
    unittest.main()
