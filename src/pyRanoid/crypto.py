# ============================================================================================
# MIT License
# Copyright (c) 2020 Konstantinos Bourantas

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
# ============================================================================================
import pyAesCrypt
import io
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
bufferSize = 264 * 1024

# ============================================================================================


def generateRSAKeys(gui=None, **kwargs):
    if gui:
         password = gui.passwordEntry.get().strip('\n')
    elif 'password' in kwargs:
         password = kwargs['password']

    keypair = RSA.generate(2048)
    publicKey = keypair.publickey()

    with open("publicKey.pem", "wb") as file:
        file.write(publicKey.exportKey('PEM'))
        file.close()

    with open("privateKey.pem", "wb") as file:
        file.write(keypair.exportKey('PEM'))
        file.close()

# ============================================================================================


def encryptRSA(plaintext, filename):

    with open(filename, "rb") as file:
        publicKey = RSA.importKey(file.read())

    rsaCipher = Cipher_PKCS1_v1_5.new(publicKey)
    cipherText = rsaCipher.encrypt(plaintext.encode())

    return cipherText

# ============================================================================================


def decryptRSA(filename, cipherText, gui=None, **kwargs):
    if gui:
        password = gui.passwordEntry.get().strip('\n')
    elif 'password' in kwargs:
        password = kwargs['password']

    with open(filename, "rb") as file:
        private_key = RSA.importKey(file.read())

    rsaCipher = Cipher_PKCS1_v1_5.new(private_key)
    decryptedText = rsaCipher.decrypt(cipherText, None)

    return decryptedText

# ============================================================================================


def encryptText(message, gui=None, **kwargs):
    """Encrypt text using AES"""
    if gui:
        password = gui.passwordEntry.get().strip('\n')
    elif 'password' in kwargs:
        password = kwargs['password']
    # binary message to be encrypted
    if gui and gui.rsaOption.get() == 1:
        pbdata = encryptRSA(message, gui.rsaKeyPath)
    else:
        pbdata = str.encode(message)


    # input plaintext binary stream
    fIn = io.BytesIO(pbdata)

    # initialize cipherText binary stream
    fCiph = io.BytesIO()

    # encrypt stream
    pyAesCrypt.encryptStream(fIn, fCiph, password, bufferSize)

    return str(fCiph.getvalue())


# ============================================================================================
def decryptText(message, gui=None, **kwargs):
    """Decrypt text using AES"""
    if gui:
        password = gui.passwordEntry.get().strip('\n')
    elif 'password' in kwargs:
        password = kwargs['password']

    # initialize decrypted binary stream
    fDec = io.BytesIO()

    encrypted = io.BytesIO(eval(message))

    # get cipherText length
    ctlen = len(encrypted.getvalue())

    # go back to the start of the cipherText stream
    encrypted.seek(0)

    # decrypt stream
    pyAesCrypt.decryptStream(encrypted, fDec, password, bufferSize, ctlen)

    # print decrypted message
    # print("Decrypted message:\n" + str(fDec.getvalue()))
    if gui and gui.rsaOption.get() == 1:
        return str(decryptRSA(gui.rsaKeyPath, fDec.getvalue(),gui), "utf-8")
    else:
        return str(fDec.getvalue(), "utf-8")

# ============================================================================================
