# ============================================================================================
# MIT License
# Copyright (c) 2020 Konstantinos Bourantas

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the 'Software'), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# Part of the code was taken from:
# https://itnext.io/steganography-101-lsb-introduction-with-python-4c4803e08041
# ============================================================================================

from PIL import Image
import tkinter as tk
import crypto
import pyAesCrypt
import filetype
import os

# ============================================================================================


def stringToBin(text):
    return ''.join(format(ord(char), '08b') for char in text)

# ============================================================================================


def intToBin(x):
    return '{0:b}'.format(x)

# ============================================================================================


def encodeImage(imagePath, text, gui=None, **kwargs):

    if os.path.isfile(text):
        encodeFile(imagePath, text, kwargs['password'])
        return

    if gui:
        text = crypto.encryptText(text, gui)
        gui.btnOpImage['state'] = 'disable'
    elif 'password' in kwargs:
        print('[*]Encoding..')
        text = crypto.encryptText(text, password=kwargs['password'])

    try:
        data = stringToBin(text)
        lenData = intToBin(len(data))

        data = format(len(lenData), 'b').zfill(8)+lenData + data

        with Image.open(imagePath) as img:
            width, height = img.size

            i = 0

            for x in range(0, width):
                for y in range(0, height):
                    pixel = list(img.getpixel((x, y)))
                    for n in range(0, 3):
                        if(i < len(data)):
                            pixel[n] = pixel[n] & 0 | int(data[i])
                            i += 1

                    img.putpixel((x, y), tuple(pixel))

            img.save('secret.png', 'PNG')

        if gui:
            gui.textArea.insert(tk.END, '\n[+]Encoding finished!')
        else:
            print('\n[+]Encoding finished!')
    except Exception as e:
        if gui:
            gui.textArea.insert(tk.END, f'\n[-]Exception occured: {e}')
        else:
            print(f'\n[-]Exception occured: {e}')
    finally:
        if gui:
            gui.btnOpImage['state'] = 'normal'


# ============================================================================================


def decodeImage(imagePath, gui=None, **kwargs):

    with open(imagePath, 'rb') as f:
        data = f.read().split(b'aescrypt')

    if len(data) > 1:
        decodeFile(imagePath, kwargs['password'])
        return

    if gui:
        gui.btnOpImage['state'] = 'disable'
    else:
        print('[*]Decoding..')

    try:
        extractedBin = []
        with Image.open(imagePath) as img:
            width, height = img.size

            for x in range(0, width):
                for y in range(0, height):
                    pixel = list(img.getpixel((x, y)))
                    for n in range(0, 3):
                        extractedBin.append(pixel[n] & 1)

        len_len = int(''.join([str(i) for i in extractedBin[0:8]]), 2)
        len_data = int(''.join([str(i)
                                for i in extractedBin[8:len_len+8]]), 2)

        binaryMessage = int(''.join([str(extractedBin[i+8+len_len])
                                     for i in range(len_data)]), 2)

        decodedMessage = binaryMessage.to_bytes(
            (binaryMessage.bit_length() + 7) // 8, 'big').decode()

        if gui:
            decodedMessage = crypto.decryptText(decodedMessage, gui)

            gui.textArea.insert(
                tk.END, f'\n[+]Decrypted Message: \n{decodedMessage}\n')

            if gui.exportOpt.get() == 1:
                with open('pyhide_output.txt', 'w') as text_file:
                    print(
                        f'Decoded Message:\n {decodedMessage}', file=text_file)
        elif 'password' in kwargs:
            decodedMessage = crypto.decryptText(
                decodedMessage, password=kwargs['password'])
            print(f'[+]Decrypted Message:\n {decodedMessage}')
            return decodedMessage

    except Exception as e:
        if gui:
            gui.textArea.insert(tk.END, f'\n[-]Exception occured: {e}')
        else:
            print(f'\n[-]Exception occured: {e}')
    finally:
        if gui:
            gui.btnOpImage['state'] = 'normal'


# ============================================================================================
bufferSize = 64 * 1024


def encodeFile(imagePath, targetFile, password):

    ext = targetFile.split('.')[-1]

    pyAesCrypt.encryptFile(targetFile,
                           'temp.'+ext, password, bufferSize)

    with open(imagePath, 'wb') as out:
        out.write(open('temp.'+ext, 'rb').read() +
                  b'aescrypt,fileextension:'+ext.encode())

    os.remove('temp.'+ext)


def decodeFile(imagePath, password):

    with open(imagePath, 'rb') as f:
        ext = f.read().split(b'fileextension:')[1].decode()
        f.seek(0)
        data = f.read().split(b'aescrypt')[0]

        if ext is None:
            print('Cannot guess file type!')
        else:
            print('File extension: %s' % ext)
        with open('temp.'+ext, 'wb') as f1:
            f1.write(data)

    pyAesCrypt.decryptFile('temp.'+ext,
                           'resultFile.'+ext, password, bufferSize)

    os.remove('temp.'+ext)
