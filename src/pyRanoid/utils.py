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
# Part of the code was taken from:
# https://itnext.io/steganography-101-lsb-introduction-with-python-4c4803e08041
# ============================================================================================

import datetime
from hashlib import pbkdf2_hmac
import subprocess
import tarfile
from PIL import Image
import tkinter as tk
import os
from shutil import which

buffer_size = 64 * 1024
_OPENSSL_EXECUTABLE = which("openssl")

if not _OPENSSL_EXECUTABLE:
    raise Exception("You need to install openssl!")

TAR_FILE_PATH = "output.tar.gz"
FINAL_PNG_PATH = "output.png"
ENCR_FILE_PATH = "output.prnd"

# --------------------------------------------------------------------------------------------


def file_to_bin(file_path):
    with open(file_path, "rb") as file:
        file_data = file.read()
    return "".join(format(byte, "08b") for byte in file_data)
# --------------------------------------------------------------------------------------------


def str_to_bin(input):
    return "".join(format(ord(char), "08b") for char in input)

# --------------------------------------------------------------------------------------------


def int_to_bin(x):
    return "{0:b}".format(x)


# --------------------------------------------------------------------------------------------


def log_handler(gui, msg):
    msg = f"\n[{datetime.datetime.now()}] {msg}"
    if gui:
        gui.text_area.insert(tk.END, msg)
    else:
        print(msg)

# --------------------------------------------------------------------------------------------


def encrypt_image(image_path, target_path, gui=None, **kwargs):

    output_path = None

    try:
        if os.path.isfile(target_path):
            password = gui.password_entry.get().strip(
                "\n") if gui else kwargs["password"]

            output_path, err = encryption_handler(target_path,
                                                  password)

            if err:
                raise Exception("Encryption failed!")

            log_handler(gui, "[+]Encryption finished!")
        else:
            return

    except Exception as e:
        log_handler(gui, f"[-]Exception occured: {e}")

        return

    try:
        log_handler(gui, f"[*]Writing encrypted file to image {image_path}")

        file_contents = file_to_bin(output_path)
        file_total_bytes = len(file_contents)
        file_length = int_to_bin(file_total_bytes)

        # save all information in order to be able to locate the hidden data
        data_to_hide = format(len(file_length), "b").zfill(8) + \
            file_length + file_contents

        with Image.open(image_path) as img:
            width, height = img.size
            bit_counter = pixel_count = 0
            image_capacity = (width*height*3)//8
            pixels_needed = (file_total_bytes * 8) // 3

            log_handler(gui, f"[*]Going to need {pixels_needed} pixels")

            if image_capacity < file_total_bytes:
                raise Exception(
                    f'[-]You need a bigger image! your file is {file_total_bytes} bytes but your image fits up to {image_capacity}.')

            for x in range(0, width):
                for y in range(0, height):
                    if pixel_count >= pixels_needed:
                        break

                    pixel = list(img.getpixel((x, y)))

                    for n in range(0, 3):
                        if (bit_counter < len(data_to_hide)):
                            pixel[n] = pixel[n] & 0 | int(
                                data_to_hide[bit_counter])
                            bit_counter += 1

                    img.putpixel((x, y), tuple(pixel))
                    pixel_count += 1

            final_img_path = os.path.join(os.path.dirname(
                image_path), FINAL_PNG_PATH)

            img.save(final_img_path, "PNG")

        log_handler(
            gui, "[+]Encryption finished!")

    except Exception as e:
        log_handler(gui, f"[-]Exception occured: {e}")
    else:
        log_handler(gui, f"[+]Final image ready {final_img_path}")
    finally:
        if output_path and os.path.exists(output_path):
            os.remove(output_path)

        if gui:
            gui.image_op_btn["state"] = "normal"
        else:
            return True

# --------------------------------------------------------------------------------------------


def decrypt_image(image_path, gui=None, **kwargs):

    password = gui.password_entry.get().strip(
        "\n") if gui else kwargs["password"]

    if gui:
        gui.image_op_btn["state"] = "disable"

    try:
        extracted_bin = []

        with Image.open(image_path) as img:
            width, height = img.size
            extraction_completed = False
            length = length_of_data = None

            for x in range(0, width):
                if extraction_completed:
                    break

                for y in range(0, height):
                    pixel = list(img.getpixel((x, y)))

                    for n in range(0, 3):
                        extracted_bin.append(pixel[n] & 1)

                        if length is None and len(extracted_bin) >= 8:
                            length = int(
                                "".join([str(i) for i in extracted_bin[0:8]]), 2)

                        if length is not None and \
                                len(extracted_bin) >= 8 + length:
                            length_of_data = int("".join([str(i)
                                                          for i in extracted_bin[8:length+8]]), 2)

                        if length_of_data is not None and \
                                len(extracted_bin) >= 8 + length + length_of_data:
                            extraction_completed = True

                    if extraction_completed:
                        break

            if length is not None:
                binary_msg = int(
                    "".join([str(extracted_bin[i+8+length]) for i in range(length_of_data)]), 2)
            else:
                raise Exception(
                    f"[-]Couldn't extract hidden file from {image_path}, image file is corrupted!")

        decrypted_msg = binary_msg.to_bytes(
            (binary_msg.bit_length() + 7) // 8, "big")

        with open(ENCR_FILE_PATH, "wb") as f:
            f.write(decrypted_msg)

        _, err = encryption_handler(ENCR_FILE_PATH, password, decrypt=True)

        if err:
            raise Exception("Decryption failed!")

    except Exception as e:
        log_handler(gui, f"[-]Exception occured: {e}")
    else:
        extract_tar_archive(TAR_FILE_PATH, ".")

        log_handler(
            gui, f"[+]Hidden file has been exported succesfuly to {os.getcwd()}")
    finally:
        if os.path.exists(TAR_FILE_PATH):
            os.remove(TAR_FILE_PATH)

        if os.path.exists(ENCR_FILE_PATH):
            os.remove(ENCR_FILE_PATH)

        if gui:
            gui.image_op_btn["state"] = "normal"

# --------------------------------------------------------------------------------------------


def create_tar_archive(source_file, filename):
    tar_path = filename.split(".")[0]

    with tarfile.open(tar_path, "w") as tar:
        tar.add(source_file, arcname=filename)

    return tar_path

# --------------------------------------------------------------------------------------------


def extract_tar_archive(archive_file, output_directory):
    with tarfile.open(archive_file, "r") as tar:
        tar.extractall(output_directory)

# --------------------------------------------------------------------------------------------


def encryption_handler(target_filepath, password, decrypt=False):

    target_filename = os.path.basename(target_filepath)

    open_ssl_cmd = [_OPENSSL_EXECUTABLE, "enc"]

    if decrypt:
        open_ssl_cmd.append("-d")
    else:
        target_filename = create_tar_archive(target_filepath, target_filename)

    final_path = target_filename.split(
        ".prnd")[0]+".tar.gz" if decrypt else target_filename + ".prnd"

    open_ssl_cmd.extend(["-aes-256-cbc", "-in", target_filename,
                         "-out", final_path, "-md", "sha256",
                         "-pass", "stdin"])

    password = password.encode("utf8")

    process = subprocess.Popen(open_ssl_cmd,
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    encr_key = pbkdf2_hmac(
        "sha256", password, password[::-1], 20000)

    _, stderr = process.communicate(input=encr_key)

    if not decrypt:
        os.remove(target_filename)

    if process.returncode != 0:
        return None, stderr.decode("utf-8")

    return final_path, None
