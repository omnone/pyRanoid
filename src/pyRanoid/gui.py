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
import utils
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog
import threading
from ttkthemes import ThemedTk
import sys
import pyfiglet
from PIL import ImageTk, Image
import os

import logging
logging.basicConfig(level=logging.DEBUG)
# ============================================================================================


class pyRanoid:
    def __init__(self, root, image=None):

        root.minsize(1000, 500)
        root.title("PyRanoid")
        root.resizable(False, False)

        # icon made by : https://www.flaticon.com/authors/becris
        self.base_path = os.path.dirname(__file__)
        icon_path = os.path.join(self.base_path, "../../icon.png")

        try:
            ico = Image.open(os.path.abspath(os.path.realpath(icon_path)))
        except Exception:
            logging.error("Exception:", exc_info=True)
        else:
            photo = ImageTk.PhotoImage(ico)
            root.wm_iconphoto(False, photo)

        self.export_checkbox = None
        self.export_opt = 0
        self.image_path = None
        self.target_path = None
        self.rsa_key_path = None
        self.target_to_encrypt = None

        self.root = root

        self.inputs_frame = ttk.Frame(root,  borderwidth=1, relief=tk.SUNKEN)
        self.inputs_frame.grid(row=0, column=0, pady=10,
                               padx=30, sticky=tk.W+tk.E)
        self.inputs_frame["padding"] = (5, 20, 5, 20)

        self.output_frame = ttk.Frame(root, borderwidth=1, relief=tk.SUNKEN)
        self.output_frame.grid(row=6, column=0, rowspan=8,
                               pady=5, padx=10, sticky=tk.W+tk.E)
        self.output_frame["padding"] = (5, 0, 5, 0)
        self.output_frame.columnconfigure(0, weight=1)

        self.image_frame = ttk.Frame(self.inputs_frame)
        self.image_frame.grid(row=2, column=2, rowspan=10,
                              columnspan=10, pady=30, padx=30)

        # -----------------------------------------------
        # operation type combobox
        self.op_type = tk.StringVar()
        self.op_label = ttk.Label(
            self.inputs_frame, text="Operation Type:")
        self.op_label.grid(row=0, column=0, sticky=tk.W)
        self.op_dropdown = ttk.Combobox(
            self.inputs_frame, textvariable=self.op_type,
            state="readonly",  width=27)
        self.op_dropdown.grid(row=1, column=0, sticky=tk.W)
        self.op_dropdown["values"] = ("encrypt", "decrypt")
        self.op_dropdown.current(0)
        self.op_dropdown.bind(
            "<<ComboboxSelected>>", lambda _: self.op_type_changed())

        # --------------------------------------------------------------------------------------------
        # Input type combobox
        self.input_type = tk.StringVar()
        self.input_label = ttk.Label(self.inputs_frame, text="Input Type:")
        self.input_label.grid(row=0, column=1, sticky=tk.W)
        self.input_dropdown = ttk.Combobox(
            self.inputs_frame, textvariable=self.input_type,
            state="readonly",  width=27)
        self.input_dropdown.grid(row=1, column=1, sticky=tk.W)
        self.input_dropdown["values"] = ("File", )
        self.input_dropdown.current(0)
        self.input_dropdown.bind(
            "<<ComboboxSelected>>", lambda _: self.input_type_changed())

        # --------------------------------------------------------------------------------------------
        # Image selection
        self.source_img_path_label = ttk.Label(
            self.inputs_frame, text="Image Path:")
        self.source_img_path_label.grid(row=2, column=0, sticky=tk.W)

        self.source_img_path_input = ttk.Entry(self.inputs_frame, width="50")
        self.source_img_path_input.grid(row=3, column=0, sticky=tk.W)

        self.img_picker_btn = ttk.Button(self.inputs_frame, text="Open", width=8,
                                         command=lambda: self.select_image_file())
        self.img_picker_btn.grid(row=3, column=1, sticky=tk.W)

        # --------------------------------------------------------------------------------------------
        # target file selection
        self.target_path_label = ttk.Label(
            self.inputs_frame, text="Target Path:")
        self.target_path_label.grid(row=4, column=0, sticky=tk.W)

        self.target_path_entry = ttk.Entry(self.inputs_frame, width="50")
        self.target_path_entry.grid(row=5, column=0, sticky=tk.W)

        self.target_picker_btn = ttk.Button(self.inputs_frame, text="Open", width=8,
                                            command=lambda: self.select_target_file())
        self.target_picker_btn.grid(row=5, column=1, sticky=tk.W)

        self.text_msg_label = ttk.Label(
            self.inputs_frame, text="Text Message:")
        self.text_msg_entry = ttk.Entry(self.inputs_frame, width="50")
        # --------------------------------------------------------------------------------------------
        # password input
        self.password_label = ttk.Label(self.inputs_frame, text="Password:")
        self.password_label.grid(row=6, column=0, sticky=tk.W)

        self.password_entry = ttk.Entry(
            self.inputs_frame, show="*", width="30")
        self.password_entry.grid(row=7, column=0, sticky=tk.W)

        # --------------------------------------------------------------------------------------------
        # Text area
        self.text_area = tk.Text(self.output_frame, height=18,
                                 width=95, bg="black", fg="darkorchid1",
                                 insertbackground="darkorchid1")
        self.text_area.config(state="normal")
        self.text_area.grid(row=8, column=0,  rowspan=2,
                            sticky=tk.W+tk.E+tk.N+tk.S, pady=5)

        self.text_area.columnconfigure(0, weight=1)
        self.output_frame.columnconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        # # --------------------------------------------------------------------------------------------
        # # ascii banner
        self.ascii_banner = pyfiglet.figlet_format("pyRanoid")
        self.text_area.insert(
            tk.END, f"{self.ascii_banner}\n*Stay safe, use a strong password!\n-------------------------------------------------------------------------------------------")

        # # --------------------------------------------------------------------------------------------
        # progress bar
        self.progress_bar = ttk.Progressbar(
            self.output_frame, orient="horizontal",
            length=650, mode="indeterminate")
        self.progress_bar.columnconfigure(0, weight=1)

        # # --------------------------------------------------------------------------------------------
        # # cancel button
        self.cancel_btn = ttk.Button(self.output_frame, text="Exit", width=8,
                                     command=lambda: sys.exit(0))
        self.cancel_btn.grid(row=13, column=3, sticky=tk.E, pady=10)

        self.op_type_changed()
        self.input_type_changed()

        self.root.mainloop()
    # --------------------------------------------------------------------------------------------

    def op_handler(self):
        """encrypt/decrypt operations on selected image"""
        if self.input_type.get() == "Text":
            self.target_to_encrypt = self.text_msg_entry.get()
        else:
            self.target_to_encrypt = self.target_path

        if self.op_type.get() == "encrypt":
            password_score = self.password_score(
                self.password_entry.get().strip("\n"))

            if password_score <= 3:
                utils.log_handler(
                    self, f"[!]Caution your password is weak!")

            utils.log_handler(
                self, f"[*]Encrypting {self.target_to_encrypt}...")
            self.worker_thread = threading.Thread(
                target=utils.encrypt_image, args=(self.source_img_path_input.get(),
                                                  self.target_to_encrypt, self))

        else:
            utils.log_handler(self, f"[*]Decrypting {self.image_path}")

            self.worker_thread = threading.Thread(
                target=utils.decrypt_image, args=(self.source_img_path_input.get(), self))

        self.progress_bar.grid(row=5, column=0, sticky=tk.W)
        self.progress_bar.start()

        self.worker_thread.daemon = True
        self.worker_thread.start()
        self.root.after(100, self.progress_handler)
    # --------------------------------------------------------------------------------------------

    def progress_handler(self):

        if (self.worker_thread.is_alive()):
            self.root.after(100, self.progress_handler)
            return
        else:
            self.progress_bar.stop()
            self.progress_bar.grid_remove()

    # --------------------------------------------------------------------------------------------

    def input_type_changed(self):
        if (self.input_type.get() == "Text"):
            self.text_msg_label.grid(row=4, column=0, sticky=tk.W)
            self.text_msg_entry.grid(row=5, column=0, sticky=tk.W)
            self.target_path_label.grid_remove()
            self.target_path_entry.grid_remove()
            self.target_picker_btn.grid_remove()
        else:
            self.target_path_label.grid(row=4, column=0, sticky=tk.W)
            self.target_path_entry.grid(row=5, column=0, sticky=tk.W)
            self.target_picker_btn.grid(row=5, column=1, sticky=tk.W)
            self.text_msg_label.grid_remove()
            self.text_msg_entry.grid_remove()
    # --------------------------------------------------------------------------------------------

    def op_type_changed(self):
        selected_op = self.op_type.get()
        if selected_op == "encrypt":
            if self.export_checkbox:
                self.export_checkbox.grid_remove()
            self.input_type_changed()
        else:
            self.target_path_label.grid_remove()
            self.target_path_entry.grid_remove()
            self.target_picker_btn.grid_remove()
            self.text_msg_entry.grid_remove()
            self.text_msg_label.grid_remove()

        # encrypt/decrypt button
        self.image_op_btn = ttk.Button(self.inputs_frame, text=selected_op, width=8,
                                       command=lambda: self.op_handler(),
                                       state="normal" if self.image_path else "disabled")
        self.image_op_btn.grid(row=1, column=2)

    # --------------------------------------------------------------------------------------------

    def select_image_file(self):
        """Open an image from a directory"""
        # Select the Imagename  from a folder
        tk.Tk().withdraw()
        self.image_path = filedialog.askopenfilename(title="Open Image", filetypes=[
                                                    ("Image Files", ".png .jpg .jpeg")])
        self.source_img_path_input.delete(0, tk.END)
        self.source_img_path_input.insert(tk.INSERT, self.image_path)

        # opens the image
        source_image = Image.open(self.image_path)

        max_width = 300
        width, height = source_image.size
        aspect_ratio = width / height
        scaled_width = min(width, max_width)
        scaled_height = int(scaled_width / aspect_ratio)

        # resize the image and apply a high-quality down sampling filter
        source_image = source_image.resize(
            (scaled_width, scaled_height), Image.ANTIALIAS)

        # PhotoImage class is used to add image to widgets, icons etc
        source_image = ImageTk.PhotoImage(source_image)

        # create a label
        self.panel = ttk.Label(self.image_frame, image=source_image)

        # set the image as source_image
        self.panel.image = source_image
        self.panel.grid(row=6, column=3, padx=5)

        try:
            self.image_op_btn["state"] = "normal"
        except Exception:
            logging.error("Exception:", exc_info=True)

    # --------------------------------------------------------------------------------------------

    def select_target_file(self):
        """Select file to encrypt from a directory"""
        tk.Tk().withdraw()
        self.target_path = filedialog.askopenfilename(title="Select File")
        self.target_path_entry.delete(0, tk.END)
        self.target_path_entry.insert(tk.INSERT, self.target_path)

        try:
            self.image_op_btn["state"] = "normal"
        except Exception:
            logging.error("Exception:", exc_info=True)

    # --------------------------------------------------------------------------------------------

    def password_score(self, password):
        score = 0

        if len(password) >= 8:
            score += 1

        if any(char.isupper() for char in password):
            score += 1
        if any(char.islower() for char in password):
            score += 1
        if any(char.isdigit() for char in password):
            score += 1
        if any(not char.isalnum() for char in password):
            score += 1

        unique_chars = set(password)
        if len(unique_chars) >= len(password) / 2:
            score += 1

        return score


if __name__ == "__main__":
    root = ThemedTk(background=True, theme="equilux")
    pyRanoid(root)
