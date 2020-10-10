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

import lsbSteg
import tkinter as tk
import tkinter.ttk as ttk
from tkinter.filedialog import askdirectory
from tkinter import filedialog
import threading
from ttkthemes import ThemedTk
import sys
import pyfiglet
from PIL import ImageTk, Image
# ============================================================================================


class pyHide:
    def __init__(self, root, image=None):

        root.minsize(700, 700)
        root.title('PyHide')
        # icon made by : https://www.flaticon.com/authors/becris
        ico = Image.open('../icon.png')
        photo = ImageTk.PhotoImage(ico)
        root.wm_iconphoto(False, photo)

        self.checkboxExport = None
        self.exportOpt = 0
        self.imagePath = None

        self.root = root

        self.frame = ttk.Frame(root)
        self.frame.grid(row=0, column=1, rowspan=5, pady=30, padx=10)

        # -----------------------------------------------
        self.dirLabel = ttk.Label(self.frame, font=25, text="Image Path:")
        self.dirLabel.grid(row=0, column=0, sticky=tk.W)

        self.imagePathEntry = ttk.Entry(self.frame, font=40, width="50")
        self.imagePathEntry.grid(row=0, column=1)

        self.passLabel = ttk.Label(self.frame, font=25, text="Password:")
        self.passLabel.grid(row=1, column=0, sticky=tk.W)

        self.passwordEntry = ttk.Entry(
            self.frame, show="*", font=40, width="50")
        self.passwordEntry.grid(row=1, column=1)

        self.btnChooseDir = ttk.Button(self.frame, text="Open",   width=8,
                                       command=lambda: self.selectImage())
        self.btnChooseDir.grid(row=0, column=2)

        # --------------------------------------------------------------------------------------------
        # radio buttons
        self.radioOption = tk.StringVar(value="")
        self.radioEncode = ttk.Radiobutton(
            self.frame, text="Encode", variable=self.radioOption, value='Encode', command=lambda: self.radioBtnCallback('Encode'))

        self.radioEncode.grid(row=2, column=1,sticky=tk.W)

        self.radioDecode = ttk.Radiobutton(
            self.frame, text="Decode", variable=self.radioOption, value='Decode', command=lambda: self.radioBtnCallback('Decode'))
        self.radioDecode.grid(row=2, column=1,sticky=tk.E)

        self.textArea = tk.Text(self.frame, height=30,
                                width=40, bg="black", fg="purple", insertbackground="purple")
        self.textArea.config(state='normal')
        self.textArea.grid(row=3, column=1, columnspan=1, rowspan=2,
                           sticky=tk.W+tk.E+tk.N+tk.S, pady=5)

        # --------------------------------------------------------------------------------------------
        # ascii banner
        self.ascii_banner = pyfiglet.figlet_format('pyHide')
        self.textArea.insert(
            tk.END, self.ascii_banner+"\n========================================================")

        # --------------------------------------------------------------------------------------------
        # progress bar
        self.progressBar = ttk.Progressbar(
            self.frame, orient="horizontal", length=550, mode="indeterminate")

        # --------------------------------------------------------------------------------------------
        # cancel button
        self.btnCancel = ttk.Button(self.frame, text="Exit", width=8,
                                    command=lambda: sys.exit(1))
        self.btnCancel.grid(row=6, column=2, sticky=tk.W, pady=10)

        root.mainloop()
    # --------------------------------------------------------------------------------------------
    # Buttons callbacks functions

    def imageSteg(self):
        """Encode/Decode operations on selected image"""
        if self.btnOpImage['text'] == 'Encode':
            # Encode message to the selected image
            self.textArea.insert(tk.END, "\n[*]Encoding...")
            self.subThread = threading.Thread(
                target=lsbSteg.encodeImage, args=(self.imagePathEntry.get(),
                                                  self.textArea.get("1.0", tk.END).split('[*]Encoding...')[0].split('[*]Enter message:')[-1], self))
            self.progressBar.grid(row=5, column=1, columnspan=1, sticky=tk.W)
            self.progressBar.start()
            self.subThread.start()
            self.root.after(100, self.checkThread)

        else:
            # Decode message from the selected image
            self.textArea.insert(tk.END, f"\n[*]Decoding {self.imagePath}")

            self.subThread = threading.Thread(
                target=lsbSteg.decodeImage, args=(self.imagePathEntry.get(), self))

            self.progressBar.grid(row=5, column=1, columnspan=1, sticky=tk.W)
            self.progressBar.start()
            self.subThread.start()
            self.root.after(100, self.checkThread)
    # --------------------------------------------------------------------------------------------

    def checkThread(self):

        if (self.subThread.is_alive()):

            self.root.after(100, self.checkThread)
            return
        else:
            self.progressBar.stop()
            self.progressBar.grid_remove()

    # --------------------------------------------------------------------------------------------

    def radioBtnCallback(self, text):
        self.textArea.delete('1.0', tk.END)

        self.textArea.insert(
            tk.END, self.ascii_banner+"\n========================================================")

        if text == "Encode":
            self.textArea.insert(tk.END, "\n[*]Enter message:")
            if self.checkboxExport:
                self.checkboxExport.grid_remove()
        else:
            self.exportOpt = tk.IntVar()
            self.checkboxExport = ttk.Checkbutton(
                self.frame, text="Export to file", variable=self.exportOpt)
            self.checkboxExport.grid(row=2, column=2, sticky=tk.E)

        self.btnOpImage = ttk.Button(self.frame, text=text, width=8,
                                     command=lambda: self.imageSteg(), state="normal" if self.imagePath else "disabled")
        self.btnOpImage.grid(row=1, column=2)

    # --------------------------------------------------------------------------------------------

    def selectImage(self):
        """Open an image from a directory"""
        # Select the Imagename  from a folder
        tk.Tk().withdraw()
        self.imagePath = filedialog.askopenfilename(title='Open Image')
        self.imagePathEntry.delete(0, tk.END)
        self.imagePathEntry.insert(tk.INSERT, self.imagePath)

        # opens the image
        img = Image.open(self.imagePath)

        # resize the image and apply a high-quality down sampling filter
        img = img.resize((200, 200), Image.ANTIALIAS)

        # PhotoImage class is used to add image to widgets, icons etc
        img = ImageTk.PhotoImage(img)

        # create a label
        self.panel = ttk.Label(self.frame, image=img)

        # set the image as img
        self.panel.image = img
        self.panel.grid(row=3, column=0, padx=5)

        try:
            self.btnOpImage['state'] = 'normal'
        except:
            pass


# ============================================================================================
if __name__ == "__main__":
    root = ThemedTk(background=True, theme="equilux")
    pyHide(root)
# ============================================================================================
