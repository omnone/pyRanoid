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
import os
from encryption import generateRSAKeys, encryptRSA
# ============================================================================================


class pyRanoid:
    def __init__(self, root, image=None):

        root.minsize(500, 500)
        root.title("PyRanoid")
        root.resizable(True, True)
        # icon made by : https://www.flaticon.com/authors/becris
        self.basePath = os.path.dirname(__file__)
        iconPath = os.path.join(self.basePath, "../../icon.png")
        try:
            ico = Image.open(os.path.abspath(os.path.realpath(iconPath)))
        except:
            pass
        else:
            photo = ImageTk.PhotoImage(ico)
            root.wm_iconphoto(False, photo)

        self.checkboxExport = None
        self.exportOpt = 0
        self.imagePath = None
        self.targetFilePath = None
        self.rsaKeyPath = None
        self.valueToEncrypt = None

        self.root = root

        self.inputsFrame = ttk.Frame(root,  borderwidth=1, relief=tk.SUNKEN)
        self.inputsFrame.grid(row=0, column=1, rowspan=5,
                              columnspan=10, pady=10, padx=30)
        self.inputsFrame["padding"] = (5, 20, 5, 20)

        self.outputsFrame = ttk.Frame(root, borderwidth=1, relief=tk.SUNKEN)
        self.outputsFrame.grid(row=6, column=1, rowspan=8, pady=5, padx=10)
        self.outputsFrame["padding"] = (5, 0, 5, 0)

        self.imageFrame = ttk.Frame(self.inputsFrame)
        self.imageFrame.grid(row=2, column=2, rowspan=10,
                             columnspan=10, pady=30, padx=30)

        # -----------------------------------------------
        # operation type combobox
        self.opTypeStr = tk.StringVar()
        self.operationLabel = ttk.Label(
            self.inputsFrame, text="Operation Type:")
        self.operationLabel.grid(row=0, column=0, sticky=tk.W)
        self.operationDropDown = ttk.Combobox(
            self.inputsFrame, textvariable=self.opTypeStr, state="readonly",  width=27)
        self.operationDropDown.grid(row=1, column=0, sticky=tk.W)
        self.operationDropDown["values"] = ("encrypt", "decrypt")
        self.operationDropDown.current(0)
        self.operationDropDown.bind(
            "<<ComboboxSelected>>", lambda event: self.operationTypeChanged())

        # --------------------------------------------------------------------------------------------
        # Input type combobox
        self.inputTypeStr = tk.StringVar()
        self.inputTypeLabel = ttk.Label(self.inputsFrame, text="Input Type:")
        self.inputTypeLabel.grid(row=0, column=1, sticky=tk.W)
        self.inputTypeDropDown = ttk.Combobox(
            self.inputsFrame, textvariable=self.inputTypeStr, state="readonly",  width=27)
        self.inputTypeDropDown.grid(row=1, column=1, sticky=tk.W)
        self.inputTypeDropDown["values"] = ("File", "Text")
        self.inputTypeDropDown.current(0)
        self.inputTypeDropDown.bind(
            "<<ComboboxSelected>>", lambda event: self.inputTypeChanged())

        # --------------------------------------------------------------------------------------------
        # Image selection
        self.imageDirLabel = ttk.Label(self.inputsFrame, text="Image Path:")
        self.imageDirLabel.grid(row=2, column=0, sticky=tk.W)

        self.imagePathEntry = ttk.Entry(self.inputsFrame, width="50")
        self.imagePathEntry.grid(row=3, column=0, sticky=tk.W)

        self.btnChooseImgDir = ttk.Button(self.inputsFrame, text="Open",   width=8,
                                          command=lambda: self.selectImage())
        self.btnChooseImgDir.grid(row=3, column=1, sticky=tk.W)

        # --------------------------------------------------------------------------------------------
        # target file selection
        self.targetDirLabel = ttk.Label(self.inputsFrame, text="Target Path:")
        self.targetDirLabel.grid(row=4, column=0, sticky=tk.W)

        self.targetPathEntry = ttk.Entry(self.inputsFrame, width="50")
        self.targetPathEntry.grid(row=5, column=0, sticky=tk.W)

        self.btnChooseTargetDir = ttk.Button(self.inputsFrame, text="Open",   width=8,
                                             command=lambda: self.selectTargetFile())
        self.btnChooseTargetDir.grid(row=5, column=1, sticky=tk.W)

        self.rsaKeyDirLabel = ttk.Label(
            self.inputsFrame, text="Public RSA key Path:")
        self.rsaKeyPathEntry = ttk.Entry(self.inputsFrame, width="50")
        self.btnChooseRsaKeyDir = ttk.Button(self.inputsFrame, text="Open",   width=8,
                                             command=lambda: self.selectRsaKeyFile())

        self.generateRsaKeysBtn = ttk.Button(self.inputsFrame, text="Generate Keys",   width=15,
                                             command=lambda: self.generateRSAKeysCallback())

        self.messageLabel = ttk.Label(self.inputsFrame, text="Text Message:")
        self.messageEntry = ttk.Entry(self.inputsFrame, width="50")
        # --------------------------------------------------------------------------------------------

        self.passLabel = ttk.Label(self.inputsFrame, text="Password:")
        self.passLabel.grid(row=6, column=0, sticky=tk.W)

        self.passwordEntry = ttk.Entry(
            self.inputsFrame, show="*", width="30")
        self.passwordEntry.grid(row=7, column=0, sticky=tk.W)
        # --------------------------------------------------------------------------------------------
        # RSA support
        self.rsaOption = tk.IntVar()
        self.rsaencrypt = ttk.Checkbutton(
            self.inputsFrame, text="RSA Support", variable=self.rsaOption, command=lambda: self.rsaSupport())

        self.rsaencrypt.grid(row=8, column=0, sticky=tk.W)

        self.publicKeyLabel = ttk.Label(
            self.inputsFrame, text="RSA public key:")

        self.publicKeyEntry = ttk.Entry(
            self.inputsFrame, width="30")

        # --------------------------------------------------------------------------------------------
        # Text area
        self.textArea = tk.Text(self.outputsFrame, height=18,
                                width=95, bg="black", fg="purple", insertbackground="purple")
        self.textArea.config(state="normal")
        self.textArea.grid(row=8, column=1, columnspan=3, rowspan=2,
                           sticky=tk.W+tk.E+tk.N+tk.S, pady=5)

        # # --------------------------------------------------------------------------------------------
        # # ascii banner
        self.ascii_banner = pyfiglet.figlet_format("pyRanoid")
        self.textArea.insert(
            tk.END, self.ascii_banner+"\n========================================================")

        # # --------------------------------------------------------------------------------------------
        # progress bar
        self.progressBar = ttk.Progressbar(
            self.outputsFrame, orient="horizontal", length=550, mode="indeterminate")

        # # --------------------------------------------------------------------------------------------
        # # cancel button
        self.btnCancel = ttk.Button(self.outputsFrame, text="Exit", width=8,
                                    command=lambda: sys.exit(0))
        self.btnCancel.grid(row=13, column=3, sticky=tk.E, pady=10)

        self.operationTypeChanged()
        self.inputTypeChanged()

        root.mainloop()
    # --------------------------------------------------------------------------------------------
    # Buttons callbacks functions

    def imageSteg(self):
        """encrypt/decrypt operations on selected image"""
        if(self.inputTypeStr.get() == "Text"):
            self.valueToEncrypt = self.messageEntry.get()
        else:
            self.valueToEncrypt = self.targetFilePath

        if self.opTypeStr.get() == "encrypt":
            # encrypt message to the selected image
            self.textArea.insert(tk.END, "\n[*]Encrypting...")
            self.subThread = threading.Thread(
                target=lsbSteg.encryptImage, args=(self.imagePathEntry.get(), self.valueToEncrypt, self))
            self.progressBar.grid(row=5, column=1, columnspan=1, sticky=tk.W)
            self.progressBar.start()
            self.subThread.start()
            self.root.after(100, self.checkThread)

            # if (self.rsaOption.get() == 1):
            #     encryptedPswd = encryptRSA(
            #         self.passwordEntry.get().strip("\n"),self.rsaKeyPath)
            #     self.textArea.insert(
            #         tk.END, "\n[+]Encrypted Password: ")
            #     print(<encryptedPswd)

        else:
            # decrypt message from the selected image
            self.textArea.insert(tk.END, f"\n[*]Decrypting {self.imagePath}")

            self.subThread = threading.Thread(
                target=lsbSteg.decryptImage, args=(self.imagePathEntry.get(), self))

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
    def generateRSAKeysCallback(self):
        self.subThread = threading.Thread(
            target=generateRSAKeys, args=(self,))
        self.progressBar.grid(row=5, column=1, columnspan=1, sticky=tk.W)
        self.progressBar.start()
        self.subThread.start()
        self.root.after(100, self.checkThread)
        self.textArea.insert(tk.END, f"\n[+]RSA keys have been generated.")
        basePath = os.path.dirname(__file__)
        publicKeyPath = os.path.join(basePath, "publicKey.pem")
        privateKeyPath = os.path.join(basePath, "privateKey.pem")

        self.textArea.insert(tk.END, "\n"+publicKeyPath)
        self.textArea.insert(tk.END, "\n"+privateKeyPath)
        text = self.opTypeStr.get()

        self.rsaKeyPath = publicKeyPath if text == "encrypt" else privateKeyPath
        self.rsaKeyPathEntry.insert(tk.INSERT, self.rsaKeyPath)

    # --------------------------------------------------------------------------------------------

    def rsaSupport(self):
        if (self.rsaOption.get() == 1):
            self.rsaKeyPathEntry.grid(row=10, column=0, sticky=tk.W)
            self.rsaKeyDirLabel.grid(row=9, column=0, sticky=tk.W)
            self.btnChooseRsaKeyDir.grid(row=10, column=1, sticky=tk.W)
            self.generateRsaKeysBtn.grid(row=10, column=2, sticky=tk.W)
            try:
                self.btnOpImage["state"] = "disabled"
            except:
                pass
        else:
            self.rsaKeyPathEntry.grid_remove()
            self.rsaKeyDirLabel.grid_remove()
            self.btnChooseRsaKeyDir.grid_remove()
            self.generateRsaKeysBtn.grid_remove()

    # --------------------------------------------------------------------------------------------

    def inputTypeChanged(self):
        text = self.inputTypeStr.get()
        if(text == "Text"):
            self.messageLabel.grid(row=4, column=0, sticky=tk.W)
            self.messageEntry.grid(row=5, column=0, sticky=tk.W)
            self.targetDirLabel.grid_remove()
            self.targetPathEntry.grid_remove()
            self.btnChooseTargetDir.grid_remove()
        else:
            self.targetDirLabel.grid(row=4, column=0, sticky=tk.W)
            self.targetPathEntry.grid(row=5, column=0, sticky=tk.W)
            self.btnChooseTargetDir.grid(row=5, column=1, sticky=tk.W)
            self.messageLabel.grid_remove()
            self.messageEntry.grid_remove()

    def operationTypeChanged(self):
        text = self.opTypeStr.get()

        if text == "encrypt":
            self.rsaKeyDirLabel.config(text="RSA Public Key Path:")
            if self.checkboxExport:
                self.checkboxExport.grid_remove()
            self.inputTypeChanged()
        else:
            self.targetDirLabel.grid_remove()
            self.targetPathEntry.grid_remove()
            self.btnChooseTargetDir.grid_remove()
            self.messageEntry.grid_remove()
            self.messageLabel.grid_remove()
            self.rsaKeyDirLabel.config(text="RSA Private Key Path:")

            self.exportOpt = tk.IntVar()
            self.checkboxExport = ttk.Checkbutton(
                self.inputsFrame, text="Export to file", variable=self.exportOpt)
            self.checkboxExport.grid(row=2, column=2, sticky=tk.E)

        # encrypt/decrypt button
        self.btnOpImage = ttk.Button(self.inputsFrame, text=text, width=8,
                                     command=lambda: self.imageSteg(), state="normal" if self.imagePath else "disabled")
        self.btnOpImage.grid(row=1, column=2)

    # --------------------------------------------------------------------------------------------

    def selectImage(self):
        """Open an image from a directory"""
        # Select the Imagename  from a folder
        tk.Tk().withdraw()
        self.imagePath = filedialog.askopenfilename(title="Open Image", filetypes=[
                                                    ("Image Files", ".png .jpg .jpeg .svg")])
        self.imagePathEntry.delete(0, tk.END)
        self.imagePathEntry.insert(tk.INSERT, self.imagePath)

        # opens the image
        img = Image.open(self.imagePath)

        # resize the image and apply a high-quality down sampling filter
        img = img.resize((100, 100), Image.ANTIALIAS)

        # PhotoImage class is used to add image to widgets, icons etc
        img = ImageTk.PhotoImage(img)

        # create a label
        self.panel = ttk.Label(self.imageFrame, image=img)

        # set the image as img
        self.panel.image = img
        self.panel.grid(row=6, column=3, padx=5)

        try:
            self.btnOpImage["state"] = "normal"
        except:
            pass

    def selectTargetFile(self):
        """Select file to encrypt from a directory"""
        tk.Tk().withdraw()
        self.targetFilePath = filedialog.askopenfilename(title="Select File")
        self.targetPathEntry.delete(0, tk.END)
        self.targetPathEntry.insert(tk.INSERT, self.targetFilePath)

        try:
            self.btnOpImage["state"] = "normal"
        except:
            pass

    def selectRsaKeyFile(self):
        """Select file to encrypt from a directory"""
        tk.Tk().withdraw()
        self.rsaKeyPath = filedialog.askopenfilename(
            title="Select RSA key file", defaultextension=".pem", filetypes=[("RSA key files", ".pem")])
        self.rsaKeyPathEntry.delete(0, tk.END)
        self.rsaKeyPathEntry.insert(tk.INSERT, self.rsaKeyPath)

        try:
            self.btnOpImage["state"] = "normal"
        except:
            pass


# ============================================================================================
if __name__ == "__main__":
    root = ThemedTk(background=True, theme="equilux")
    pyRanoid(root)
# ============================================================================================
