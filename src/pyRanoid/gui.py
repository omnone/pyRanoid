# ============================================================================================
# MIT License
# Copyright (c) 2025 Konstantinos Bourantas

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

"""
PyRanoid GUI module.

This module provides the graphical user interface for the PyRanoid steganography
application. It allows users to encrypt files into images and decrypt files from
images using a modern GTK3 interface.
"""

import logging
import os
import sys
import threading
from datetime import datetime

from PIL import Image

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Gdk, GdkPixbuf, GLib, Gtk  # noqa: E402

from .utils import (
    decrypt_image,
)  # noqa: E402

logging.basicConfig(level=logging.DEBUG)


class pyRanoid:
    """
    Main GUI class for the PyRanoid steganography application.

    This class manages the GTK3 user interface, handles user interactions,
    and coordinates encryption/decryption operations.

    :ivar base_path: Base directory path of the application.
    :type base_path: str
    :ivar builder: GTK Builder for loading UI from XML file.
    :type builder: Gtk.Builder
    :ivar window: Main application window.
    :type window: Gtk.Window
    :ivar image_path: Path to the selected source image.
    :type image_path: str or None
    :ivar target_path: Path to the file to encrypt.
    :type target_path: str or None
    :ivar worker_thread: Background thread for encryption/decryption operations.
    :type worker_thread: threading.Thread or None
    """

    def __init__(self):
        self.base_path = os.path.dirname(__file__)
        ui_path = os.path.join(self.base_path, "../../pyRanoid.ui")

        self.builder = Gtk.Builder()
        try:
            self.builder.add_from_file(os.path.abspath(os.path.realpath(ui_path)))
        except Exception as e:
            logging.error(f"Failed to load UI file: {e}", exc_info=True)
            sys.exit(1)

        self.window = self.builder.get_object("window")
        self.window.connect("destroy", Gtk.main_quit)

        icon_path = os.path.join(self.base_path, "../../icon.png")
        try:
            if os.path.exists(icon_path):
                pixbuf = GdkPixbuf.Pixbuf.new_from_file(
                    os.path.abspath(os.path.realpath(icon_path))
                )
                self.window.set_icon(pixbuf)
        except Exception:
            logging.error("Exception:", exc_info=True)

        self.export_checkbox = None
        self.export_opt = 0
        self.image_path = None
        self.target_paths = []
        self.rsa_public_key_path = None
        self.rsa_private_key_path = None
        self.key_password = None
        self.use_rsa_mode = False
        self.target_to_encrypt = None
        self.worker_thread = None
        self.output_path = None
        self.output_dir = None

        self.op_dropdown = self.builder.get_object("op_dropdown")
        self.image_op_btn = self.builder.get_object("image_op_btn")
        self.source_img_path_input = self.builder.get_object("source_img_path_input")
        self.img_picker_btn = self.builder.get_object("img_picker_btn")
        self.target_path_label = self.builder.get_object("target_path_label")
        self.target_path_entry = self.builder.get_object("target_path_entry")
        self.target_picker_btn = self.builder.get_object("target_picker_btn")

        self.password_label = self.builder.get_object("password_label")
        self.password_entry = self.builder.get_object("password_entry")
        self.password_visibility_btn = self.builder.get_object(
            "password_visibility_btn"
        )
        self.password_strength_label = self.builder.get_object(
            "password_strength_label"
        )

        self.mode_toggle_btn = self.builder.get_object("mode_toggle_btn")

        self.image_frame = self.builder.get_object("image_frame")
        self.preview_placeholder = self.builder.get_object("preview_placeholder")
        self.text_area = self.builder.get_object("text_area")
        self.text_buffer = self.text_area.get_buffer()
        self.progress_bar = self.builder.get_object("progress_bar")
        self.status_bar = self.builder.get_object("status_bar")

        self.builder.connect_signals(
            {
                "on_op_dropdown_changed": lambda _: self.op_type_changed(),
                "on_image_op_btn_clicked": lambda _: self.op_handler(),
                "on_img_picker_btn_clicked": lambda _: self.select_image_file(),
                "on_target_picker_btn_clicked": lambda _: self.select_target_file(),
                "on_clear_btn_clicked": lambda _: self.clear_all_fields(),
                "on_password_entry_changed": self.on_password_changed,
                "on_password_visibility_btn_toggled": self.on_password_visibility_toggled,
                "on_password_entry_activate": lambda _: self.on_password_activate(),
                "on_mode_toggle": self.on_mode_toggle,
                "gtk_main_quit": Gtk.main_quit,
            }
        )

        self.password_entry.connect("activate", self.on_password_activate)

        self.status_context_id = self.status_bar.get_context_id("main")
        self.status_bar.push(self.status_context_id, "Ready - Select an image to begin")

        self.progress_bar.set_fraction(0.0)
        self.progress_bar.set_no_show_all(True)

        self.image_widget = None
        self.op_dropdown.set_active(0)

        self.setup_drag_and_drop_for_image(self.source_img_path_input)
        self.setup_drag_and_drop_for_image(self.image_frame)
        self.setup_drag_and_drop_for_target(self.target_path_entry)

        self.op_type_changed()
        self.update_password_strength("")

        self.window.show_all()
        self.progress_bar.hide()

        self.on_mode_toggle(self.mode_toggle_btn)

    # --------------------------------------------------------------------------------------------

    def setup_drag_and_drop_for_image(self, widget):
        """
        Setup drag and drop for image file selection.

        This method configures a widget to accept dragged image files (PNG, JPG, JPEG).
        When a file is dropped, it validates the file type and loads the image.

        :param widget: The widget to enable drag and drop on.
        :type widget: Gtk.Widget
        """
        widget.drag_dest_set(Gtk.DestDefaults.ALL, [], Gdk.DragAction.COPY)
        widget.drag_dest_add_uri_targets()
        widget.connect("drag-data-received", self.on_image_drag_data_received)

    # --------------------------------------------------------------------------------------------

    def setup_drag_and_drop_for_target(self, widget):
        """
        Setup drag and drop for target file selection.

        This method configures a widget to accept any dragged file for encryption.

        :param widget: The widget to enable drag and drop on.
        :type widget: Gtk.Widget
        """
        widget.drag_dest_set(Gtk.DestDefaults.ALL, [], Gdk.DragAction.COPY)
        widget.drag_dest_add_uri_targets()
        widget.connect("drag-data-received", self.on_target_drag_data_received)

    # --------------------------------------------------------------------------------------------

    def on_image_drag_data_received(self, widget, drag_context, x, y, data, info, time):
        """
        Handle drag and drop of image files.

        This callback is triggered when a file is dropped on the source image widget.
        It validates that the file is an image and loads it.

        :param widget: The widget that received the drop.
        :type widget: Gtk.Widget
        :param drag_context: The drag context.
        :type drag_context: Gdk.DragContext
        :param x: X coordinate of the drop.
        :type x: int
        :param y: Y coordinate of the drop.
        :type y: int
        :param data: The selection data.
        :type data: Gtk.SelectionData
        :param info: The info that has been registered with the target.
        :type info: int
        :param time: The timestamp of the event.
        :type time: int
        """
        uris = data.get_uris()
        if uris:
            file_path = uris[0]
            if file_path.startswith("file://"):
                file_path = file_path[7:]

            import urllib.parse

            file_path = urllib.parse.unquote(file_path)

            if not os.path.exists(file_path):
                self.show_error_dialog(
                    "File Not Found", f"The dropped file does not exist:\n{file_path}"
                )
                return

            valid_extensions = (".png", ".jpg", ".jpeg", ".PNG", ".JPG", ".JPEG")
            if not file_path.lower().endswith(valid_extensions):
                self.show_error_dialog(
                    "Invalid File Type",
                    "Please drop a valid image file (PNG, JPG, or JPEG).",
                )
                return

            self.image_path = file_path
            self.source_img_path_input.set_text(file_path)

            try:
                source_image = Image.open(file_path)
                max_size = 250
                width, height = source_image.size
                aspect_ratio = width / height

                if width > height:
                    scaled_width = max_size
                    scaled_height = int(max_size / aspect_ratio)
                else:
                    scaled_height = max_size
                    scaled_width = int(max_size * aspect_ratio)

                source_image = source_image.resize(
                    (scaled_width, scaled_height), Image.Resampling.LANCZOS
                )

                import io

                img_byte_arr = io.BytesIO()
                source_image.save(img_byte_arr, format="PNG")
                img_data = img_byte_arr.getvalue()

                loader = GdkPixbuf.PixbufLoader()
                loader.write(img_data)
                loader.close()
                pixbuf = loader.get_pixbuf()

                if self.image_widget:
                    self.image_frame.remove(self.image_widget)
                if self.preview_placeholder.get_parent():
                    self.image_frame.remove(self.preview_placeholder)

                self.image_widget = Gtk.Image.new_from_pixbuf(pixbuf)
                self.image_widget.set_size_request(scaled_width, scaled_height)
                self.image_frame.pack_start(self.image_widget, False, False, 0)
                self.image_widget.show()

                file_size = os.path.getsize(file_path)
                size_mb = file_size / (1024 * 1024)
                self.status_bar.push(
                    self.status_context_id,
                    f"Image loaded: {os.path.basename(file_path)} ({size_mb:.2f} MB)",
                )

            except Exception as e:
                logging.error("Exception loading dropped image:", exc_info=True)
                self.show_error_dialog(
                    "Image Error", f"Failed to load dropped image:\n{str(e)}"
                )

            self.update_button_state()

    # --------------------------------------------------------------------------------------------

    def on_target_drag_data_received(
        self, widget, drag_context, x, y, data, info, time
    ):
        """
        Handle drag and drop of target files to encrypt.

        This callback is triggered when files are dropped on the target file widget.
        Supports multiple files.

        :param widget: The widget that received the drop.
        :type widget: Gtk.Widget
        :param drag_context: The drag context.
        :type drag_context: Gdk.DragContext
        :param x: X coordinate of the drop.
        :type x: int
        :param y: Y coordinate of the drop.
        :type y: int
        :param data: The selection data.
        :type data: Gtk.SelectionData
        :param info: The info that has been registered with the target.
        :type info: int
        :param time: The timestamp of the event.
        :type time: int
        """
        uris = data.get_uris()
        if uris:
            import urllib.parse

            valid_files = []
            for uri in uris:
                file_path = uri
                if file_path.startswith("file://"):
                    file_path = file_path[7:]

                file_path = urllib.parse.unquote(file_path)

                if os.path.exists(file_path) and os.path.isfile(file_path):
                    valid_files.append(file_path)

            if not valid_files:
                self.show_error_dialog(
                    "No Valid Files", "None of the dropped items are valid files."
                )
                return

            self.target_paths = valid_files

            if len(valid_files) == 1:
                self.target_path_entry.set_text(valid_files[0])
                file_size = os.path.getsize(valid_files[0])
                size_mb = file_size / (1024 * 1024)
                self.status_bar.push(
                    self.status_context_id,
                    f"File selected: {os.path.basename(valid_files[0])} ({size_mb:.2f} MB)",
                )
            else:
                file_names = ", ".join([os.path.basename(f) for f in valid_files])
                self.target_path_entry.set_text(
                    f"{len(valid_files)} files: {file_names}"
                )
                total_size = sum(os.path.getsize(f) for f in valid_files)
                size_mb = total_size / (1024 * 1024)
                self.status_bar.push(
                    self.status_context_id,
                    f"{len(valid_files)} files selected ({size_mb:.2f} MB total)",
                )

            self.update_button_state()

    # --------------------------------------------------------------------------------------------

    def on_mode_toggle(self, button):
        """
        Handle toggle between password mode and RSA mode.

        :param button: The toggle button widget.
        :type button: Gtk.CheckButton
        """
        self.use_rsa_mode = button.get_active()

        if self.use_rsa_mode:
            self.password_label.set_text("RSA Key:")
            self.password_label.set_tooltip_text(
                "Select an RSA public key (for encryption) or private key (for decryption). "
                "Click the field to browse for your key file."
            )

            self.password_entry.set_editable(False)
            self.password_entry.set_visibility(True)
            self.password_entry.set_text("")
            self.password_entry.set_placeholder_text("Click to select RSA key file...")
            self.password_entry.set_tooltip_text(
                "Click here to select your RSA key file. For encryption, select your public key. "
                "For decryption, select your private key."
            )
            self.password_visibility_btn.hide()
            self.password_strength_label.hide()

            if not hasattr(self, "_rsa_click_handler"):
                self._rsa_click_handler = self.password_entry.connect(
                    "button-press-event", lambda w, e: self.select_rsa_key()
                )
        else:
            self.password_label.set_text("Password:")
            self.password_label.set_tooltip_text(
                "Enter a strong password for encryption/decryption. "
                "Use a mix of uppercase, lowercase, numbers, and symbols."
            )

            self.password_entry.set_editable(True)
            self.password_entry.set_text("")
            self.password_entry.set_placeholder_text("Enter a strong password...")
            self.password_entry.set_tooltip_text(
                "Enter a strong password for encryption/decryption. "
                "Use a mix of uppercase, lowercase, numbers, and symbols. Press Enter to execute."
            )
            self.password_entry.set_visibility(False)
            self.password_visibility_btn.show()
            self.password_strength_label.show()

            if hasattr(self, "_rsa_click_handler"):
                self.password_entry.disconnect(self._rsa_click_handler)
                delattr(self, "_rsa_click_handler")

        self.rsa_public_key_path = None
        self.rsa_private_key_path = None
        self.key_password = None

        self.update_button_state()

    # --------------------------------------------------------------------------------------------

    def on_password_changed(self, entry):
        """
        Update password strength indicator when password changes.

        This callback is triggered whenever the user types in the password field.
        It updates the strength indicator and button state.

        :param entry: The password entry widget.
        :type entry: Gtk.Entry
        """
        if not self.use_rsa_mode:
            password = entry.get_text()
            self.update_password_strength(password)
            self.update_button_state()

    # --------------------------------------------------------------------------------------------

    def on_password_visibility_toggled(self, button):
        """
        Toggle password visibility between hidden and visible.

        :param button: The toggle button for password visibility.
        :type button: Gtk.ToggleButton
        """
        self.password_entry.set_visibility(button.get_active())

    # --------------------------------------------------------------------------------------------

    def on_password_activate(self, entry=None):
        """
        Handle Enter key press on password entry.

        If the operation button is enabled, this triggers the encryption/decryption
        operation, allowing users to quickly execute by pressing Enter.

        :param entry: The password entry widget (optional).
        :type entry: Gtk.Entry or None
        """
        if self.image_op_btn.get_sensitive():
            self.op_handler()

    # --------------------------------------------------------------------------------------------

    def update_password_strength(self, password):
        """
        Update the password strength indicator based on password quality.

        Calculates a password strength score and displays it with color coding:
        - Red: Weak (score <= 2)
        - Orange: Medium (score <= 4)
        - Green: Strong (score > 4)

        :param password: The password to evaluate.
        :type password: str
        """
        score = self.password_score(password)

        if len(password) == 0:
            self.password_strength_label.set_text("")
            return

        if score <= 2:
            color = "#ff0000"
            strength = "Weak"
        elif score <= 4:
            color = "#ff8800"
            strength = "Medium"
        else:
            color = "#00ff00"
            strength = "Strong"

        self.password_strength_label.set_markup(
            f"<span color='{color}' weight='bold'>{strength}</span>"
        )

    # --------------------------------------------------------------------------------------------

    def select_rsa_key(self):
        """
        Open a file chooser dialog to select RSA key file.

        This method allows users to browse and select an RSA public key (for encryption)
        or private key (for decryption) file.
        """
        selected_op = self.op_dropdown.get_active_text()

        if selected_op == "Encrypt":
            title = "Select RSA Public Key"
            filter_name = "PEM Files (*.pem)"
        else:
            title = "Select RSA Private Key"
            filter_name = "PEM Files (*.pem)"

        dialog = Gtk.FileChooserDialog(
            title=title,
            parent=self.window,
            action=Gtk.FileChooserAction.OPEN,
        )
        dialog.add_buttons(
            "_Cancel", Gtk.ResponseType.CANCEL, "_Open", Gtk.ResponseType.OK
        )

        filter_keys = Gtk.FileFilter()
        filter_keys.set_name(filter_name)
        filter_keys.add_pattern("*.pem")
        dialog.add_filter(filter_keys)

        filter_all = Gtk.FileFilter()
        filter_all.set_name("All Files")
        filter_all.add_pattern("*")
        dialog.add_filter(filter_all)

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            key_path = dialog.get_filename()

            if selected_op == "Encrypt":
                self.rsa_public_key_path = key_path
                self.password_entry.set_text(key_path)
                self.status_bar.push(
                    self.status_context_id,
                    f"Public key selected: {os.path.basename(key_path)}",
                )
            else:
                self.rsa_private_key_path = key_path
                self.password_entry.set_text(key_path)

                password_dialog = Gtk.MessageDialog(
                    parent=self.window,
                    flags=Gtk.DialogFlags.MODAL,
                    type=Gtk.MessageType.QUESTION,
                    buttons=Gtk.ButtonsType.YES_NO,
                    message_format="Is your private key encrypted with a password?",
                )
                password_response = password_dialog.run()
                password_dialog.destroy()

                if password_response == Gtk.ResponseType.YES:
                    pwd_dialog = Gtk.Dialog(
                        title="Enter Private Key Password",
                        parent=self.window,
                        flags=Gtk.DialogFlags.MODAL,
                    )
                    pwd_dialog.add_buttons(
                        Gtk.STOCK_CANCEL,
                        Gtk.ResponseType.CANCEL,
                        Gtk.STOCK_OK,
                        Gtk.ResponseType.OK,
                    )

                    content_area = pwd_dialog.get_content_area()
                    content_area.set_spacing(10)
                    content_area.set_margin_start(10)
                    content_area.set_margin_end(10)
                    content_area.set_margin_top(10)
                    content_area.set_margin_bottom(10)

                    label = Gtk.Label(label="Enter password for private key:")
                    content_area.pack_start(label, False, False, 0)

                    pwd_entry = Gtk.Entry()
                    pwd_entry.set_visibility(False)
                    pwd_entry.set_invisible_char("*")
                    content_area.pack_start(pwd_entry, False, False, 0)

                    pwd_dialog.show_all()
                    pwd_response = pwd_dialog.run()

                    if pwd_response == Gtk.ResponseType.OK:
                        self.key_password = pwd_entry.get_text()

                    pwd_dialog.destroy()

                self.status_bar.push(
                    self.status_context_id,
                    f"Private key selected: {os.path.basename(key_path)}",
                )

            self.update_button_state()

        dialog.destroy()

    # --------------------------------------------------------------------------------------------

    def show_error_dialog(self, title, message):
        """
        Display an error dialog to the user.

        :param title: The dialog title.
        :type title: str
        :param message: The error message to display.
        :type message: str
        """
        dialog = Gtk.MessageDialog(
            parent=self.window,
            flags=Gtk.DialogFlags.MODAL,
            type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.OK,
            message_format=title,
        )
        dialog.format_secondary_text(message)
        dialog.run()
        dialog.destroy()

    # --------------------------------------------------------------------------------------------

    def show_info_dialog(self, title, message):
        """
        Display an information dialog to the user.

        :param title: The dialog title.
        :type title: str
        :param message: The information message to display.
        :type message: str
        """
        dialog = Gtk.MessageDialog(
            parent=self.window,
            flags=Gtk.DialogFlags.MODAL,
            type=Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.OK,
            message_format=title,
        )
        dialog.format_secondary_text(message)
        dialog.run()
        dialog.destroy()

    # --------------------------------------------------------------------------------------------

    def clear_all_fields(self):
        """
        Clear all input fields and reset the form to its initial state.

        This method:
        - Shows a confirmation dialog before clearing
        - Clears all file paths and text entries
        - Removes the image preview
        - Clears the log text area
        - Resets the operation dropdown to "Encrypt"
        - Updates the button state
        """
        dialog = Gtk.MessageDialog(
            parent=self.window,
            flags=Gtk.DialogFlags.MODAL,
            type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            message_format="Clear All Fields?",
        )
        dialog.format_secondary_text(
            "This will clear all input fields, the password, and the log.\n\n"
            "Are you sure you want to continue?"
        )
        response = dialog.run()
        dialog.destroy()

        if response != Gtk.ResponseType.YES:
            return

        self.image_path = None
        self.target_paths = []
        self.rsa_public_key_path = None
        self.rsa_private_key_path = None
        self.key_password = None
        self.source_img_path_input.set_text("")
        self.target_path_entry.set_text("")

        self.password_entry.set_text("")

        self.text_buffer.set_text("")

        if self.image_widget:
            self.image_frame.remove(self.image_widget)
            self.image_widget = None

        if not self.preview_placeholder.get_parent():
            self.image_frame.pack_start(self.preview_placeholder, True, True, 0)
            self.preview_placeholder.show()

        self.op_dropdown.set_active(0)

        self.update_button_state()

        self.status_bar.push(self.status_context_id, "Ready - Select an image to begin")

        logging.debug("All fields cleared")

    # --------------------------------------------------------------------------------------------

    def op_handler(self):
        """
        Perform encryption or decryption operations on the selected image.

        This method validates all inputs, displays appropriate warnings for weak
        passwords, and starts a background thread to perform the operation without
        freezing the GUI.

        The operation performed depends on the selected dropdown value:
        - Encrypt: Hides a file inside an image
        - Decrypt: Extracts a hidden file from an image
        """
        self.text_buffer.set_text("")

        image_path = self.source_img_path_input.get_text().strip()
        if not image_path:
            self.show_error_dialog(
                "Missing Image", "Please select a source image file."
            )
            return

        if not os.path.exists(image_path):
            self.show_error_dialog(
                "Invalid Image",
                f"The specified image file does not exist:\n{image_path}",
            )
            return

        selected_op = self.op_dropdown.get_active_text()
        logging.debug(f"Operation handler called with operation: {selected_op}")

        if self.use_rsa_mode:
            if selected_op == "Encrypt":
                if not self.rsa_public_key_path:
                    self.show_error_dialog(
                        "Missing RSA Key", "Please select an RSA public key."
                    )
                    return
                if not os.path.exists(self.rsa_public_key_path):
                    self.show_error_dialog(
                        "Invalid RSA Key",
                        f"The specified RSA public key does not exist:\n{self.rsa_public_key_path}",
                    )
                    return
            else:
                if not self.rsa_private_key_path:
                    self.show_error_dialog(
                        "Missing RSA Key", "Please select an RSA private key."
                    )
                    return
                if not os.path.exists(self.rsa_private_key_path):
                    self.show_error_dialog(
                        "Invalid RSA Key",
                        f"The specified RSA private key does not exist:\n{self.rsa_private_key_path}",
                    )
                    return
        else:
            password = self.password_entry.get_text().strip()
            if not password:
                self.show_error_dialog("Missing Password", "Please enter a password.")
                return

            if selected_op == "Encrypt":
                password_score = self.password_score(password)
                if password_score <= 3:
                    dialog = Gtk.MessageDialog(
                        parent=self.window,
                        flags=Gtk.DialogFlags.MODAL,
                        type=Gtk.MessageType.WARNING,
                        buttons=Gtk.ButtonsType.OK_CANCEL,
                        message_format="Weak Password Detected",
                    )
                    dialog.format_secondary_text(
                        "Your password is weak. It is recommended to use a stronger password.\n\nDo you want to continue anyway?"
                    )
                    response = dialog.run()
                    dialog.destroy()
                    if response != Gtk.ResponseType.OK:
                        return

        if selected_op == "Encrypt":
            self.target_to_encrypt = self.target_paths
            if not self.target_to_encrypt:
                self.show_error_dialog(
                    "Missing File", "Please select at least one file to encrypt."
                )
                return

            invalid_files = [f for f in self.target_to_encrypt if not os.path.exists(f)]
            if invalid_files:
                self.show_error_dialog(
                    "Invalid Files",
                    "The following files do not exist:\n" + "\n".join(invalid_files),
                )
                return

            output_dialog = Gtk.FileChooserDialog(
                title="Save Encrypted Image As",
                parent=self.window,
                action=Gtk.FileChooserAction.SAVE,
            )
            output_dialog.add_buttons(
                Gtk.STOCK_CANCEL,
                Gtk.ResponseType.CANCEL,
                Gtk.STOCK_SAVE,
                Gtk.ResponseType.OK,
            )
            output_dialog.set_current_name("output.png")

            png_filter = Gtk.FileFilter()
            png_filter.set_name("PNG Images")
            png_filter.add_pattern("*.png")
            output_dialog.add_filter(png_filter)

            response = output_dialog.run()
            if response == Gtk.ResponseType.OK:
                self.output_path = output_dialog.get_filename()
                if not self.output_path.endswith(".png"):
                    self.output_path += ".png"
            output_dialog.destroy()

            if response != Gtk.ResponseType.OK:
                return

            if len(self.target_to_encrypt) == 1:
                file_desc = os.path.basename(self.target_to_encrypt[0])
            else:
                file_desc = f"{len(self.target_to_encrypt)} files"

            self.status_bar.push(
                self.status_context_id,
                f"Hiding {file_desc} to {self.output_path}...",
            )
            self.write_to_logs_area(
                self, f"[*] Hiding {file_desc} to {self.output_path}..."
            )
            self.worker_thread = threading.Thread(
                target=self.encrypt_image,
                args=(image_path, self.target_to_encrypt),
            )

        else:
            output_dialog = Gtk.FileChooserDialog(
                title="Select Output Directory for Extracted Files",
                parent=self.window,
                action=Gtk.FileChooserAction.SELECT_FOLDER,
            )
            output_dialog.add_buttons(
                Gtk.STOCK_CANCEL,
                Gtk.ResponseType.CANCEL,
                Gtk.STOCK_OPEN,
                Gtk.ResponseType.OK,
            )
            output_dialog.set_current_folder(os.getcwd())

            response = output_dialog.run()
            if response == Gtk.ResponseType.OK:
                self.output_dir = output_dialog.get_filename()
            output_dialog.destroy()

            if response != Gtk.ResponseType.OK:
                return

            self.status_bar.push(
                self.status_context_id,
                f"Extracting files from {os.path.basename(image_path)}...",
            )
            self.write_to_logs_area(self, f"[*] Extracting files from {image_path}...")
            self.worker_thread = threading.Thread(
                target=self.decrypt_image,
                args=(image_path,),
            )

        self.image_op_btn.set_sensitive(False)
        self.progress_bar.show()
        self.progress_bar.set_text("Processing...")
        self.progress_bar.pulse()

        self.worker_thread.daemon = True
        self.worker_thread.start()
        GLib.timeout_add(100, self.progress_handler)

    # --------------------------------------------------------------------------------------------

    def encrypt_image(self, image_path, target_paths):
        """
        Encrypt one or more files into an image using steganography (LSB method).

        This function takes one or more target files, encrypts them using AES-256-GCM,
        and hides them within the pixels of an image using the Least Significant
        Bit (LSB) steganography technique.

        :param image_path: Path to the source image file (PNG, JPG, JPEG).
        :type image_path: str
        :param target_paths: List of paths to files to encrypt and hide.
        :type target_paths: list[str]
        :return: True if successful (CLI mode only), None otherwise.
        :rtype: bool or None
        :raises Exception: If encryption fails or image is too small for the files.
        """

        try:
            from .utils import encrypt_image

            if self.use_rsa_mode:
                encrypt_image(
                    image_path,
                    target_paths,
                    self.output_path,
                    rsa_public_key_path=self.rsa_public_key_path,
                )
            else:
                password = self.password_entry.get_text().strip("\n")
                encrypt_image(
                    image_path, target_paths, self.output_path, password=password
                )

            if len(target_paths) == 1:
                file_desc = target_paths[0]
            else:
                file_desc = f"{len(target_paths)} files"

            self.write_to_logs_area(
                self,
                f"[+] Successfully hidden {file_desc} in {image_path} as {self.output_path}",
            )

        except Exception as e:
            if len(target_paths) == 1:
                file_desc = target_paths[0]
            else:
                file_desc = f"{len(target_paths)} files"

            self.write_to_logs_area(
                self, f"[-] Failed to hide {file_desc} in {image_path}: {e}"
            )
            self.status_bar.push(self.status_context_id, f"Encryption failed: {str(e)}")
        else:
            self.write_to_logs_area(self, f"[+] Final image ready: {self.output_path}")
            self.status_bar.push(
                self.status_context_id,
                f"Encryption complete! Output: {self.output_path}",
            )
        finally:
            self.image_op_btn.set_sensitive(True)

    # --------------------------------------------------------------------------------------------

    def decrypt_image(self, image_path):
        temp_encr_path = None
        temp_tar_path = None

        self.image_op_btn.set_sensitive(False)

        try:
            output_dir = self.output_dir

            if self.use_rsa_mode:
                extracted_files = decrypt_image(
                    image_path,
                    output_dir=output_dir,
                    rsa_private_key_path=self.rsa_private_key_path,
                    key_password=self.key_password,
                )
            else:
                password = self.password_entry.get_text().strip("\n")
                extracted_files = decrypt_image(
                    image_path, output_dir=output_dir, password=password
                )
        except Exception as e:
            self.write_to_logs_area(
                self, f"[-] Failed to extract files from {image_path}: {e}"
            )
            self.status_bar.push(self.status_context_id, f"Extraction failed: {str(e)}")
        else:
            output_abs_path = os.path.abspath(output_dir)
            self.write_to_logs_area(
                self,
                f"[+] Successfully extracted {', '.join(extracted_files)} from {image_path} to {output_abs_path}",
            )
            self.status_bar.push(
                self.status_context_id,
                f"Decryption complete! Files extracted to: {output_abs_path}",
            )
        finally:
            if temp_tar_path and os.path.exists(temp_tar_path):
                os.remove(temp_tar_path)

            if temp_encr_path and os.path.exists(temp_encr_path):
                os.remove(temp_encr_path)

            self.image_op_btn.set_sensitive(True)

    # --------------------------------------------------------------------------------------------

    def progress_handler(self):
        """
        Handle progress bar updates during background operations.

        This method is called periodically to update the progress bar animation
        while encryption/decryption is in progress. It returns True to continue
        updates or False when the operation completes.

        :return: True if operation is still running, False if completed.
        :rtype: bool
        """
        if self.worker_thread and self.worker_thread.is_alive():
            self.progress_bar.pulse()
            return True
        else:
            self.progress_bar.hide()
            self.progress_bar.set_fraction(0.0)
            self.image_op_btn.set_sensitive(True)
            self.status_bar.push(self.status_context_id, "Ready")
            return False

    # --------------------------------------------------------------------------------------------

    def op_type_changed(self):
        """
        Handle changes to the operation type dropdown.

        This method is called when the user switches between Encrypt and Decrypt
        modes. It shows/hides the appropriate UI elements and updates the button
        label and state.
        """
        selected_op = self.op_dropdown.get_active_text()
        logging.debug(f"op_type_changed called: selected_op={selected_op}")

        if selected_op is None:
            selected_op = "Encrypt"
            self.op_dropdown.set_active(0)
            logging.debug("No operation selected, defaulting to Encrypt")

        self.rsa_public_key_path = None
        self.rsa_private_key_path = None
        self.key_password = None
        self.password_entry.set_text("")

        if selected_op == "Encrypt":
            if self.export_checkbox:
                self.export_checkbox.hide()
            self.target_path_label.show()
            self.target_path_entry.show()
            self.target_picker_btn.show()
        else:
            self.target_path_label.hide()
            self.target_path_entry.hide()
            self.target_picker_btn.hide()

        self.image_op_btn.set_label(selected_op)
        logging.debug(f"Button label set to: {selected_op}")
        self.update_button_state()

    # --------------------------------------------------------------------------------------------

    @staticmethod
    def write_to_logs_area(self, msg):
        """
        Handle logging messages to the GUI text area or console.

        Thread-safe logging function that updates the GUI text buffer and
        automatically scrolls to the end.

        :param msg: Message to log.
        :type msg: str
        """
        msg = f"\n[{datetime.now()}] {msg}"
        if GLib:

            def update_text():
                end_iter = self.text_buffer.get_end_iter()
                self.text_buffer.insert(end_iter, msg)
                end_iter = self.text_buffer.get_end_iter()
                self.text_area.scroll_to_iter(end_iter, 0.0, False, 0.0, 1.0)

            GLib.idle_add(update_text)
        else:
            end_iter = self.text_buffer.get_end_iter()
            self.text_buffer.insert(end_iter, msg)
            end_iter = self.text_buffer.get_end_iter()
            self.text_area.scroll_to_iter(end_iter, 0.0, False, 0.0, 1.0)

    # --------------------------------------------------------------------------------------------

    def update_button_state(self):
        """
        Update the state of the operation button based on current inputs.

        The button is enabled only when all required fields are filled:
        - Password mode: image, password, and target file(s) (for encrypt) must be provided
        - RSA mode: image, RSA key, and target file(s) (for encrypt) must be provided

        This method is called whenever any input field changes.
        """
        has_image = bool(self.image_path and os.path.exists(self.image_path))

        selected_op = self.op_dropdown.get_active_text()

        if self.use_rsa_mode:
            if selected_op == "Encrypt":
                has_auth = bool(
                    self.rsa_public_key_path
                    and os.path.exists(self.rsa_public_key_path)
                )
                has_input = bool(
                    self.target_paths
                    and all(os.path.exists(f) for f in self.target_paths)
                )
            else:
                has_auth = bool(
                    self.rsa_private_key_path
                    and os.path.exists(self.rsa_private_key_path)
                )
                has_input = True
        else:
            has_auth = bool(self.password_entry.get_text().strip())
            if selected_op == "Encrypt":
                has_input = bool(
                    self.target_paths
                    and all(os.path.exists(f) for f in self.target_paths)
                )
            else:
                has_input = True

        should_enable = has_image and has_auth and has_input
        logging.debug(
            f"update_button_state: operation={selected_op}, mode={'RSA' if self.use_rsa_mode else 'Password'}, has_image={has_image}, has_auth={has_auth}, has_input={has_input}, should_enable={should_enable}"
        )
        self.image_op_btn.set_sensitive(should_enable)

    # --------------------------------------------------------------------------------------------

    def select_image_file(self):
        """
        Open a file chooser dialog to select an image file.

        This method allows users to browse and select a PNG, JPG, or JPEG image
        file. Once selected, it displays a preview of the image and updates the
        button state.

        Supported formats: PNG, JPG, JPEG
        """
        dialog = Gtk.FileChooserDialog(
            title="Select Source Image",
            parent=self.window,
            action=Gtk.FileChooserAction.OPEN,
        )
        dialog.add_buttons(
            "_Cancel", Gtk.ResponseType.CANCEL, "_Open", Gtk.ResponseType.OK
        )

        filter_images = Gtk.FileFilter()
        filter_images.set_name("Image Files (PNG, JPG, JPEG)")
        filter_images.add_mime_type("image/png")
        filter_images.add_mime_type("image/jpeg")
        filter_images.add_mime_type("image/jpg")
        filter_images.add_pattern("*.png")
        filter_images.add_pattern("*.jpg")
        filter_images.add_pattern("*.jpeg")
        dialog.add_filter(filter_images)

        filter_all = Gtk.FileFilter()
        filter_all.set_name("All Files")
        filter_all.add_pattern("*")
        dialog.add_filter(filter_all)

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            self.image_path = dialog.get_filename()
            self.source_img_path_input.set_text(self.image_path)

            try:
                source_image = Image.open(self.image_path)
                max_size = 250
                width, height = source_image.size
                aspect_ratio = width / height

                if width > height:
                    scaled_width = max_size
                    scaled_height = int(max_size / aspect_ratio)
                else:
                    scaled_height = max_size
                    scaled_width = int(max_size * aspect_ratio)

                source_image = source_image.resize(
                    (scaled_width, scaled_height), Image.Resampling.LANCZOS
                )

                import io

                img_byte_arr = io.BytesIO()
                source_image.save(img_byte_arr, format="PNG")
                img_data = img_byte_arr.getvalue()

                loader = GdkPixbuf.PixbufLoader()
                loader.write(img_data)
                loader.close()
                pixbuf = loader.get_pixbuf()

                if self.image_widget:
                    self.image_frame.remove(self.image_widget)
                if self.preview_placeholder.get_parent():
                    self.image_frame.remove(self.preview_placeholder)

                self.image_widget = Gtk.Image.new_from_pixbuf(pixbuf)
                self.image_widget.set_size_request(scaled_width, scaled_height)
                self.image_frame.pack_start(self.image_widget, False, False, 0)
                self.image_widget.show()

                file_size = os.path.getsize(self.image_path)
                size_mb = file_size / (1024 * 1024)
                self.status_bar.push(
                    self.status_context_id,
                    f"Image loaded: {os.path.basename(self.image_path)} ({size_mb:.2f} MB)",
                )

            except Exception as e:
                logging.error("Exception:", exc_info=True)
                self.show_error_dialog(
                    "Image Error", f"Failed to load image:\n{str(e)}"
                )

            self.update_button_state()

        dialog.destroy()

    # --------------------------------------------------------------------------------------------

    def select_target_file(self):
        """
        Open a file chooser dialog to select files to encrypt.

        This method allows users to browse and select one or more files to hide
        inside the image. Supports multiple file selection.
        """
        dialog = Gtk.FileChooserDialog(
            title="Select File(s) to Encrypt",
            parent=self.window,
            action=Gtk.FileChooserAction.OPEN,
        )
        dialog.add_buttons(
            "_Cancel", Gtk.ResponseType.CANCEL, "_Open", Gtk.ResponseType.OK
        )

        dialog.set_select_multiple(True)

        filter_all = Gtk.FileFilter()
        filter_all.set_name("All Files")
        filter_all.add_pattern("*")
        dialog.add_filter(filter_all)

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            selected_files = dialog.get_filenames()
            self.target_paths = selected_files

            if len(selected_files) == 1:
                self.target_path_entry.set_text(selected_files[0])
                file_size = os.path.getsize(selected_files[0])
                size_mb = file_size / (1024 * 1024)
                self.status_bar.push(
                    self.status_context_id,
                    f"File selected: {os.path.basename(selected_files[0])} ({size_mb:.2f} MB)",
                )
            else:
                file_names = ", ".join([os.path.basename(f) for f in selected_files])
                self.target_path_entry.set_text(
                    f"{len(selected_files)} files: {file_names}"
                )
                total_size = sum(os.path.getsize(f) for f in selected_files)
                size_mb = total_size / (1024 * 1024)
                self.status_bar.push(
                    self.status_context_id,
                    f"{len(selected_files)} files selected ({size_mb:.2f} MB total)",
                )

            self.update_button_state()

        dialog.destroy()

    # --------------------------------------------------------------------------------------------

    def password_score(self, password):
        """
        Calculate a password strength score.

        The score is based on multiple criteria:
        - Length >= 8 characters (+1)
        - Contains uppercase letters (+1)
        - Contains lowercase letters (+1)
        - Contains digits (+1)
        - Contains special characters (+1)
        - High character diversity (+1)

        :param password: The password to evaluate.
        :type password: str
        :return: Password strength score (0-6).
        :rtype: int
        """
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

    # --------------------------------------------------------------------------------------------


def main():
    """Main entry point for GUI application."""
    pyRanoid()
    Gtk.main()


if __name__ == "__main__":
    main()
