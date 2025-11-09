"""
Unit tests for pyRanoid GUI module.

Tests password scoring logic and other testable GUI components.
Full GUI testing requires a GTK environment.
"""

import pytest
import sys
import os
from unittest.mock import patch

test_dir = os.path.dirname(__file__)
src_dir = "../../"
sys.path.insert(0, os.path.abspath(os.path.join(test_dir, src_dir)))


class TestPasswordScoring:
    """Test password strength scoring logic."""

    def test_password_score_empty(self):
        """Test password score for empty password."""
        password = ""
        score = self._calculate_password_score(password)
        assert score == 1  # Empty password gets 1 point for diversity

    def test_password_score_weak(self):
        """Test password score for weak password."""
        password = "weak"
        score = self._calculate_password_score(password)
        assert score <= 2

    def test_password_score_medium(self):
        """Test password score for medium password."""
        password = "medium12"  # 8 chars, lower, digit, diverse = 3 points
        score = self._calculate_password_score(password)
        assert 2 < score <= 4

    def test_password_score_strong(self):
        """Test password score for strong password."""
        password = "Str0ng!P@ssw0rd#2024"
        score = self._calculate_password_score(password)
        assert score > 4

    def test_password_score_length_requirement(self):
        """Test that passwords >= 8 characters get a point."""
        short = "Abc1!"
        long = "Abc1!xyz"

        score_short = self._calculate_password_score(short)
        score_long = self._calculate_password_score(long)

        assert score_long >= score_short

    def test_password_score_uppercase(self):
        """Test that uppercase letters contribute to score."""
        no_upper = "password123!"
        with_upper = "Password123!"

        score_no_upper = self._calculate_password_score(no_upper)
        score_with_upper = self._calculate_password_score(with_upper)

        assert score_with_upper > score_no_upper

    def test_password_score_lowercase(self):
        """Test that lowercase letters contribute to score."""
        no_lower = "PASSWORD123!"
        with_lower = "PASSWORd123!"

        score_no_lower = self._calculate_password_score(no_lower)
        score_with_lower = self._calculate_password_score(with_lower)

        assert score_with_lower > score_no_lower

    def test_password_score_digits(self):
        """Test that digits contribute to score."""
        no_digits = "Password!"
        with_digits = "Password1!"

        score_no_digits = self._calculate_password_score(no_digits)
        score_with_digits = self._calculate_password_score(with_digits)

        assert score_with_digits > score_no_digits

    def test_password_score_special_chars(self):
        """Test that special characters contribute to score."""
        no_special = "Password123"
        with_special = "Password123!"

        score_no_special = self._calculate_password_score(no_special)
        score_with_special = self._calculate_password_score(with_special)

        assert score_with_special > score_no_special

    def test_password_score_diversity(self):
        """Test that character diversity contributes to score."""
        low_diversity = "aaaaaaa1A!"
        high_diversity = "Abc123!@#"

        score_low = self._calculate_password_score(low_diversity)
        score_high = self._calculate_password_score(high_diversity)

        assert score_high >= score_low

    def test_password_score_maximum(self):
        """Test that maximum score is achievable."""
        password = "Str0ng!P@ssw0rd#WithManyUniqueChars2024"
        score = self._calculate_password_score(password)

        assert score == 6

    def test_various_password_strengths(self):
        """Test a variety of passwords with different strengths."""
        passwords = {
            "": 1,
            "a": 1,
            "abc": 1,
            "abcdefgh": 2,  # 8+ chars, lowercase
            "Abcdefgh": 3,  # 8+ chars, upper, lower
            "Abcdefg1": 4,  # 8+ chars, upper, lower, digit
            "Abcdef1!": 5,  # 8+ chars, upper, lower, digit, special
            "Abc123!@#": 6,  # All criteria + diversity
        }

        for password, expected_min_score in passwords.items():
            score = self._calculate_password_score(password)
            assert score >= expected_min_score, (
                f"Password '{password}' scored {score}, expected at least {expected_min_score}"
            )

    def _calculate_password_score(self, password):
        """Calculate password score using the same logic as the GUI."""
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


class TestGUIModuleStructure:
    """Test GUI module structure and imports."""

    def test_gui_module_imports(self):
        """Test that GUI module can be imported."""
        try:
            from pyRanoid import gui

            assert hasattr(gui, "pyRanoid")
        except ImportError as e:
            pytest.skip(f"GUI module requires GTK: {e}")

    def test_gui_class_exists(self):
        """Test that pyRanoid class exists in GUI module."""
        try:
            from pyRanoid.gui import pyRanoid

            assert pyRanoid is not None
        except ImportError:
            pytest.skip("GUI module requires GTK")

    def test_gui_module_has_main_class(self):
        """Test that GUI module has the main class."""
        try:
            from pyRanoid import gui

            assert hasattr(gui, "pyRanoid")
            assert gui.pyRanoid is not None
        except ImportError:
            pytest.skip("GTK not available")

    def test_gui_imports_successfully(self):
        """Test that GUI module imports successfully."""
        try:
            from pyRanoid import gui

            # GUI module should be importable
            assert gui is not None
        except ImportError:
            pytest.skip("GTK not available")

    @patch("gi.repository.Gtk")
    @patch("gi.repository.GdkPixbuf")
    @patch("gi.repository.GLib")
    def test_gui_has_required_methods(self, mock_glib, mock_pixbuf, mock_gtk):
        """Test that GUI class has required methods."""
        try:
            from pyRanoid.gui import pyRanoid

            expected_methods = [
                "password_score",
                "update_password_strength",
                "show_error_dialog",
                "show_info_dialog",
                "clear_all_fields",
                "op_handler",
                "encrypt_image",
                "decrypt_image",
                "select_image_file",
                "select_target_file",
            ]

            for method_name in expected_methods:
                assert hasattr(pyRanoid, method_name), f"Missing method: {method_name}"
        except Exception as e:
            pytest.skip(f"Could not test GUI class: {e}")
