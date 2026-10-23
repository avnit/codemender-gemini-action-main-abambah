#!/usr/bin/env python3
"""
Unit tests for worker/logger.py:
- Logger configuration and levels
- Formatting and visual hierarchy helpers
- GitHub Actions workflow commands and grouping
- CLI invocation
"""

import io
import logging
import os
import sys
import unittest
from unittest.mock import patch

from logger import (
    configure_logging,
    get_codemender_version,
    get_logger,
    gha_endgroup,
    gha_error,
    gha_group,
    gha_notice,
    gha_warning,
    log_debug,
    log_error,
    log_group,
    log_header,
    log_info,
    log_step,
    log_success,
    log_version,
    log_warn,
)


class TestLogger(unittest.TestCase):
    def setUp(self):
        # Configure logging cleanly before each test
        configure_logging("DEBUG")

    def test_get_logger(self):
        log = get_logger("test-component")
        self.assertEqual(log.name, "test-component")
        self.assertEqual(log.getEffectiveLevel(), logging.DEBUG)

        log_explicit = get_logger("test-explicit", level="WARNING")
        self.assertEqual(log_explicit.level, logging.WARNING)

    def test_additional_logging_env(self):
        with patch.dict(os.environ, {"ADDITIONAL_LOGGING": "true"}, clear=False):
            configure_logging()
            log = get_logger("test-additional-logging")
            self.assertEqual(logging.getLogger().level, logging.DEBUG)

        with patch.dict(os.environ, {"ADDITIONAL_LOGGING": "false", "LOG_LEVEL": "WARNING"}, clear=False):
            configure_logging()
            self.assertEqual(logging.getLogger().level, logging.WARNING)

    def test_log_helpers(self):
        log = get_logger("test-helpers")
        with patch.object(log, "info") as mock_info:
            log_header("Test Title", logger=log)
            self.assertEqual(mock_info.call_count, 3)

        with patch.object(log, "info") as mock_info:
            log_step("Step Name", step_num=1, total_steps=3, logger=log)
            self.assertEqual(mock_info.call_count, 3)

        with patch.object(log, "info") as mock_info:
            log_info("Info message", logger=log)
            mock_info.assert_called_with("ℹ️ Info message")

        with patch.object(log, "info") as mock_info:
            log_success("Success message", logger=log)
            mock_info.assert_called_with("✅ Success message")

        with patch.object(log, "warning") as mock_warn:
            log_warn("Warning message", logger=log)
            mock_warn.assert_called_with("⚠️ Warning message")

        with patch.object(log, "error") as mock_error:
            log_error("Error message", logger=log)
            mock_error.assert_called_with("❌ Error message")

        with patch.object(log, "debug") as mock_debug:
            log_debug("Debug message", logger=log)
            mock_debug.assert_called_with("🔬 Debug message")

    @patch.dict(os.environ, {"GITHUB_ACTIONS": "true"})
    def test_gha_commands_enabled(self):
        stdout = io.StringIO()
        with patch("sys.stdout", stdout):
            gha_group("My Group")
            gha_warning("Watch out", file="src/main.py", line=42)
            gha_error("Critical failure", file="src/main.py", line=10)
            gha_notice("FYI", file="README.md", line=1)
            gha_endgroup()

        out = stdout.getvalue()
        self.assertIn("::group::My Group", out)
        self.assertIn("::warning file=src/main.py,line=42::Watch out", out)
        self.assertIn("::error file=src/main.py,line=10::Critical failure", out)
        self.assertIn("::notice file=README.md,line=1::FYI", out)
        self.assertIn("::endgroup::", out)

    @patch.dict(os.environ, {"GITHUB_ACTIONS": ""})
    def test_gha_commands_disabled_outside_ci(self):
        stdout = io.StringIO()
        with patch("sys.stdout", stdout):
            gha_group("My Group")
            gha_endgroup()

        out = stdout.getvalue()
        self.assertNotIn("::group::", out)
        self.assertNotIn("::endgroup::", out)

    def test_log_group_context_manager(self):
        log = get_logger("test-cm")
        with patch.object(log, "info"):
            with patch("logger.gha_group") as mock_g, patch("logger.gha_endgroup") as mock_eg:
                with log_group("Testing Context Manager", logger=log):
                    pass
                mock_g.assert_called_once_with("Testing Context Manager")
                mock_eg.assert_called_once()

    def test_version_helpers(self):
        with patch.dict(os.environ, {"CODEMENDER_VERSION": "v1.2.3"}):
            self.assertEqual(get_codemender_version(), "v1.2.3")
            log = get_logger("ver-test")
            with patch.object(log, "info") as mock_info:
                ver = log_version(logger=log)
                self.assertEqual(ver, "v1.2.3")
                mock_info.assert_called_with("📦 CodeMender Version: v1.2.3")


if __name__ == "__main__":
    unittest.main()
