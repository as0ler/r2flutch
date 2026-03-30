#!/usr/bin/env python
# -*- coding: utf-8 -*-

from unittest.mock import patch
from r2flutch.repl import print_console, INFO, SUCCESS, ERROR, DEBUG, DEFAULT, WARNING


class TestPrintConsole:

    @patch("builtins.print")
    def test_info_level(self, mock_print):
        print_console("hello", level=INFO)
        output = mock_print.call_args[0][0]
        assert "[ℹ]" in output
        assert "hello" in output

    @patch("builtins.print")
    def test_success_level(self, mock_print):
        print_console("done", level=SUCCESS)
        output = mock_print.call_args[0][0]
        assert "SUCCESS" in output
        assert "done" in output

    @patch("builtins.print")
    def test_error_level(self, mock_print):
        print_console("fail", level=ERROR)
        output = mock_print.call_args[0][0]
        assert "ERROR" in output
        assert "fail" in output

    @patch("builtins.print")
    def test_debug_level(self, mock_print):
        print_console("trace", level=DEBUG)
        output = mock_print.call_args[0][0]
        assert "DEBUG" in output
        assert "trace" in output

    @patch("builtins.print")
    def test_default_level(self, mock_print):
        print_console("plain", level=DEFAULT)
        output = mock_print.call_args[0][0]
        assert "plain" in output

    @patch("builtins.print")
    def test_warning_level(self, mock_print):
        print_console("warn", level=WARNING)
        output = mock_print.call_args[0][0]
        assert "warn" in output

    @patch("builtins.print")
    def test_formatter_adds_indentation(self, mock_print):
        print_console("indented", level=INFO, formatter=2)
        output = mock_print.call_args[0][0]
        assert "        " in output

    @patch("builtins.print")
    def test_formatter_zero_no_indent(self, mock_print):
        print_console("flat", level=DEFAULT, formatter=0)
        output = mock_print.call_args[0][0]
        assert "flat" in output
