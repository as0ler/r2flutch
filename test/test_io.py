#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import pytest
from unittest.mock import patch, MagicMock, call
from r2flutch.config import TRANSPORT_SSH, TRANSPORT_FRIDA
from r2flutch.io import (
    get_file,
    get_application_content,
    list_content_path,
    list_content_path_with_progress,
    list_application_content,
)


class TestGetFile:

    @patch("r2flutch.io.ssh_get_remote_file")
    def test_ssh_transport_delegates_to_ssh(self, mock_ssh_get):
        mock_sftp = MagicMock()
        get_file(None, "/remote/file.bin", "/dest", transport=TRANSPORT_SSH, sftp=mock_sftp)
        mock_ssh_get.assert_called_once_with(mock_sftp, "/remote/file.bin", "/dest", False)

    @patch("r2flutch.io.shutil.move")
    @patch("r2flutch.io.os.path.isfile", return_value=True)
    @patch("r2flutch.io.os.path.exists", return_value=True)
    @patch("r2flutch.io.get_remote_file")
    def test_frida_transport_delegates_to_r2frida(self, mock_r2f_get, mock_exists, mock_isfile, mock_move):
        mock_r2f = MagicMock()
        get_file(mock_r2f, "/r2f/remote/file.bin", "/dest", transport=TRANSPORT_FRIDA)
        mock_r2f_get.assert_called_once_with(mock_r2f, "/r2f/remote/file.bin", False)

    @patch("r2flutch.io.ssh_get_remote_file")
    def test_ssh_transport_does_not_call_r2frida(self, mock_ssh_get):
        mock_r2f = MagicMock()
        mock_sftp = MagicMock()
        get_file(mock_r2f, "/remote/file", "/dest", transport=TRANSPORT_SSH, sftp=mock_sftp)
        mock_r2f.cmd.assert_not_called()

    @patch("r2flutch.io.get_remote_file")
    def test_frida_default_transport(self, mock_r2f_get):
        mock_r2f = MagicMock()
        # default transport is TRANSPORT_FRIDA
        get_file(mock_r2f, "/r2f/file", "/dest")
        mock_r2f_get.assert_called_once()


class TestListContentPath:

    @patch("r2flutch.io.ssh_list_remote_folder")
    def test_ssh_transport_lists_via_sftp(self, mock_ssh_list):
        mock_sftp = MagicMock()
        mock_ssh_list.return_value = [
            {"name": "file.txt", "type": "file", "size": 100},
        ]
        result = list_content_path(None, "/app", transport=TRANSPORT_SSH, sftp=mock_sftp)
        mock_ssh_list.assert_called_once_with(mock_sftp, "/app")
        assert result == ["/app/file.txt"]

    @patch("r2flutch.io.list_remote_folder")
    def test_frida_transport_lists_via_r2frida(self, mock_r2f_list):
        mock_r2f = MagicMock()
        mock_r2f_list.return_value = [
            {"name": "binary", "type": "file", "size": 2048},
        ]
        result = list_content_path(mock_r2f, "/r2f/app", transport=TRANSPORT_FRIDA)
        mock_r2f_list.assert_called_once_with(mock_r2f, "/r2f/app")
        assert result == ["/r2f/app/binary"]

    @patch("r2flutch.io.ssh_list_remote_folder")
    def test_ssh_recurses_into_directories(self, mock_ssh_list):
        mock_sftp = MagicMock()
        mock_ssh_list.side_effect = [
            [
                {"name": "Frameworks", "type": "directory", "size": 0},
                {"name": "Info.plist", "type": "file", "size": 500},
            ],
            [
                {"name": "lib.dylib", "type": "file", "size": 4096},
            ],
        ]
        result = list_content_path(None, "/app", transport=TRANSPORT_SSH, sftp=mock_sftp)
        assert "/app/Info.plist" in result
        assert "/app/Frameworks/lib.dylib" in result
        assert len(result) == 2

    @patch("r2flutch.io.ssh_list_remote_folder")
    def test_ssh_skips_zero_size_files(self, mock_ssh_list):
        mock_sftp = MagicMock()
        # First call returns both entries; zero-size file triggers recursion into it,
        # so second call (for the "empty" path) returns nothing.
        mock_ssh_list.side_effect = [
            [
                {"name": "empty", "type": "file", "size": 0},
                {"name": "real", "type": "file", "size": 10},
            ],
            [],  # recursion into "empty" finds nothing
        ]
        result = list_content_path(None, "/app", transport=TRANSPORT_SSH, sftp=mock_sftp)
        assert result == ["/app/real"]


class TestListContentPathWithProgress:

    @patch("r2flutch.io.ssh_list_remote_folder")
    def test_ssh_returns_file_list(self, mock_ssh_list):
        mock_sftp = MagicMock()
        mock_ssh_list.return_value = [
            {"name": "a.txt", "type": "file", "size": 1},
        ]
        result = list_content_path_with_progress(None, "/app", transport=TRANSPORT_SSH, sftp=mock_sftp)
        assert result == ["/app/a.txt"]

    @patch("r2flutch.io.list_remote_folder")
    def test_frida_returns_file_list(self, mock_r2f_list):
        mock_r2f = MagicMock()
        mock_r2f_list.return_value = [
            {"name": "b.bin", "type": "file", "size": 2},
        ]
        result = list_content_path_with_progress(mock_r2f, "/r2f/app", transport=TRANSPORT_FRIDA)
        assert result == ["/r2f/app/b.bin"]


class TestListApplicationContent:

    @patch("r2flutch.io.list_content_path_with_progress")
    def test_ssh_uses_bundle_path_directly(self, mock_list):
        mock_list.return_value = ["/bundle/file.txt"]
        mock_sftp = MagicMock()
        result = list_application_content(
            None, transport=TRANSPORT_SSH, sftp=mock_sftp, bundle_path="/bundle"
        )
        mock_list.assert_called_once_with(None, "/bundle", False, TRANSPORT_SSH, mock_sftp)
        assert result == ["/bundle/file.txt"]

    @patch("r2flutch.io.list_content_path_with_progress")
    @patch("r2flutch.io.get_main_bundle_path", return_value="/var/containers/App.app")
    def test_frida_prefixes_bundle_path(self, mock_bundle, mock_list):
        mock_r2f = MagicMock()
        mock_list.return_value = []
        list_application_content(mock_r2f, transport=TRANSPORT_FRIDA)
        args = mock_list.call_args[0]
        assert args[1].startswith("/r2f/")


class TestGetApplicationContent:

    @patch("r2flutch.io.ssh_get_remote_file")
    def test_ssh_downloads_files(self, mock_ssh_get, tmp_path):
        mock_sftp = MagicMock()
        dest = str(tmp_path / "dest")
        bundle_path = "/var/containers/App.app"
        app_content = [
            "/var/containers/App.app/Info.plist",
            "/var/containers/App.app/binary",
        ]
        get_application_content(
            None, app_content, dest, False,
            transport=TRANSPORT_SSH, sftp=mock_sftp, bundle_path=bundle_path
        )
        assert mock_ssh_get.call_count == 2

    @patch("r2flutch.io.get_file")
    @patch("r2flutch.io.get_main_bundle_path", return_value="/var/containers/App.app")
    def test_frida_downloads_files(self, mock_bundle, mock_get_file, tmp_path):
        mock_r2f = MagicMock()
        dest = str(tmp_path / "dest")
        app_content = [
            "/r2f/var/containers/App.app/Info.plist",
        ]
        get_application_content(mock_r2f, app_content, dest, False, transport=TRANSPORT_FRIDA)
        mock_get_file.assert_called_once()

    @patch("r2flutch.io.ssh_get_remote_file")
    def test_ssh_skips_ignored_files(self, mock_ssh_get, tmp_path):
        mock_sftp = MagicMock()
        dest = str(tmp_path / "dest")
        app_content = [
            "/bundle/.gitkeep",
            "/bundle/.gitignore",
            "/bundle/real_file",
        ]
        get_application_content(
            None, app_content, dest, False,
            transport=TRANSPORT_SSH, sftp=mock_sftp, bundle_path="/bundle"
        )
        assert mock_ssh_get.call_count == 1
