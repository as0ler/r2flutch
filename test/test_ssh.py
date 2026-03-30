#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import stat as stat_module
import pytest
from unittest.mock import patch, MagicMock, call
from r2flutch.ssh import ssh_connect, ssh_disconnect, ssh_list_remote_folder, ssh_get_remote_file


class TestSshConnect:

    @patch("r2flutch.ssh.paramiko.SSHClient")
    def test_connect_success(self, mock_ssh_cls):
        mock_client = MagicMock()
        mock_sftp = MagicMock()
        mock_ssh_cls.return_value = mock_client
        mock_client.open_sftp.return_value = mock_sftp

        cfg = {"host": "1.2.3.4", "port": 22, "username": "root", "password": "alpine"}
        client, sftp = ssh_connect(cfg)

        mock_client.set_missing_host_key_policy.assert_called_once()
        mock_client.connect.assert_called_once_with(
            hostname="1.2.3.4",
            port=22,
            username="root",
            password="alpine",
            look_for_keys=False,
            allow_agent=False,
        )
        assert client is mock_client
        assert sftp is mock_sftp

    @patch("r2flutch.ssh.paramiko.SSHClient")
    def test_connect_failure_exits(self, mock_ssh_cls):
        mock_client = MagicMock()
        mock_ssh_cls.return_value = mock_client
        mock_client.connect.side_effect = Exception("Connection refused")

        cfg = {"host": "1.2.3.4", "port": 22, "username": "root", "password": "wrong"}
        with pytest.raises(SystemExit):
            ssh_connect(cfg)


class TestSshDisconnect:

    def test_disconnect_closes_both(self):
        mock_client = MagicMock()
        mock_sftp = MagicMock()
        ssh_disconnect(mock_client, mock_sftp)
        mock_sftp.close.assert_called_once()
        mock_client.close.assert_called_once()


class TestSshListRemoteFolder:

    def test_list_files_and_dirs(self):
        mock_sftp = MagicMock()

        file_attr = MagicMock()
        file_attr.filename = "Info.plist"
        file_attr.st_mode = stat_module.S_IFREG | 0o644
        file_attr.st_size = 1024

        dir_attr = MagicMock()
        dir_attr.filename = "Frameworks"
        dir_attr.st_mode = stat_module.S_IFDIR | 0o755
        dir_attr.st_size = 128

        mock_sftp.listdir_attr.return_value = [file_attr, dir_attr]

        result = ssh_list_remote_folder(mock_sftp, "/var/containers/Bundle/Application/xxx/App.app")
        assert len(result) == 2
        assert result[0] == {"name": "Info.plist", "type": "file", "size": 1024}
        assert result[1] == {"name": "Frameworks", "type": "directory", "size": 128}

    def test_list_empty_dir(self):
        mock_sftp = MagicMock()
        mock_sftp.listdir_attr.return_value = []
        result = ssh_list_remote_folder(mock_sftp, "/some/path")
        assert result == []

    def test_list_ioerror_returns_empty(self):
        mock_sftp = MagicMock()
        mock_sftp.listdir_attr.side_effect = IOError("No such file")
        result = ssh_list_remote_folder(mock_sftp, "/nonexistent")
        assert result == []


class TestSshGetRemoteFile:

    def test_download_creates_dest_and_calls_get(self, tmp_path):
        mock_sftp = MagicMock()
        dest = str(tmp_path / "output")
        ssh_get_remote_file(mock_sftp, "/remote/path/Info.plist", dest)

        assert os.path.isdir(dest)
        mock_sftp.get.assert_called_once_with(
            "/remote/path/Info.plist",
            os.path.join(dest, "Info.plist")
        )

    def test_download_existing_dest(self, tmp_path):
        mock_sftp = MagicMock()
        dest = str(tmp_path)
        ssh_get_remote_file(mock_sftp, "/remote/binary", dest)
        mock_sftp.get.assert_called_once_with(
            "/remote/binary",
            os.path.join(dest, "binary")
        )

    def test_download_failure_does_not_raise(self, tmp_path):
        mock_sftp = MagicMock()
        mock_sftp.get.side_effect = Exception("Permission denied")
        dest = str(tmp_path)
        # Should not raise, just print an error
        ssh_get_remote_file(mock_sftp, "/remote/file", dest)

    @patch("r2flutch.ssh.print_console")
    def test_download_debug_prints_message(self, mock_print, tmp_path):
        mock_sftp = MagicMock()
        dest = str(tmp_path)
        ssh_get_remote_file(mock_sftp, "/remote/file", dest, debug_enabled=True)
        assert any("SSH downloading" in str(c) for c in mock_print.call_args_list)
