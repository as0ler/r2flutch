#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import sys
import pytest
from unittest.mock import patch, MagicMock
from r2flutch.config import TRANSPORT_SSH, TRANSPORT_FRIDA, DEFAULT_TRANSPORT


class TestCliArguments:

    @patch("r2flutch.bin.run.ssh_disconnect")
    @patch("r2flutch.bin.run.kill_process")
    @patch("r2flutch.bin.run.generate_ipa")
    @patch("r2flutch.bin.run.copy_modules_to_app_bundle")
    @patch("r2flutch.bin.run.get_application_content")
    @patch("r2flutch.bin.run.dump_decrypted_modules", return_value=[])
    @patch("r2flutch.bin.run.load_all_modules")
    @patch("r2flutch.bin.run.list_application_content", return_value=[])
    @patch("r2flutch.bin.run.get_main_bundle_path", return_value="/var/containers/App.app")
    @patch("r2flutch.bin.run.set_block_size")
    @patch("r2flutch.bin.run.load_r2f_plugin")
    @patch("r2flutch.bin.run.spawn_r2frida_process")
    @patch("r2flutch.bin.run.get_usb_device")
    @patch("r2flutch.bin.run.ssh_connect")
    @patch("r2flutch.bin.run.load_ssh_config")
    @patch("r2flutch.bin.run.init")
    def test_default_transport_is_ssh(self, mock_init, mock_load_cfg, mock_ssh_conn,
                                       mock_device, mock_spawn, mock_plugin, mock_bs,
                                       mock_bundle, mock_list, mock_load_mods,
                                       mock_dump, mock_get_content, mock_copy,
                                       mock_ipa, mock_kill, mock_ssh_disc):
        mock_r2f = MagicMock()
        mock_r2f.cmd.return_value = ""
        mock_spawn.return_value = mock_r2f
        mock_device.return_value = MagicMock(id="usb-123")
        mock_ssh_conn.return_value = (MagicMock(), MagicMock())
        mock_load_cfg.return_value = {"host": "1.2.3.4", "port": 22, "username": "root", "password": "alpine"}

        with patch("sys.argv", ["r2flutch", "com.example.app"]):
            from r2flutch.bin.run import main
            main()

        mock_load_cfg.assert_called_once()
        mock_ssh_conn.assert_called_once()
        assert DEFAULT_TRANSPORT == TRANSPORT_SSH

    @patch("r2flutch.bin.run.kill_process")
    @patch("r2flutch.bin.run.dump_decrypted_modules", return_value=[])
    @patch("r2flutch.bin.run.load_all_modules")
    @patch("r2flutch.bin.run.list_application_content", return_value=[])
    @patch("r2flutch.bin.run.get_main_bundle_path", return_value="/var/containers/App.app")
    @patch("r2flutch.bin.run.set_block_size")
    @patch("r2flutch.bin.run.load_r2f_plugin")
    @patch("r2flutch.bin.run.spawn_r2frida_process")
    @patch("r2flutch.bin.run.get_usb_device")
    @patch("r2flutch.bin.run.init")
    def test_frida_transport_skips_ssh(self, mock_init, mock_device, mock_spawn,
                                        mock_plugin, mock_bs, mock_bundle,
                                        mock_list, mock_load_mods, mock_dump, mock_kill):
        mock_r2f = MagicMock()
        mock_r2f.cmd.return_value = ""
        mock_spawn.return_value = mock_r2f
        mock_device.return_value = MagicMock(id="usb-123")

        with patch("sys.argv", ["r2flutch", "-t", "frida", "com.example.app"]):
            from r2flutch.bin.run import main
            main()

        # list_application_content should be called with frida transport
        call_kwargs = mock_list.call_args
        assert call_kwargs[1]["transport"] == TRANSPORT_FRIDA

    @patch("r2flutch.bin.run.ssh_disconnect")
    @patch("r2flutch.bin.run.kill_process")
    @patch("r2flutch.bin.run.dump_decrypted_modules", return_value=[])
    @patch("r2flutch.bin.run.load_all_modules")
    @patch("r2flutch.bin.run.list_application_content", return_value=[])
    @patch("r2flutch.bin.run.get_main_bundle_path", return_value="/var/containers/App.app")
    @patch("r2flutch.bin.run.set_block_size")
    @patch("r2flutch.bin.run.load_r2f_plugin")
    @patch("r2flutch.bin.run.spawn_r2frida_process")
    @patch("r2flutch.bin.run.get_usb_device")
    @patch("r2flutch.bin.run.ssh_connect")
    @patch("r2flutch.bin.run.load_ssh_config")
    @patch("r2flutch.bin.run.init")
    def test_custom_config_path(self, mock_init, mock_load_cfg, mock_ssh_conn,
                                 mock_device, mock_spawn, mock_plugin, mock_bs,
                                 mock_bundle, mock_list, mock_load_mods,
                                 mock_dump, mock_kill, mock_ssh_disc):
        mock_r2f = MagicMock()
        mock_r2f.cmd.return_value = ""
        mock_spawn.return_value = mock_r2f
        mock_device.return_value = MagicMock(id="usb-123")
        mock_ssh_conn.return_value = (MagicMock(), MagicMock())
        mock_load_cfg.return_value = {"host": "1.2.3.4", "port": 22, "username": "root", "password": "alpine"}

        with patch("sys.argv", ["r2flutch", "-c", "/custom/config.json", "com.example.app"]):
            from r2flutch.bin.run import main
            main()

        mock_load_cfg.assert_called_once_with("/custom/config.json")

    def test_no_args_prints_help_and_exits(self):
        with patch("sys.argv", ["r2flutch"]):
            from r2flutch.bin.run import main
            with pytest.raises(SystemExit):
                main()


class TestInit:

    @patch("r2flutch.bin.run.os.makedirs")
    @patch("r2flutch.bin.run.shutil.rmtree")
    @patch("r2flutch.bin.run.os.path.isdir", return_value=True)
    def test_init_removes_and_recreates(self, mock_isdir, mock_rmtree, mock_makedirs):
        from r2flutch.bin.run import init
        init()
        mock_rmtree.assert_called_once()
        assert mock_makedirs.call_count == 3

    @patch("r2flutch.bin.run.os.makedirs")
    @patch("r2flutch.bin.run.shutil.rmtree")
    @patch("r2flutch.bin.run.os.path.isdir", return_value=False)
    def test_init_no_existing_dir(self, mock_isdir, mock_rmtree, mock_makedirs):
        from r2flutch.bin.run import init
        init()
        mock_rmtree.assert_not_called()
        assert mock_makedirs.call_count == 3


class TestMainIpaFlow:

    @patch("r2flutch.bin.run.ssh_disconnect")
    @patch("r2flutch.bin.run.kill_process")
    @patch("r2flutch.bin.run.generate_ipa")
    @patch("r2flutch.bin.run.copy_modules_to_app_bundle")
    @patch("r2flutch.bin.run.get_application_content")
    @patch("r2flutch.bin.run.dump_decrypted_modules",
           return_value=[{"src_path": "/tmp/bin/binary", "relative_path": "binary"}])
    @patch("r2flutch.bin.run.get_main_bundle_name", return_value="TestApp")
    @patch("r2flutch.bin.run.load_all_modules")
    @patch("r2flutch.bin.run.list_application_content", return_value=[])
    @patch("r2flutch.bin.run.get_main_bundle_path", return_value="/var/containers/App.app")
    @patch("r2flutch.bin.run.set_block_size")
    @patch("r2flutch.bin.run.load_r2f_plugin")
    @patch("r2flutch.bin.run.spawn_r2frida_process")
    @patch("r2flutch.bin.run.get_usb_device")
    @patch("r2flutch.bin.run.ssh_connect")
    @patch("r2flutch.bin.run.load_ssh_config")
    @patch("r2flutch.bin.run.init")
    def test_ipa_generation_flow(self, mock_init, mock_load_cfg, mock_ssh_conn,
                                   mock_device, mock_spawn, mock_plugin, mock_bs,
                                   mock_bundle, mock_list, mock_load_mods,
                                   mock_bundle_name, mock_dump, mock_get_content,
                                   mock_copy, mock_ipa, mock_kill, mock_ssh_disc):
        mock_r2f = MagicMock()
        mock_r2f.cmd.return_value = ""
        mock_spawn.return_value = mock_r2f
        mock_device.return_value = MagicMock(id="usb-123")
        mock_ssh_conn.return_value = (MagicMock(), MagicMock())
        mock_load_cfg.return_value = {"host": "1.2.3.4", "port": 22, "username": "root", "password": "alpine"}

        with patch("sys.argv", ["r2flutch", "-i", "com.example.app"]):
            from r2flutch.bin.run import main
            main()

        mock_bundle_name.assert_called_once()
        mock_get_content.assert_called_once()
        mock_copy.assert_called_once()
        mock_ipa.assert_called_once()

    @patch("r2flutch.bin.run.ssh_disconnect")
    @patch("r2flutch.bin.run.kill_process")
    @patch("r2flutch.bin.run.shutil.move")
    @patch("r2flutch.bin.run.dump_decrypted_modules",
           return_value=[{"src_path": "/tmp/bin/binary", "relative_path": "binary"}])
    @patch("r2flutch.bin.run.load_all_modules")
    @patch("r2flutch.bin.run.list_application_content", return_value=[])
    @patch("r2flutch.bin.run.get_main_bundle_path", return_value="/var/containers/App.app")
    @patch("r2flutch.bin.run.set_block_size")
    @patch("r2flutch.bin.run.load_r2f_plugin")
    @patch("r2flutch.bin.run.spawn_r2frida_process")
    @patch("r2flutch.bin.run.get_usb_device")
    @patch("r2flutch.bin.run.ssh_connect")
    @patch("r2flutch.bin.run.load_ssh_config")
    @patch("r2flutch.bin.run.init")
    def test_non_ipa_moves_modules(self, mock_init, mock_load_cfg, mock_ssh_conn,
                                     mock_device, mock_spawn, mock_plugin, mock_bs,
                                     mock_bundle, mock_list, mock_load_mods,
                                     mock_dump, mock_move, mock_kill, mock_ssh_disc):
        mock_r2f = MagicMock()
        mock_r2f.cmd.return_value = ""
        mock_spawn.return_value = mock_r2f
        mock_device.return_value = MagicMock(id="usb-123")
        mock_ssh_conn.return_value = (MagicMock(), MagicMock())
        mock_load_cfg.return_value = {"host": "1.2.3.4", "port": 22, "username": "root", "password": "alpine"}

        with patch("sys.argv", ["r2flutch", "-o", "/tmp/out", "com.example.app"]):
            from r2flutch.bin.run import main
            main()

        mock_move.assert_called_once()

    @patch("r2flutch.bin.run.kill_process")
    @patch("r2flutch.bin.run.list_applications")
    @patch("r2flutch.bin.run.get_usb_device")
    @patch("r2flutch.bin.run.ssh_connect")
    @patch("r2flutch.bin.run.load_ssh_config")
    @patch("r2flutch.bin.run.init")
    def test_list_mode_exits(self, mock_init, mock_load_cfg, mock_ssh_conn,
                               mock_device, mock_list_apps, mock_kill):
        mock_device.return_value = MagicMock(id="usb-123")

        with patch("sys.argv", ["r2flutch", "-l"]):
            from r2flutch.bin.run import main
            with pytest.raises(SystemExit):
                main()
        mock_list_apps.assert_called_once()
        mock_load_cfg.assert_not_called()
        mock_ssh_conn.assert_not_called()


class TestDumpDecryptedModules:

    @patch("r2flutch.bin.run.get_file")
    @patch("r2flutch.bin.run.patch_bin")
    @patch("r2flutch.bin.run.dump_decrypted_module_data")
    @patch("r2flutch.bin.run.get_encryption_info")
    @patch("r2flutch.bin.run.get_modules_to_decrypt")
    def test_ssh_transport_uses_raw_module_path(self, mock_modules, mock_enc,
                                                  mock_dump_data, mock_patch,
                                                  mock_get_file):
        mock_modules.return_value = [{
            "name": "binary",
            "path": "/var/containers/App.app/binary",
            "base": "0x100000",
            "encryption_info": {
                "cryptoff": 0x4000,
                "cryptsize": 0x8000,
                "addr": "0x100010",
            }
        }]
        mock_enc.return_value = {
            "crypt_offset": "0x4000",
            "base_addr": "0x100000",
            "offset": "0x104000",
            "size": "0x8000",
            "crypt_header": "0x100010",
        }
        mock_sftp = MagicMock()

        from r2flutch.bin.run import dump_decrypted_modules
        mock_r2f = MagicMock()
        dump_decrypted_modules(mock_r2f, transport=TRANSPORT_SSH, sftp=mock_sftp)

        # For SSH transport, module["path"] is used directly (no REMOTE_PREFIX)
        get_file_call = mock_get_file.call_args
        assert get_file_call[0][1] == "/var/containers/App.app/binary"
        assert get_file_call[1]["transport"] == TRANSPORT_SSH
        assert get_file_call[1]["sftp"] is mock_sftp

    @patch("r2flutch.bin.run.get_file")
    @patch("r2flutch.bin.run.patch_bin")
    @patch("r2flutch.bin.run.dump_decrypted_module_data")
    @patch("r2flutch.bin.run.get_encryption_info")
    @patch("r2flutch.bin.run.get_modules_to_decrypt")
    def test_frida_transport_uses_remote_prefix(self, mock_modules, mock_enc,
                                                  mock_dump_data, mock_patch,
                                                  mock_get_file):
        mock_modules.return_value = [{
            "name": "binary",
            "path": "/var/containers/App.app/binary",
            "base": "0x100000",
            "encryption_info": {
                "cryptoff": 0x4000,
                "cryptsize": 0x8000,
                "addr": "0x100010",
            }
        }]
        mock_enc.return_value = {
            "crypt_offset": "0x4000",
            "base_addr": "0x100000",
            "offset": "0x104000",
            "size": "0x8000",
            "crypt_header": "0x100010",
        }

        from r2flutch.bin.run import dump_decrypted_modules
        mock_r2f = MagicMock()
        dump_decrypted_modules(mock_r2f, transport=TRANSPORT_FRIDA)

        get_file_call = mock_get_file.call_args
        assert get_file_call[0][1].startswith("/r2f/")

    @patch("r2flutch.bin.run.get_file")
    @patch("r2flutch.bin.run.patch_bin")
    @patch("r2flutch.bin.run.dump_decrypted_module_data")
    @patch("r2flutch.bin.run.print_encryption_info")
    @patch("r2flutch.bin.run.get_encryption_info")
    @patch("r2flutch.bin.run.get_modules_to_decrypt")
    def test_debug_enabled_prints_encryption_info(self, mock_modules, mock_enc,
                                                    mock_print_enc, mock_dump_data,
                                                    mock_patch, mock_get_file):
        mock_modules.return_value = [{
            "name": "binary",
            "path": "/var/containers/App.app/binary",
            "base": "0x100000",
            "encryption_info": {
                "cryptoff": 0x4000,
                "cryptsize": 0x8000,
                "addr": "0x100010",
            }
        }]
        mock_enc.return_value = {
            "crypt_offset": "0x4000",
            "base_addr": "0x100000",
            "offset": "0x104000",
            "size": "0x8000",
            "crypt_header": "0x100010",
        }

        from r2flutch.bin.run import dump_decrypted_modules
        mock_r2f = MagicMock()
        dump_decrypted_modules(mock_r2f, debug_enabled=True, transport=TRANSPORT_FRIDA)
        mock_print_enc.assert_called_once()

    @patch("r2flutch.bin.run.get_file")
    @patch("r2flutch.bin.run.patch_bin")
    @patch("r2flutch.bin.run.dump_decrypted_module_data")
    @patch("r2flutch.bin.run.get_encryption_info")
    @patch("r2flutch.bin.run.get_modules_to_decrypt")
    def test_returns_correct_relative_paths(self, mock_modules, mock_enc,
                                              mock_dump_data, mock_patch,
                                              mock_get_file):
        mock_modules.return_value = [{
            "name": "binary",
            "path": "/var/containers/Bundle/App.app/Frameworks/lib.dylib",
            "base": "0x100000",
            "encryption_info": {
                "cryptoff": 0x4000,
                "cryptsize": 0x8000,
                "addr": "0x100010",
            }
        }]
        mock_enc.return_value = {
            "crypt_offset": "0x4000",
            "base_addr": "0x100000",
            "offset": "0x104000",
            "size": "0x8000",
            "crypt_header": "0x100010",
        }

        from r2flutch.bin.run import dump_decrypted_modules
        mock_r2f = MagicMock()
        result = dump_decrypted_modules(mock_r2f, transport=TRANSPORT_FRIDA)
        assert len(result) == 1
        assert result[0]["relative_path"] == "Frameworks/lib.dylib"

    @patch("r2flutch.bin.run.get_file")
    @patch("r2flutch.bin.run.patch_bin")
    @patch("r2flutch.bin.run.dump_decrypted_module_data")
    @patch("r2flutch.bin.run.get_encryption_info")
    @patch("r2flutch.bin.run.get_modules_to_decrypt")
    def test_no_modules_returns_empty_list(self, mock_modules, mock_enc,
                                             mock_dump_data, mock_patch,
                                             mock_get_file):
        mock_modules.return_value = []
        from r2flutch.bin.run import dump_decrypted_modules
        mock_r2f = MagicMock()
        result = dump_decrypted_modules(mock_r2f, transport=TRANSPORT_FRIDA)
        assert result == []
