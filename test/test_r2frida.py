#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import os
import pytest
from unittest.mock import patch, MagicMock, call
from r2flutch.r2frida import (
    load_all_modules,
    load_library,
    load_framework,
    load_r2f_plugin,
    get_main_bundle_name,
    get_main_bundle_path,
    get_remote_file,
    list_remote_folder,
    get_modules_to_decrypt,
    get_module_paths,
    get_encryption_info,
    print_encryption_info,
    dump_decrypted_module_data,
    patch_bin,
)
from r2flutch.config import TMP_FOLDER, DUMP_FOLDER, BIN_FOLDER


class TestLoadAllModules:

    def test_loads_dylib_and_framework(self):
        mock_r2f = MagicMock()
        app_content = [
            "/app/Frameworks/lib.dylib",
            "/app/Frameworks/Core.framework",
            "/app/Info.plist",
            "/app/Assets.car",
        ]
        with patch("r2flutch.r2frida.load_library") as mock_load:
            load_all_modules(mock_r2f, app_content)
            assert mock_load.call_count == 2

    def test_ignores_non_library_files(self):
        mock_r2f = MagicMock()
        app_content = ["/app/Info.plist", "/app/icon.png"]
        with patch("r2flutch.r2frida.load_library") as mock_load:
            load_all_modules(mock_r2f, app_content)
            mock_load.assert_not_called()


class TestLoadLibrary:

    def test_calls_dl_command(self):
        mock_r2f = MagicMock()
        mock_r2f.cmdj.return_value = True
        result = load_library(mock_r2f, "/app/lib.dylib")
        mock_r2f.cmdj.assert_called_once_with(":dl /app/lib.dylib")


class TestLoadFramework:

    def test_calls_dlf_command(self):
        mock_r2f = MagicMock()
        mock_r2f.cmdj.return_value = True
        result = load_framework(mock_r2f, "/app/Core.framework")
        mock_r2f.cmdj.assert_called_once_with(":dlf /app/Core.framework")


class TestLoadR2fPlugin:

    @patch("r2flutch.r2frida.r2flutch")
    def test_loads_plugin_ts(self, mock_r2flutch_mod):
        mock_r2flutch_mod.__file__ = "/fake/r2flutch/__init__.py"
        mock_r2f = MagicMock()
        load_r2f_plugin(mock_r2f)
        cmd_arg = mock_r2f.cmd.call_args[0][0]
        assert ":." in cmd_arg
        assert "plugin.ts" in cmd_arg


class TestGetMainBundleName:

    def test_returns_stripped_name(self):
        mock_r2f = MagicMock()
        mock_r2f.cmd.return_value = "  MyApp  \n"
        assert get_main_bundle_name(mock_r2f) == "MyApp"


class TestGetMainBundlePath:

    def test_returns_stripped_path(self):
        mock_r2f = MagicMock()
        mock_r2f.cmd.return_value = "/var/containers/App.app\n"
        assert get_main_bundle_path(mock_r2f) == "/var/containers/App.app"


class TestGetRemoteFile:

    def test_sends_base64_encoded_path(self):
        mock_r2f = MagicMock()
        filepath = "/r2f/var/app/binary"
        get_remote_file(mock_r2f, filepath)
        expected_b64 = base64.b64encode(filepath.encode()).decode()
        mock_r2f.cmd.assert_called_once_with("mg base64:%s 2>/dev/null" % expected_b64)

    @patch("r2flutch.r2frida.print_console")
    def test_debug_prints_path(self, mock_print):
        mock_r2f = MagicMock()
        get_remote_file(mock_r2f, "/r2f/file", debug_enabled=True)
        assert any("mg base64:" in str(c) for c in mock_print.call_args_list)


class TestListRemoteFolder:

    def test_sends_base64_encoded_path(self):
        mock_r2f = MagicMock()
        mock_r2f.cmdj.return_value = [{"name": "file", "type": "file", "size": 100}]
        path = "/r2f/var/app"
        result = list_remote_folder(mock_r2f, path)
        expected_b64 = base64.b64encode(path.encode()).decode()
        mock_r2f.cmdj.assert_called_once_with("mdj base64:%s" % expected_b64)
        assert result == [{"name": "file", "type": "file", "size": 100}]


class TestGetModulesToDecrypt:

    def test_returns_cmdj_dump(self):
        mock_r2f = MagicMock()
        mock_r2f.cmdj.return_value = [{"name": "binary"}]
        result = get_modules_to_decrypt(mock_r2f)
        mock_r2f.cmdj.assert_called_once_with(":dump")
        assert result == [{"name": "binary"}]


class TestGetModulePaths:

    def test_generates_correct_paths(self):
        module = {"name": "MyBinary"}
        paths = get_module_paths(module)
        assert paths["decrypted_bin"] == os.path.join(TMP_FOLDER, DUMP_FOLDER, "MyBinary")
        assert paths["patched_bin"] == os.path.join(TMP_FOLDER, BIN_FOLDER, "MyBinary")


class TestGetEncryptionInfo:

    def test_computes_offsets(self):
        module = {
            "base": "0x100000",
            "encryption_info": {
                "cryptoff": 0x4000,
                "cryptsize": 0x8000,
                "addr": "0x100010",
            }
        }
        info = get_encryption_info(module)
        assert info["crypt_offset"] == hex(0x4000)
        assert info["base_addr"] == hex(0x100000)
        assert info["offset"] == hex(0x100000 + 0x4000)
        assert info["size"] == hex(0x8000)
        assert info["crypt_header"] == hex(0x100010)


class TestPrintEncryptionInfo:

    @patch("r2flutch.r2frida.print_console")
    def test_prints_all_fields(self, mock_print):
        module = {"name": "binary"}
        enc_info = {
            "base_addr": "0x100000",
            "crypt_offset": "0x4000",
            "offset": "0x104000",
            "size": "0x8000",
            "crypt_header": "0x100010",
        }
        print_encryption_info(module, enc_info, True)
        assert mock_print.call_count == 5


class TestDumpDecryptedModuleData:

    def test_seeks_and_writes(self):
        mock_r2f = MagicMock()
        dump_decrypted_module_data(mock_r2f, "0x104000", "/tmp/decrypted", "0x8000")
        calls = mock_r2f.cmd.call_args_list
        assert calls[0] == call("s 0x104000")
        b64_path = base64.b64encode(b"/tmp/decrypted").decode()
        assert calls[1] == call("wtf base64:%s 0x8000" % b64_path)


class TestPatchBin:

    @patch("r2flutch.r2frida.r2pipe")
    def test_patches_binary(self, mock_r2pipe):
        mock_r2_raw = MagicMock()
        mock_r2pipe.open.return_value = mock_r2_raw

        patch_bin("/tmp/decrypted", "/tmp/patched", "0x100010", "0x4000")

        mock_r2pipe.open.assert_called_once_with("/tmp/patched", ["-nw"])
        calls = mock_r2_raw.cmd.call_args_list
        assert any("wff /tmp/decrypted" in str(c) for c in calls)
        assert any("wx 00" in str(c) for c in calls)
        mock_r2_raw.quit.assert_called_once()

    @patch("r2flutch.r2frida.print_console")
    @patch("r2flutch.r2frida.r2pipe")
    def test_patches_binary_debug(self, mock_r2pipe, mock_print):
        mock_r2_raw = MagicMock()
        mock_r2pipe.open.return_value = mock_r2_raw

        patch_bin("/tmp/decrypted", "/tmp/patched", "0x100010", "0x4000", debug_enabled=True)

        debug_calls = [c for c in mock_print.call_args_list if "DEBUG" in str(c) or "crypt" in str(c[0][0]).lower()]
        assert len(debug_calls) >= 3
