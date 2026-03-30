#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import zipfile
from unittest.mock import patch
from r2flutch.utils import generate_ipa, copy_modules_to_app_bundle


class TestGenerateIpa:

    def test_creates_ipa_zip(self, tmp_path):
        # Create a fake payload directory structure
        payload = tmp_path / "Payload"
        app_dir = payload / "Test.app"
        app_dir.mkdir(parents=True)
        (app_dir / "Info.plist").write_text("plist content")
        (app_dir / "binary").write_bytes(b"\x00" * 100)

        target_dir = str(tmp_path / "output")
        os.makedirs(target_dir)

        generate_ipa(str(payload), "Test", target_dir=target_dir)

        ipa_path = os.path.join(target_dir, "Test.ipa")
        assert os.path.isfile(ipa_path)

        with zipfile.ZipFile(ipa_path, "r") as zf:
            names = zf.namelist()
            assert any("Info.plist" in n for n in names)
            assert any("binary" in n for n in names)

    def test_default_target_dir(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        payload = tmp_path / "Payload"
        app_dir = payload / "App.app"
        app_dir.mkdir(parents=True)
        (app_dir / "file.txt").write_text("content")

        generate_ipa(str(payload), "App")
        assert os.path.isfile(str(tmp_path / "App.ipa"))


class TestCopyModulesToAppBundle:

    def test_copies_modules(self, tmp_path):
        # Create source file
        src = tmp_path / "src"
        src.mkdir()
        src_file = src / "binary"
        src_file.write_bytes(b"\xDE\xAD")

        app_path = tmp_path / "App.app"
        app_path.mkdir()

        dumped_modules = [
            {"src_path": str(src_file), "relative_path": "binary"},
        ]
        copy_modules_to_app_bundle(dumped_modules, str(app_path))
        assert os.path.isfile(str(app_path / "binary"))

    @patch("r2flutch.utils.shutil.move")
    @patch("r2flutch.utils.os.makedirs")
    def test_copies_modules_with_subdir(self, mock_makedirs, mock_move):
        dumped_modules = [
            {"src_path": "/tmp/bin/lib.dylib", "relative_path": "Frameworks/lib.dylib"},
        ]
        copy_modules_to_app_bundle(dumped_modules, "/dest/App.app")
        mock_makedirs.assert_called_once_with("Frameworks", exist_ok=True)
        mock_move.assert_called_once_with(
            "/tmp/bin/lib.dylib",
            os.path.join("/dest/App.app", "Frameworks/lib.dylib")
        )

    def test_empty_modules_list(self, tmp_path):
        app_path = tmp_path / "App.app"
        app_path.mkdir()
        copy_modules_to_app_bundle([], str(app_path))
        # No error should be raised
