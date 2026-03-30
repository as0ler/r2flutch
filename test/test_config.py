#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import tempfile
import pytest
from r2flutch.config import load_ssh_config


@pytest.fixture
def valid_config(tmp_path):
    config = {
        "ssh": {
            "host": "192.168.1.100",
            "port": 2222,
            "username": "root",
            "password": "alpine"
        }
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    return str(path)


@pytest.fixture
def minimal_config(tmp_path):
    config = {
        "ssh": {
            "host": "10.0.0.1",
            "username": "mobile",
            "password": "secret"
        }
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    return str(path)


class TestLoadSshConfig:

    def test_valid_config_all_fields(self, valid_config):
        cfg = load_ssh_config(valid_config)
        assert cfg["host"] == "192.168.1.100"
        assert cfg["port"] == 2222
        assert cfg["username"] == "root"
        assert cfg["password"] == "alpine"

    def test_minimal_config_defaults_port(self, minimal_config):
        cfg = load_ssh_config(minimal_config)
        assert cfg["host"] == "10.0.0.1"
        assert cfg["port"] == 22
        assert cfg["username"] == "mobile"
        assert cfg["password"] == "secret"

    def test_missing_file_exits(self):
        with pytest.raises(SystemExit):
            load_ssh_config("/nonexistent/path/config.json")

    def test_invalid_json_exits(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not json {{{")
        with pytest.raises(SystemExit):
            load_ssh_config(str(path))

    def test_missing_ssh_section_exits(self, tmp_path):
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"other": {}}))
        with pytest.raises(SystemExit):
            load_ssh_config(str(path))

    def test_missing_host_exits(self, tmp_path):
        config = {"ssh": {"username": "root", "password": "alpine"}}
        path = tmp_path / "config.json"
        path.write_text(json.dumps(config))
        with pytest.raises(SystemExit):
            load_ssh_config(str(path))

    def test_missing_username_exits(self, tmp_path):
        config = {"ssh": {"host": "1.2.3.4", "password": "alpine"}}
        path = tmp_path / "config.json"
        path.write_text(json.dumps(config))
        with pytest.raises(SystemExit):
            load_ssh_config(str(path))

    def test_missing_password_exits(self, tmp_path):
        config = {"ssh": {"host": "1.2.3.4", "username": "root"}}
        path = tmp_path / "config.json"
        path.write_text(json.dumps(config))
        with pytest.raises(SystemExit):
            load_ssh_config(str(path))

    def test_empty_host_exits(self, tmp_path):
        config = {"ssh": {"host": "", "username": "root", "password": "alpine"}}
        path = tmp_path / "config.json"
        path.write_text(json.dumps(config))
        with pytest.raises(SystemExit):
            load_ssh_config(str(path))

    def test_invalid_port_type_exits(self, tmp_path):
        config = {"ssh": {"host": "1.2.3.4", "username": "root", "password": "alpine", "port": "abc"}}
        path = tmp_path / "config.json"
        path.write_text(json.dumps(config))
        with pytest.raises(SystemExit):
            load_ssh_config(str(path))

    def test_port_out_of_range_exits(self, tmp_path):
        config = {"ssh": {"host": "1.2.3.4", "username": "root", "password": "alpine", "port": 99999}}
        path = tmp_path / "config.json"
        path.write_text(json.dumps(config))
        with pytest.raises(SystemExit):
            load_ssh_config(str(path))

    def test_port_zero_exits(self, tmp_path):
        config = {"ssh": {"host": "1.2.3.4", "username": "root", "password": "alpine", "port": 0}}
        path = tmp_path / "config.json"
        path.write_text(json.dumps(config))
        with pytest.raises(SystemExit):
            load_ssh_config(str(path))
