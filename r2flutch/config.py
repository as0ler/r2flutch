# Author : Murphy
# LICENSE: GPL v3
# Copyright (C) 2025 Murphy <me@0xmurphy.me>

import json
import sys
import tempfile

BLOCKSIZE = "0x400000"
TMP_FOLDER = tempfile.mkdtemp(prefix="r2flutch-")
DUMP_FOLDER = "dump"
BIN_FOLDER = "bin"
REMOTE_PREFIX = "/r2f"

TRANSPORT_SSH = "ssh"
TRANSPORT_FRIDA = "frida"
DEFAULT_TRANSPORT = TRANSPORT_SSH


def load_ssh_config(config_path):
    """
    Load and validate SSH configuration from a JSON file.

    The config file must contain an "ssh" object with at least
    "host", "username" and "password" fields.

    Args:
        config_path (str): Path to the config.json file

    Returns:
        dict: Validated SSH configuration dictionary with keys
              host, port, username, password
    """
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        sys.exit("[x] Config file not found: %s" % config_path)
    except json.JSONDecodeError as err:
        sys.exit("[x] Invalid JSON in config file: %s" % err)

    ssh_cfg = data.get("ssh")
    if ssh_cfg is None:
        sys.exit("[x] Config file missing 'ssh' section")

    for required_field in ("host", "username", "password"):
        if required_field not in ssh_cfg or not ssh_cfg[required_field]:
            sys.exit("[x] Config file missing required SSH field: %s" % required_field)

    # Normalize and validate port
    port = ssh_cfg.get("port", 22)
    try:
        port = int(port)
    except (TypeError, ValueError):
        sys.exit("[x] Invalid SSH port value in config file: %r" % port)

    if not (1 <= port <= 65535):
        sys.exit("[x] SSH port out of valid range (1-65535): %d" % port)

    ssh_cfg["port"] = port
    return ssh_cfg
