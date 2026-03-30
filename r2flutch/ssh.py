#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Murphy
# LICENSE: GPL v3
# Copyright (C) 2025 Murphy <me@0xmurphy.me>

"""
SSH/SFTP transport module for r2flutch.

This module provides functions for listing and downloading files from
an iOS device over SSH/SFTP, as an alternative to the r2frida-based
file transfer.
"""

import os
import stat
import sys
import paramiko
from r2flutch.repl import print_console, DEBUG, ERROR


def ssh_connect(ssh_config):
    """
    Establish an SSH connection and return an SFTP client.

    Args:
        ssh_config (dict): SSH configuration with keys host, port, username, password

    Returns:
        tuple: (paramiko.SSHClient, paramiko.SFTPClient)
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=ssh_config["host"],
            port=ssh_config["port"],
            username=ssh_config["username"],
            password=ssh_config["password"],
            look_for_keys=False,
            allow_agent=False,
        )
    except Exception as err:
        sys.exit("[x] SSH connection failed: %s" % err)
    sftp = client.open_sftp()
    print_console("SSH connection established to %s@%s:%d" % (
        ssh_config["username"], ssh_config["host"], ssh_config["port"]))
    return client, sftp


def ssh_disconnect(client, sftp):
    """
    Close the SFTP and SSH connections.

    Args:
        client (paramiko.SSHClient): The SSH client
        sftp (paramiko.SFTPClient): The SFTP client
    """
    sftp.close()
    client.close()


def ssh_list_remote_folder(sftp, path):
    """
    List contents of a remote folder over SFTP.

    Returns the same format as the r2frida list_remote_folder function
    so that io.py can consume it transparently.

    Args:
        sftp (paramiko.SFTPClient): The SFTP client
        path (str): The remote directory path to list

    Returns:
        list: List of dicts with keys "name", "type", "size"
    """
    results = []
    try:
        entries = sftp.listdir_attr(path)
    except IOError:
        return results
    for entry in entries:
        if stat.S_ISDIR(entry.st_mode):
            entry_type = "directory"
        else:
            entry_type = "file"
        results.append({
            "name": entry.filename,
            "type": entry_type,
            "size": entry.st_size,
        })
    return results


def ssh_get_remote_file(sftp, remote_path, dest_folder, debug_enabled=False):
    """
    Download a single file from the remote device over SFTP.

    Args:
        sftp (paramiko.SFTPClient): The SFTP client
        remote_path (str): Full remote path to the file
        dest_folder (str): Local destination folder
        debug_enabled (bool): Whether to enable debug output
    """
    if debug_enabled:
        print_console("SSH downloading %s to %s" % (remote_path, dest_folder), level=DEBUG)
    if not os.path.exists(dest_folder):
        os.makedirs(dest_folder, exist_ok=True)
    filename = os.path.basename(remote_path)
    local_path = os.path.join(dest_folder, filename)
    try:
        sftp.get(remote_path, local_path)
    except Exception as err:
        print_console("Failed to download file via SSH: %s (%s)" % (remote_path, err), level=ERROR)
