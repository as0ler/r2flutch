#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Murphy
# LICENSE: GPL v3
# Copyright (C) 2025 Murphy <me@0xmurphy.me>

"""
I/O operations module for r2flutch.

This module provides functions for file operations, remote file handling,
and application bundle management in the r2flutch framework.
"""

import sys
import os
import shutil
from tqdm import tqdm
from r2flutch.repl import print_console, ERROR, DEBUG
from r2flutch.config import REMOTE_PREFIX, TRANSPORT_SSH, TRANSPORT_FRIDA
from r2flutch.r2frida import get_remote_file, list_remote_folder, get_main_bundle_path
from r2flutch.ssh import ssh_list_remote_folder, ssh_get_remote_file


IGNORED_FILES = [".gitkeep", ".gitignore"]


def set_block_size(r2f, blocksize, debug_enabled=False):
    """
    Set the block size in the radare2 session.
    
    Args:
        r2f: The r2frida instance to configure
        blocksize (int): The block size to set
        debug_enabled (bool, optional): Whether to enable debug output. Defaults to False.
    """
    if debug_enabled:
        print_console("r2.cmd: b %s" % blocksize, level=DEBUG)
    r2f.cmd(r"b %s" % blocksize)
    print_console("Set block size to " + r2f.cmd(r"b").strip())


def get_application_content(r2f, app_content, dest_folder, debug_enabled, transport=TRANSPORT_FRIDA, sftp=None, bundle_path=None):
    """
    Copy remote application bundle content to a local destination directory.
    
    Creates the destination directory if it doesn't exist and downloads
    all files from the remote application bundle, excluding ignored files.
    
    Args:
        r2f: The r2frida instance for remote operations
        app_content (list): List of file paths in the application bundle
        dest_folder (str): Local destination directory path
        debug_enabled (bool): Whether to enable debug output
        transport (str): Transport mode - 'ssh' or 'frida'
        sftp: paramiko SFTPClient instance (required when transport is 'ssh')
        bundle_path (str): Pre-resolved bundle path (used with SSH transport)
    """
    if not os.path.exists(dest_folder):
        os.makedirs(dest_folder)
    print_console("Copy application bundle to: %s" % dest_folder)
    if bundle_path is None:
        bundle_path = get_main_bundle_path(r2f)
    with tqdm(total=len(app_content), desc="Copying application bundle", unit="file") as pbar:
        for filepath in app_content:
            if os.path.basename(filepath) not in IGNORED_FILES:
                if transport == TRANSPORT_SSH:
                    dest_path = os.path.dirname(filepath.replace(bundle_path, dest_folder))
                    ssh_get_remote_file(sftp, filepath, dest_path, debug_enabled)
                else:
                    dest_path = os.path.dirname(filepath.removeprefix(REMOTE_PREFIX).replace(bundle_path, dest_folder))
                    get_file(r2f, filepath, dest_path, debug_enabled)
                pbar.update(1)


def get_remote_path(r2f, filepath):
    """
    Convert a local file path to a remote path using the remote prefix.
    
    Args:
        r2f: The r2frida instance (unused but kept for consistency)
        filepath (str): The local file path to convert
    
    Returns:
        str: The remote path
    """
    return os.path.join(REMOTE_PREFIX, filepath.lstrip(os.sep))


def get_file(r2f, filepath, dest_folder, debug_enabled=False, transport=TRANSPORT_FRIDA, sftp=None):
    """
    Download a single file from the remote device to a local destination folder.
    
    Creates the destination folder if it doesn't exist.
    
    Args:
        r2f: The r2frida instance for remote operations
        filepath (str): The remote file path to download including the remote prefix
        dest_folder (str): The local destination folder
        debug_enabled (bool, optional): Whether to enable debug output. Defaults to False.
        transport (str): Transport mode - 'ssh' or 'frida'
        sftp: paramiko SFTPClient instance (required when transport is 'ssh')
    """
    if transport == TRANSPORT_SSH:
        if sftp is None:
            sys.exit("[x] sftp client is required for SSH transport but was not provided")
        ssh_get_remote_file(sftp, filepath, dest_folder, debug_enabled)
        return
    if debug_enabled:
        print_console("Downloading file %s to %s" % (filepath, dest_folder), level=DEBUG)
    get_remote_file(r2f, filepath, debug_enabled)
    downloaded_file = os.path.basename(filepath)
    if os.path.isfile(downloaded_file):
        if not os.path.exists(dest_folder):
            os.makedirs(dest_folder, exist_ok=True)
        shutil.move(downloaded_file, dest_folder)
    else:
        print_console("Failed to copy file: %s to %s" % (downloaded_file, dest_folder), level=ERROR)

def list_content_path(r2f, path, debug_enabled=False, progress_bar=None, transport=TRANSPORT_FRIDA, sftp=None):
    """
    Recursively list all files in a remote directory path.
    
    Traverses the directory tree and returns a flat list of all file paths,
    excluding directories. This function is called recursively for subdirectories.
    
    Args:
        r2f: The r2frida instance for remote operations
        path (str): The remote directory path to list
        debug_enabled (bool, optional): Whether to enable debug output. Defaults to False.
        progress_bar (tqdm, optional): Progress bar instance for tracking progress
        transport (str): Transport mode - 'ssh' or 'frida'
        sftp: paramiko SFTPClient instance (required when transport is 'ssh')
    
    Returns:
        list: A list of file paths found in the directory and subdirectories
    """
    app_content = []
    if transport == TRANSPORT_SSH:
        folder_contents = ssh_list_remote_folder(sftp, path)
    else:
        folder_contents = list_remote_folder(r2f, path)
    for file_obj in folder_contents:
        file_path = os.path.join(path, file_obj["name"])
        if progress_bar:
            progress_bar.update(1)
        if file_obj["type"] == "file" and file_obj["size"] > 0:
            app_content.append(file_path)
        else:
            app_content.extend(list_content_path(r2f, file_path, debug_enabled, progress_bar, transport, sftp))
    return app_content

def list_content_path_with_progress(r2f, path, debug_enabled=False, transport=TRANSPORT_FRIDA, sftp=None):
    """
    Wrapper function that provides a progress bar for list_content_path.
    
    Args:
        r2f: The r2frida instance for remote operations
        path (str): The remote directory path to list
        debug_enabled (bool, optional): Whether to enable debug output. Defaults to False.
        transport (str): Transport mode - 'ssh' or 'frida'
        sftp: paramiko SFTPClient instance (required when transport is 'ssh')
    
    Returns:
        list: A list of file paths found in the directory and subdirectories
    """
    def count_files_recursive(r2f, path):
        count = 0
        if transport == TRANSPORT_SSH:
            current_items = ssh_list_remote_folder(sftp, path)
        else:
            current_items = list_remote_folder(r2f, path)
        count += len(current_items)
        for file_obj in current_items:
            if file_obj["type"] == "directory":
                count += count_files_recursive(r2f, os.path.join(path, file_obj["name"]))
        return count
    
    total_files = count_files_recursive(r2f, path)
    with tqdm(total=total_files, desc="Listing application content", unit="files") as pbar:
        return list_content_path(r2f, path, debug_enabled, pbar, transport, sftp)


def list_application_content(r2f, debug_enabled=False, transport=TRANSPORT_FRIDA, sftp=None, bundle_path=None):
    """
    List all content files in the main application bundle.
    
    Gets the main bundle path from the device and lists all files
    recursively within that bundle.
    
    Args:
        r2f: The r2frida instance for remote operations
        debug_enabled (bool, optional): Whether to enable debug output. Defaults to False.
        transport (str): Transport mode - 'ssh' or 'frida'
        sftp: paramiko SFTPClient instance (required when transport is 'ssh')
        bundle_path (str): Pre-resolved bundle path (used with SSH transport)
    
    Returns:
        list: A list of all file paths in the application bundle
    """
    if transport == TRANSPORT_SSH:
        # Use provided bundle_path when available, otherwise resolve it to avoid
        # passing None into recursive listing functions.
        if bundle_path is None:
            remote_app_path = get_main_bundle_path(r2f)
        else:
            remote_app_path = bundle_path
    else:
        remote_app_path = os.path.join(REMOTE_PREFIX, get_main_bundle_path(r2f).lstrip(os.sep))
    return list_content_path_with_progress(r2f, remote_app_path, debug_enabled, transport, sftp)
