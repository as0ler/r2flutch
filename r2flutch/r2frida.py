#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Murphy
# LICENSE: GPL v3
# Copyright (C) 2025 Murphy <me@0xmurphy.me>

"""
r2frida integration and module management module for r2flutch.

This module provides core functionality for interacting with r2frida which 
handles module loading, encryption information extraction, binary patching,
and file operations through r2frida commands.
"""

import base64
import os
import r2pipe
import r2flutch
from r2flutch.repl import print_console, DEBUG
from r2flutch.config import TMP_FOLDER, DUMP_FOLDER, BIN_FOLDER


def load_all_modules(r2f, app_content):
    """
    Load all dynamic libraries and frameworks from the application content.
    
    Args:
        r2f: The r2frida instance connected to the target application
        app_content: List of file paths representing the application content
    """
    print_console("Loading all modules")
    for filepath in app_content:
        ext = os.path.splitext(filepath)[1]
        if ext == ".dylib":
            load_library(r2f, filepath)
        elif ext == ".framework":
            load_library(r2f,filepath)


def load_library(r2f, path):
    """
    Load a dynamic library into r2frida for analysis.
    
    Args:
        r2f: The r2frida instance connected to the target application
        path: Path to the dynamic library file to load
    """
    print_console("Loading library %s" % path)
    r2cmd = ":dl %s" % path
    return r2f.cmdj(r2cmd)


def load_framework(r2f, path):
    """
    Load a framework into r2frida for analysis.
    
    Uses the r2frida :dlf command to load a framework file into
    the current analysis session.
    
    Args:
        r2f: The r2frida instance connected to the target application
        path: Path to the framework file to load
    """
    print_console("Loading framework %s" % path)
    r2cmd = ":dlf %s" % path
    return r2f.cmdj(r2cmd)


def load_r2f_plugin(r2f):
    """
    Load the r2flutch TypeScript plugin into r2frida.
    
    Args:
        r2f: The r2frida instance connected to the target application    
    """
    plugin_path = os.path.join(os.path.dirname(os.path.abspath(r2flutch.__file__)), "agent", "plugin.ts")
    r2f.cmd(":. %s" % plugin_path)


def get_main_bundle_name(r2f):
    """
    Get the main bundle name of the target iOS application.
    
    Args:
        r2f: The r2frida instance connected to the target application
        
    Returns:
        str: The main bundle name of the target application
    """
    return r2f.cmd(":getMainBundleName").strip()


def get_main_bundle_path(r2f):
    """
    Get the main bundle path of the target iOS application.
        
    Args:
        r2f: The r2frida instance connected to the target application
        
    Returns:
        str: The main bundle path of the target application
    """
    return r2f.cmd(":getMainBundlePath").strip()


def get_remote_file(r2f, filepath, debug_enabled=False):
    """
    Get a remote file from the target device using r2frida.
    
    Args:
        r2f: The r2frida instance connected to the target application
        filepath: Path to the file to retrieve from the remote device
        debug_enabled: Boolean flag to enable debug output and error display
    """
    b64_full_path = base64.b64encode(filepath.encode()).decode()
    if debug_enabled:
        print_console("r2f.cmd: mg base64:%s" % b64_full_path, level=DEBUG)
    r2f.cmd("mg base64:%s 2>/dev/null" % b64_full_path)


def list_remote_folder(r2f, path):
    """
    List contents of a remote folder on the target device.
    
    Args:
        r2f: The r2frida instance connected to the target application
        path: Path to the remote directory to list
        
    Returns:
        The JSON result of the directory listing command
    """
    b64_full_path = base64.b64encode(path.encode()).decode()
    r2cmd = "mdj base64:%s" % b64_full_path
    return r2f.cmdj(r2cmd)


def get_modules_to_decrypt(r2f):
    """
    Get list of modules that require decryption.
    
    Args:
        r2f: The r2frida instance connected to the target application
        
    Returns:
        List of module dictionaries containing decryption information
    """
    return r2f.cmdj(":dump")


def get_module_paths(module):
    """
    Generate file paths for module decryption operations.
    
    Args:
        module: Module dictionary containing module information
        
    Returns:
        dict: Dictionary with paths for decrypted binary file and destination binary file path
    """
    decrypted_bin = os.path.join(TMP_FOLDER, DUMP_FOLDER, module["name"])
    patched_bin = os.path.join(TMP_FOLDER, BIN_FOLDER, module["name"])
    return {"decrypted_bin": decrypted_bin, "patched_bin": patched_bin}


def get_encryption_info(module):
    """
    Extract encryption information from a module.
   
    Args:
        module: Module dictionary containing encryption information
        
    Returns:
        dict: Dictionary containing calculated encryption offsets and addresses
    """
    crypt_offset = hex(module["encryption_info"]["cryptoff"])
    base_addr = hex(int(module["base"], 16))
    offset = hex(int(module["base"], 16) + module["encryption_info"]["cryptoff"])
    size = hex(module["encryption_info"]["cryptsize"])
    crypt_header = hex(int(module["encryption_info"]["addr"], 16))
    return {
        "crypt_offset": crypt_offset,
        "base_addr": base_addr,
        "offset": offset,
        "size": size,
        "crypt_header": crypt_header
    }


def print_encryption_info(module, encryption_info, debug_enabled):
    """
    Print encryption information for debugging purposes.
        
    Args:
        module: Module dictionary containing module information
        encryption_info: Dictionary containing calculated encryption data
        debug_enabled: Boolean flag to control debug output
    """
    print_console("BaseAddr: %s" % encryption_info["base_addr"], level=DEBUG)
    print_console("CryptOff: %s" % encryption_info["crypt_offset"], level=DEBUG)
    print_console("BaseAddr + CryptOff: %s" % encryption_info["offset"], level=DEBUG)
    print_console("CryptSize: %s" % encryption_info["size"], level=DEBUG)
    print_console("Crypt Header: %s" % encryption_info["crypt_header"], level=DEBUG)


def dump_decrypted_module_data(r2f, offset, destination_path, size):
    """
    Dump decrypted module data from memory to a file.
        
    Args:
        r2f: The r2frida instance connected to the target application
        offset: Memory offset where decrypted data begins
        destination_path: Path where the decrypted data should be saved
        size: Size of the decrypted data to dump
    """
    r2f.cmd("s %s" % offset)
    b64_destination_path = base64.b64encode(destination_path.encode()).decode()
    r2f.cmd("wtf base64:%s %s" % (b64_destination_path, size))


def patch_bin(decrypted_bin, patched_bin, crypt_header, cryptoff, debug_enabled=False):
    """
    Patch a binary file with decrypted data and update encryption flags.
    
    Args:
        decrypted_bin: Path to the file containing decrypted data
        patched_bin: Path where the patched data is found
        crypt_header: Address of the encryption header in the binary
        cryptoff: Offset where decrypted data should be written
        debug_enabled: Boolean flag to enable debug output
    """
    print_console("Writing decrypted data %s to file %s at %s" % (decrypted_bin, patched_bin, cryptoff))
    r2_raw = r2pipe.open(patched_bin, ["-nw"])
    cryptid_offset = hex(int(crypt_header, 16) + int("0x10", 16))
    if debug_enabled:
        print_console("crypt_header: %s" % crypt_header, level=DEBUG)
        print_console("crypt_offset: %s" % cryptoff, level=DEBUG)
        print_console("cryptid_offset: %s" % cryptid_offset, level=DEBUG)
    r2_raw.cmd("s %s; wff %s" % (cryptoff, decrypted_bin))
    print_console("Patching cryptid at offset %s" % cryptid_offset)
    r2_raw.cmd("s %s; wx 00" % cryptid_offset)
    r2_raw.quit()
