#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Murphy
# LICENSE: GPL v3
# Copyright (C) 2025 Murphy <me@0xmurphy.me>

"""
r2flutch command-line interface module.

This module provides the main entry point for the r2flutch tool, which is used
for decrypting iOS applications using r2frida.
"""

import argparse
import re
import os
import shutil
import sys
from r2flutch.repl import print_console, SUCCESS
from r2flutch.device import get_usb_device, list_applications, spawn_r2frida_process
from r2flutch.io import set_block_size, get_application_content, list_application_content
from r2flutch.r2frida import load_all_modules, get_main_bundle_name, load_r2f_plugin, get_modules_to_decrypt, get_module_paths
from r2flutch.r2frida import get_encryption_info, print_encryption_info, dump_decrypted_module_data, patch_bin
from r2flutch.io import get_file, REMOTE_PREFIX
from r2flutch.config import BLOCKSIZE, TMP_FOLDER, DUMP_FOLDER, BIN_FOLDER
from r2flutch.utils import generate_ipa, copy_modules_to_app_bundle


def init():
    """
    Initialize the temporary directory structure.
    """
    if os.path.isdir(TMP_FOLDER):
        shutil.rmtree(TMP_FOLDER)
    os.makedirs(TMP_FOLDER)
    os.makedirs(os.path.join(TMP_FOLDER, DUMP_FOLDER))
    os.makedirs(os.path.join(TMP_FOLDER, BIN_FOLDER))


def main():
    """
    Main entry point for the r2flutch command-line tool.
    
    Parses command-line arguments and orchestrates the iOS application
    decryption process. Handles device connection, r2frida process spawning,
    module loading, decryption, and optional IPA generation.
    """
    parser = argparse.ArgumentParser(description='r2flutch (by Murphy)')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true', help='Show debug messages')
    parser.add_argument('-o', '--output', type=str, help='Path where output files will be stored.')
    parser.add_argument('-i', '--ipa', dest='generate_ipa', action='store_true', help='Generate an IPA file')
    parser.add_argument('-l', '--list', dest='list', action='store_true', help='List the installed apps')
    parser.add_argument('target', nargs='?', help='Bundle identifier of the target app')
    arguments = parser.parse_args()
    if len(sys.argv[1:]) == 0:
        parser.print_help()
        sys.exit(0)
    init()
    output_dir = arguments.output if arguments.output else '.'
    os.makedirs(output_dir, exist_ok=True)
    debug_enabled = arguments.debug
    device = get_usb_device()
    if arguments.list:
        list_applications(device)
        sys.exit(0)
    r2f = spawn_r2frida_process(arguments.target, device.id)
    load_r2f_plugin(r2f)
    set_block_size(r2f, BLOCKSIZE, debug_enabled)
    app_content = list_application_content(r2f, debug_enabled)
    load_all_modules(r2f, app_content)
    dumped_modules = dump_decrypted_modules(r2f, debug_enabled)
    if arguments.generate_ipa:
        app_name = get_main_bundle_name(r2f)
        payload_path = os.path.join(TMP_FOLDER, 'Payload')
        app_path = os.path.join(payload_path, '%s.app' % app_name)
        os.makedirs(app_path, exist_ok=True)
        get_application_content(r2f, app_content, app_path, debug_enabled)
        copy_modules_to_app_bundle(dumped_modules, app_path)
        generate_ipa(payload_path, app_name, target_dir=output_dir)
    else:
        for module in dumped_modules:
            shutil.move(module['src_path'], output_dir)
        print_console('Decrypted modules saved at %s' % output_dir)
    if dumped_modules:
        end_msg = 'r2flutch Decryption Complete!'
        print_console(end_msg, level=SUCCESS)
        r2f.cmd(':?E ' + end_msg)
    r2f.quit()


def dump_decrypted_modules(r2f, debug_enabled=False):
    """
    Decrypt all modules in the target iOS application.
    
    Iterates through all modules that require decryption, extracts encryption
    information, dumps decrypted data, and patches the binary files with
    the decrypted content.
    
    Args:
        r2f: The r2frida instance connected to the target application
        debug_enabled: Boolean flag to enable debug output and verbose logging
    
    Returns:
        list: A list of dictionaries containing information about each dumped
              module, including source path and relative path within the app bundle
    """
    dumped_modules = []
    for module in get_modules_to_decrypt(r2f):
        print_console("Decrypting module %s" % module["name"])
        paths = get_module_paths(module)
        encryption_info = get_encryption_info(module)
        if debug_enabled:
            print_encryption_info(module, encryption_info, debug_enabled)
        print_console("Dumping decrypted data from %s at %s (%s Bytes)" % (module["name"], encryption_info["offset"], encryption_info["size"]))
        dump_decrypted_module_data(r2f, encryption_info["offset"], paths["decrypted_bin"], encryption_info["size"])
        print_console("Copying original binary to %s" % paths["patched_bin"])
        get_file(r2f, os.path.join(REMOTE_PREFIX, module["path"].lstrip(os.path.sep)), os.path.dirname(paths["patched_bin"]), debug_enabled)
        patch_bin(paths["decrypted_bin"], paths["patched_bin"], encryption_info["crypt_header"], encryption_info["crypt_offset"], debug_enabled)
        print_console("Module %s successfully decrypted" % paths["patched_bin"])
        relative_path = re.sub(r".*\.app/", "", module["path"])
        dumped_modules.append({"src_path": paths["patched_bin"], "relative_path": relative_path})
    return dumped_modules


if __name__ == '__main__':
    main()

