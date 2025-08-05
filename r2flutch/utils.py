#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Murphy
# LICENSE: GPL v3
# Copyright (C) 2025 Murphy <me@0xmurphy.me>

"""
Utility functions module for r2flutch.

This module provides utility functions for iOS application processing and
IPA generation.
"""

import os
import shutil
import zipfile
from r2flutch.repl import print_console


def generate_ipa(path, app_name, target_dir="."):
    """
    Generate an IPA file from a decrypted iOS application.
    
    Args:
        path: Path to the directory containing the decrypted application
        app_name: Name of the application (used for the IPA filename)
        target_dir: Directory where the IPA file should be saved (default: current directory)
    """
    ipa_filename = app_name + ".ipa"
    output_path = os.path.join(target_dir, ipa_filename)
    print_console("Creating IPA file at %s" % output_path)
    with zipfile.ZipFile(output_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zip_handle:
        for (root, _, files) in os.walk(path):
            for file in files:
                zip_handle.write(os.path.join(root, file),
                                 os.path.relpath(os.path.join(root, file), os.path.join(path, "..")))
    print_console("IPA file saved at %s" % output_path)


def copy_modules_to_app_bundle(dumped_modules, app_path):
    """
    Copy decrypted modules back into the application bundle structure.
    
    Args:
        dumped_modules: List of module dictionaries containing module information
        app_path: Path to the destination application bundle directory
    """
    for module in dumped_modules:
        if os.path.dirname(module["relative_path"]):
            os.makedirs(os.path.dirname(module["relative_path"]), exist_ok=True)
        shutil.move(module["src_path"], os.path.join(app_path, module["relative_path"]))
