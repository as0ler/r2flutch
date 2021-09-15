#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Murphy
# LICENSE: GPL v3

import os
import shutil
import zipfile
from r2flutch.repl import print_console


def generate_ipa(path, app_name, target_dir='.'):
    ipa_filename = app_name + '.ipa'
    output_path = os.path.join(target_dir, ipa_filename)
    print_console('Creating IPA file at %s' % output_path)
    with zipfile.ZipFile(output_path, mode='w', compression=zipfile.ZIP_DEFLATED) as zip_handle:
        for (root, _, files) in os.walk(path):
            for file in files:
                zip_handle.write(os.path.join(root, file),
                                 os.path.relpath(os.path.join(root, file), os.path.join(path, '..')))
    print_console('IPA file saved at %s' % output_path)


def copy_modules_to_app_bundle(dumped_modules, app_path):
    for module in dumped_modules:
        if os.path.dirname(module['relative_path']):
            os.makedirs(os.path.dirname(module['relative_path']), exist_ok=True)
        shutil.move(module['src_path'], os.path.join(app_path, module['relative_path']))
