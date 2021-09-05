#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Murphy
# LICENSE: GPL v3

import argparse
import os
import shutil
import sys
from r2flutch.lib.repl import print_console, SUCCESS
from r2flutch.lib.device import get_usb_device, list_applications, spawn_r2frida_process
from r2flutch.lib.io import set_block_size, mount_app_bundle, copy_application_bundle, list_application_content
from r2flutch.lib.r2frida import load_all_modules, dump_decrypted_modules, get_main_bundle_name, load_r2f_plugin
from r2flutch.lib.config import BLOCKSIZE, TMP_FOLDER, DUMP_FOLDER, BIN_FOLDER
from r2flutch.lib.utils import generate_ipa, copy_modules_to_app_bundle


def init():
    if os.path.isdir(TMP_FOLDER):
        shutil.rmtree(TMP_FOLDER)
    os.makedirs(TMP_FOLDER)
    os.makedirs(os.path.join(TMP_FOLDER, DUMP_FOLDER))
    os.makedirs(os.path.join(TMP_FOLDER, BIN_FOLDER))


def main():
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
    mount_app_bundle(r2f)
    load_r2f_plugin(r2f)
    set_block_size(r2f, BLOCKSIZE)
    app_content = list_application_content(r2f, '')
    load_all_modules(r2f, app_content)
    dumped_modules = dump_decrypted_modules(r2f, debug_enabled)
    app_name = get_main_bundle_name(r2f)
    if arguments.generate_ipa:
        payload_path = os.path.join(TMP_FOLDER, 'Payload')
        app_path = os.path.join(payload_path, '%s.app' % app_name)
        os.makedirs(app_path, exist_ok=True)
        copy_application_bundle(r2f, app_content, app_path, debug_enabled)
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


if __name__ == '__main__':
    main()
