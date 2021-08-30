#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Murphy
# LICENSE: GPL v3

import argparse
import os
import shutil
import sys
from lib.repl import print_console, SUCCESS
from lib.device import get_usb_device, list_applications, spawn_r2frida_process
from lib.io import set_block_size, mount_app_bundle, copy_application_bundle, list_application_content
from lib.r2frida import load_all_modules, dump_decrypted_modules, get_main_bundle_name,load_r2f_plugin
from lib.config import *


def init():
    shutil.rmtree(TMP_FOLDER)
    os.makedirs(TMP_FOLDER)
    os.makedirs(os.path.join(TMP_FOLDER, DUMP_FOLDER))

def main(args):
    init()
    IS_DEBUG = args.debug
    device = get_usb_device()
    if args.list:
        list_applications(device)
        sys.exit(0)
    r2f = spawn_r2frida_process(args.target, device.id)
    mount_app_bundle(r2f)
    load_r2f_plugin(r2f)
    set_block_size(r2f, BLOCKSIZE)
    app_content = list_application_content(r2f, '')
    load_all_modules(r2f, app_content)
    dump_decrypted_modules(r2f, IS_DEBUG)
    dst_path = os.path.join(TMP_FOLDER, 'Payload',get_main_bundle_name(r2f))
    if (not args.binary):
        copy_application_bundle(r2f, app_content, dst_path)
    end_msg = 'r2flutch Decryption Complete!'
    print_console(end_msg, level=SUCCESS)
    r2f.cmd(':?E ' + end_msg)
    r2f.quit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='r2flutch (by Murphy)')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true', help='Show debug messages')
    parser.add_argument('-b', '--binary', dest='binary', action='store_true', help='Dump only the binary app')
    parser.add_argument('-l', '--list', dest='list', action='store_true', help='List the installed apps')
    parser.add_argument('target', nargs='?', help='Bundle identifier of the target app')
    args = parser.parse_args()
    if not len(sys.argv[1:]):
        parser.print_help()
        sys.exit(0)
    main(args)
