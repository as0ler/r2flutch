#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Murphy
# LICENSE: GPL v3

import os
import shutil
import base64
from tqdm import tqdm
from r2flutch.repl import print_console, ERROR


PREFIX = '/r2f'
APP_BUNDLE_BASE_PATH = '%s/AppBundle' % PREFIX
DEVICE_PATH = '%s/Device' % PREFIX


def set_block_size(r2f, blocksize):
    r2f.cmd(r'b %s' % blocksize)
    print_console('Set block size to ' + r2f.cmd(r'b'))


def mount_app_bundle(r2f):
    print_console('Mount Application Bundle')
    r2f.cmd(r'm %s io 0x0' % PREFIX)


def copy_application_bundle(r2f, app_content, dest, debug_enabled):
    print_console('Copy application bundle to: %s' % dest)
    if not os.path.exists(dest):
        os.makedirs(dest)
    print_console('Copy App Bundle to disk')
    for filepath in tqdm(app_content):
        get_file(r2f, filepath, dest, debug_enabled)


def download_module(r2f, module_path, dest_path):
    basename = os.path.basename(module_path)
    full_path = os.path.join(DEVICE_PATH, module_path[1:])
    r2f.cmd('\"mg %s\"' % full_path)
    shutil.move(basename, dest_path)


def get_file(r2f, filepath, dest, debug_enabled):
    dirs = os.path.dirname(filepath)
    basename = os.path.basename(filepath)
    if dirs:
        os.makedirs(os.path.join(dest, dirs), exist_ok=True)
    b64_full_path = base64.b64encode(os.path.join(APP_BUNDLE_BASE_PATH, filepath).encode()).decode()
    if debug_enabled:
        r2f.cmd('mg base64:%s' % b64_full_path)
    else:
        r2f.cmd('mg base64:%s 2>/dev/null' % b64_full_path)
    if os.path.isfile(basename):
        shutil.move(basename, os.path.join(dest, dirs, basename))
    else:
        print_console('Failed to copy file: %s' % basename, level=ERROR)


def list_content_path(r2f, path):
    full_path = os.path.join(APP_BUNDLE_BASE_PATH, path)
    r2cmd = 'mdj %s' % full_path
    return r2f.cmdj(r2cmd)


def list_application_content(r2f, path):
    app_content = []
    for file_obj in list_content_path(r2f, path):
        if file_obj['type'] == 'file':
            file_path = os.path.join(path, file_obj['name'])
            app_content.append(file_path)
        else:
            app_content.extend(list_application_content(r2f, os.path.join(path, file_obj['name'])))
    return app_content
