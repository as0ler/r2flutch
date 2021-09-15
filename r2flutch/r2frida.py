#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Murphy
# LICENSE: GPL v3

import os
import re
import r2pipe
import r2flutch
from r2flutch.repl import print_console, DEBUG
from r2flutch.io import APP_BUNDLE_BASE_PATH, download_module
from r2flutch.config import TMP_FOLDER, DUMP_FOLDER, BIN_FOLDER


def load_all_modules(r2f, app_content):
    print_console('Loading all modules')
    for filepath in app_content:
        ext = os.path.splitext(filepath)[1]
        if ext == '.dylib':
            load_library(r2f, os.path.join(APP_BUNDLE_BASE_PATH, filepath))
        elif ext == '.framework':
            load_library(r2f, os.path.join(APP_BUNDLE_BASE_PATH, filepath))


def load_library(r2f, path):
    print_console('Loading library %s' % path)
    r2cmd = ':dl %s' % path
    return r2f.cmdj(r2cmd)


def load_framework(r2f, path):
    print_console('Loading framework %s' % path)
    r2cmd = ':dlf %s' % path
    return r2f.cmdj(r2cmd)


def load_r2f_plugin(r2f):
    plugin_path = os.path.join(os.path.dirname(os.path.abspath(r2flutch.__file__)), 'agent', 'plugin.js')
    r2f.cmd(':. %s' % plugin_path)


def get_main_bundle_name(r2f):
    return r2f.cmd(':getMainBundleName').strip()


def dump_decrypted_modules(r2f, debug_enabled=False):
    dumped_modules = []
    modules_to_decrypt = r2f.cmdj(':dump')
    for module in modules_to_decrypt:
        bin_dumped = os.path.join(TMP_FOLDER, DUMP_FOLDER, module['name'])
        dst_bin = os.path.join(TMP_FOLDER, BIN_FOLDER, module['name'])
        crypt_offset = hex(module['encryption_info']['cryptoff'])
        base_addr = hex(int(module['base'], 16))
        offset = hex(int(module['base'], 16) + module['encryption_info']['cryptoff'])
        size = hex(module['encryption_info']['cryptsize'])
        crypt_header = hex(int(module['encryption_info']['addr'], 16))
        print_console('Dumping Module %s at %s (%s Bytes)' % (module['name'], offset, size))
        if debug_enabled:
            print_console('BaseAddr: %s' % base_addr, level=DEBUG)
            print_console('CryptOff: %s' % crypt_offset, level=DEBUG)
            print_console('BaseAddr + CryptOff: %s' % offset, level=DEBUG)
            print_console('CryptSize: %s' % size, level=DEBUG)
            print_console('Crypt Header: %s' % crypt_header, level=DEBUG)
        r2f.cmd('s %s' % offset)
        r2f.cmd('wtf %s %s' % (bin_dumped, size))
        download_module(r2f, module['path'], dst_bin)
        patch_bin(bin_dumped, dst_bin, crypt_header, crypt_offset, debug_enabled)
        print_console('Module %s successfully decrypted' % dst_bin)
        relative_path = re.sub(r".*\.app/", "", module['path'])
        dumped_modules.append({'src_path': dst_bin, 'relative_path': relative_path})
    return dumped_modules


def patch_bin(bin_dumped, dst_bin, crypt_header, cryptoff, debug_enabled=False):
    r2_raw = r2pipe.open(dst_bin, ['-nw'])
    cryptid_offset = hex(int(crypt_header, 16) + int('0x10', 16))
    if debug_enabled:
        print_console('dst_bin: %s' % dst_bin, level=DEBUG)
        print_console('crypt_header: %s' % crypt_header, level=DEBUG)
        print_console('crypt_offset: %s' % cryptoff, level=DEBUG)
        print_console('cryptid_offset: %s' % cryptid_offset, level=DEBUG)
    print_console('Writing decrypted data to file %s at %s' % (dst_bin, cryptoff))
    r2_raw.cmd('s %s; wff %s' % (cryptoff, bin_dumped))
    print_console('Patching cryptid at offset %s' % cryptid_offset)
    r2_raw.cmd('s %s; wx 00' % cryptid_offset)
    r2_raw.quit()
