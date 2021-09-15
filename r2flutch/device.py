#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Murphy
# LICENSE: GPL v3

import sys
import threading
import frida
import r2pipe
from r2flutch.repl import print_console, ERROR, DEFAULT


def get_usb_device():
    device_type = 'usb'
    device_manager = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()

    device_manager.on('changed', on_changed)
    device = None
    while device is None:
        devices = [dev for dev in device_manager.enumerate_devices() if dev.type == device_type]
        if len(devices) == 0:
            print_console('Waiting for USB device...')
            changed.wait()
        else:
            device = devices[0]
    device_manager.off('changed', on_changed)
    return device


def list_applications(device):
    try:
        applications = device.enumerate_applications()
    except Exception as err:
        sys.exit('[x] Failed to enumerate applications: %s' % err)
    print_console('Bundle Identifier', level=DEFAULT)
    print_console('------------------------------', level=DEFAULT)
    for application in applications:
        print_console(application.identifier, level=DEFAULT)


def spawn_r2frida_process(bundle_id, device_id):
    print_console('Open Application Process %s' % bundle_id)
    r2frida_handle = 'frida://launch/usb/%s/%s' % (device_id, bundle_id)
    try:
        r2f = r2pipe.open(r2frida_handle)
        return r2f
    except Exception:
        print_console('Cannot open target process: ' + bundle_id, ERROR)
        sys.exit(0)
