#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Murphy
# LICENSE: GPL v3
# Copyright (C) 2025 Murphy <me@0xmurphy.me>

"""
Device management and communication module.

This module handles USB device detection, connection management, and process
spawning for iOS applications.

The module integrates with Frida for device management and r2pipe for r2frida.
"""

import sys
import threading
import frida
import r2pipe
from r2flutch.repl import print_console, ERROR, DEFAULT


def get_usb_device():
    """
    Wait for and return the first available USB device.
    
    Uses Frida's device manager to detect device changes and
    automatically connects to the first USB device found.
    
    Returns:
        frida.core.Device: The connected USB device instance
    """
    device_type = "usb"
    device_manager = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()

    device_manager.on("changed", on_changed)
    device = None
    while device is None:
        devices = [dev for dev in device_manager.enumerate_devices() if dev.type == device_type]
        if len(devices) == 0:
            print_console("Waiting for USB device...")
            changed.wait()
        else:
            device = devices[0]
    device_manager.off("changed", on_changed)
    return device


def list_applications(device):
    """
    List all installed applications on the connected device.
    
    Enumerates all applications installed on the specified device and
    displays their bundle identifiers in a formatted table.
    
    Args:
        device: The Frida device instance to query for applications
    """
    try:
        applications = device.enumerate_applications()
    except Exception as err:
        sys.exit("[x] Failed to enumerate applications: %s" % err)
    print_console("Bundle Identifier", level=DEFAULT)
    print_console("------------------------------", level=DEFAULT)
    for application in applications:
        print_console(application.identifier, level=DEFAULT)


def spawn_r2frida_process(bundle_id, device_id):
    """
    Spawn and connect to a target iOS application process using r2frida.
    
    Creates an r2frida connection to a specified iOS application by spawning
    the process on the target device. 
    
    Args:
        bundle_id: The bundle identifier of the target iOS application
        device_id: The identifier of the USB device where the app is installed
        
    Returns:
        r2pipe.r2pipe: An r2pipe instance connected to the target process
    """
    print_console("Open Application Process %s" % bundle_id)
    r2frida_handle = "frida://spawn/usb/%s/%s" % (device_id, bundle_id)
    try:
        r2f = r2pipe.open(r2frida_handle)
        return r2f
    except Exception:
        print_console("Cannot open target process: " + bundle_id, ERROR)
        sys.exit(0)

def kill_process(device, r2f):
    """
    Kill the target process.
    """
    pid = r2f.cmd(":getPID")
    print_console("Killing process %s" % pid)
    try:
     device.kill(int(pid))
    except Exception as err:
        print_console("[x] an error occurred killing process: %s" % err, ERROR)
