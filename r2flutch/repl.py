#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Murphy
# LICENSE: GPL v3
# Copyright (C) 2025 Murphy <me@0xmurphy.me>

from colorama import Fore, Style

# Global Vars
INFO = 0
SUCCESS = 1
ERROR = 2
DEBUG = 3
DEFAULT = 4


def print_console(msg, level=INFO, formatter=0):
    tabs, color = ["", ""]
    for _ in range(formatter):
        tabs += "    "
    
    if level == ERROR:
        msg = "[✗] ERROR - " + msg
        color = Fore.RED + Style.BRIGHT
    elif level == SUCCESS:
        msg = "[✓] SUCCESS - " + msg
        color = Fore.GREEN + Style.BRIGHT
    elif level == DEBUG:
        msg = "[🔍] DEBUG - " + msg
        color = Fore.CYAN
    elif level == INFO:
        msg = "[ℹ] " + msg
        color = Fore.LIGHTBLUE_EX
    elif level == DEFAULT:
        msg = msg
        color = Fore.WHITE
    
    print(color + tabs + msg + Style.RESET_ALL)
