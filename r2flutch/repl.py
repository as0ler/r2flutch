#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Murphy
# LICENSE: GPL v3

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
        msg = "[x] ERROR - " + msg
        color = Fore.RED
    elif level == SUCCESS:
        msg = "[*] SUCCESS - " + msg
        color = Fore.YELLOW
    elif level == DEBUG:
        msg = "[DEBUG] - " + msg
        color = Fore.BLUE
    elif level == INFO:
        msg = "[+] " + msg
    print(color + tabs + msg + Style.RESET_ALL)
