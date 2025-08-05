# Author : Murphy
# LICENSE: GPL v3
# Copyright (C) 2025 Murphy <me@0xmurphy.me>
# -*- coding: utf-8 -*-

from setuptools import setup

setup(
    setup_requires=["pbr"],
    pbr=True,
    package_files=[("agent", ["r2flutch/agent/plugin.ts"])]
)
