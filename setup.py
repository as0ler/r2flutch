# -*- coding: utf-8 -*-

from setuptools import setup

setup(
    setup_requires=['pbr'],
    pbr=True,
    package_files=[('agent', ['r2flutch/agent/plugin.js'])]
)
