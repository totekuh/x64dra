# -*- coding: utf-8 -*-

version = "1.0.0"

from setuptools import setup, find_packages

setup(
    name="x64dra",
    version=version,
    description='Bridge and sync tool for Ghidra and x64dbg/x32dbg using GhidraBridge and x64dbg-python API.',
    long_description_content_type='text/markdown',
    author="totekuh",
    author_email="totekuh@protonmail.com",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    entry_points={
        "console_scripts": [
            "x64dra=x64dra.x64dbg_api:main",
        ],
    },
    url='https://github.com/totekuh/x64dra',  # Optional
    install_requires=[
        "ghidra-bridge==1.0.0",
        "x32dbg==1.1.0",
        "x64dbg==1.1.0"
    ],
    project_urls={  # Optional
        'Bug Reports': 'https://github.com/totekuh/x64dra/issues',
        'Source': 'https://github.com/totekuh/x64dra',
    },

)