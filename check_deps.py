#!/usr/bin/env python3
"""Check Python dependencies for APKStudioAI"""
import sys

pkgs = [
    'requests', 'bs4', 'lxml', 'elftools', 'capstone',
    'tkinter', 'json', 'hashlib', 'pathlib', 'datetime',
    'threading', 'subprocess', 'tempfile', 'shutil', 'zipfile',
    'xml.etree.ElementTree', 're', 'base64', 'binascii',
    'androguard', 'apkid', 'networkx', 'jsonschema', 'structlog'
]

missing = []
for p in pkgs:
    try:
        __import__(p)
        print('  [OK] ' + p)
    except ImportError:
        print('  [MISSING] ' + p)
        missing.append(p)

if missing:
    print('Missing packages: ' + str(missing))
    sys.exit(1)
else:
    print('[OK] All required packages available')