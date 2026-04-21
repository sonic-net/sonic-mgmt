# -----------------------------------------------------------------------------
# Copyright 2015-2025 by PyCLibrary Authors, see AUTHORS for more details.
#
# Distributed under the terms of the MIT/X11 license.
#
# The full license is in the file LICENCE, distributed with this software.
# -----------------------------------------------------------------------------
"""
Windows headers are not included in this distribution due to possible
copyright issues. Thus there is the cache file 'WinDefs.cache' here
which encapsulate definitions pulled from several headers included
in Visual Studio

This script updates the WinDefs.cache file.
It has to be run on one of the following conditions:
* another Visual C/C++ compiler version is used
* the object model of the parser was updated.
"""

from pyclibrary.c_parser import win_defs
from pyclibrary.utils import add_header_locations

SDK_DIR = r"c:\program files\microsoft sdks\windows\v6.0a\include"

if __name__ == "__main__":
    print("parsing windows definitions (may take some while)")
    add_header_locations([SDK_DIR])
    parser = win_defs()
    print("parsed:")
    for objcls in ["variables", "functions", "types", "macros", "fnmacros"]:
        print("   ", len(parser.defs[objcls]), objcls)
