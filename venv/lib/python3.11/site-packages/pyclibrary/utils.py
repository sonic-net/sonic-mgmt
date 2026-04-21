# -----------------------------------------------------------------------------
# Copyright 2015-2025 by PyCLibrary Authors, see AUTHORS for more details.
#
# Distributed under the terms of the MIT/X11 license.
#
# The full license is in the file LICENCE, distributed with this software.
# -----------------------------------------------------------------------------
"""Utility functions to retrieve headers or library path and architecture.

Most of those function have been taken or adapted from the ones found in
PyVISA.

Functions
---------
find_header : Find the path to a header file.
find_library : Find the path to a shared library from its name.

"""

import io
import logging
import os
import struct
import subprocess
import sys

from .thirdparty.find_library import find_library as find_lib

logger = logging.getLogger(__name__)


HEADER_DIRS = [os.path.join(os.path.dirname(__file__), "headers")]


def add_header_locations(dir_list):
    """Add directories in which to look for header files."""
    dirs = [d for d in dir_list if os.path.isdir(d)]
    rejected = [d for d in dir_list if d not in dirs]
    if rejected:
        msg = "The following directories are invalid: {}"
        logging.warning(msg.format(rejected))
    HEADER_DIRS.extend(dirs)


def find_header(h_name, dirs=None):
    """Look for a header file.

    Headers are looked for in the directories specified by the user using the
    add_header_locations function, in the headers directory of PyCLibrary, and
    in the standards locations according to the operation system.

    Parameters
    ----------
    h_name : unicode
        Name of the header to retrieve (should include the ".h")
    dirs : list, optional
        List of directory which should be searched for the header in addition
        to the default ones.

    Returns
    -------
    path : unicode
        Path to the header file.

    Raises
    ------
    OSError : if no matching file can be found.

    """
    if dirs:
        dirs += HEADER_DIRS[::-1]
    else:
        dirs = HEADER_DIRS[::-1]

    if sys.platform == "win32":
        pass

    if sys.platform == "darwin":
        dirs.extend(
            (
                "/usr/local/include",
                "/usr/include",
                "/System/Library/Frameworks",
                "/Library/Frameworks",
            )
        )

    if sys.platform == "linux2":
        dirs.extend(("/usr/local/include", "/usr/target/include", "/usr/include"))

    for d in dirs:
        path = os.path.join(d, h_name)
        if os.path.isfile(path):
            return path

    raise OSError("Can't find header with h_name {}".format(h_name))


LIBRARY_DIRS = []


def add_library_locations(dir_list):
    """Add directories in which to look for libraries."""
    dirs = [d for d in dir_list if os.path.isdir(d)]
    rejected = [d for d in dir_list if d not in dirs]
    if rejected:
        msg = "The following directories are invalid: {}"
        logging.warning(msg.format(rejected))
    LIBRARY_DIRS.extend(dirs)


def find_library(name, dirs=None):
    """Look for a library file.

    Libraries are looked for in the directories specified by the user using the
    add_library_locations function, and using the find_library function found
    the thirdparty package.

    Parameters
    ----------
    name : unicode
        Name of the library to retrieve (should include the extension)
    dirs : list, optional
        List of directory which should be searched for the library before
        ressorting to using thirdparty.find_library.

    Returns
    -------
    path : unicode
        Path to the library file.

    Raises
    ------
    OSError : if no matching file can be found.

    """
    if dirs:
        dirs += LIBRARY_DIRS[::-1]
    else:
        dirs = LIBRARY_DIRS[::-1]

    for d in dirs:
        path = os.path.join(d, name)
        if os.path.isfile(path):
            return LibraryPath(path)

    path = find_lib(name)
    if path:
        return LibraryPath(path)

    raise OSError("Can't find library with name {}".format(name))


# --- Private API -------------------------------------------------------------


class LibraryPath(str):
    #: Architectural information (32, ) or (64, ) or (32, 64)
    _arch = None

    def __new__(cls, path, found_by="auto"):
        obj = super(LibraryPath, cls).__new__(cls, path)
        obj.path = path
        obj.found_by = found_by

        return obj

    @property
    def arch(self):
        if self._arch is None:
            try:
                self._arch = get_arch(self.path)
            except Exception:
                self._arch = ()

        return self._arch

    @property
    def is_32bit(self):
        if not self.arch:
            return "n/a"
        return 32 in self.arch

    @property
    def is_64bit(self):
        if not self.arch:
            return "n/a"
        return 64 in self.arch

    @property
    def bitness(self):
        if not self.arch:
            return "n/a"
        return ", ".join(str(a) for a in self.arch)


def get_arch(filename):
    this_platform = sys.platform
    if this_platform.startswith("win"):
        machine_type = get_shared_library_arch(filename)
        if machine_type == "I386":
            return (32,)
        elif machine_type in ("IA64", "AMD64"):
            return (64,)
        else:
            return ()
    elif this_platform not in ("linux2", "linux3", "linux", "darwin"):
        raise OSError("")

    out = check_output(["file", filename], stderr=subprocess.STDOUT)
    out = out.decode("ascii")
    ret = []
    if this_platform.startswith("linux"):
        if "32-bit" in out:
            ret.append(32)
        if "64-bit" in out:
            ret.append(64)
    elif this_platform == "darwin":
        if "(for architecture i386)" in out:
            ret.append(32)
        if "(for architecture x86_64)" in out:
            ret.append(64)

    return tuple(ret)


machine_types = {
    0: "UNKNOWN",
    0x014C: "I386",
    0x0162: "R3000",
    0x0166: "R4000",
    0x0168: "R10000",
    0x0169: "WCEMIPSV2",
    0x0184: "ALPHA",
    0x01A2: "SH3",
    0x01A3: "SH3DSP",
    0x01A4: "SH3E",
    0x01A6: "SH4",
    0x01A8: "SH5",
    0x01C0: "ARM",
    0x01C2: "THUMB",
    0x01C4: "ARMNT",
    0x01D3: "AM33",
    0x01F0: "POWERPC",
    0x01F1: "POWERPCFP",
    0x0200: "IA64",
    0x0266: "MIPS16",
    0x0284: "ALPHA64",
    0x0366: "MIPSFPU",
    0x0466: "MIPSFPU16",
    0x0520: "TRICORE",
    0x0CEF: "CEF",
    0x0EBC: "EBC",
    0x8664: "AMD64",
    0x9041: "M32R",
    0xC0EE: "CEE",
}


def get_shared_library_arch(filename):
    with io.open(filename, "rb") as fp:
        dos_headers = fp.read(64)
        fp.read(4)

        magic, skip, offset = struct.unpack(str("2s58sl"), dos_headers)

        if magic != b"MZ":
            raise Exception("Not an executable")

        fp.seek(offset, io.SEEK_SET)
        pe_header = fp.read(6)

        sig, skip, machine = struct.unpack(str("2s2sH"), pe_header)

        if sig != b"PE":
            raise Exception("Not a PE executable")

        return machine_types.get(machine, "UNKNOWN")


def check_output(*popenargs, **kwargs):
    """Run command with arguments and return its output as a byte string.

    Backported from Python 2.7 as it's implemented as pure python on stdlib.

    >>> check_output(['/usr/bin/python', '--version'])
    Python 2.6.2
    """
    process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
    output, unused_err = process.communicate()
    retcode = process.poll()
    if retcode:
        cmd = kwargs.get("args")
        if cmd is None:
            cmd = popenargs[0]
        error = subprocess.CalledProcessError(retcode, cmd)
        error.output = output
        raise error
    return output
