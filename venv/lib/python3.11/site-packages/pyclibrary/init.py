# -----------------------------------------------------------------------------
# Copyright 2015-2025 by PyCLibrary Authors, see AUTHORS for more details.
#
# Distributed under the terms of the MIT/X11 license.
#
# The full license is in the file LICENCE, distributed with this software.
# -----------------------------------------------------------------------------
"""Initialisation routines.

Those should be run before creating a CParser and can be run only once. They
are used to declare additional types and modifiers for the parser.

"""

import sys

from .backends import init_libraries
from .c_library import CLibrary
from .c_parser import CParser, _init_cparser


def init(extra_types=None, extra_modifiers=None):
    """Init CParser and CLibrary classes.

    Parameters
    ----------
    extra_types : dict, optional
        typeName->c_type pairs to extend typespace.
    extra_modifiers : list, optional
        List of modifiers, such as '__stdcall'.

    """
    if CParser._init or CLibrary._init:
        raise RuntimeError("Can only initialise the parser once")

    extra_types = extra_types if extra_types else {}
    extra_modifiers = extra_modifiers if extra_modifiers else []

    _init_cparser(extra_types.keys(), extra_modifiers)
    init_libraries(extra_types)

    CParser._init = True
    CLibrary._init = True


WIN_TYPES = {"__int64": None}
WIN_MODIFIERS = [
    "__based",
    "__declspec",
    "__fastcall",
    "__restrict",
    "__sptr",
    "__uptr",
    "__w64",
    "__unaligned",
    "__nullterminated",
]


def auto_init(extra_types=None, extra_modifiers=None, os=None):
    """Init CParser and CLibrary classes based on the targeted OS.

    Parameters
    ----------
    extra_types : dict, optional
        Extra typeName->c_type pairs to extend typespace.
    extra_modifiers : list, optional
        List of extra modifiers, such as '__stdcall'.
    os : {'win32', 'linux2', 'darwin'}, optional
        OS for which to prepare the system. If not specified sys is used to
        identify the OS.

    """
    extra_types = extra_types if extra_types else {}
    extra_modifiers = extra_modifiers if extra_modifiers else []

    if os == "win32" or sys.platform == "win32":
        extra_types.update(WIN_TYPES)
        extra_modifiers += WIN_MODIFIERS

    init(extra_types, extra_modifiers)
