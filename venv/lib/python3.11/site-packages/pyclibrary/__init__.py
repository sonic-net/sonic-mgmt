# -----------------------------------------------------------------------------
# Copyright 2015-2025 by PyCLibrary Authors, see AUTHORS for more details.
#
# Distributed under the terms of the MIT/X11 license.
#
# The full license is in the file LICENCE, distributed with this software.
# -----------------------------------------------------------------------------
import logging

from .c_library import CLibrary, build_array, cast_to
from .c_parser import CParser, win_defs
from .errors import DefinitionError
from .init import auto_init, init

logging.getLogger("pyclibrary").addHandler(logging.NullHandler())

__all__ = (
    "CLibrary",
    "CParser",
    "DefinitionError",
    "auto_init",
    "build_array",
    "cast_to",
    "init",
    "win_defs",
)
