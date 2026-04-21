# -----------------------------------------------------------------------------
# Copyright 2015-2025 by PyCLibrary Authors, see AUTHORS for more details.
#
# Distributed under the terms of the MIT/X11 license.
#
# The full license is in the file LICENCE, distributed with this software.
# -----------------------------------------------------------------------------
"""Errors that can happen during parsing or binding."""


class PyCLibError(Exception):
    """Base exception for all PyCLibrary exceptions."""

    pass


class DefinitionError(PyCLibError):
    """Excepion signaling that one definition found in the header is malformed
    or meaningless.

    """

    pass
