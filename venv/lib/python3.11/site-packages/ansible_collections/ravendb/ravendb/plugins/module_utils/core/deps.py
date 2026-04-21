# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import traceback
import importlib

HAS_RAVEN = True
RAVEN_IMP_ERR = None

try:
    importlib.import_module("ravendb")
except Exception:
    HAS_RAVEN = False
    RAVEN_IMP_ERR = traceback.format_exc()


def require_ravendb():
    if not HAS_RAVEN:
        msg = (
            "The 'ravendb' Python client is required. "
            "Install it via the ravendb_python_client_prerequisites role.\n"
        )
        if RAVEN_IMP_ERR:
            msg += "Original import error:\n" + str(RAVEN_IMP_ERR)
        raise ImportError(msg)
