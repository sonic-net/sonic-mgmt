# -*- coding: utf-8 -*-
# This code is part of the Ansible collection community.docker, but is an independent component.
# This particular file, and this file only, is based on the Docker SDK for Python (https://github.com/docker/docker-py/)
#
# Copyright (c) 2016-2022 Docker, Inc.
#
# It is licensed under the Apache 2.0 license (see LICENSES/Apache-2.0.txt in this collection)
# SPDX-License-Identifier: Apache-2.0

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import sys

from ansible_collections.community.docker.plugins.module_utils._six import PY2

if PY2:
    from distutils.spawn import find_executable as which
else:
    from shutil import which


def find_executable(executable, path=None):
    """
    As distutils.spawn.find_executable, but on Windows, look up
    every extension declared in PATHEXT instead of just `.exe`
    """
    if not PY2:
        # shutil.which() already uses PATHEXT on Windows, so on
        # Python 3 we can simply use shutil.which() in all cases.
        # (https://github.com/docker/docker-py/commit/42789818bed5d86b487a030e2e60b02bf0cfa284)
        return which(executable, path=path)

    if sys.platform != 'win32':
        return which(executable, path)

    if path is None:
        path = os.environ['PATH']

    paths = path.split(os.pathsep)
    extensions = os.environ.get('PATHEXT', '.exe').split(os.pathsep)
    base, ext = os.path.splitext(executable)

    if not os.path.isfile(executable):
        for p in paths:
            for ext in extensions:
                f = os.path.join(p, base + ext)
                if os.path.isfile(f):
                    return f
        return None
    else:
        return executable


def create_environment_dict(overrides):
    """
    Create and return a copy of os.environ with the specified overrides
    """
    result = os.environ.copy()
    result.update(overrides or {})
    return result
