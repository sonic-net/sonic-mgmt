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

import json
import logging
import os

from ..constants import IS_WINDOWS_PLATFORM

DOCKER_CONFIG_FILENAME = os.path.join('.docker', 'config.json')
LEGACY_DOCKER_CONFIG_FILENAME = '.dockercfg'

log = logging.getLogger(__name__)


def get_default_config_file():
    return os.path.join(home_dir(), DOCKER_CONFIG_FILENAME)


def find_config_file(config_path=None):
    homedir = home_dir()
    paths = list(filter(None, [
        config_path,  # 1
        config_path_from_environment(),  # 2
        os.path.join(homedir, DOCKER_CONFIG_FILENAME),  # 3
        os.path.join(homedir, LEGACY_DOCKER_CONFIG_FILENAME),  # 4
    ]))

    log.debug("Trying paths: %s", repr(paths))

    for path in paths:
        if os.path.exists(path):
            log.debug("Found file at path: %s", path)
            return path

    log.debug("No config file found")

    return None


def config_path_from_environment():
    config_dir = os.environ.get('DOCKER_CONFIG')
    if not config_dir:
        return None
    return os.path.join(config_dir, os.path.basename(DOCKER_CONFIG_FILENAME))


def home_dir():
    """
    Get the user's home directory, using the same logic as the Docker Engine
    client - use %USERPROFILE% on Windows, $HOME/getuid on POSIX.
    """
    if IS_WINDOWS_PLATFORM:
        return os.environ.get('USERPROFILE', '')
    else:
        return os.path.expanduser('~')


def load_general_config(config_path=None):
    config_file = find_config_file(config_path)

    if not config_file:
        return {}

    try:
        with open(config_file) as f:
            return json.load(f)
    except (IOError, ValueError) as e:
        # In the case of a legacy `.dockercfg` file, we will not
        # be able to load any JSON data.
        log.debug(e)

    log.debug("All parsing attempts failed - returning empty config")
    return {}
