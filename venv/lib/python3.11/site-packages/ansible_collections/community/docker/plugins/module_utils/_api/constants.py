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

import sys

MINIMUM_DOCKER_API_VERSION = '1.21'
DEFAULT_TIMEOUT_SECONDS = 60
STREAM_HEADER_SIZE_BYTES = 8
CONTAINER_LIMITS_KEYS = [
    'memory', 'memswap', 'cpushares', 'cpusetcpus'
]

DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_UNIX_SOCKET = "http+unix:///var/run/docker.sock"
DEFAULT_NPIPE = 'npipe:////./pipe/docker_engine'

BYTE_UNITS = {
    'b': 1,
    'k': 1024,
    'm': 1024 * 1024,
    'g': 1024 * 1024 * 1024
}

IS_WINDOWS_PLATFORM = (sys.platform == 'win32')
WINDOWS_LONGPATH_PREFIX = '\\\\?\\'

DEFAULT_USER_AGENT = "ansible-community.docker"
DEFAULT_NUM_POOLS = 25

# The OpenSSH server default value for MaxSessions is 10 which means we can
# use up to 9, leaving the final session for the underlying SSH connection.
# For more details see: https://github.com/docker/docker-py/issues/2246
DEFAULT_NUM_POOLS_SSH = 9

DEFAULT_MAX_POOL_SIZE = 10

DEFAULT_DATA_CHUNK_SIZE = 1024 * 2048
