# -*- coding: utf-8 -*-
# This code is part of the Ansible collection community.docker, but is an independent component.
# This particular file, and this file only, is based on the Docker SDK for Python (https://github.com/docker/docker-py/)
#
# Copyright (c) 2016-2025 Docker, Inc.
#
# It is licensed under the Apache 2.0 license (see LICENSES/Apache-2.0.txt in this collection)
# SPDX-License-Identifier: Apache-2.0

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import hashlib
import json
import os

from ..constants import DEFAULT_UNIX_SOCKET, IS_WINDOWS_PLATFORM
from ..utils.config import find_config_file, get_default_config_file
from ..utils.utils import parse_host

METAFILE = "meta.json"


def get_current_context_name_with_source():
    if os.environ.get('DOCKER_HOST'):
        return "default", "DOCKER_HOST environment variable set"
    if os.environ.get('DOCKER_CONTEXT'):
        return os.environ['DOCKER_CONTEXT'], "DOCKER_CONTEXT environment variable set"
    docker_cfg_path = find_config_file()
    if docker_cfg_path:
        try:
            with open(docker_cfg_path) as f:
                return json.load(f).get("currentContext", "default"), "configuration file {file}".format(file=docker_cfg_path)
        except Exception:
            pass
    return "default", "fallback value"


def get_current_context_name():
    return get_current_context_name_with_source()[0]


def write_context_name_to_docker_config(name=None):
    if name == 'default':
        name = None
    docker_cfg_path = find_config_file()
    config = {}
    if docker_cfg_path:
        try:
            with open(docker_cfg_path) as f:
                config = json.load(f)
        except Exception as e:
            return e
    current_context = config.get("currentContext", None)
    if current_context and not name:
        del config["currentContext"]
    elif name:
        config["currentContext"] = name
    else:
        return
    if not docker_cfg_path:
        docker_cfg_path = get_default_config_file()
    try:
        with open(docker_cfg_path, "w") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        return e


def get_context_id(name):
    return hashlib.sha256(name.encode('utf-8')).hexdigest()


def get_context_dir():
    docker_cfg_path = find_config_file() or get_default_config_file()
    return os.path.join(os.path.dirname(docker_cfg_path), "contexts")


def get_meta_dir(name=None):
    meta_dir = os.path.join(get_context_dir(), "meta")
    if name:
        return os.path.join(meta_dir, get_context_id(name))
    return meta_dir


def get_meta_file(name):
    return os.path.join(get_meta_dir(name), METAFILE)


def get_tls_dir(name=None, endpoint=""):
    context_dir = get_context_dir()
    if name:
        return os.path.join(context_dir, "tls", get_context_id(name), endpoint)
    return os.path.join(context_dir, "tls")


def get_context_host(path=None, tls=False):
    host = parse_host(path, IS_WINDOWS_PLATFORM, tls)
    if host == DEFAULT_UNIX_SOCKET:
        # remove http+ from default docker socket url
        if host.startswith("http+"):
            host = host[5:]
    return host
