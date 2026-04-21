# -*- coding: utf-8 -*-

# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    # Docker doc fragment
    DOCUMENTATION = r"""
options:
  project_src:
    description:
      - Path to a directory containing a Compose file (C(compose.yml), C(compose.yaml), C(docker-compose.yml), or C(docker-compose.yaml)).
      - If O(files) is provided, will look for these files in this directory instead.
      - Mutually exclusive with O(definition). One of O(project_src) and O(definition) must be provided.
    type: path
  project_name:
    description:
      - Provide a project name. If not provided, the project name is taken from the basename of O(project_src).
      - Required when O(definition) is provided.
    type: str
  files:
    description:
      - List of Compose file names relative to O(project_src) to be used instead of the main Compose file (C(compose.yml),
        C(compose.yaml), C(docker-compose.yml), or C(docker-compose.yaml)).
      - Files are loaded and merged in the order given.
      - Mutually exclusive with O(definition).
    type: list
    elements: path
    version_added: 3.7.0
  definition:
    description:
      - Compose file describing one or more services, networks and volumes.
      - Mutually exclusive with O(project_src) and O(files). One of O(project_src) and O(definition) must be provided.
      - If provided, PyYAML must be available to this module, and O(project_name) must be specified.
      - Note that a temporary directory will be created and deleted afterwards when using this option.
    type: dict
    version_added: 3.9.0
  env_files:
    description:
      - By default environment files are loaded from a C(.env) file located directly under the O(project_src) directory.
      - O(env_files) can be used to specify the path of one or multiple custom environment files instead.
      - The path is relative to the O(project_src) directory.
    type: list
    elements: path
  profiles:
    description:
      - List of profiles to enable when starting services.
      - Equivalent to C(docker compose --profile).
    type: list
    elements: str
  check_files_existing:
    description:
      - If set to V(false), the module will not check whether one of the files C(compose.yaml), C(compose.yml), C(docker-compose.yaml),
        or C(docker-compose.yml) exists in O(project_src) if O(files) is not provided.
      - This can be useful if environment files with C(COMPOSE_FILE) are used to configure a different filename. The module
        currently does not check for C(COMPOSE_FILE) in environment files or the current environment.
    type: bool
    default: true
    version_added: 3.9.0
requirements:
  - "PyYAML if O(definition) is used"
notes:
  - |-
    The Docker compose CLI plugin has no stable output format (see for example U(https://github.com/docker/compose/issues/10872)),
    and for the main operations also no machine friendly output format. The module tries to accomodate this with various
    version-dependent behavior adjustments and with testing older and newer versions of the Docker compose CLI plugin.
    Currently the module is tested with multiple plugin versions between 2.18.1 and 2.23.3. The exact list of plugin versions
    will change over time. New releases of the Docker compose CLI plugin can break this module at any time.
"""

    # The following needs to be kept in sync with the compose_v2 module utils
    MINIMUM_VERSION = r'''
options: {}
requirements:
  - "Docker CLI with Docker compose plugin 2.18.0 or later"
'''
