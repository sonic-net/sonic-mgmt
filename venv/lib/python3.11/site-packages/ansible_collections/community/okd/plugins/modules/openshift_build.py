#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Red Hat
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# STARTREMOVE (downstream)
DOCUMENTATION = r"""

module: openshift_build

short_description: Start a new build or Cancel running, pending, or new builds.

version_added: "2.3.0"

author:
  - Aubin Bikouo (@abikouo)

description:
  - This module starts a new build from the provided build config or build name.
  - This module also cancel a new, pending or running build by requesting a graceful shutdown of the build.
    There may be a delay between requesting the build and the time the build is terminated.
  - This can also restart a new build when the current is cancelled.
  - Analogous to C(oc cancel-build) and C(oc start-build).

extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options

options:
  state:
    description:
      - Determines if a Build should be started ,cancelled or restarted.
      - When set to C(restarted) a new build will be created after the current build is cancelled.
    choices:
      - started
      - cancelled
      - restarted
    default: started
    type: str
  build_name:
    description:
    - Specify the name of a build which should be re-run.
    - Mutually exclusive with parameter I(build_config_name).
    type: str
  build_config_name:
    description:
    - Specify the name of a build config from which a new build will be run.
    - Mutually exclusive with parameter I(build_name).
    type: str
  namespace:
    description:
    - Specify the namespace for the build or the build config.
    type: str
    required: True
  build_args:
    description:
    - Specify a list of key-value pair to pass to Docker during the build.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - docker build argument name.
        type: str
        required: true
      value:
        description:
          - docker build argument value.
        type: str
        required: true
  commit:
    description:
    - Specify the source code commit identifier the build should use;
      requires a build based on a Git repository.
    type: str
  env_vars:
    description:
    - Specify a list of key-value pair for an environment variable to set for the build container.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Environment variable name.
        type: str
        required: true
      value:
        description:
          - Environment variable value.
        type: str
        required: true
  incremental:
    description:
    - Overrides the incremental setting in a source-strategy build, ignored if not specified.
    type: bool
  no_cache:
    description:
    - Overrides the noCache setting in a docker-strategy build, ignored if not specified.
    type: bool
  wait:
    description:
    - When C(state=started), specify whether to wait for a build to complete
      and exit with a non-zero return code if the build fails.
    - When I(state=cancelled), specify whether to wait for a build phase to be Cancelled.
    default: False
    type: bool
  wait_sleep:
    description:
    - Number of seconds to sleep between checks.
    - Ignored if C(wait=false).
    default: 5
    type: int
  wait_timeout:
    description:
    - How long in seconds to wait for a build to complete.
    - Ignored if C(wait=false).
    default: 120
    type: int
  build_phases:
    description:
    - List of state for build to cancel.
    - Ignored when C(state=started).
    type: list
    elements: str
    choices:
      - New
      - Pending
      - Running
    default: []

requirements:
  - python >= 3.6
  - kubernetes >= 12.0.0
"""

EXAMPLES = r"""
# Starts build from build config default/hello-world
- name: Starts build from build config
  community.okd.openshift_build:
    namespace: default
    build_config_name: hello-world

# Starts build from a previous build "default/hello-world-1"
- name: Starts build from a previous build
  community.okd.openshift_build:
    namespace: default
    build_name: hello-world-1

# Cancel the build with the given name
- name: Cancel build from default namespace
  community.okd.openshift_build:
    namespace: "default"
    build_name: ruby-build-1
    state: cancelled

# Cancel the named build and create a new one with the same parameters
- name: Cancel build from default namespace and create a new one
  community.okd.openshift_build:
    namespace: "default"
    build_name: ruby-build-1
    state: restarted

# Cancel all builds created from 'ruby-build' build configuration that are in 'new' state
- name: Cancel build from default namespace and create a new one
  community.okd.openshift_build:
    namespace: "default"
    build_config_name: ruby-build
    build_phases:
      - New
    state: cancelled
"""

RETURN = r"""
builds:
  description:
  - The builds that were started/cancelled.
  returned: success
  type: complex
  contains:
    api_version:
      description: The versioned schema of this representation of an object.
      returned: success
      type: str
    kind:
      description: Represents the REST resource this object represents.
      returned: success
      type: str
    metadata:
      description: Standard object metadata. Includes name, namespace, annotations, labels, etc.
      returned: success
      type: dict
    spec:
      description: Specific attributes of the build.
      returned: success
      type: dict
    status:
      description: Current status details for the object.
      returned: success
      type: dict
"""
# ENDREMOVE (downstream)

import copy

from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
    AUTH_ARG_SPEC,
)


def argument_spec():
    args = copy.deepcopy(AUTH_ARG_SPEC)

    args_options = dict(
        name=dict(type="str", required=True), value=dict(type="str", required=True)
    )

    args.update(
        dict(
            state=dict(
                type="str",
                choices=["started", "cancelled", "restarted"],
                default="started",
            ),
            build_args=dict(type="list", elements="dict", options=args_options),
            commit=dict(type="str"),
            env_vars=dict(type="list", elements="dict", options=args_options),
            build_name=dict(type="str"),
            build_config_name=dict(type="str"),
            namespace=dict(type="str", required=True),
            incremental=dict(type="bool"),
            no_cache=dict(type="bool"),
            wait=dict(type="bool", default=False),
            wait_sleep=dict(type="int", default=5),
            wait_timeout=dict(type="int", default=120),
            build_phases=dict(
                type="list",
                elements="str",
                default=[],
                choices=["New", "Pending", "Running"],
            ),
        )
    )
    return args


def main():
    mutually_exclusive = [
        ("build_name", "build_config_name"),
    ]
    from ansible_collections.community.okd.plugins.module_utils.openshift_builds import (
        OpenShiftBuilds,
    )

    module = OpenShiftBuilds(
        argument_spec=argument_spec(),
        mutually_exclusive=mutually_exclusive,
        required_one_of=[
            [
                "build_name",
                "build_config_name",
            ]
        ],
    )
    module.run_module()


if __name__ == "__main__":
    main()
