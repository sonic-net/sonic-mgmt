#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Red Hat
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# STARTREMOVE (downstream)
DOCUMENTATION = r"""

module: openshift_adm_prune_deployments

short_description: Remove old completed and failed deployment configs

version_added: "2.2.0"

author:
  - Aubin Bikouo (@abikouo)

description:
  - This module allow administrators to remove old completed and failed deployment configs.
  - Analogous to C(oc adm prune deployments).

extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options

options:
  namespace:
    description:
    - Use to specify namespace for deployments to be deleted.
    type: str
  keep_younger_than:
    description:
    - Specify the minimum age (in minutes) of a deployment for it to be considered a candidate for pruning.
    type: int
  orphans:
    description:
    - If C(true), prune all deployments where the associated DeploymentConfig no longer exists,
      the status is complete or failed, and the replica size is C(0).
    type: bool
    default: False

requirements:
  - python >= 3.6
  - kubernetes >= 12.0.0
"""

EXAMPLES = r"""
- name: Prune Deployments from testing namespace
  community.okd.openshift_adm_prune_deployments:
    namespace: testing

- name: Prune orphans deployments, keep younger than 2hours
  community.okd.openshift_adm_prune_deployments:
    orphans: true
    keep_younger_than: 120
"""


RETURN = r"""
replication_controllers:
  type: list
  description: list of replication controllers candidate for pruning.
  returned: always
"""
# ENDREMOVE (downstream)

import copy

try:
    from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
        AUTH_ARG_SPEC,
    )
except ImportError as e:
    pass


def argument_spec():
    args = copy.deepcopy(AUTH_ARG_SPEC)
    args.update(
        dict(
            namespace=dict(
                type="str",
            ),
            keep_younger_than=dict(
                type="int",
            ),
            orphans=dict(type="bool", default=False),
        )
    )
    return args


def main():
    from ansible_collections.community.okd.plugins.module_utils.openshift_adm_prune_deployments import (
        OpenShiftAdmPruneDeployment,
    )

    module = OpenShiftAdmPruneDeployment(
        argument_spec=argument_spec(), supports_check_mode=True
    )
    module.run_module()


if __name__ == "__main__":
    main()
