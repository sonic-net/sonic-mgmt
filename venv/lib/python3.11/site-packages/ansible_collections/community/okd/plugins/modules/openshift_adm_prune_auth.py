#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Red Hat
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# STARTREMOVE (downstream)
DOCUMENTATION = r"""

module: openshift_adm_prune_auth

short_description: Removes references to the specified roles, clusterroles, users, and groups

version_added: "2.2.0"

author:
  - Aubin Bikouo (@abikouo)

description:
  - This module allow administrators to remove references to the specified roles, clusterroles, users, and groups.
  - Analogous to C(oc adm prune auth).

extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options

options:
  resource:
    description:
    - The specified resource to remove.
    choices:
    - roles
    - clusterroles
    - users
    - groups
    type: str
    required: True
  name:
    description:
    - Use to specify an object name to remove.
    - Mutually exclusive with option I(label_selectors).
    - If neither I(name) nor I(label_selectors) are specified, prune all resources in the namespace.
    type: str
  namespace:
    description:
    - Use to specify an object namespace.
    - Ignored when I(resource) is set to C(clusterroles).
    type: str
  label_selectors:
    description:
    - Selector (label query) to filter on.
    - Mutually exclusive with option I(name).
    type: list
    elements: str

requirements:
  - python >= 3.6
  - kubernetes >= 12.0.0
"""

EXAMPLES = r"""
- name: Prune all roles from default namespace
  openshift_adm_prune_auth:
    resource: roles
    namespace: testing

- name: Prune clusterroles using label selectors
  openshift_adm_prune_auth:
    resource: roles
    namespace: testing
    label_selectors:
      - phase=production
"""


RETURN = r"""
cluster_role_binding:
  type: list
  description: list of cluster role binding deleted.
  returned: always
role_binding:
  type: list
  description: list of role binding deleted.
  returned: I(resource=users) or I(resource=groups) or I(resource=clusterroles)
security_context_constraints:
  type: list
  description: list of Security Context Constraints deleted.
  returned: I(resource=users) or I(resource=groups)
authorization:
  type: list
  description: list of OAuthClientAuthorization deleted.
  returned: I(resource=users)
group:
  type: list
  description: list of Security Context Constraints deleted.
  returned: I(resource=users)
"""
# ENDREMOVE (downstream)

import copy

from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
    AUTH_ARG_SPEC,
)


def argument_spec():
    args = copy.deepcopy(AUTH_ARG_SPEC)
    args.update(
        dict(
            resource=dict(
                type="str",
                required=True,
                choices=["roles", "clusterroles", "users", "groups"],
            ),
            namespace=dict(type="str"),
            name=dict(type="str"),
            label_selectors=dict(type="list", elements="str"),
        )
    )
    return args


def main():
    from ansible_collections.community.okd.plugins.module_utils.openshift_adm_prune_auth import (
        OpenShiftAdmPruneAuth,
    )

    module = OpenShiftAdmPruneAuth(
        argument_spec=argument_spec(),
        mutually_exclusive=[("name", "label_selectors")],
        supports_check_mode=True,
    )
    module.run_module()


if __name__ == "__main__":
    main()
