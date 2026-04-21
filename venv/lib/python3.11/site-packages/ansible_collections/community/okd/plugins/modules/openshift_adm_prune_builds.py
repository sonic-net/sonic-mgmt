#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Red Hat
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# STARTREMOVE (downstream)
DOCUMENTATION = r"""

module: openshift_adm_prune_builds

short_description: Prune old completed and failed builds

version_added: "2.3.0"

author:
  - Aubin Bikouo (@abikouo)

description:
  - This module allow administrators to delete old completed and failed builds.
  - Analogous to C(oc adm prune builds).

extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options

options:
  namespace:
    description:
    - Use to specify namespace for builds to be deleted.
    type: str
  keep_younger_than:
    description:
    - Specify the minimum age (in minutes) of a Build for it to be considered a candidate for pruning.
    type: int
  orphans:
    description:
    - If C(true), prune all builds whose associated BuildConfig no longer exists and whose status is
      complete, failed, error, or cancelled.
    type: bool
    default: False

requirements:
  - python >= 3.6
  - kubernetes >= 12.0.0
"""

EXAMPLES = r"""
# Run deleting older completed and failed builds and also including
# all builds whose associated BuildConfig no longer exists
- name: Run delete orphan Builds
  community.okd.openshift_adm_prune_builds:
    orphans: true

# Run deleting older completed and failed builds keep younger than 2hours
- name: Run delete builds, keep younger than 2h
  community.okd.openshift_adm_prune_builds:
    keep_younger_than: 120

# Run deleting builds from specific namespace
- name: Run delete builds from namespace
  community.okd.openshift_adm_prune_builds:
    namespace: testing_namespace
"""

RETURN = r"""
builds:
  description:
  - The builds that were deleted
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
      description: Specific attributes of the object. Will vary based on the I(api_version) and I(kind).
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
    args.update(
        dict(
            namespace=dict(type="str"),
            keep_younger_than=dict(type="int"),
            orphans=dict(type="bool", default=False),
        )
    )
    return args


def main():
    from ansible_collections.community.okd.plugins.module_utils.openshift_builds import (
        OpenShiftPruneBuilds,
    )

    module = OpenShiftPruneBuilds(
        argument_spec=argument_spec(), supports_check_mode=True
    )
    module.run_module()


if __name__ == "__main__":
    main()
