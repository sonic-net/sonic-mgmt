#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Alina Buzachis <@alinabuzachis>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
module: k8s_taint
short_description: Taint a node in a Kubernetes/OpenShift cluster
version_added: 2.3.0
author: Alina Buzachis (@alinabuzachis)
description:
    - Taint allows a node to refuse Pod to be scheduled unless that Pod has a matching toleration.
    - Untaint will remove taints from nodes as needed.
extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options
options:
    state:
        description:
            - Determines whether to add or remove taints.
        type: str
        default: present
        choices: [ present, absent ]
    name:
        description:
            - The name of the node.
        required: true
        type: str
    taints:
        description:
            - List containing the taints.
        type: list
        required: true
        elements: dict
        suboptions:
            key:
                description:
                    - The taint key to be applied to a node.
                type: str
            value:
                description:
                    - The taint value corresponding to the taint key.
                type: str
            effect:
                description:
                    - The effect of the taint on Pods that do not tolerate the taint.
                    - Required when I(state=present).
                type: str
                choices: [ NoSchedule, NoExecute, PreferNoSchedule ]
    replace:
        description:
            - If C(true), allow taints to be replaced.
        required: false
        default: false
        type: bool
requirements:
  - python >= 3.9
  - kubernetes >= 24.2.0
"""

EXAMPLES = r"""
- name: Taint node "foo"
  kubernetes.core.k8s_taint:
    state: present
    name: foo
    taints:
    - effect: NoExecute
      key: "key1"

- name: Taint node "foo"
  kubernetes.core.k8s_taint:
    state: present
    name: foo
    taints:
    - effect: NoExecute
      key: "key1"
      value: "value1"
    - effect: NoSchedule
      key: "key1"
      value: "value1"

- name: Remove taint from "foo".
  kubernetes.core.k8s_taint:
    state: absent
    name: foo
    taints:
    - effect: NoExecute
      key: "key1"
      value: "value1"
"""

RETURN = r"""
result:
    description:
        - The tainted Node object. Will be empty in the case of a deletion.
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
            type: complex
        spec:
            description: Specific attributes of the object. Will vary based on the I(api_version) and I(kind).
            returned: success
            type: complex
        status:
            description: Current status details for the object.
            returned: success
            type: complex
"""

import copy

from ansible.module_utils._text import to_native
from ansible_collections.kubernetes.core.plugins.module_utils.ansiblemodule import (
    AnsibleModule,
)
from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
    AUTH_ARG_SPEC,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.client import (
    get_api_client,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.core import (
    AnsibleK8SModule,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.exceptions import (
    CoreException,
)

try:
    from kubernetes.client.api import core_v1_api
    from kubernetes.client.exceptions import ApiException
except ImportError:
    # ImportErrors are handled during module setup
    pass


def _equal_dicts(a, b):
    keys = ["key", "effect"]
    if "effect" not in set(a).intersection(b):
        keys.remove("effect")

    return all((a[x] == b[x] for x in keys))


def _get_difference(a, b):
    return [
        a_item for a_item in a if not any(_equal_dicts(a_item, b_item) for b_item in b)
    ]


def _get_intersection(a, b):
    return [a_item for a_item in a if any(_equal_dicts(a_item, b_item) for b_item in b)]


def _update_exists(a, b):
    return any(
        (
            any(
                _equal_dicts(a_item, b_item)
                and a_item.get("value") != b_item.get("value")
                for b_item in b
            )
            for a_item in a
        )
    )


def argspec():
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            state=dict(type="str", choices=["present", "absent"], default="present"),
            name=dict(type="str", required=True),
            taints=dict(type="list", required=True, elements="dict"),
            replace=dict(type="bool", default=False),
        )
    )

    return argument_spec


class K8sTaintAnsible:
    def __init__(self, module, client):
        self.module = module
        self.api_instance = core_v1_api.CoreV1Api(client.client)
        self.changed = False

    def get_node(self, name):
        try:
            node = self.api_instance.read_node(name=name)
        except ApiException as exc:
            if exc.reason == "Not Found":
                self.module.fail_json(msg="Node '{0}' has not been found.".format(name))
            self.module.fail_json(
                msg="Failed to retrieve node '{0}' due to: {1}".format(
                    name, exc.reason
                ),
                status=exc.status,
            )
        except Exception as exc:
            self.module.fail_json(
                msg="Failed to retrieve node '{0}' due to: {1}".format(
                    name, to_native(exc)
                )
            )

        return node

    def patch_node(self, taints):
        body = {"spec": {"taints": taints}}

        try:
            result = self.api_instance.patch_node(
                name=self.module.params.get("name"), body=body
            )
        except Exception as exc:
            self.module.fail_json(
                msg="Failed to patch node due to: {0}".format(to_native(exc))
            )

        return result.to_dict()

    def execute_module(self):
        result = {"result": {}}
        state = self.module.params.get("state")
        taints = self.module.params.get("taints")
        name = self.module.params.get("name")

        node = self.get_node(name)
        existing_taints = node.spec.to_dict().get("taints") or []
        diff = _get_difference(taints, existing_taints)

        if state == "present":
            if diff:
                # There are new taints to be added
                self.changed = True
                if self.module.check_mode:
                    self.module.exit_json(changed=self.changed, **result)

                if self.module.params.get("replace"):
                    # Patch with the new taints
                    result["result"] = self.patch_node(taints=taints)
                    self.module.exit_json(changed=self.changed, **result)

                result["result"] = self.patch_node(
                    taints=[*_get_difference(existing_taints, taints), *taints]
                )
            else:
                # No new taints to be added, but maybe there is something to be updated
                if _update_exists(existing_taints, taints):
                    self.changed = True
                    if self.module.check_mode:
                        self.module.exit_json(changed=self.changed, **result)
                    result["result"] = self.patch_node(
                        taints=[*_get_difference(existing_taints, taints), *taints]
                    )
                else:
                    result["result"] = node.to_dict()
        elif state == "absent":
            # Nothing to be removed
            if not existing_taints:
                result["result"] = node.to_dict()
            if not diff:
                self.changed = True
                if self.module.check_mode:
                    self.module.exit_json(changed=self.changed, **result)
                self.patch_node(taints=_get_difference(existing_taints, taints))
            else:
                if _get_intersection(existing_taints, taints):
                    self.changed = True
                    if self.module.check_mode:
                        self.module.exit_json(changed=self.changed, **result)
                    self.patch_node(taints=_get_difference(existing_taints, taints))
                else:
                    self.module.exit_json(changed=self.changed, **result)

        self.module.exit_json(changed=self.changed, **result)


def main():
    module = AnsibleK8SModule(
        module_class=AnsibleModule,
        argument_spec=argspec(),
        supports_check_mode=True,
    )
    try:
        client = get_api_client(module)
        k8s_taint = K8sTaintAnsible(module, client.client)
        k8s_taint.execute_module()
    except CoreException as e:
        module.fail_from_exception(e)


if __name__ == "__main__":
    main()
