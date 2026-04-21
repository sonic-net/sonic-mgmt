#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, Will Thames <@willthames>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
module: k8s_info

short_description: Describe Kubernetes (K8s) objects

author:
    - "Will Thames (@willthames)"

description:
  - Use the Kubernetes Python client to perform read operations on K8s objects.
  - Access to the full range of K8s APIs.
  - Authenticate using either a config file, certificates, password or token.
  - Supports check mode.
  - This module was called C(k8s_facts) before Ansible 2.9. The usage did not change.

options:
  kind:
    description:
    - Use to specify an object model.
    - Use to create, delete, or discover an object without providing a full resource definition.
    - Use in conjunction with I(api_version), I(name), and I(namespace) to identify a specific object.
    - If I(resource definition) is provided, the I(kind) value from the I(resource_definition)
      will override this option.
    type: str
    required: True
  label_selectors:
    description: List of label selectors to use to filter results
    type: list
    elements: str
    default: []
  field_selectors:
    description: List of field selectors to use to filter results
    type: list
    elements: str
    default: []
  hidden_fields:
    description:
      - Hide fields matching any of the field definitions in the result
      - An example might be C(hidden_fields=[metadata.managedFields])
        or V(hidden_fields=[spec.containers[0].env[3].value])
        or V(hidden_fields=[metadata.annotations[kubectl.kubernetes.io/last-applied-configuration]])
    type: list
    elements: str
    version_added: 3.0.0

extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options
  - kubernetes.core.k8s_name_options
  - kubernetes.core.k8s_wait_options

requirements:
  - "python >= 3.9"
  - "kubernetes >= 24.2.0"
  - "PyYAML >= 3.11"
"""

EXAMPLES = r"""
- name: Get an existing Service object
  kubernetes.core.k8s_info:
    api_version: v1
    kind: Service
    name: web
    namespace: testing
  register: web_service

- name: Get a list of all service objects
  kubernetes.core.k8s_info:
    api_version: v1
    kind: Service
    namespace: testing
  register: service_list

- name: Get a list of all pods from any namespace
  kubernetes.core.k8s_info:
    kind: Pod
  register: pod_list

- name: Search for all Pods labelled app=web
  kubernetes.core.k8s_info:
    kind: Pod
    label_selectors:
      - app = web
      - tier in (dev, test)

- name: Using vars while using label_selectors
  kubernetes.core.k8s_info:
    kind: Pod
    label_selectors:
      - "app = {{ app_label_web }}"
  vars:
    app_label_web: web

- name: Search for all running pods
  kubernetes.core.k8s_info:
    kind: Pod
    field_selectors:
      - status.phase=Running

- name: List custom objects created using CRD
  kubernetes.core.k8s_info:
    kind: MyCustomObject
    api_version: "stable.example.com/v1"

- name: Wait till the Object is created
  kubernetes.core.k8s_info:
    kind: Pod
    wait: yes
    name: pod-not-yet-created
    namespace: default
    wait_sleep: 10
    wait_timeout: 360
"""

RETURN = r"""
api_found:
  description:
  - Whether the specified api_version and kind were successfully mapped to an existing API on the targeted cluster.
  - Version added 1.2.0.
  returned: always
  type: bool
resources:
  description:
  - The object(s) that exists
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

import copy

from ansible_collections.kubernetes.core.plugins.module_utils.ansiblemodule import (
    AnsibleModule,
)
from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
    AUTH_ARG_SPEC,
    WAIT_ARG_SPEC,
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
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.service import (
    K8sService,
)


def execute_module(module, svc):
    facts = svc.find(
        module.params["kind"],
        module.params["api_version"],
        name=module.params["name"],
        namespace=module.params["namespace"],
        label_selectors=module.params["label_selectors"],
        field_selectors=module.params["field_selectors"],
        wait=module.params["wait"],
        wait_sleep=module.params["wait_sleep"],
        wait_timeout=module.params["wait_timeout"],
        condition=module.params["wait_condition"],
        hidden_fields=module.params["hidden_fields"],
    )
    module.exit_json(changed=False, **facts)


def argspec():
    args = copy.deepcopy(AUTH_ARG_SPEC)
    args.update(WAIT_ARG_SPEC)
    args.update(
        dict(
            kind=dict(required=True),
            api_version=dict(default="v1", aliases=["api", "version"]),
            name=dict(),
            namespace=dict(),
            label_selectors=dict(type="list", elements="str", default=[]),
            field_selectors=dict(type="list", elements="str", default=[]),
            hidden_fields=dict(type="list", elements="str"),
        )
    )
    return args


def main():
    module = AnsibleK8SModule(
        module_class=AnsibleModule, argument_spec=argspec(), supports_check_mode=True
    )
    try:
        client = get_api_client(module)
        svc = K8sService(client, module)
        execute_module(module, svc)
    except CoreException as e:
        module.fail_from_exception(e)


if __name__ == "__main__":
    main()
