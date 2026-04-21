#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2018, KubeVirt Team <@kubevirt>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""

module: k8s_service

short_description: Manage Services on Kubernetes

author: KubeVirt Team (@kubevirt)

description:
  - Use Kubernetes Python SDK to manage Services on Kubernetes

extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options
  - kubernetes.core.k8s_resource_options
  - kubernetes.core.k8s_state_options

options:
  merge_type:
    description:
    - Whether to override the default patch merge approach with a specific type. By default, the strategic
      merge will typically be used.
    - For example, Custom Resource Definitions typically aren't updatable by the usual strategic merge. You may
      want to use C(merge) if you see "strategic merge patch format is not supported"
    - See U(https://kubernetes.io/docs/tasks/run-application/update-api-object-kubectl-patch/#use-a-json-merge-patch-to-update-a-deployment)
    - If more than one C(merge_type) is given, the merge_types will be tried in order
    - This defaults to C(['strategic-merge', 'merge']), which is ideal for using the same parameters
      on resource kinds that combine Custom Resources and built-in resources.
    choices:
    - json
    - merge
    - strategic-merge
    type: list
    elements: str
  name:
    description:
      - Use to specify a Service object name.
    required: true
    type: str
  namespace:
    description:
      - Use to specify a Service object namespace.
    required: true
    type: str
  type:
    description:
      - Specifies the type of Service to create.
      - See U(https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types)
    choices:
      - NodePort
      - ClusterIP
      - LoadBalancer
      - ExternalName
    type: str
  ports:
    description:
      - A list of ports to expose.
      - U(https://kubernetes.io/docs/concepts/services-networking/service/#multi-port-services)
    type: list
    elements: dict
  selector:
    description:
      - Label selectors identify objects this Service should apply to.
      - U(https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/)
    type: dict
  apply:
    description:
    - C(apply) compares the desired resource definition with the previously supplied resource definition,
      ignoring properties that are automatically generated
    - C(apply) works better with Services than 'force=yes'
    - mutually exclusive with C(merge_type)
    default: False
    type: bool

requirements:
  - python >= 3.9
  - kubernetes >= 24.2.0
"""

EXAMPLES = r"""
- name: Expose https port with ClusterIP
  kubernetes.core.k8s_service:
    state: present
    name: test-https
    namespace: default
    ports:
    - port: 443
      protocol: TCP
    selector:
      key: special

- name: Expose https port with ClusterIP using spec
  kubernetes.core.k8s_service:
    state: present
    name: test-https
    namespace: default
    inline:
      spec:
        ports:
        - port: 443
          protocol: TCP
        selector:
          key: special
"""

RETURN = r"""
result:
  description:
  - The created, patched, or otherwise present Service object. Will be empty in the case of a deletion.
  returned: success
  type: complex
  contains:
     api_version:
       description: The versioned schema of this representation of an object.
       returned: success
       type: str
     kind:
       description: Always 'Service'.
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
from collections import defaultdict

from ansible_collections.kubernetes.core.plugins.module_utils.ansiblemodule import (
    AnsibleModule,
)
from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
    AUTH_ARG_SPEC,
    COMMON_ARG_SPEC,
    RESOURCE_ARG_SPEC,
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
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.resource import (
    create_definitions,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.runner import (
    perform_action,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.service import (
    K8sService,
)

SERVICE_ARG_SPEC = {
    "apply": {"type": "bool", "default": False},
    "name": {"required": True},
    "namespace": {"required": True},
    "merge_type": {
        "type": "list",
        "elements": "str",
        "choices": ["json", "merge", "strategic-merge"],
    },
    "selector": {"type": "dict"},
    "type": {
        "type": "str",
        "choices": ["NodePort", "ClusterIP", "LoadBalancer", "ExternalName"],
    },
    "ports": {"type": "list", "elements": "dict"},
}


def merge_dicts(x, y):
    for k in set(x.keys()).union(y.keys()):
        if k in x and k in y:
            if isinstance(x[k], dict) and isinstance(y[k], dict):
                yield (k, dict(merge_dicts(x[k], y[k])))
            else:
                yield (k, y[k] if y[k] else x[k])
        elif k in x:
            yield (k, x[k])
        else:
            yield (k, y[k])


def argspec():
    """argspec property builder"""
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(COMMON_ARG_SPEC)
    argument_spec.update(RESOURCE_ARG_SPEC)
    argument_spec.update(SERVICE_ARG_SPEC)
    return argument_spec


def execute_module(svc):
    """Module execution"""
    module = svc.module
    api_version = "v1"
    selector = module.params.get("selector")
    service_type = module.params.get("type")
    ports = module.params.get("ports")

    definition = defaultdict(defaultdict)

    definition["kind"] = "Service"
    definition["apiVersion"] = api_version

    def_spec = definition["spec"]
    def_spec["type"] = service_type
    def_spec["ports"] = ports
    def_spec["selector"] = selector

    def_meta = definition["metadata"]
    def_meta["name"] = module.params.get("name")
    def_meta["namespace"] = module.params.get("namespace")

    definitions = create_definitions(module.params)

    # 'resource_definition:' has lower priority than module parameters
    definition = dict(merge_dicts(definitions[0], definition))

    result = perform_action(svc, definition, module.params)

    module.exit_json(**result)


def main():
    module = AnsibleK8SModule(
        module_class=AnsibleModule,
        argument_spec=argspec(),
        supports_check_mode=True,
    )

    try:
        client = get_api_client(module=module)
        svc = K8sService(client, module)
        execute_module(svc)
    except CoreException as e:
        module.fail_from_exception(e)


if __name__ == "__main__":
    main()
