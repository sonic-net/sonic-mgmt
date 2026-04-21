#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Julien Huon <@julienhuon> Institut National de l'Audiovisuel
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
module: k8s_rollback
short_description: Rollback Kubernetes (K8S) Deployments and DaemonSets
version_added: 1.0.0
author:
    - "Julien Huon (@julienhuon)"
description:
  - Use the Kubernetes Python client to perform the Rollback.
  - Authenticate using either a config file, certificates, password or token.
  - Similar to the C(kubectl rollout undo) command.
options:
  label_selectors:
    description: List of label selectors to use to filter results.
    type: list
    elements: str
    default: []
  field_selectors:
    description: List of field selectors to use to filter results.
    type: list
    elements: str
    default: []
extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options
  - kubernetes.core.k8s_name_options
requirements:
  - "python >= 3.9"
  - "kubernetes >= 24.2.0"
  - "PyYAML >= 3.11"
"""

EXAMPLES = r"""
- name: Rollback a failed deployment
  kubernetes.core.k8s_rollback:
    api_version: apps/v1
    kind: Deployment
    name: web
    namespace: testing
"""

RETURN = r"""
rollback_info:
  description:
  - The object that was rolled back.
  returned: success
  type: complex
  contains:
    api_version:
      description: The versioned schema of this representation of an object.
      returned: success
      type: str
    code:
      description: The HTTP Code of the response
      returned: success
      type: str
    kind:
      description: Status
      returned: success
      type: str
    metadata:
      description:
        - Standard object metadata.
        - Includes name, namespace, annotations, labels, etc.
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
    NAME_ARG_SPEC,
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


def get_managed_resource(kind):
    managed_resource = {}

    if kind == "DaemonSet":
        managed_resource["kind"] = "ControllerRevision"
        managed_resource["api_version"] = "apps/v1"
    elif kind == "Deployment":
        managed_resource["kind"] = "ReplicaSet"
        managed_resource["api_version"] = "apps/v1"
    else:
        raise CoreException(
            "Cannot perform rollback on resource of kind {0}".format(kind)
        )
    return managed_resource


def execute_module(svc):
    results = []
    module = svc.module

    resources = svc.find(
        module.params["kind"],
        module.params["api_version"],
        module.params["name"],
        module.params["namespace"],
        module.params["label_selectors"],
        module.params["field_selectors"],
    )

    changed = False
    for resource in resources["resources"]:
        result = perform_action(svc, resource)
        changed = result["changed"] or changed
        results.append(result)

    module.exit_json(**{"changed": changed, "rollback_info": results})


def perform_action(svc, resource):
    module = svc.module

    if module.params["kind"] == "DaemonSet":
        current_revision = resource["metadata"]["generation"]
    elif module.params["kind"] == "Deployment":
        current_revision = resource["metadata"]["annotations"][
            "deployment.kubernetes.io/revision"
        ]

    managed_resource = get_managed_resource(module.params["kind"])
    managed_resources = svc.find(
        managed_resource["kind"],
        managed_resource["api_version"],
        "",
        module.params["namespace"],
        resource["spec"]["selector"]["matchLabels"],
        "",
    )

    prev_managed_resource = get_previous_revision(
        managed_resources["resources"], current_revision
    )
    if not prev_managed_resource:
        warn = "No rollout history found for resource %s/%s" % (
            module.params["kind"],
            resource["metadata"]["name"],
        )
        result = {"changed": False, "warnings": [warn]}
        return result

    if module.params["kind"] == "Deployment":
        del prev_managed_resource["spec"]["template"]["metadata"]["labels"][
            "pod-template-hash"
        ]

        resource_patch = [
            {
                "op": "replace",
                "path": "/spec/template",
                "value": prev_managed_resource["spec"]["template"],
            },
            {
                "op": "replace",
                "path": "/metadata/annotations",
                "value": {
                    "deployment.kubernetes.io/revision": prev_managed_resource[
                        "metadata"
                    ]["annotations"]["deployment.kubernetes.io/revision"]
                },
            },
        ]

        api_target = "deployments"
        content_type = "application/json-patch+json"
    elif module.params["kind"] == "DaemonSet":
        resource_patch = prev_managed_resource["data"]

        api_target = "daemonsets"
        content_type = "application/strategic-merge-patch+json"

    rollback = resource
    if not module.check_mode:
        rollback = svc.client.client.request(
            "PATCH",
            "/apis/{0}/namespaces/{1}/{2}/{3}".format(
                module.params["api_version"],
                module.params["namespace"],
                api_target,
                module.params["name"],
            ),
            body=resource_patch,
            content_type=content_type,
        ).to_dict()

    result = {"changed": True}
    result["method"] = "patch"
    result["body"] = resource_patch
    result["resources"] = rollback
    return result


def argspec():
    args = copy.deepcopy(AUTH_ARG_SPEC)
    args.update(NAME_ARG_SPEC)
    args.update(
        dict(
            label_selectors=dict(type="list", elements="str", default=[]),
            field_selectors=dict(type="list", elements="str", default=[]),
        )
    )
    return args


def get_previous_revision(all_resources, current_revision):
    for resource in all_resources:
        if resource["kind"] == "ReplicaSet":
            if (
                int(
                    resource["metadata"]["annotations"][
                        "deployment.kubernetes.io/revision"
                    ]
                )
                == int(current_revision) - 1
            ):
                return resource
        elif resource["kind"] == "ControllerRevision":
            if (
                int(
                    resource["metadata"]["annotations"][
                        "deprecated.daemonset.template.generation"
                    ]
                )
                == int(current_revision) - 1
            ):
                return resource
    return None


def main():
    module = AnsibleK8SModule(
        module_class=AnsibleModule, argument_spec=argspec(), supports_check_mode=True
    )

    try:
        client = get_api_client(module=module)
        svc = K8sService(client, module)
        execute_module(svc)
    except CoreException as e:
        module.fail_from_exception(e)


if __name__ == "__main__":
    main()
