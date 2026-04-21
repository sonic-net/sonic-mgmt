#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, Chris Houseknecht <@chouseknecht>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""

module: k8s_scale

short_description: Set a new size for a Deployment, ReplicaSet, Replication Controller, or Job.

author:
    - "Chris Houseknecht (@chouseknecht)"
    - "Fabian von Feilitzsch (@fabianvf)"

description:
  - Similar to the kubectl scale command. Use to set the number of replicas for a Deployment, ReplicaSet,
    or Replication Controller, or the parallelism attribute of a Job. Supports check mode.
  - C(wait) parameter is not supported for Jobs.

extends_documentation_fragment:
  - kubernetes.core.k8s_name_options
  - kubernetes.core.k8s_auth_options
  - kubernetes.core.k8s_resource_options
  - kubernetes.core.k8s_scale_options

options:
  label_selectors:
    description: List of label selectors to use to filter results.
    type: list
    elements: str
    default: []
    version_added: 2.0.0
  continue_on_error:
    description:
    - Whether to continue on errors when multiple resources are defined.
    type: bool
    default: False
    version_added: 2.0.0

requirements:
    - "python >= 3.9"
    - "kubernetes >= 24.2.0"
    - "PyYAML >= 3.11"
"""

EXAMPLES = r"""
- name: Scale deployment up, and extend timeout
  kubernetes.core.k8s_scale:
    api_version: v1
    kind: Deployment
    name: elastic
    namespace: myproject
    replicas: 3
    wait_timeout: 60

- name: Scale deployment down when current replicas match
  kubernetes.core.k8s_scale:
    api_version: v1
    kind: Deployment
    name: elastic
    namespace: myproject
    current_replicas: 3
    replicas: 2

- name: Increase job parallelism
  kubernetes.core.k8s_scale:
    api_version: batch/v1
    kind: job
    name: pi-with-timeout
    namespace: testing
    replicas: 2

# Match object using local file or inline definition

- name: Scale deployment based on a file from the local filesystem
  kubernetes.core.k8s_scale:
    src: /myproject/elastic_deployment.yml
    replicas: 3
    wait: no

- name: Scale deployment based on a template output
  kubernetes.core.k8s_scale:
    resource_definition: "{{ lookup('template', '/myproject/elastic_deployment.yml') | from_yaml }}"
    replicas: 3
    wait: no

- name: Scale deployment based on a file from the Ansible controller filesystem
  kubernetes.core.k8s_scale:
    resource_definition: "{{ lookup('file', '/myproject/elastic_deployment.yml') | from_yaml }}"
    replicas: 3
    wait: no

- name: Scale deployment using label selectors (continue operation in case error occured on one resource)
  kubernetes.core.k8s_scale:
    replicas: 3
    kind: Deployment
    namespace: test
    label_selectors:
      - app=test
    continue_on_error: true
"""

RETURN = r"""
result:
  description:
  - If a change was made, will return the patched object, otherwise returns the existing object.
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
     duration:
       description: elapsed time of task in seconds
       returned: when C(wait) is true
       type: int
       sample: 48
"""

import copy

try:
    from kubernetes.dynamic.exceptions import NotFoundError
except ImportError:
    # Handled in module setup
    pass

from ansible.module_utils._text import to_native
from ansible_collections.kubernetes.core.plugins.module_utils.ansiblemodule import (
    AnsibleModule,
)
from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
    AUTH_ARG_SPEC,
    NAME_ARG_SPEC,
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
    ResourceTimeout,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.resource import (
    create_definitions,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.service import (
    diff_objects,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.waiter import (
    get_waiter,
)

SCALE_ARG_SPEC = {
    "replicas": {"type": "int", "required": True},
    "current_replicas": {"type": "int"},
    "resource_version": {},
    "wait": {"type": "bool", "default": True},
    "wait_timeout": {"type": "int", "default": 20},
    "wait_sleep": {"type": "int", "default": 5},
}


def execute_module(client, module):
    current_replicas = module.params.get("current_replicas")
    replicas = module.params.get("replicas")
    resource_version = module.params.get("resource_version")
    definitions = create_definitions(module.params)
    definition = definitions[0]
    name = definition["metadata"].get("name")
    namespace = definition["metadata"].get("namespace")
    api_version = definition["apiVersion"]
    kind = definition["kind"]
    label_selectors = module.params.get("label_selectors")
    if not label_selectors:
        label_selectors = []
    continue_on_error = module.params.get("continue_on_error")
    wait = module.params.get("wait")
    wait_time = module.params.get("wait_timeout")
    wait_sleep = module.params.get("wait_sleep")
    existing = None
    existing_count = None
    return_attributes = dict(result=dict())
    if module._diff:
        return_attributes["diff"] = dict()
    if wait:
        return_attributes["duration"] = 0

    resource = client.resource(kind, api_version)
    multiple_scale = False
    try:
        existing = resource.get(
            name=name, namespace=namespace, label_selector=",".join(label_selectors)
        )
        if existing.kind.endswith("List"):
            existing_items = existing.items
            multiple_scale = len(existing_items) > 1
        else:
            existing_items = [existing]
    except NotFoundError as e:
        reason = e.body if hasattr(e, "body") else e
        msg = "Failed to retrieve requested object: {0}".format(reason)
        raise CoreException(msg) from e

    if multiple_scale:
        # when scaling multiple resource, the 'result' is changed to 'results' and is a list
        return_attributes = {"results": []}
    changed = False

    def _continue_or_fail(error):
        if multiple_scale and continue_on_error:
            if "errors" not in return_attributes:
                return_attributes["errors"] = []
            return_attributes["errors"].append({"error": error, "failed": True})
        else:
            module.fail_json(msg=error, **return_attributes)

    def _continue_or_exit(warn):
        if multiple_scale:
            return_attributes["results"].append({"warning": warn, "changed": False})
        else:
            module.exit_json(warning=warn, **return_attributes)

    for existing in existing_items:
        if kind.lower() == "job":
            existing_count = existing.spec.parallelism
        elif hasattr(existing.spec, "replicas"):
            existing_count = existing.spec.replicas

        if existing_count is None:
            error = "Failed to retrieve the available count for object kind={0} name={1} namespace={2}.".format(
                existing.kind, existing.metadata.name, existing.metadata.namespace
            )
            _continue_or_fail(error)
            continue

        if resource_version and resource_version != existing.metadata.resourceVersion:
            warn = "expected resource version {0} does not match with actual {1} for object kind={2} name={3} namespace={4}.".format(
                resource_version,
                existing.metadata.resourceVersion,
                existing.kind,
                existing.metadata.name,
                existing.metadata.namespace,
            )
            _continue_or_exit(warn)
            continue

        if current_replicas is not None and existing_count != current_replicas:
            warn = "current replicas {0} does not match with actual {1} for object kind={2} name={3} namespace={4}.".format(
                current_replicas,
                existing_count,
                existing.kind,
                existing.metadata.name,
                existing.metadata.namespace,
            )
            _continue_or_exit(warn)
            continue

        if existing_count != replicas:
            if kind.lower() == "job":
                existing.spec.parallelism = replicas
                result = {"changed": True}
                if module.check_mode:
                    result["result"] = existing.to_dict()
                else:
                    result["result"] = client.patch(
                        resource, existing.to_dict()
                    ).to_dict()
            else:
                try:
                    result = scale(
                        client,
                        module,
                        resource,
                        existing,
                        replicas,
                        wait,
                        wait_time,
                        wait_sleep,
                    )
                except CoreException as e:
                    module.fail_json(msg=to_native(e))
                changed = changed or result["changed"]
        else:
            name = existing.metadata.name
            namespace = existing.metadata.namespace
            existing = client.get(resource, name=name, namespace=namespace)
            result = {"changed": False, "result": existing.to_dict()}
            if module._diff:
                result["diff"] = {}
            if wait:
                result["duration"] = 0
        # append result to the return attribute
        if multiple_scale:
            return_attributes["results"].append(result)
        else:
            module.exit_json(**result)

    module.exit_json(changed=changed, **return_attributes)


def argspec():
    args = copy.deepcopy(SCALE_ARG_SPEC)
    args.update(RESOURCE_ARG_SPEC)
    args.update(NAME_ARG_SPEC)
    args.update(AUTH_ARG_SPEC)
    args.update({"label_selectors": {"type": "list", "elements": "str", "default": []}})
    args.update(({"continue_on_error": {"type": "bool", "default": False}}))
    return args


def scale(
    client,
    module,
    resource,
    existing_object,
    replicas,
    wait,
    wait_time,
    wait_sleep,
):
    name = existing_object.metadata.name
    namespace = existing_object.metadata.namespace
    kind = existing_object.kind

    if not hasattr(resource, "scale"):
        raise CoreException(
            "Cannot perform scale on resource of kind {0}".format(resource.kind)
        )

    scale_obj = {
        "kind": kind,
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"replicas": replicas},
    }

    existing = client.get(resource, name=name, namespace=namespace)

    result = dict()
    if module.check_mode:
        k8s_obj = copy.deepcopy(existing.to_dict())
        k8s_obj["spec"]["replicas"] = replicas
        if wait:
            result["duration"] = 0
        result["result"] = k8s_obj
    else:
        try:
            resource.scale.patch(body=scale_obj)
        except Exception as e:
            reason = e.body if hasattr(e, "body") else e
            msg = "Scale request failed: {0}".format(reason)
            raise CoreException(msg) from e

        k8s_obj = client.get(resource, name=name, namespace=namespace).to_dict()
        result["result"] = k8s_obj
        if wait:
            waiter = get_waiter(client, resource)
            success, result["result"], result["duration"] = waiter.wait(
                timeout=wait_time,
                sleep=wait_sleep,
                name=name,
                namespace=namespace,
            )
            if not success:
                raise ResourceTimeout("Resource scaling timed out", result)

    match, diffs = diff_objects(existing.to_dict(), result["result"])
    result["changed"] = not match
    if module._diff:
        result["diff"] = diffs

    return result


def main():
    mutually_exclusive = [
        ("resource_definition", "src"),
    ]
    module = AnsibleK8SModule(
        module_class=AnsibleModule,
        argument_spec=argspec(),
        mutually_exclusive=mutually_exclusive,
        supports_check_mode=True,
    )

    try:
        client = get_api_client(module=module)
        execute_module(client, module)
    except CoreException as e:
        module.fail_from_exception(e)


if __name__ == "__main__":
    main()
