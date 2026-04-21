#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (C), 2018 Red Hat | Ansible
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
module: k8s_json_patch

short_description: Apply JSON patch operations to existing objects

description:
  - This module is used to apply RFC 6902 JSON patch operations only.
  - Use the M(kubernetes.core.k8s) module for strategic merge or JSON merge operations.
  - The jsonpatch library is required for check mode.

version_added: 2.0.0

author:
- Mike Graves (@gravesm)

options:
  api_version:
    description:
      - Use to specify the API version.
      - Use in conjunction with I(kind), I(name), and I(namespace) to identify a specific object.
    type: str
    default: v1
    aliases:
      - api
      - version
  hidden_fields:
    description:
      - List of fields to hide from the diff output.
      - This is useful for fields that are not relevant to the patch operation, such as `metadata.managedFields`.
    type: list
    elements: str
    default: []
    version_added: 6.1.0
  kind:
    description:
      - Use to specify an object model.
      - Use in conjunction with I(api_version), I(name), and I(namespace) to identify a specific object.
    type: str
    required: yes
  namespace:
    description:
      - Use to specify an object namespace.
      - Use in conjunction with I(api_version), I(kind), and I(name) to identify a specific object.
    type: str
  name:
    description:
      - Use to specify an object name.
      - Use in conjunction with I(api_version), I(kind), and I(namespace) to identify a specific object.
    type: str
    required: yes
  patch:
    description:
      - List of JSON patch operations.
    required: yes
    type: list
    elements: dict

extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options
  - kubernetes.core.k8s_wait_options

requirements:
  - "python >= 3.9"
  - "kubernetes >= 24.2.0"
  - "PyYAML >= 3.11"
  - "jsonpatch"
"""

EXAMPLES = r"""
- name: Apply multiple patch operations to an existing Pod
  kubernetes.core.k8s_json_patch:
    kind: Pod
    namespace: testing
    name: mypod
    patch:
      - op: add
        path: /metadata/labels/app
        value: myapp
      - op: replace
        path: /spec/containers/0/image
        value: nginx
"""

RETURN = r"""
result:
  description: The modified object.
  returned: success
  type: dict
  contains:
     api_version:
       description: The versioned schema of this representation of an object.
       returned: success
       type: str
     kind:
       description: The REST resource this object represents.
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
duration:
  description: Elapsed time of task in seconds.
  returned: when C(wait) is true
  type: int
  sample: 48
error:
  description: The error when patching the object.
  returned: error
  type: dict
  sample: {
      "msg": "Failed to import the required Python library (jsonpatch) ...",
      "exception": "Traceback (most recent call last): ..."
    }
"""

import copy
import traceback

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import missing_required_lib
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
    diff_objects,
    hide_fields,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.waiter import (
    get_waiter,
)

try:
    from kubernetes.dynamic.exceptions import DynamicApiError
except ImportError:
    # kubernetes library check happens in common.py
    pass

JSON_PATCH_IMPORT_ERR = None
try:
    import jsonpatch

    HAS_JSON_PATCH = True
except ImportError:
    HAS_JSON_PATCH = False
    JSON_PATCH_IMPORT_ERR = traceback.format_exc()


JSON_PATCH_ARGS = {
    "api_version": {"default": "v1", "aliases": ["api", "version"]},
    "kind": {"type": "str", "required": True},
    "namespace": {"type": "str"},
    "name": {"type": "str", "required": True},
    "patch": {"type": "list", "required": True, "elements": "dict"},
    "hidden_fields": {"type": "list", "elements": "str", "default": []},
}


def json_patch(existing, patch):
    if not HAS_JSON_PATCH:
        error = {
            "msg": missing_required_lib("jsonpatch"),
            "exception": JSON_PATCH_IMPORT_ERR,
        }
        return None, error
    try:
        patch = jsonpatch.JsonPatch(patch)
        patched = patch.apply(existing)
        return patched, None
    except jsonpatch.InvalidJsonPatch as e:
        error = {"msg": "Invalid JSON patch", "exception": e}
        return None, error
    except jsonpatch.JsonPatchConflict as e:
        error = {"msg": "Patch could not be applied due to a conflict", "exception": e}
        return None, error


def execute_module(module, client):
    kind = module.params.get("kind")
    api_version = module.params.get("api_version")
    name = module.params.get("name")
    namespace = module.params.get("namespace")
    patch = module.params.get("patch")

    hidden_fields = module.params.get("hidden_fields")
    wait = module.params.get("wait")
    wait_sleep = module.params.get("wait_sleep")
    wait_timeout = module.params.get("wait_timeout")
    wait_condition = None
    if module.params.get("wait_condition") and module.params.get("wait_condition").get(
        "type"
    ):
        wait_condition = module.params["wait_condition"]

    def build_error_msg(kind, name, msg):
        return "%s %s: %s" % (kind, name, msg)

    resource = client.resource(kind, api_version)

    try:
        existing = client.get(resource, name=name, namespace=namespace)
    except DynamicApiError as exc:
        msg = "Failed to retrieve requested object: {0}".format(exc.body)
        module.fail_json(
            msg=build_error_msg(kind, name, msg),
            error=exc.status,
            status=exc.status,
            reason=exc.reason,
        )
    except ValueError as exc:
        msg = "Failed to retrieve requested object: {0}".format(to_native(exc))
        module.fail_json(
            msg=build_error_msg(kind, name, msg), error="", status="", reason=""
        )

    if module.check_mode and not client.dry_run:
        obj, error = json_patch(existing.to_dict(), patch)
        if error:
            module.fail_json(**error)
    else:
        params = {}
        if module.check_mode:
            params["dry_run"] = "All"
        try:
            obj = client.patch(
                resource,
                patch,
                name=name,
                namespace=namespace,
                content_type="application/json-patch+json",
                **params
            ).to_dict()
        except DynamicApiError as exc:
            msg = "Failed to patch existing object: {0}".format(exc.body)
            module.fail_json(
                msg=msg, error=exc.status, status=exc.status, reason=exc.reason
            )
        except Exception as exc:
            msg = "Failed to patch existing object: {0}".format(exc)
            module.fail_json(msg=msg, error=to_native(exc), status="", reason="")

    success = True
    result = {"result": hide_fields(obj, hidden_fields)}
    if wait and not module.check_mode:
        waiter = get_waiter(client, resource, condition=wait_condition)
        success, result["result"], result["duration"] = waiter.wait(
            wait_timeout, wait_sleep, name, namespace
        )
    match, diffs = diff_objects(existing.to_dict(), obj, hidden_fields)
    result["changed"] = not match
    if module._diff:
        result["diff"] = diffs

    if not success:
        msg = "Resource update timed out"
        module.fail_json(msg=msg, **result)

    module.exit_json(**result)


def main():
    args = copy.deepcopy(AUTH_ARG_SPEC)
    args.update(copy.deepcopy(WAIT_ARG_SPEC))
    args.update(JSON_PATCH_ARGS)
    module = AnsibleK8SModule(
        module_class=AnsibleModule, argument_spec=args, supports_check_mode=True
    )
    try:
        client = get_api_client(module)
        execute_module(module, client)
    except CoreException as e:
        module.fail_from_exception(e)


if __name__ == "__main__":
    main()
