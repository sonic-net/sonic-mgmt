# Copyright: (c) 2021, Red Hat | Ansible
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from typing import Dict

from ansible.module_utils._text import to_native
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.client import (
    get_api_client,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.exceptions import (
    CoreException,
    ResourceTimeout,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.resource import (
    create_definitions,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.service import (
    K8sService,
    diff_objects,
    hide_fields,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.waiter import exists
from ansible_collections.kubernetes.core.plugins.module_utils.selector import (
    LabelSelectorFilter,
)


def validate(client, module, resource):
    def _prepend_resource_info(resource, msg):
        return "%s %s: %s" % (resource["kind"], resource["metadata"]["name"], msg)

    module.requires("kubernetes-validate")

    warnings, errors = client.validate(
        resource,
        module.params["validate"].get("version"),
        module.params["validate"].get("strict"),
    )

    if errors and module.params["validate"]["fail_on_error"]:
        module.fail_json(
            msg="\n".join([_prepend_resource_info(resource, error) for error in errors])
        )
    return [_prepend_resource_info(resource, msg) for msg in warnings + errors]


def get_definitions(svc, params):
    try:
        definitions = create_definitions(params)
    except Exception as e:
        msg = "Failed to load resource definition: {0}".format(e)
        raise CoreException(msg) from e

    delete_all = params.get("delete_all")
    src = params.get("src")
    resource_definition = params.get("resource_definition")
    name = params.get("name")
    state = params.get("state")

    if (
        delete_all
        and state == "absent"
        and name is None
        and resource_definition is None
        and src is None
    ):
        # Delete all resources in the namespace for the specified resource type
        if params.get("kind") is None:
            raise CoreException(
                "'kind' option is required to specify the resource type."
            )

        resource = svc.find_resource(
            params.get("kind"), params.get("api_version"), fail=True
        )
        definitions = svc.retrieve_all(
            resource,
            params.get("namespace"),
            params.get("label_selectors"),
        )

    return definitions


def run_module(module) -> None:
    results = []
    changed = False
    client = get_api_client(module)
    svc = K8sService(client, module)

    definitions = get_definitions(svc, module.params)

    for definition in definitions:
        result = {"changed": False, "result": {}}
        warnings = []

        if module.params.get("validate") is not None:
            warnings = validate(client, module, definition)

        try:
            result = perform_action(svc, definition, module.params)
        except Exception as e:
            try:
                error = e.result
            except AttributeError:
                error = {}
            try:
                error["reason"] = e.__cause__.reason
            except AttributeError:
                pass
            error["msg"] = to_native(e)
            if warnings:
                error.setdefault("warnings", []).extend(warnings)

            if module.params.get("continue_on_error"):
                result["error"] = error
            else:
                module.fail_json(**error)

        if warnings:
            result.setdefault("warnings", []).extend(warnings)
        changed |= result["changed"]
        results.append(result)

    if len(results) == 1:
        module.exit_json(**results[0])

    module.exit_json(**{"changed": changed, "result": {"results": results}})


def perform_action(svc, definition: Dict, params: Dict) -> Dict:
    origin_name = definition["metadata"].get("name")
    namespace = definition["metadata"].get("namespace")
    label_selectors = params.get("label_selectors")
    state = params.get("state", None)
    kind = definition.get("kind")
    api_version = definition.get("apiVersion")
    hidden_fields = params.get("hidden_fields")

    result = {"changed": False, "result": {}}
    instance = {}
    warnings = []

    resource = svc.find_resource(kind, api_version, fail=True)
    definition["kind"] = resource.kind
    definition["apiVersion"] = resource.group_version
    existing = svc.retrieve(resource, definition)

    if state == "absent":
        if exists(existing) and existing.kind.endswith("List"):
            instance = []
            for item in existing.items:
                r = svc.delete(resource, item, existing)
                instance.append(r)
        else:
            instance = svc.delete(resource, definition, existing)
        result["method"] = "delete"
        if exists(existing):
            result["changed"] = True
    else:
        if label_selectors:
            filter_selector = LabelSelectorFilter(label_selectors)
            if not filter_selector.isMatching(definition):
                result["changed"] = False
                result["msg"] = (
                    "resource 'kind={kind},name={name},namespace={namespace}' "
                    "filtered by label_selectors.".format(
                        kind=kind,
                        name=origin_name,
                        namespace=namespace,
                    )
                )
                return result

        if params.get("apply"):
            instance, warnings = svc.apply(resource, definition, existing)
            result["method"] = "apply"
        elif not existing:
            if state == "patched":
                result.setdefault("warnings", []).append(
                    "resource 'kind={kind},name={name}' was not found but will not be "
                    "created as 'state' parameter has been set to '{state}'".format(
                        kind=kind, name=definition["metadata"].get("name"), state=state
                    )
                )
                return result
            instance, warnings = svc.create(resource, definition)
            result["method"] = "create"
            result["changed"] = True
        elif params.get("force", False):
            instance, warnings = svc.replace(resource, definition, existing)
            result["method"] = "replace"
        else:
            instance, warnings = svc.update(resource, definition, existing)
            result["method"] = "update"

    if warnings:
        result["warnings"] = warnings

    # If needed, wait and/or create diff
    success = True

    if result["method"] == "delete":
        # wait logic is a bit different for delete as `instance` may be a status object
        if params.get("wait") and not svc.module.check_mode:
            success, waited, duration = svc.wait(resource, definition)
            result["duration"] = duration
    else:
        if params.get("wait") and not svc.module.check_mode:
            success, instance, duration = svc.wait(resource, instance)
            result["duration"] = duration

    if result["method"] not in ("create", "delete"):
        if existing:
            existing = existing.to_dict()
        else:
            existing = {}
        match, diffs = diff_objects(existing, instance, hidden_fields)
        if match and diffs:
            result.setdefault("warnings", []).append(
                "No meaningful diff was generated, but the API may not be idempotent "
                "(only metadata.generation or metadata.resourceVersion were changed)"
            )
        result["changed"] = not match
        if svc.module._diff:
            result["diff"] = diffs

    result["result"] = hide_fields(instance, hidden_fields)
    if not success:
        raise ResourceTimeout(
            '"{0}" "{1}": Timed out waiting on resource'.format(
                definition["kind"], origin_name
            ),
            result,
        )

    return result
