#!/usr/bin/env python

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re
import operator
from functools import reduce
from ansible_collections.community.okd.plugins.module_utils.openshift_common import (
    AnsibleOpenshiftModule,
)

try:
    from ansible_collections.kubernetes.core.plugins.module_utils.k8s.resource import (
        create_definitions,
    )
    from ansible_collections.kubernetes.core.plugins.module_utils.k8s.exceptions import (
        CoreException,
    )
except ImportError:
    pass

from ansible.module_utils._text import to_native

try:
    from kubernetes.dynamic.exceptions import (
        DynamicApiError,
        NotFoundError,
        ForbiddenError,
    )
except ImportError as e:
    pass


TRIGGER_ANNOTATION = "image.openshift.io/triggers"
TRIGGER_CONTAINER = re.compile(
    r"(?P<path>.*)\[((?P<index>[0-9]+)|\?\(@\.name==[\"'\\]*(?P<name>[a-z0-9]([-a-z0-9]*[a-z0-9])?))"
)


class OKDRawModule(AnsibleOpenshiftModule):
    def __init__(self, **kwargs):
        super(OKDRawModule, self).__init__(**kwargs)

    @property
    def module(self):
        return self._module

    def execute_module(self):
        results = []
        changed = False

        try:
            definitions = create_definitions(self.params)
        except Exception as e:
            msg = "Failed to load resource definition: {0}".format(e)
            raise CoreException(msg) from e

        for definition in definitions:
            result = {"changed": False, "result": {}}
            warnings = []

            if self.params.get("state") != "absent":
                existing = None
                name = definition.get("metadata", {}).get("name")
                namespace = definition.get("metadata", {}).get("namespace")
                if definition.get("kind") in ["Project", "ProjectRequest"]:
                    try:
                        resource = self.svc.find_resource(
                            kind=definition.get("kind"),
                            api_version=definition.get("apiVersion", "v1"),
                        )
                        existing = resource.get(
                            name=name, namespace=namespace
                        ).to_dict()
                    except (NotFoundError, ForbiddenError):
                        result = self.create_project_request(definition)
                        changed |= result["changed"]
                        results.append(result)
                        continue
                    except DynamicApiError as exc:
                        self.fail_json(
                            msg="Failed to retrieve requested object: {0}".format(
                                exc.body
                            ),
                            error=exc.status,
                            status=exc.status,
                            reason=exc.reason,
                        )

                if definition.get("kind") not in ["Project", "ProjectRequest"]:
                    try:
                        resource = self.svc.find_resource(
                            kind=definition.get("kind"),
                            api_version=definition.get("apiVersion", "v1"),
                        )
                        existing = resource.get(
                            name=name, namespace=namespace
                        ).to_dict()
                    except Exception:
                        existing = None

                if existing:
                    if resource.kind == "DeploymentConfig":
                        if definition.get("spec", {}).get("triggers"):
                            definition = self.resolve_imagestream_triggers(
                                existing, definition
                            )
                    elif (
                        existing["metadata"]
                        .get("annotations", {})
                        .get(TRIGGER_ANNOTATION)
                    ):
                        definition = self.resolve_imagestream_trigger_annotation(
                            existing, definition
                        )

            if self.params.get("validate") is not None:
                warnings = self.validate(definition)

            try:
                result = self.perform_action(definition, self.params)
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

                if self.params.get("continue_on_error"):
                    result["error"] = error
                else:
                    self.fail_json(**error)

            if warnings:
                result.setdefault("warnings", []).extend(warnings)
            changed |= result["changed"]
            results.append(result)

        if len(results) == 1:
            self.exit_json(**results[0])

        self.exit_json(**{"changed": changed, "result": {"results": results}})

    @staticmethod
    def get_index(desired, objects, keys):
        """Iterates over keys, returns the first object from objects where the value of the key
        matches the value in desired
        """
        # pylint: disable=use-a-generator
        # Use a generator instead 'all(desired.get(key, True) == item.get(key, False) for key in keys)'
        for i, item in enumerate(objects):
            if item and all(
                [desired.get(key, True) == item.get(key, False) for key in keys]
            ):
                return i

    def resolve_imagestream_trigger_annotation(self, existing, definition):
        import yaml

        def get_from_fields(d, fields):
            try:
                return reduce(operator.getitem, fields, d)
            except Exception:
                return None

        def set_from_fields(d, fields, value):
            get_from_fields(d, fields[:-1])[fields[-1]] = value

        if TRIGGER_ANNOTATION in definition["metadata"].get("annotations", {}).keys():
            triggers = yaml.safe_load(
                definition["metadata"]["annotations"][TRIGGER_ANNOTATION] or "[]"
            )
        else:
            triggers = yaml.safe_load(
                existing["metadata"]
                .get("annotations", "{}")
                .get(TRIGGER_ANNOTATION, "[]")
            )

        if not isinstance(triggers, list):
            return definition

        for trigger in triggers:
            if trigger.get("fieldPath"):
                parsed = self.parse_trigger_fieldpath(trigger["fieldPath"])
                path = parsed.get("path", "").split(".")
                if path:
                    existing_containers = get_from_fields(existing, path)
                    new_containers = get_from_fields(definition, path)
                    if parsed.get("name"):
                        existing_index = self.get_index(
                            {"name": parsed["name"]}, existing_containers, ["name"]
                        )
                        new_index = self.get_index(
                            {"name": parsed["name"]}, new_containers, ["name"]
                        )
                    elif parsed.get("index") is not None:
                        existing_index = new_index = int(parsed["index"])
                    else:
                        existing_index = new_index = None
                    if existing_index is not None and new_index is not None:
                        if existing_index < len(
                            existing_containers
                        ) and new_index < len(new_containers):
                            set_from_fields(
                                definition,
                                path + [new_index, "image"],
                                get_from_fields(
                                    existing, path + [existing_index, "image"]
                                ),
                            )
        return definition

    def resolve_imagestream_triggers(self, existing, definition):
        existing_triggers = existing.get("spec", {}).get("triggers")
        new_triggers = definition["spec"]["triggers"]
        existing_containers = (
            existing.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        )
        new_containers = (
            definition.get("spec", {})
            .get("template", {})
            .get("spec", {})
            .get("containers", [])
        )
        for i, trigger in enumerate(new_triggers):
            if trigger.get("type") == "ImageChange" and trigger.get(
                "imageChangeParams"
            ):
                names = trigger["imageChangeParams"].get("containerNames", [])
                for name in names:
                    old_container_index = self.get_index(
                        {"name": name}, existing_containers, ["name"]
                    )
                    new_container_index = self.get_index(
                        {"name": name}, new_containers, ["name"]
                    )
                    if (
                        old_container_index is not None
                        and new_container_index is not None
                    ):
                        image = existing["spec"]["template"]["spec"]["containers"][
                            old_container_index
                        ]["image"]
                        definition["spec"]["template"]["spec"]["containers"][
                            new_container_index
                        ]["image"] = image

                    existing_index = self.get_index(
                        trigger["imageChangeParams"],
                        [x.get("imageChangeParams") for x in existing_triggers],
                        ["containerNames"],
                    )
                    if existing_index is not None:
                        existing_image = (
                            existing_triggers[existing_index]
                            .get("imageChangeParams", {})
                            .get("lastTriggeredImage")
                        )
                        if existing_image:
                            definition["spec"]["triggers"][i]["imageChangeParams"][
                                "lastTriggeredImage"
                            ] = existing_image
                        existing_from = (
                            existing_triggers[existing_index]
                            .get("imageChangeParams", {})
                            .get("from", {})
                        )
                        new_from = trigger["imageChangeParams"].get("from", {})
                        existing_namespace = existing_from.get("namespace")
                        existing_name = existing_from.get("name", False)
                        new_name = new_from.get("name", True)
                        add_namespace = (
                            existing_namespace
                            and "namespace" not in new_from.keys()
                            and existing_name == new_name
                        )
                        if add_namespace:
                            definition["spec"]["triggers"][i]["imageChangeParams"][
                                "from"
                            ]["namespace"] = existing_from["namespace"]

        return definition

    def parse_trigger_fieldpath(self, expression):
        parsed = TRIGGER_CONTAINER.search(expression).groupdict()
        if parsed.get("index"):
            parsed["index"] = int(parsed["index"])
        return parsed

    def create_project_request(self, definition):
        definition["kind"] = "ProjectRequest"
        result = {"changed": False, "result": {}}
        resource = self.svc.find_resource(
            kind="ProjectRequest", api_version=definition["apiVersion"], fail=True
        )
        if not self.check_mode:
            try:
                k8s_obj = resource.create(definition)
                result["result"] = k8s_obj.to_dict()
            except DynamicApiError as exc:
                self.fail_json(
                    msg="Failed to create object: {0}".format(exc.body),
                    error=exc.status,
                    status=exc.status,
                    reason=exc.reason,
                )
        result["changed"] = True
        result["method"] = "create"
        return result
