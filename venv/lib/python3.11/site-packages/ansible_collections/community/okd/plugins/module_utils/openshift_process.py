#!/usr/bin/env python

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os

from ansible.module_utils._text import to_native

from ansible_collections.community.okd.plugins.module_utils.openshift_common import (
    AnsibleOpenshiftModule,
)

try:
    from kubernetes.dynamic.exceptions import DynamicApiError
except ImportError:
    pass


class OpenShiftProcess(AnsibleOpenshiftModule):
    def __init__(self, **kwargs):
        super(OpenShiftProcess, self).__init__(**kwargs)

    def execute_module(self):
        v1_templates = self.find_resource(
            "templates", "template.openshift.io/v1", fail=True
        )
        v1_processed_templates = self.find_resource(
            "processedtemplates", "template.openshift.io/v1", fail=True
        )

        name = self.params.get("name")
        namespace = self.params.get("namespace")
        namespace_target = self.params.get("namespace_target")
        definition = self.params.get("resource_definition")
        src = self.params.get("src")

        state = self.params.get("state")

        parameters = self.params.get("parameters") or {}
        parameter_file = self.params.get("parameter_file")

        if (name and definition) or (name and src) or (src and definition):
            self.fail_json("Only one of src, name, or definition may be provided")

        if name and not namespace:
            self.fail_json("namespace is required when name is set")

        template = None

        if src or definition:
            self.set_resource_definitions()
            if len(self.resource_definitions) < 1:
                self.fail_json(
                    "Unable to load a Template resource from src or resource_definition"
                )
            elif len(self.resource_definitions) > 1:
                self.fail_json(
                    "Multiple Template resources found in src or resource_definition, only one Template may be processed at a time"
                )
            template = self.resource_definitions[0]
            template_namespace = template.get("metadata", {}).get("namespace")
            namespace = template_namespace or namespace or namespace_target or "default"
        elif name and namespace:
            try:
                template = v1_templates.get(name=name, namespace=namespace).to_dict()
            except DynamicApiError as exc:
                self.fail_json(
                    msg="Failed to retrieve Template with name '{0}' in namespace '{1}': {2}".format(
                        name, namespace, exc.body
                    ),
                    error=exc.status,
                    status=exc.status,
                    reason=exc.reason,
                )
            except Exception as exc:
                self.fail_json(
                    msg="Failed to retrieve Template with name '{0}' in namespace '{1}': {2}".format(
                        name, namespace, to_native(exc)
                    ),
                    error="",
                    status="",
                    reason="",
                )
        else:
            self.fail_json(
                "One of resource_definition, src, or name and namespace must be provided"
            )

        if parameter_file:
            parameters = self.parse_dotenv_and_merge(parameters, parameter_file)

        for k, v in parameters.items():
            template = self.update_template_param(template, k, v)

        result = {"changed": False}

        try:
            response = v1_processed_templates.create(
                body=template, namespace=namespace
            ).to_dict()
        except DynamicApiError as exc:
            self.fail_json(
                msg="Server failed to render the Template: {0}".format(exc.body),
                error=exc.status,
                status=exc.status,
                reason=exc.reason,
            )
        except Exception as exc:
            self.fail_json(
                msg="Server failed to render the Template: {0}".format(to_native(exc)),
                error="",
                status="",
                reason="",
            )
        result["message"] = ""
        if "message" in response:
            result["message"] = response["message"]
        result["resources"] = response["objects"]

        if state != "rendered":
            self.create_resources(response["objects"])

        self.exit_json(**result)

    def create_resources(self, definitions):
        params = {"namespace": self.params.get("namespace_target")}

        self.params["apply"] = False
        self.params["validate"] = None

        changed = False
        results = []

        flattened_definitions = []
        for definition in definitions:
            if definition is None:
                continue
            kind = definition.get("kind")
            if kind and kind.endswith("List"):
                flattened_definitions.extend(self.flatten_list_kind(definition, params))
            else:
                flattened_definitions.append(self.merge_params(definition, params))

        for definition in flattened_definitions:
            result = self.perform_action(definition, self.params)
            changed = changed or result["changed"]
            results.append(result)

        if len(results) == 1:
            self.exit_json(**results[0])

        self.exit_json(**{"changed": changed, "result": {"results": results}})

    def update_template_param(self, template, k, v):
        for i, param in enumerate(template["parameters"]):
            if param["name"] == k:
                template["parameters"][i]["value"] = v
                return template
        return template

    def parse_dotenv_and_merge(self, parameters, parameter_file):
        import re

        DOTENV_PARSER = re.compile(
            r"(?x)^(\s*(\#.*|\s*|(export\s+)?(?P<key>[A-z_][A-z0-9_.]*)=(?P<value>.+?)?)\s*)[\r\n]*$"
        )
        path = os.path.normpath(parameter_file)
        if not os.path.exists(path):
            self.fail(msg="Error accessing {0}. Does the file exist?".format(path))
        try:
            with open(path, "r") as f:
                multiline = ""
                for line in f.readlines():
                    line = line.strip()
                    if line.endswith("\\"):
                        multiline += " ".join(line.rsplit("\\", 1))
                        continue
                    if multiline:
                        line = multiline + line
                        multiline = ""
                    match = DOTENV_PARSER.search(line)
                    if not match:
                        continue
                    match = match.groupdict()
                    if match.get("key"):
                        if match["key"] in parameters:
                            self.fail_json(
                                msg="Duplicate value for '{0}' detected in parameter file".format(
                                    match["key"]
                                )
                            )
                        parameters[match["key"]] = match["value"]
        except IOError as exc:
            self.fail(msg="Error loading parameter file: {0}".format(exc))
        return parameters
