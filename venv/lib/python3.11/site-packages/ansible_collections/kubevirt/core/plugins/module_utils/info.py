# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat, Inc.
# Apache License 2.0 (see LICENSE or http://www.apache.org/licenses/LICENSE-2.0)


from ansible_collections.kubernetes.core.plugins.module_utils.k8s.client import (
    get_api_client,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.exceptions import (
    CoreException,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.service import (
    K8sService,
)


INFO_ARG_SPEC = {
    "api_version": {"default": "kubevirt.io/v1"},
    "name": {},
    "namespace": {},
    "label_selectors": {"type": "list", "elements": "str", "default": []},
    "field_selectors": {"type": "list", "elements": "str", "default": []},
    "wait": {"type": "bool"},
    "wait_sleep": {"type": "int", "default": 5},
    "wait_timeout": {"type": "int", "default": 120},
}


def execute_info_module(module, kind, wait_condition):
    """
    execute_info_module runs the lookup of resources.
    """
    try:
        client = get_api_client(module)
        svc = K8sService(client, module)
        facts = svc.find(
            kind=kind,
            api_version=module.params["api_version"],
            name=module.params["name"],
            namespace=module.params["namespace"],
            label_selectors=module.params["label_selectors"],
            field_selectors=module.params["field_selectors"],
            wait=module.params["wait"],
            wait_sleep=module.params["wait_sleep"],
            wait_timeout=module.params["wait_timeout"],
            hidden_fields=module.params["hidden_fields"],
            condition=wait_condition,
        )
        module.exit_json(changed=False, **facts)
    except CoreException as exc:
        module.fail_from_exception(exc)
