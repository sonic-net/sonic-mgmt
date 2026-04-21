# -*- coding: utf-8 -*-
# Copyright 2025 Red Hat, Inc.
# Apache License 2.0 (see LICENSE or http://www.apache.org/licenses/LICENSE-2.0)

from typing import Dict, Tuple, Optional

from ansible_collections.kubernetes.core.plugins.module_utils.k8s import service


# Copied from
# https://github.com/ansible-collections/kubernetes.core/blob/d329e7ee42799ae9d86b54cf2c7dfc8059103504/plugins/module_utils/k8s/service.py#L493
# Removed this once this fix was merged into kubernetes.core.
def _diff_objects(
    existing: Dict, new: Dict, hidden_fields: Optional[list] = None
) -> Tuple[bool, Dict]:
    result = {}
    diff = service.recursive_diff(existing, new)
    if not diff:
        return True, result

    result["before"] = service.hide_fields(diff[0], hidden_fields)
    result["after"] = service.hide_fields(diff[1], hidden_fields)

    if list(result["after"].keys()) == ["metadata"] and list(
        result["before"].keys()
    ) == ["metadata"]:
        # If only metadata.generation and metadata.resourceVersion changed, ignore it
        ignored_keys = set(["generation", "resourceVersion"])

        if set(result["after"]["metadata"].keys()).issubset(ignored_keys) and set(
            result["before"]["metadata"].keys()
        ).issubset(ignored_keys):
            return True, result

    return False, result


service.diff_objects = _diff_objects


def _patch_diff_objects():
    """_dummy is required to satisfy the unused import linter and the ansible-doc sanity check."""
    pass
