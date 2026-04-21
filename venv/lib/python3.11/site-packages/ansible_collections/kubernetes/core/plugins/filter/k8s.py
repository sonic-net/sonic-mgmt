# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type


from ansible.errors import AnsibleFilterError
from ansible_collections.kubernetes.core.plugins.module_utils.hashes import (
    generate_hash,
)


def k8s_config_resource_name(resource):
    """
    Generate resource name for the given resource of type ConfigMap, Secret
    """
    try:
        return resource["metadata"]["name"] + "-" + generate_hash(resource)
    except KeyError:
        raise AnsibleFilterError(
            "resource must have a metadata.name key to generate a resource name"
        )


# ---- Ansible filters ----
class FilterModule(object):
    def filters(self):
        return {"k8s_config_resource_name": k8s_config_resource_name}
