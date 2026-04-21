#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_protection_domain
short_description: Manages protection domains on VSP One SDS Block and Cloud systems.
description:
    - This module manages protection domains including creation, modification, and data relocation operations on Hitachi SDS Block storage systems.
    - For examples, go to URL
        U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/protection_domain.yml)
version_added: "4.4.0"
author:
    - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
    - python >= 3.9
attributes:
    check_mode:
        description: Determines if the module should run in check mode.
        support: none
extends_documentation_fragment:
    - hitachivantara.vspone_block.common.sdsb_connection_info
options:
    state:
        description: The desired state of the protection domain.
        type: str
        required: false
        default: present
        choices: ["present", "resume_drive_data_relocation", "suspend_drive_data_relocation"]
    spec:
        description: Specification for the protection domain settings.
        type: dict
        required: true
        suboptions:
            id:
                description: The ID of the protection domain.
                type: str
                required: false
            async_processing_resource_usage_rate:
                description: The resource usage rate for asynchronous processing choices are C(very_high), C(high), C(middle), C(low).
                type: str
                required: false
"""

EXAMPLES = """
- name: Configure protection domain settings
  hitachivantara.vspone_block.hv_sds_block_protection_domain:
    connection_info:
      address: "{{ management_address }}"
      username: "{{ management_username }}"
      password: "{{ management_password }}"
    state: present
    spec:
      id: "PD001"
      async_processing_resource_usage_rate: "high"

- name: Resume drive data relocation for protection domain
  hitachivantara.vspone_block.hv_sds_block_protection_domain:
    connection_info:
      address: "{{ management_address }}"
      username: "{{ management_username }}"
      password: "{{ management_password }}"
    state: resume_drive_data_relocation
    spec:
      id: "PD001"

- name: Suspend drive data relocation for protection domain
  hitachivantara.vspone_block.hv_sds_block_protection_domain:
    connection_info:
      address: "{{ management_address }}"
      username: "{{ management_username }}"
      password: "{{ management_password }}"
    state: suspend_drive_data_relocation
    spec:
      id: "PD001"
"""

RETURN = r"""
protection_domain_settings:
    description: >
        Dictionary containing the discovered properties of the protection domains.
    returned: always
    type: dict
    contains:
        id:
            description: Unique identifier for the protection domain.
            type: str
            sample: "8a047591-7acd-4d61-8b2b-39d703b1ed11"
        name:
            description: Name of the protection domain.
            type: str
            sample: "SC01-PD01"
        redundant_policy:
            description: Redundancy policy used by the protection domain.
            type: str
            sample: "Mirroring"
        redundant_type:
            description: Redundancy type used in the protection domain.
            type: str
            sample: "Duplication"
        drive_data_relocation_status:
            description: Current status of drive data relocation.
            type: str
            sample: "Stopped"
        drive_data_relocation_progress_rate:
            description: Progress percentage of data relocation. -1 if not active.
            type: int
            sample: -1
        rebuild_status:
            description: Current rebuild status.
            type: str
            sample: "Error"
        rebuild_progress_rate:
            description: Rebuild progress rate as a percentage.
            type: int
            sample: 0
        memory_mode:
            description: Memory mode used in the protection domain.
            type: str
            sample: "VolatileMemory"
        async_processing_resource_usage_rate:
            description: Usage level of asynchronous processing resources.
            type: str
            sample: "High"
        number_of_fault_domains:
            description: The total number of fault domains in the protection domain.
            type: int
            sample: 1
        number_of_fault_sets:
            description: The total number of fault sets in the protection domain. -1 if not applicable.
            type: int
            sample: -1
        storage_controller_clustering_policy:
            description: Clustering policy of the storage controllers.
            type: str
            sample: "OneRedundantStorageNode"
        minimum_memory_size:
            description: Minimum memory size in MB.
            type: int
            sample: 196608
        is_fast_rebuild_enabled:
            description: Whether fast rebuild is enabled for the protection domain.
            type: bool
            sample: true
        total_physical_capacity:
            description: Total physical capacity in MB.
            type: int
            sample: 36628608
"""

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    ProtectionDomainSettingsArgs,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_storage_cluster_mgmt_reconciler import (
    SDSBStorageControllerReconciler,
)
from ansible.module_utils.basic import AnsibleModule


class SDSBProtectionDomainManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = ProtectionDomainSettingsArgs().protection_domain_settings()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            parameter_manager = SDSBParametersManager(self.module.params)
            self.connection_info = parameter_manager.get_connection_info()
            self.spec = parameter_manager.protection_domain_settings_spec()
            self.state = parameter_manager.get_state()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo(
            "=== Start of SDSB Protection Domain Configuration Operation ==="
        )
        protection_domain_settings = None
        registration_message = validate_ansible_product_registration()
        try:
            sdsb_reconciler = SDSBStorageControllerReconciler(self.connection_info)
            protection_domain_settings = sdsb_reconciler.protection_domain_reconcile(
                self.state, self.spec
            )
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo(
                "=== End of SDSB Protection Domain Configuration Operation ==="
            )
            self.module.fail_json(msg=str(e))

        data = {
            "changed": self.connection_info.changed,
            "protection_domain_settings": protection_domain_settings,
            "message": self.spec.comment if self.spec.comment else "",
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo(
            "=== End of SDSB Protection Domain Configuration Operation ==="
        )
        self.module.exit_json(**data)


def main():
    obj_store = SDSBProtectionDomainManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
