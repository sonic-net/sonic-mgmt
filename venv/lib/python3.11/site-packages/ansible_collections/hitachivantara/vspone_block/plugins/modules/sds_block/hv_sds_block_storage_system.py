#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_storage_system
short_description: Manages storage system settings on VSP One SDS Block and Cloud systems.
description:
    - This module manages storage system configuration including certificate management,
      cache settings, and other system-level configurations on VSP One SDS Block and Cloud systems.
    - For examples, see the project repository on GitHub.
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
        description: >
            Desired state of the storage system choices are C(present), C(absent), C(delete_root_certificate),
            C(import_root_certificate), C(download_root_certificate).
        type: str
        choices: ["present", "absent", "delete_root_certificate", "import_root_certificate", "download_root_certificate"]
        default: 'present'
    spec:
        description:
            - Specification for storage system configuration settings.
        type: dict
        required: false
        suboptions:
            root_certificate_file_path:
                description:
                    - Path to the root certificate file for SSL/TLS authentication.
                type: str
                required: false
            download_path:
                description:
                    - Local path where files will be downloaded.
                type: str
                required: false
            enable_write_back_mode_with_cache_protection:
                description:
                    - Enable write-back mode with cache protection for improved performance.
                type: bool
                required: false
            force:
                description:
                    - Force the operation even if it might cause data loss or system disruption.
                type: bool
                required: false
"""

EXAMPLES = """
- name: Configure storage system with write-back cache protection
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_system:
    connection_info:
      address: "{{ storage_system_ip }}"
      username: "{{ username }}"
      password: "{{ password }}"
    state: present
    spec:
      enable_write_back_mode_with_cache_protection: true

- name: Import root certificate
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_system:
    connection_info:
      address: "{{ storage_system_ip }}"
      username: "{{ username }}"
      password: "{{ password }}"
    state: import_root_certificate
    spec:
      root_certificate_file_path: "/path/to/certificate.pem"

- name: Download root certificate
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_system:
    connection_info:
      address: "{{ storage_system_ip }}"
      username: "{{ username }}"
      password: "{{ password }}"
    state: download_root_certificate
    spec:
      download_path: "/local/path/certificates/"

- name: Delete root certificate
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_system:
    connection_info:
      address: "{{ storage_system_ip }}"
      username: "{{ username }}"
      password: "{{ password }}"
    state: delete_root_certificate
    spec:
      force: true
"""


RETURN = r"""
storage_system:
    description: The storage system information.
    returned: always
    type: dict
    contains:
        id:
            description: Storage system UUID.
            type: str
            sample: "20ea66d2-99a5-43ed-a733-304d99dafe42"
        internal_id:
            description: Internal identifier for the storage system.
            type: str
            sample: "095562"
        storage_device_id:
            description: Storage device identifier.
            type: str
            sample: "400000095562"
        model_name:
            description: Model name of the storage system.
            type: str
            sample: "VSSBB1"
        nickname:
            description: User-friendly name for the storage system.
            type: str
            sample: "SC01"
        service_id:
            description: Service identifier if present.
            type: str
            sample: ""
        software_version:
            description: Software version installed on the storage system.
            type: str
            sample: "01.18.01.40"
        status:
            description: Operational status of the storage system.
            type: str
            sample: "Ready"
        status_summary:
            description: Summary of health/status.
            type: str
            sample: "Normal"
        meta_data_redundancy_of_cache_protection_summary:
            description: Summary value for cache protection metadata redundancy.
            type: int
            sample: 1
        number_of_fault_domains:
            description: Number of fault domains.
            type: int
            sample: 1
        number_of_ready_storage_nodes:
            description: Number of ready storage nodes.
            type: int
            sample: 3
        number_of_total_servers:
            description: Number of total servers.
            type: int
            sample: 14
        number_of_total_storage_nodes:
            description: Number of total storage nodes.
            type: int
            sample: 3
        number_of_total_volumes:
            description: Number of total volumes.
            type: int
            sample: 30
        free_pool_capacity:
            description: Free pool capacity in bytes (or unit as returned by API).
            type: int
            sample: 9518460
        free_pool_capacity_in_mb:
            description: Free pool capacity in megabytes.
            type: int
            sample: 9518460
        total_pool_capacity:
            description: Total pool capacity in bytes (or unit as returned by API).
            type: int
            sample: 9519048
        total_pool_capacity_in_mb:
            description: Total pool capacity in megabytes.
            type: int
            sample: 9519048
        total_pool_physical_capacity:
            description: Total physical capacity of the pool in bytes (or unit as returned by API).
            type: int
            sample: 30523824
        total_pool_physical_capacity_in_mb:
            description: Total physical capacity in megabytes.
            type: int
            sample: 30523824
        total_pool_raw_capacity:
            description: Total raw capacity of the pool in bytes (or unit as returned by API).
            type: int
            sample: 24226272
        total_pool_raw_capacity_in_mb:
            description: Total raw capacity in megabytes.
            type: int
            sample: 24226272
        used_pool_capacity:
            description: Used pool capacity in bytes (or unit as returned by API).
            type: int
            sample: 588
        used_pool_capacity_in_mb:
            description: Used pool capacity in megabytes.
            type: int
            sample: 588
        system_requirements_file_version:
            description: Version of the system requirements file.
            type: int
            sample: 20250830
        saving_effects:
            description: Efficiency and saving related metrics.
            type: dict
            contains:
                efficiency_data_reduction:
                    description: Efficiency data reduction percentage.
                    type: int
                    sample: 100
                total_efficiency:
                    description: Total efficiency metric (as returned by API).
                    type: int
                    sample: 75385
        write_back_mode_with_cache_protection:
            description: Write-back mode with cache protection status.
            type: str
            sample: "Enabled"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_storage_cluster_mgmt_reconciler import (
    SDSBStorageControllerReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBStorageSystemArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SBSBStorageSystemFactManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBStorageSystemArguments().storage_system_version_fact()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.storage_system_spec()
        self.state = parameter_manager.get_state()

    def apply(self):
        self.logger.writeInfo(
            "=== Start of SDSB Storage System Configuration Operation ==="
        )
        storage_system = None
        registration_message = validate_ansible_product_registration()
        try:
            sdsb_reconciler = SDSBStorageControllerReconciler(self.connection_info)
            storage_system = sdsb_reconciler.storage_system_reconciler(
                self.state, self.spec
            )
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo(
                "=== End of SDSB Storage System Configuration Operation ==="
            )
            self.module.fail_json(msg=str(e))

        data = {
            "changed": self.connection_info.changed,
            "storage_system": storage_system,
            "message": self.spec.comment if self.spec and self.spec.comment else None,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo(
            "=== End of SDSB Storage System Configuration Operation ==="
        )
        self.module.exit_json(**data)


def main():
    obj_store = SBSBStorageSystemFactManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
