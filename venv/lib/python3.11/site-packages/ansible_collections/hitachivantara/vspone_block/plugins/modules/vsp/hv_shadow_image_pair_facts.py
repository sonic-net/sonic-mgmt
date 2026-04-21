#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_shadow_image_pair_facts
short_description: Retrieves information about shadow image pairs from Hitachi VSP storage systems.
description:
  - This module retrieves information about shadow image pairs from Hitachi VSP storage systems.
  - It provides details about shadow image pair such as ID, status and other relevant information.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/shadow_image_pair_facts.yml)
version_added: '3.0.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: full
extends_documentation_fragment:
- hitachivantara.vspone_block.common.gateway_note
- hitachivantara.vspone_block.common.connection_with_type
notes:
  - The output parameters C(entitlement_status), C(subscriber_id) and C(partner_id) were removed in version 3.4.0.
    They were also deprecated due to internal API simplification and are no longer supported.
options:
  storage_system_info:
    description: Information about the storage system. This field is an optional field.
    type: dict
    required: false
    suboptions:
      serial:
        description: The serial number of the storage system.
        type: str
        required: false
  spec:
    description: Specification for retrieving shadow image pair information.
    type: dict
    required: false
    suboptions:
      primary_volume_id:
        type: str
        description: Primary volume id.
          Required for the Get ShadowImage pairs by P-VOL task.
        required: false
      copy_group_name:
        type: str
        description: Name of the copy group.
          Required for the Get ShadowImage pairs by copy_group_name and copy_pair_name task.
        required: false
      copy_pair_name:
        type: str
        description: Name of the copy pair.
          Required for the Get ShadowImage pairs by copy_group_name and copy_pair_name task.
        required: false
      refresh:
        type: bool
        description: Whether refresh pairs
          Required for the Get all ShadowImage pairs along with refresh task.
        required: false
"""

EXAMPLES = """
- name: Retrieve information about all shadow image pairs
  hitachivantara.vspone_block.vsp.hv_shadow_image_pair_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"

    storage_system_info:
      serial: 811150

- name: Retrieve information about a specific shadow image pair
  hitachivantara.vspone_block.vsp.hv_shadow_image_pair_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    spec:
      primary_volume_id: 274

- name: Retrieve information about a specific shadow image pair using copy group name and copy pair name
  hitachivantara.vspone_block.vsp.hv_shadow_image_pair_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    spec:
      copy_group_name: "copy_group_1"
      copy_pair_name: "copy_pair_1"
"""

RETURN = """
ansible_facts:
  description: List of shadow image pairs.
  returned: success
  type: dict
  contains:
    data:
      description: List of shadow image pairs.
      returned: success
      type: list
      elements: dict
      contains:
        consistency_group_id:
          description: Consistency group ID.
          type: int
          sample: -1
        copy_group_name:
          description: Copy group name.
          type: str
          sample: "SI_768"
        copy_pace_track_size:
          description: Copy pace track size.
          type: str
          sample: "MEDIUM"
        copy_pair_name:
          description: Copy pair name.
          type: str
          sample: "SI_768"
        copy_rate:
          description: Copy rate.
          type: int
          sample: 100
        mirror_unit_id:
          description: Mirror unit ID.
          type: int
          sample: 0
        primary_volume_id_hex:
          description: Primary hex volume ID in hexadecimal.
          type: str
          sample: "00:03:00"
        primary_volume_id:
          description: Primary volume ID.
          type: int
          sample: 768
        pvol_host_groups:
          description: Primary volume host groups.
          type: list
          elements: dict
          sample: []
        pvol_iscsi_targets:
          description: Primary volume iSCSI targets.
          type: list
          elements: dict
          sample: [{"host_group_name": "iscsi176", "host_group_number": 2, "lun": 0, "port_id": "CL2-C"}]
          contains:
            host_group_name:
              description: Host group name.
              type: str
            host_group_number:
              description: Host group number.
              type: int
            lun:
              description: LUN number.
              type: int
            port_id:
              description: Port ID.
              type: str
        pvol_nvm_subsystem_name:
          description: Primary volume NVM subsystem name.
          type: str
          sample: ""
        resource_id:
          description: Resource ID.
          type: str
          sample: "localpair-2749fed78e8d23a61ed17a8af71c85f8"
        secondary_volume_id_hex:
          description: Secondary hex volume ID in hexadecimal.
          type: str
          sample: "00:03:03"
        secondary_volume_id:
          description: Secondary volume ID.
          type: int
          sample: 771
        status:
          description: Status of the shadow image pair.
          type: str
          sample: "PAIR"
        storage_serial_number:
          description: Storage serial number.
          type: str
          sample: "810045"
        svol_host_groups:
          description: Secondary volume host groups.
          type: list
          elements: dict
          sample: []
        svol_iscsi_targets:
          description: Secondary volume iSCSI targets.
          type: list
          elements: dict
          sample: [{"host_group_name": "iscsi176", "host_group_number": 2, "lun": 3, "port_id": "CL2-C"}]
          contains:
            host_group_name:
              description: Host group name.
              type: str
            host_group_number:
              description: Host group number.
              type: int
            lun:
              description: LUN number.
              type: int
            port_id:
              description: Port ID.
              type: str
        svol_nvm_subsystem_name:
          description: Secondary volume NVM subsystem name.
          type: str
          sample: ""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPShadowImagePairArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_shadow_image_pair_reconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPShadowImagePairManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = (
            VSPShadowImagePairArguments().get_all_shadow_image_pair_fact()
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        self.params_manager = VSPParametersManager(self.module.params)
        self.spec = self.params_manager.set_shadow_image_pair_fact_spec()
        self.logger.writeInfo(f"{self.spec} SPEC")

    def apply(self):
        self.logger.writeInfo("=== Start of Shadow Image Pair Facts ===")
        registration_message = validate_ansible_product_registration()
        shadow_image_pair_data = None

        try:

            shadow_image_pair_data = self.gateway_shadow_image_pair_read()

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of Shadow Image Pair Facts ===")
            self.module.fail_json(msg=str(e))

        data = {"data": shadow_image_pair_data}

        if not shadow_image_pair_data:
            if self.spec.pvol is not None:
                data["comment"] = "Data not available with pvol " + str(self.spec.pvol)
            elif (
                self.spec.copy_group_name is not None
                and self.spec.copy_pair_name is not None
            ):
                data["comment"] = (
                    "Shadow image pair not available with copy group name "
                    + str(self.spec.copy_group_name)
                    + " and copy pair name "
                    + str(self.spec.copy_pair_name)
                )
            else:
                data["comment"] = "Couldn't read shadow image pairs. "
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of Shadow Image Pair Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)

    def gateway_shadow_image_pair_read(self):

        reconciler = vsp_shadow_image_pair_reconciler.VSPShadowImagePairReconciler(
            self.params_manager.connection_info,
            self.params_manager.storage_system_info.serial,
        )

        result = reconciler.shadow_image_pair_facts(self.spec)
        return result


def main():
    obj_store = VSPShadowImagePairManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
