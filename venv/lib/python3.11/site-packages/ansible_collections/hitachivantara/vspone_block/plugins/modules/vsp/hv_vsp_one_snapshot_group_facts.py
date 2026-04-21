#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_vsp_one_snapshot_group_facts
short_description: Retrieves snapshot group information from VSP E series and VSP One Block 20 series storage systems.
description:
  - This module retrieves snapshot group information from VSP E series and VSP One Block 20 series storage systems.
  - Utilizes the Hitachi Virtual Storage Platform One Simple API for snapshot group facts retrieval across VSP one B20 series and VSP E series models.
  - Retrieves detailed information about snapshot groups including individual snapshots within each group.
  - For usage examples, visit
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/vsp_one_snapshot_group_facts.yml)
version_added: '4.4.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Specifies whether the module operates in check mode.
    support: full
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.connection_info
options:
  spec:
    description: Query parameters for retrieving snapshot group information.
    type: dict
    required: false
    suboptions:
      snapshot_group_name:
        description: Snapshot group name. Information about the snapshot group that is a perfect match with the specified value is obtained.
        type: str
        required: false
      include_snapshots:
        description: When set to true, includes detailed information about individual snapshots within each snapshot group.
        type: bool
        required: false
        default: false
"""
EXAMPLES = """
- name: Get snapshot groups with specific snapshot group name
  hitachivantara.vspone_block.vsp.hv_vsp_one_snapshot_group_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      snapshot_group_name: "test_sp_group"

- name: Get all snapshot groups with detailed snapshot information
  hitachivantara.vspone_block.vsp.hv_vsp_one_snapshot_group_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      include_snapshots: true
"""

RETURN = """
ansible_facts:
  description: Facts about snapshot groups retrieved from the storage system.
  returned: always
  type: dict
  contains:
    snapshots:
      description: List of snapshot groups retrieved from the storage system.
      returned: always
      type: list
      elements: dict
      contains:
        name:
          description: Name of the snapshot group.
          type: str
          sample: "Thin-AnsibleAuto222303"
        snapshots:
          description: List of snapshots within the snapshot group.
          type: list
          elements: dict
          contains:
            master_volume_id:
              description: Master volume ID of the snapshot.
              type: int
              sample: 8009
            snapshot_id:
              description: Snapshot ID. The mirror unit number is obtained.
              type: int
              sample: 41
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_one_snapshot import (
    VspOneSnapshotReconciler,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPOneSnapshotArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPOneSnapshotGroupFacts:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPOneSnapshotArguments().get_vsp_one_snapshot_group_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            params_manager = VSPParametersManager(self.module.params)
            self.spec = params_manager.get_vsp_one_snapshot_group_facts_spec()
            self.connection_info = params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of VSP One Snapshot Group Facts Retrieval ===")
        snapshots = None
        registration_message = validate_ansible_product_registration()

        try:
            sng_grp_reconciler = VspOneSnapshotReconciler(self.connection_info)
            snapshots = sng_grp_reconciler.get_snapshot_groups_facts_reconcile(
                self.spec
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo(
                "=== End of VSP One Snapshot Group Facts Retrieval ==="
            )
            self.module.fail_json(msg=str(e))

        response = {
            "snapshots": snapshots,
        }
        if registration_message:
            response["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of VSP One Snapshot Group Facts Retrieval ===")
        self.module.exit_json(changed=False, ansible_facts=response)


def main():
    obj_store = VSPOneSnapshotGroupFacts()
    obj_store.apply()


if __name__ == "__main__":
    main()
