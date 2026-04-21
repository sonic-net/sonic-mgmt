#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_event_logs_facts
short_description: Get event logs from VSP One SDS Block and Cloud systems.
description:
  - Get event logs from storage system with various filtering options
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/events_log_facts.yml)
version_added: "4.1.0"
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: full
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.sdsb_connection_info
options:
  spec:
    description: Specification for retrieving CHAP user information.
    type: dict
    required: false
    suboptions:
      severity:
          description: Filter events by exact severity level. If you specify severity_ge, you can't specify this.
          required: false
          type: str
          choices: [ 'Info', 'Warning', 'Error', 'Critical' ]
      severity_ge:
          description: Filter events by severity level greater than or equal to. If you specify severity, you can't specify this.
          required: false
          type: str
          choices: [ 'Info', 'Warning', 'Error', 'Critical' ]
      start_time:
          description: Start time for event log retrieval (ISO 8601 format)
          required: false
          type: str
      end_time:
          description: End time for event log retrieval (ISO 8601 format)
          required: false
          type: str
      max_events:
          description: Maximum number of events to retrieve (1-1000)
          required: false
          type: int
          default: 1000
"""

EXAMPLES = """
- name: Retrieve information about all Event logss
  hitachivantara.vspone_block.sds_block.hv_sds_block_event_logs_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Retrieve information about Event logs by specifying optional parameters
  hitachivantara.vspone_block.sds_block.hv_sds_block_event_logs_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
        severity: "Info"
        severity_ge: "Warning"
        start_time: "2023-01-01T00:00:00Z"
        end_time: "2023-12-31T23:59:59Z"
        max_events: 10
"""

RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the Event Logs.
  returned: always
  type: dict
  contains:
    event_logs:
      description: Wrapper for event logs results.
      type: dict
      contains:
        data:
          description: List of event log entries.
          type: list
          elements: dict
          contains:
            id:
              description: Unique identifier for the event log entry.
              type: str
              sample: "ec99bd4b-68f0-4b3b-899c-a70744f16e5e"
            time:
              description: Time when the event occurred (ISO 8601 format).
              type: str
              sample: "2025-11-26T10:41:47Z"
            time_in_microseconds:
              description: Timestamp in microseconds.
              type: int
              sample: 1764153707900467
            category:
              description: Category of the event.
              type: str
              sample: "Service"
            event_name:
              description: Name or short description of the event.
              type: str
              sample: "Successful completion of job"
            message_id:
              description: Message identifier code.
              type: str
              sample: "KARS13010-I"
            severity:
              description: Severity level as a string.
              type: str
              sample: "Info"
            message:
              description: Detailed message about the event.
              type: str
              sample: "The job has completed successfully. (Operation = CHAP_USER_DELETE, Job ID = 286bf06d-811c-4359-8cc7-c66417884866)"
            solution:
              description: Suggested solution or resolution for the event, if any.
              type: str
              sample: ""
            node_location:
              description: Unique identifier of the node location associated with the event.
              type: str
              sample: "152d2d10-4e18-44aa-86a4-fbd4f7e4cb08"
            event_type:
              description: Type of the event (if available).
              type: str
              sample: ""
            severity_level:
              description: Numerical or categorized severity level (if available).
              type: str
              sample: ""
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBEventLogsArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_event_logs_reconciler import (
    SDSBEventLogsReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBEventLogsFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBEventLogsArguments().event_log_facts()
        self.logger.writeDebug(
            f"MOD:hv_sds_block_event_log_facts:argument_spec= {self.argument_spec}"
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_event_log_fact_spec()
        self.logger.writeDebug(f"MOD:hv_sds_block_event_log_facts:spec= {self.spec}")

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Event Log Facts ===")
        event_logs = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBEventLogsReconciler(self.connection_info)
            event_logs = sdsb_reconciler.get_event_logs(self.spec)

            self.logger.writeDebug(
                f"MOD:hv_sds_block_event_logs_facts:event_logs= {event_logs}"
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Event Log Facts ===")
            self.module.fail_json(msg=str(e))

        data = {"event_logs": event_logs}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Event Log Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBEventLogsFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
