#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_job_facts
short_description: Retrieves information about storage system jobs.
description:
  - This module retrieves information about jobs.
  - It provides details about a job such as ID, state, status and other details.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/job_facts.yml)
version_added: '4.1.0'
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
    description: Specification for retrieving job information.
    type: dict
    required: false
    suboptions:
      id:
        description: The ID of the job.
        type: str
        required: false
      count:
        description: The number of jobs to be retrieved.
        type: int
        required: false
"""

EXAMPLES = """
- name: Retrieve information about most recent 100 jobs
  hitachivantara.vspone_block.sds_block.hv_sds_block_job_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Retrieve information about most recent 10 jobs
  hitachivantara.vspone_block.sds_block.hv_sds_block_job_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      count: 10

- name: Retrieve information about job by fault job ID
  hitachivantara.vspone_block.sds_block.hv_sds_block_job_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "c0b833cd-1fee-417d-bbf2-d25aac767ad4"
"""

RETURN = """
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the jobs.
  returned: always
  type: dict
  contains:
    jobs:
      description: A list of jobs.
      type: list
      elements: dict
      contains:
        job_info:
          description: Information about the job.
          type: dict
          contains:
            completed_time:
              description: The time when the job was completed. Returns null if the job is not completed.
              type: str
              sample: "2025-07-14T12:46:39Z"
            created_time:
              description: The time when the job was created.
              type: str
              sample: "2025-07-14T12:46:39Z"
            job_id:
              description: Job ID.
              type: str
              sample: "9595bc64-cd96-428c-8589-725831c36102"
            state:
              description: The job status.
              type: str
              sample: "Succeeded"
            status:
              description: The progress of the job.
              type: str
              sample: "Completed"
            updated_time:
              description: The time when the job state was updated.
              type: str
              sample: "2025-07-14T12:46:39Z"
            affected_resources:
              description: List of resources affected by the job.
              type: list
              elements: dict
              sample: []
            error:
              description: Error details if the job failed. Empty dict if no error.
              type: dict
              sample: {}
            request:
              description: The HTTP request information that initiated the job.
              type: dict
              contains:
                request_body:
                  description: Body of the request that started the job.
                  type: str
                  sample: ""
                request_method:
                  description: HTTP method used for the request.
                  type: str
                  sample: "POST"
                request_url:
                  description: Request URL path on the appliance.
                  type: str
                  sample: "/ConfigurationManager/simple/v1/objects/server-certificate/actions/import/invoke"
            self:
              description: API path to the job resource.
              type: str
              sample: "/ConfigurationManager/simple/v1/objects/jobs/0e9944e4-9a98-4533-ae5c-32ddd7e4ddd2"
            user_id:
              description: Identifier of the user who initiated the job.
              type: str
              sample: "testUser"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_job import (
    SDSBJobReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBJobArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBJobFactsManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBJobArguments().job_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            parameter_manager = SDSBParametersManager(self.module.params)
            self.connection_info = parameter_manager.get_connection_info()
            self.spec = parameter_manager.get_job_fact_spec()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Job Facts ===")
        jobs = None
        registration_message = validate_ansible_product_registration()
        try:
            sdsb_reconciler = SDSBJobReconciler(self.connection_info)
            jobs = sdsb_reconciler.get_jobs(self.spec)
        except Exception as e:
            self.module.fail_json(msg=str(e))
            self.logger.writeInfo("=== End of SDSB Job Facts ===")
            self.logger.writeException(e)

        data = {
            "jobs": jobs,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of SDSB Job Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBJobFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
