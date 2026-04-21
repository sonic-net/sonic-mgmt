#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: iot_fabric_rep_rings_id
short_description: Resource module for Iot Fabric Rep
  Rings Id
description:
  - Manage operation delete of the resource Iot Fabric
    Rep Rings Id. - > This API deletes the REP ring
    configured in the FABRIC deployment for the given
    id. The id of configured REP ring can be retrieved
    using the API /dna/intent/api/v1/iot/repRings/query.The
    taskid returned can be used to monitor the status
    of delete operation using following API -/intent/api/v1/task/{taskId}.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Ring ID of configured
      REP ring can be fetched using the API `/dna/intent/api/v1/iot/repRings/query`.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Industrial
      Configuration DeleteREPRingConfiguredInTheFABRICDeployment
    description: Complete reference of the DeleteREPRingConfiguredInTheFABRICDeployment
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-rep-ring-configured-in-the-fabric-deployment
notes:
  - SDK Method used are
    industrial_configuration.IndustrialConfiguration.delete_r_e_p_ring_configured_in_the_f_a_b_r_i_c_deployment,
  - Paths used are
    delete /dna/intent/api/v1/iot/fabric/repRings/{id},
"""

EXAMPLES = r"""
---
- name: Delete by id
  cisco.dnac.iot_fabric_rep_rings_id:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    id: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
