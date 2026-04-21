#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: reserve_ip_subpool_delete
short_description: Resource module for Reserve Ip Subpool
  Delete
description:
  - Manage operation delete of the resource Reserve
    Ip Subpool Delete.
  - API to delete the reserved ip subpool.
version_added: '4.0.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Id of reserve ip
      subpool to be deleted.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings ReleaseReserveIPSubpool
    description: Complete reference of the ReleaseReserveIPSubpool
      API.
    link: https://developer.cisco.com/docs/dna-center/#!release-reserve-ip-subpool
notes:
  - SDK Method used are
    network_settings.NetworkSettings.release_reserve_ip_subpool,
  - Paths used are
    delete /dna/intent/api/v1/reserve-ip-subpool/{id},
"""

EXAMPLES = r"""
---
- name: Delete by id
  cisco.dnac.reserve_ip_subpool_delete:
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
      "executionId": "string",
      "executionStatusUrl": "string",
      "message": "string"
    }
"""
