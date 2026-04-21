#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: ipam_global_ip_address_pools_global_ip_address_pool_id_subpools_info
short_description: Information module for Ipam Global
  Ip Address Pools Global Ip Address Pool Id Subpools
description:
  - Get all Ipam Global Ip Address Pools Global Ip Address
    Pool Id Subpools. - > Retrieves subpools IDs of
    a global IP address pool. The IDs can be fetched
    with `/dna/intent/api/v1/ipam/siteIpAddressPools/{id}`.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  globalIpAddressPoolId:
    description:
      - GlobalIpAddressPoolId path parameter. The `id`
        of the global IP address pool for which to retrieve
        subpool IDs.
    type: str
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page; the first record is numbered
        1.
    type: int
  limit:
    description:
      - Limit query parameter. The number of records
        to show for this page; the minimum is 1, and
        the maximum is 500.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Network
      Settings RetrievesSubpoolsIDsOfAGlobalIPAddressPool
    description: Complete reference of the RetrievesSubpoolsIDsOfAGlobalIPAddressPool
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-subpools-i-ds-of-a-global-ip-address-pool
notes:
  - SDK Method used are
    network_settings.NetworkSettings.retrieves_subpools_ids_of_a_global_ip_address_pool,
  - Paths used are
    get /dna/intent/api/v1/ipam/globalIpAddressPools/{globalIpAddressPoolId}/subpools,
"""

EXAMPLES = r"""
---
- name: Get all Ipam Global Ip Address Pools Global
    Ip Address Pool Id Subpools
  cisco.dnac.ipam_global_ip_address_pools_global_ip_address_pool_id_subpools_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    offset: 0
    limit: 0
    globalIpAddressPoolId: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": [
        {
          "id": "string"
        }
      ],
      "version": "string"
    }
"""
