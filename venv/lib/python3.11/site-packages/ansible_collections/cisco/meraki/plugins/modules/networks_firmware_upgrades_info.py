#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_firmware_upgrades_info
short_description: Information module for networks _firmware _upgrades
description:
  - Get all networks _firmware _upgrades.
  - Get firmware upgrade information for a network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module_info
author: Francisco Munoz (@fmunoz)
options:
  headers:
    description: Additional headers.
    type: dict
  networkId:
    description:
      - NetworkId path parameter. Network ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks getNetworkFirmwareUpgrades
    description: Complete reference of the getNetworkFirmwareUpgrades API.
    link: https://developer.cisco.com/meraki/api-v1/#!get-network-firmware-upgrades
notes:
  - SDK Method used are
    networks.Networks.get_network_firmware_upgrades,
  - Paths used are
    get /networks/{networkId}/firmwareUpgrades,
"""

EXAMPLES = r"""
- name: Get all networks _firmware _upgrades
  cisco.meraki.networks_firmware_upgrades_info:
    meraki_api_key: "{{ meraki_api_key }}"
    meraki_base_url: "{{ meraki_base_url }}"
    meraki_single_request_timeout: "{{ meraki_single_request_timeout }}"
    meraki_certificate_path: "{{ meraki_certificate_path }}"
    meraki_requests_proxy: "{{ meraki_requests_proxy }}"
    meraki_wait_on_rate_limit: "{{ meraki_wait_on_rate_limit }}"
    meraki_nginx_429_retry_wait_time: "{{ meraki_nginx_429_retry_wait_time }}"
    meraki_action_batch_retry_wait_time: "{{ meraki_action_batch_retry_wait_time }}"
    meraki_retry_4xx_error: "{{ meraki_retry_4xx_error }}"
    meraki_retry_4xx_error_wait_time: "{{ meraki_retry_4xx_error_wait_time }}"
    meraki_maximum_retries: "{{ meraki_maximum_retries }}"
    meraki_output_log: "{{ meraki_output_log }}"
    meraki_log_file_prefix: "{{ meraki_log_file_prefix }}"
    meraki_log_path: "{{ meraki_log_path }}"
    meraki_print_console: "{{ meraki_print_console }}"
    meraki_suppress_logging: "{{ meraki_suppress_logging }}"
    meraki_simulate: "{{ meraki_simulate }}"
    meraki_be_geo_id: "{{ meraki_be_geo_id }}"
    meraki_caller: "{{ meraki_caller }}"
    meraki_use_iterator_for_get_pages: "{{ meraki_use_iterator_for_get_pages }}"
    meraki_inherit_logging_config: "{{ meraki_inherit_logging_config }}"
    networkId: string
  register: result
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "products": {
        "appliance": {
          "availableVersions": [
            {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          ],
          "currentVersion": {
            "firmware": "string",
            "id": "string",
            "releaseDate": "string",
            "releaseType": "string",
            "shortName": "string"
          },
          "lastUpgrade": {
            "fromVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            },
            "time": "string",
            "toVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          },
          "nextUpgrade": {
            "time": "string",
            "toVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          },
          "participateInNextBetaRelease": true
        },
        "camera": {
          "availableVersions": [
            {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          ],
          "currentVersion": {
            "firmware": "string",
            "id": "string",
            "releaseDate": "string",
            "releaseType": "string",
            "shortName": "string"
          },
          "lastUpgrade": {
            "fromVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            },
            "time": "string",
            "toVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          },
          "nextUpgrade": {
            "time": "string",
            "toVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          },
          "participateInNextBetaRelease": true
        },
        "cellularGateway": {
          "availableVersions": [
            {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          ],
          "currentVersion": {
            "firmware": "string",
            "id": "string",
            "releaseDate": "string",
            "releaseType": "string",
            "shortName": "string"
          },
          "lastUpgrade": {
            "fromVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            },
            "time": "string",
            "toVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          },
          "nextUpgrade": {
            "time": "string",
            "toVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          },
          "participateInNextBetaRelease": true
        },
        "secureConnect": {
          "availableVersions": [
            {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          ],
          "currentVersion": {
            "firmware": "string",
            "id": "string",
            "releaseDate": "string",
            "releaseType": "string",
            "shortName": "string"
          },
          "lastUpgrade": {
            "fromVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            },
            "time": "string",
            "toVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          },
          "nextUpgrade": {
            "time": "string",
            "toVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          },
          "participateInNextBetaRelease": true
        },
        "sensor": {
          "availableVersions": [
            {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          ],
          "currentVersion": {
            "firmware": "string",
            "id": "string",
            "releaseDate": "string",
            "releaseType": "string",
            "shortName": "string"
          },
          "lastUpgrade": {
            "fromVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            },
            "time": "string",
            "toVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          },
          "nextUpgrade": {
            "time": "string",
            "toVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          },
          "participateInNextBetaRelease": true
        },
        "switch": {
          "availableVersions": [
            {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          ],
          "currentVersion": {
            "firmware": "string",
            "id": "string",
            "releaseDate": "string",
            "releaseType": "string",
            "shortName": "string"
          },
          "lastUpgrade": {
            "fromVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            },
            "time": "string",
            "toVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          },
          "nextUpgrade": {
            "time": "string",
            "toVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          },
          "participateInNextBetaRelease": true
        },
        "wireless": {
          "availableVersions": [
            {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          ],
          "currentVersion": {
            "firmware": "string",
            "id": "string",
            "releaseDate": "string",
            "releaseType": "string",
            "shortName": "string"
          },
          "lastUpgrade": {
            "fromVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            },
            "time": "string",
            "toVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          },
          "nextUpgrade": {
            "time": "string",
            "toVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          },
          "participateInNextBetaRelease": true
        },
        "wirelessController": {
          "availableVersions": [
            {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          ],
          "currentVersion": {
            "firmware": "string",
            "id": "string",
            "releaseDate": "string",
            "releaseType": "string",
            "shortName": "string"
          },
          "lastUpgrade": {
            "fromVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            },
            "time": "string",
            "toVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          },
          "nextUpgrade": {
            "time": "string",
            "toVersion": {
              "firmware": "string",
              "id": "string",
              "releaseDate": "string",
              "releaseType": "string",
              "shortName": "string"
            }
          },
          "participateInNextBetaRelease": true
        }
      },
      "timezone": "string",
      "upgradeWindow": {
        "dayOfWeek": "string",
        "hourOfDay": "string"
      }
    }
"""
