#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_firmware_upgrades
short_description: Resource module for networks _firmware _upgrades
description:
  - Manage operation update of the resource networks _firmware _upgrades.
  - Update firmware upgrade information for a network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  products:
    description: Contains information about the network to update.
    suboptions:
      appliance:
        description: The network device to be updated.
        suboptions:
          nextUpgrade:
            description: The pending firmware upgrade if it exists.
            suboptions:
              time:
                description: The time of the last successful upgrade.
                type: str
              toVersion:
                description: The version to be updated to.
                suboptions:
                  id:
                    description: The version ID.
                    type: str
                type: dict
            type: dict
          participateInNextBetaRelease:
            description: Whether or not the network wants beta firmware.
            type: bool
        type: dict
      camera:
        description: The network device to be updated.
        suboptions:
          nextUpgrade:
            description: The pending firmware upgrade if it exists.
            suboptions:
              time:
                description: The time of the last successful upgrade.
                type: str
              toVersion:
                description: The version to be updated to.
                suboptions:
                  id:
                    description: The version ID.
                    type: str
                type: dict
            type: dict
          participateInNextBetaRelease:
            description: Whether or not the network wants beta firmware.
            type: bool
        type: dict
      cellularGateway:
        description: The network device to be updated.
        suboptions:
          nextUpgrade:
            description: The pending firmware upgrade if it exists.
            suboptions:
              time:
                description: The time of the last successful upgrade.
                type: str
              toVersion:
                description: The version to be updated to.
                suboptions:
                  id:
                    description: The version ID.
                    type: str
                type: dict
            type: dict
          participateInNextBetaRelease:
            description: Whether or not the network wants beta firmware.
            type: bool
        type: dict
      secureConnect:
        description: The network device to be updated.
        suboptions:
          nextUpgrade:
            description: The pending firmware upgrade if it exists.
            suboptions:
              time:
                description: The time of the last successful upgrade.
                type: str
              toVersion:
                description: The version to be updated to.
                suboptions:
                  id:
                    description: The version ID.
                    type: str
                type: dict
            type: dict
          participateInNextBetaRelease:
            description: Whether or not the network wants beta firmware.
            type: bool
        type: dict
      sensor:
        description: The network device to be updated.
        suboptions:
          nextUpgrade:
            description: The pending firmware upgrade if it exists.
            suboptions:
              time:
                description: The time of the last successful upgrade.
                type: str
              toVersion:
                description: The version to be updated to.
                suboptions:
                  id:
                    description: The version ID.
                    type: str
                type: dict
            type: dict
          participateInNextBetaRelease:
            description: Whether or not the network wants beta firmware.
            type: bool
        type: dict
      switch:
        description: The network device to be updated.
        suboptions:
          nextUpgrade:
            description: The pending firmware upgrade if it exists.
            suboptions:
              time:
                description: The time of the last successful upgrade.
                type: str
              toVersion:
                description: The version to be updated to.
                suboptions:
                  id:
                    description: The version ID.
                    type: str
                type: dict
            type: dict
          participateInNextBetaRelease:
            description: Whether or not the network wants beta firmware.
            type: bool
        type: dict
      switchCatalyst:
        description: The network device to be updated.
        suboptions:
          nextUpgrade:
            description: The pending firmware upgrade if it exists.
            suboptions:
              time:
                description: The time of the last successful upgrade.
                type: str
              toVersion:
                description: The version to be updated to.
                suboptions:
                  id:
                    description: The version ID.
                    type: str
                type: dict
            type: dict
          participateInNextBetaRelease:
            description: Whether or not the network wants beta firmware.
            type: bool
        type: dict
      wireless:
        description: The network device to be updated.
        suboptions:
          nextUpgrade:
            description: The pending firmware upgrade if it exists.
            suboptions:
              time:
                description: The time of the last successful upgrade.
                type: str
              toVersion:
                description: The version to be updated to.
                suboptions:
                  id:
                    description: The version ID.
                    type: str
                type: dict
            type: dict
          participateInNextBetaRelease:
            description: Whether or not the network wants beta firmware.
            type: bool
        type: dict
      wirelessController:
        description: The network device to be updated.
        suboptions:
          nextUpgrade:
            description: The pending firmware upgrade if it exists.
            suboptions:
              time:
                description: The time of the last successful upgrade.
                type: str
              toVersion:
                description: The version to be updated to.
                suboptions:
                  id:
                    description: The version ID.
                    type: str
                type: dict
            type: dict
          participateInNextBetaRelease:
            description: Whether or not the network wants beta firmware.
            type: bool
        type: dict
    type: dict
  timezone:
    description: The timezone for the network.
    type: str
  upgradeWindow:
    description: Upgrade window for devices in network.
    suboptions:
      dayOfWeek:
        description: Day of the week.
        type: str
      hourOfDay:
        description: Hour of the day.
        type: str
    type: dict
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for networks updateNetworkFirmwareUpgrades
    description: Complete reference of the updateNetworkFirmwareUpgrades API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-firmware-upgrades
notes:
  - SDK Method used are
    networks.Networks.update_network_firmware_upgrades,
  - Paths used are
    put /networks/{networkId}/firmwareUpgrades,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_firmware_upgrades:
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
    state: present
    networkId: string
    products:
      appliance:
        nextUpgrade:
          time: '2019-03-17T17:22:52Z'
          toVersion:
            id: '1001'
        participateInNextBetaRelease: false
      camera:
        nextUpgrade:
          time: '2019-03-17T17:22:52Z'
          toVersion:
            id: '1003'
        participateInNextBetaRelease: false
      cellularGateway:
        nextUpgrade:
          time: '2019-03-17T17:22:52Z'
          toVersion:
            id: '1004'
        participateInNextBetaRelease: false
      secureConnect:
        nextUpgrade:
          time: '2019-03-17T17:22:52Z'
          toVersion:
            id: '1007'
        participateInNextBetaRelease: false
      sensor:
        nextUpgrade:
          time: '2019-03-17T17:22:52Z'
          toVersion:
            id: '1005'
        participateInNextBetaRelease: false
      switch:
        nextUpgrade:
          time: '2019-03-17T17:22:52Z'
          toVersion:
            id: '1002'
        participateInNextBetaRelease: false
      switchCatalyst:
        nextUpgrade:
          time: '2019-03-17T17:22:52Z'
          toVersion:
            id: '1234'
        participateInNextBetaRelease: false
      wireless:
        nextUpgrade:
          time: '2019-03-17T17:22:52Z'
          toVersion:
            id: '1000'
        participateInNextBetaRelease: false
      wirelessController:
        nextUpgrade:
          time: '2019-03-17T17:22:52Z'
          toVersion:
            id: '1006'
        participateInNextBetaRelease: false
    timezone: America/Los_Angeles
    upgradeWindow:
      dayOfWeek: sun
      hourOfDay: '4:00'
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
