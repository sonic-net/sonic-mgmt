#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright 2020-2021 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}
DOCUMENTATION = """
---
module: fortios_log_fact
version_added: "2.1.0"
short_description: Retrieve log data of fortios log objects.
description:
    - Retrieve log related to disk, memory, fortianalyzer and forticloud.
author:
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@fshen01)
notes:
    - Different selector may have different parameters, users are expected to look up them for a specific selector.
    - For some selectors, the objects are global, no params are allowed to appear
    - Not all parameters are required for a slector.
    - This module is exclusivly for FortiOS Log API.
requirements:
    - install galaxy collection fortinet.fortios >= 2.1.0.
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
        required: false
    filters:
        description:
            - A list of expressions to filter the returned results.
            - The items of the list are combined as LOGICAL AND with operator ampersand.
            - One item itself could be concatenated with a comma as LOGICAL OR.
        type: list
        elements: str
        required: false
    sorters:
        description:
            - A list of expressions to sort the returned results.
            - The items of the list are in ascending order with operator ampersand.
            - One item itself could be in decending order with a comma inside.
        type: list
        elements: str
        required: false
    formatters:
        description:
            - A list of fields to display for returned results.
        type: list
        elements: str
        required: false
    selectors:
        description:
            - A list of selectors for retrieving the log type.
        type: list
        elements: dict
        required: false
        suboptions:
            filters:
                description:
                    - A list of expressions to filter the returned results.
                    - The items of the list are combined as LOGICAL AND with operator ampersand.
                    - One item itself could be concatenated with a comma as LOGICAL OR.
                type: list
                elements: str
                required: false
            sorters:
                description:
                    - A list of expressions to sort the returned results.
                    - The items of the list are in ascending order with operator ampersand.
                    - One item itself could be in decending order with a comma inside.
                type: list
                elements: str
                required: false
            formatters:
                description:
                    - A list of fields to display for returned results.
                type: list
                elements: str
                required: false
            params:
                description:
                    - the parameter for each selector, see definition in above list.
                type: dict
                required: false
            selector:
                description:
                    - selector of the retrieved log type
                type: str
                required: true
                choices:
                 - 'disk_virus_archive'
                 - 'memory_virus_archive'
                 - 'fortianalyzer_virus_archive'
                 - 'forticloud_virus_archive'
                 - 'disk_ips_archive'
                 - 'disk_app-ctrl_archive'
                 - 'memory_ips_archive'
                 - 'memory_app-ctrl_archive'
                 - 'fortianalyzer_ips_archive'
                 - 'fortianalyzer_app-ctrl_archive'
                 - 'forticloud_ips_archive'
                 - 'forticloud_app-ctrl_archive'
                 - 'disk_ips_archive-download'
                 - 'disk_app-ctrl_archive-download'
                 - 'memory_ips_archive-download'
                 - 'memory_app-ctrl_archive-download'
                 - 'fortianalyzer_ips_archive-download'
                 - 'fortianalyzer_app-ctrl_archive-download'
                 - 'forticloud_ips_archive-download'
                 - 'forticloud_app-ctrl_archive-download'
                 - 'disk_virus_raw'
                 - 'disk_webfilter_raw'
                 - 'disk_waf_raw'
                 - 'disk_ips_raw'
                 - 'disk_anomaly_raw'
                 - 'disk_app-ctrl_raw'
                 - 'disk_cifs_raw'
                 - 'disk_emailfilter_raw'
                 - 'disk_dlp_raw'
                 - 'disk_voip_raw'
                 - 'disk_gtp_raw'
                 - 'disk_dns_raw'
                 - 'disk_ssh_raw'
                 - 'disk_ssl_raw'
                 - 'disk_file-filter_raw'
                 - 'memory_virus_raw'
                 - 'memory_webfilter_raw'
                 - 'memory_waf_raw'
                 - 'memory_ips_raw'
                 - 'memory_anomaly_raw'
                 - 'memory_app-ctrl_raw'
                 - 'memory_cifs_raw'
                 - 'memory_emailfilter_raw'
                 - 'memory_dlp_raw'
                 - 'memory_voip_raw'
                 - 'memory_gtp_raw'
                 - 'memory_dns_raw'
                 - 'memory_ssh_raw'
                 - 'memory_ssl_raw'
                 - 'memory_file-filter_raw'
                 - 'fortianalyzer_virus_raw'
                 - 'fortianalyzer_webfilter_raw'
                 - 'fortianalyzer_waf_raw'
                 - 'fortianalyzer_ips_raw'
                 - 'fortianalyzer_anomaly_raw'
                 - 'fortianalyzer_app-ctrl_raw'
                 - 'fortianalyzer_cifs_raw'
                 - 'fortianalyzer_emailfilter_raw'
                 - 'fortianalyzer_dlp_raw'
                 - 'fortianalyzer_voip_raw'
                 - 'fortianalyzer_gtp_raw'
                 - 'fortianalyzer_dns_raw'
                 - 'fortianalyzer_ssh_raw'
                 - 'fortianalyzer_ssl_raw'
                 - 'fortianalyzer_file-filter_raw'
                 - 'forticloud_virus_raw'
                 - 'forticloud_webfilter_raw'
                 - 'forticloud_waf_raw'
                 - 'forticloud_ips_raw'
                 - 'forticloud_anomaly_raw'
                 - 'forticloud_app-ctrl_raw'
                 - 'forticloud_cifs_raw'
                 - 'forticloud_emailfilter_raw'
                 - 'forticloud_dlp_raw'
                 - 'forticloud_voip_raw'
                 - 'forticloud_gtp_raw'
                 - 'forticloud_dns_raw'
                 - 'forticloud_ssh_raw'
                 - 'forticloud_ssl_raw'
                 - 'forticloud_file-filter_raw'
                 - 'disk_event_vpn'
                 - 'disk_event_user'
                 - 'disk_event_router'
                 - 'disk_event_wireless'
                 - 'disk_event_wad'
                 - 'disk_event_endpoint'
                 - 'disk_event_ha'
                 - 'disk_event_compliance-check'
                 - 'disk_event_system'
                 - 'disk_event_connector'
                 - 'disk_event_security-rating'
                 - 'disk_event_fortiextender'
                 - 'disk_traffic_forward'
                 - 'disk_traffic_local'
                 - 'disk_traffic_multicast'
                 - 'disk_traffic_sniffer'
                 - 'disk_traffic_fortiview'
                 - 'disk_traffic_threat'
                 - 'memory_event_vpn'
                 - 'memory_event_user'
                 - 'memory_event_router'
                 - 'memory_event_wireless'
                 - 'memory_event_wad'
                 - 'memory_event_endpoint'
                 - 'memory_event_ha'
                 - 'memory_event_compliance-check'
                 - 'memory_event_system'
                 - 'memory_event_connector'
                 - 'memory_event_security-rating'
                 - 'memory_event_fortiextender'
                 - 'memory_traffic_forward'
                 - 'memory_traffic_local'
                 - 'memory_traffic_multicast'
                 - 'memory_traffic_sniffer'
                 - 'memory_traffic_fortiview'
                 - 'memory_traffic_threat'
                 - 'fortianalyzer_event_vpn'
                 - 'fortianalyzer_event_user'
                 - 'fortianalyzer_event_router'
                 - 'fortianalyzer_event_wireless'
                 - 'fortianalyzer_event_wad'
                 - 'fortianalyzer_event_endpoint'
                 - 'fortianalyzer_event_ha'
                 - 'fortianalyzer_event_compliance-check'
                 - 'fortianalyzer_event_system'
                 - 'fortianalyzer_event_connector'
                 - 'fortianalyzer_event_security-rating'
                 - 'fortianalyzer_event_fortiextender'
                 - 'fortianalyzer_traffic_forward'
                 - 'fortianalyzer_traffic_local'
                 - 'fortianalyzer_traffic_multicast'
                 - 'fortianalyzer_traffic_sniffer'
                 - 'fortianalyzer_traffic_fortiview'
                 - 'fortianalyzer_traffic_threat'
                 - 'forticloud_event_vpn'
                 - 'forticloud_event_user'
                 - 'forticloud_event_router'
                 - 'forticloud_event_wireless'
                 - 'forticloud_event_wad'
                 - 'forticloud_event_endpoint'
                 - 'forticloud_event_ha'
                 - 'forticloud_event_compliance-check'
                 - 'forticloud_event_system'
                 - 'forticloud_event_connector'
                 - 'forticloud_event_security-rating'
                 - 'forticloud_event_fortiextender'
                 - 'forticloud_traffic_forward'
                 - 'forticloud_traffic_local'
                 - 'forticloud_traffic_multicast'
                 - 'forticloud_traffic_sniffer'
                 - 'forticloud_traffic_fortiview'
                 - 'forticloud_traffic_threat'

    selector:
        description:
            - selector of the retrieved log type
        type: str
        required: false
        choices:
         - 'disk_virus_archive'
         - 'memory_virus_archive'
         - 'fortianalyzer_virus_archive'
         - 'forticloud_virus_archive'
         - 'disk_ips_archive'
         - 'disk_app-ctrl_archive'
         - 'memory_ips_archive'
         - 'memory_app-ctrl_archive'
         - 'fortianalyzer_ips_archive'
         - 'fortianalyzer_app-ctrl_archive'
         - 'forticloud_ips_archive'
         - 'forticloud_app-ctrl_archive'
         - 'disk_ips_archive-download'
         - 'disk_app-ctrl_archive-download'
         - 'memory_ips_archive-download'
         - 'memory_app-ctrl_archive-download'
         - 'fortianalyzer_ips_archive-download'
         - 'fortianalyzer_app-ctrl_archive-download'
         - 'forticloud_ips_archive-download'
         - 'forticloud_app-ctrl_archive-download'
         - 'disk_virus_raw'
         - 'disk_webfilter_raw'
         - 'disk_waf_raw'
         - 'disk_ips_raw'
         - 'disk_anomaly_raw'
         - 'disk_app-ctrl_raw'
         - 'disk_cifs_raw'
         - 'disk_emailfilter_raw'
         - 'disk_dlp_raw'
         - 'disk_voip_raw'
         - 'disk_gtp_raw'
         - 'disk_dns_raw'
         - 'disk_ssh_raw'
         - 'disk_ssl_raw'
         - 'disk_file-filter_raw'
         - 'memory_virus_raw'
         - 'memory_webfilter_raw'
         - 'memory_waf_raw'
         - 'memory_ips_raw'
         - 'memory_anomaly_raw'
         - 'memory_app-ctrl_raw'
         - 'memory_cifs_raw'
         - 'memory_emailfilter_raw'
         - 'memory_dlp_raw'
         - 'memory_voip_raw'
         - 'memory_gtp_raw'
         - 'memory_dns_raw'
         - 'memory_ssh_raw'
         - 'memory_ssl_raw'
         - 'memory_file-filter_raw'
         - 'fortianalyzer_virus_raw'
         - 'fortianalyzer_webfilter_raw'
         - 'fortianalyzer_waf_raw'
         - 'fortianalyzer_ips_raw'
         - 'fortianalyzer_anomaly_raw'
         - 'fortianalyzer_app-ctrl_raw'
         - 'fortianalyzer_cifs_raw'
         - 'fortianalyzer_emailfilter_raw'
         - 'fortianalyzer_dlp_raw'
         - 'fortianalyzer_voip_raw'
         - 'fortianalyzer_gtp_raw'
         - 'fortianalyzer_dns_raw'
         - 'fortianalyzer_ssh_raw'
         - 'fortianalyzer_ssl_raw'
         - 'fortianalyzer_file-filter_raw'
         - 'forticloud_virus_raw'
         - 'forticloud_webfilter_raw'
         - 'forticloud_waf_raw'
         - 'forticloud_ips_raw'
         - 'forticloud_anomaly_raw'
         - 'forticloud_app-ctrl_raw'
         - 'forticloud_cifs_raw'
         - 'forticloud_emailfilter_raw'
         - 'forticloud_dlp_raw'
         - 'forticloud_voip_raw'
         - 'forticloud_gtp_raw'
         - 'forticloud_dns_raw'
         - 'forticloud_ssh_raw'
         - 'forticloud_ssl_raw'
         - 'forticloud_file-filter_raw'
         - 'disk_event_vpn'
         - 'disk_event_user'
         - 'disk_event_router'
         - 'disk_event_wireless'
         - 'disk_event_wad'
         - 'disk_event_endpoint'
         - 'disk_event_ha'
         - 'disk_event_compliance-check'
         - 'disk_event_system'
         - 'disk_event_connector'
         - 'disk_event_security-rating'
         - 'disk_event_fortiextender'
         - 'disk_traffic_forward'
         - 'disk_traffic_local'
         - 'disk_traffic_multicast'
         - 'disk_traffic_sniffer'
         - 'disk_traffic_fortiview'
         - 'disk_traffic_threat'
         - 'memory_event_vpn'
         - 'memory_event_user'
         - 'memory_event_router'
         - 'memory_event_wireless'
         - 'memory_event_wad'
         - 'memory_event_endpoint'
         - 'memory_event_ha'
         - 'memory_event_compliance-check'
         - 'memory_event_system'
         - 'memory_event_connector'
         - 'memory_event_security-rating'
         - 'memory_event_fortiextender'
         - 'memory_traffic_forward'
         - 'memory_traffic_local'
         - 'memory_traffic_multicast'
         - 'memory_traffic_sniffer'
         - 'memory_traffic_fortiview'
         - 'memory_traffic_threat'
         - 'fortianalyzer_event_vpn'
         - 'fortianalyzer_event_user'
         - 'fortianalyzer_event_router'
         - 'fortianalyzer_event_wireless'
         - 'fortianalyzer_event_wad'
         - 'fortianalyzer_event_endpoint'
         - 'fortianalyzer_event_ha'
         - 'fortianalyzer_event_compliance-check'
         - 'fortianalyzer_event_system'
         - 'fortianalyzer_event_connector'
         - 'fortianalyzer_event_security-rating'
         - 'fortianalyzer_event_fortiextender'
         - 'fortianalyzer_traffic_forward'
         - 'fortianalyzer_traffic_local'
         - 'fortianalyzer_traffic_multicast'
         - 'fortianalyzer_traffic_sniffer'
         - 'fortianalyzer_traffic_fortiview'
         - 'fortianalyzer_traffic_threat'
         - 'forticloud_event_vpn'
         - 'forticloud_event_user'
         - 'forticloud_event_router'
         - 'forticloud_event_wireless'
         - 'forticloud_event_wad'
         - 'forticloud_event_endpoint'
         - 'forticloud_event_ha'
         - 'forticloud_event_compliance-check'
         - 'forticloud_event_system'
         - 'forticloud_event_connector'
         - 'forticloud_event_security-rating'
         - 'forticloud_event_fortiextender'
         - 'forticloud_traffic_forward'
         - 'forticloud_traffic_local'
         - 'forticloud_traffic_multicast'
         - 'forticloud_traffic_sniffer'
         - 'forticloud_traffic_fortiview'
         - 'forticloud_traffic_threat'

    params:
        description:
            - the parameter for each selector, see definition in above list.
        type: dict
        required: false
"""

EXAMPLES = """
- name: get disk event user and memory event user at once.
  fortinet.fortios.fortios_log_fact:
      access_token: "you_own_value"
      selectors:
          - selector: disk_event_user
            filters:
                - log_id==41000
          - selector: memory_event_user
"""

RETURN = """
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
rows:
  description: Number of rows to return
  returned: always
  type: int
  sample: 400
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
session_id:
  description: session id for the request
  returned: always
  type: int
  sample: 7
start:
  description: Row number for the first row to return
  returned: always
  type: int
  sample: 0
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
subcategory:
  description: Type of log that can be retrieved
  returned: always
  type: str
  sample: "system"
total_lines:
  description: Total lines returned from the result
  returned: always
  type: int
  sample: 510
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"

"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)

# from urllib.parse import quote
try:
    # For Python 3
    from urllib.parse import quote
except ImportError:
    # For Python 2
    from urllib import quote

module_selectors_defs = {
    "disk_virus_archive": {
        "url": "disk/virus/archive",
        "params": {"mkey": {"type": "int", "required": "False"}},
    },
    "memory_virus_archive": {
        "url": "memory/virus/archive",
        "params": {"mkey": {"type": "int", "required": "False"}},
    },
    "fortianalyzer_virus_archive": {
        "url": "fortianalyzer/virus/archive",
        "params": {"mkey": {"type": "int", "required": "False"}},
    },
    "forticloud_virus_archive": {
        "url": "forticloud/virus/archive",
        "params": {"mkey": {"type": "int", "required": "False"}},
    },
    "disk_ips_archive": {
        "url": "disk/ips/archive",
        "params": {
            "mkey": {"type": "int", "required": "False"},
            "roll": {"type": "int", "required": "False"},
        },
    },
    "disk_app-ctrl_archive": {
        "url": "disk/app-ctrl/archive",
        "params": {
            "mkey": {"type": "int", "required": "False"},
            "roll": {"type": "int", "required": "False"},
        },
    },
    "memory_ips_archive": {
        "url": "memory/ips/archive",
        "params": {
            "mkey": {"type": "int", "required": "False"},
            "roll": {"type": "int", "required": "False"},
        },
    },
    "memory_app-ctrl_archive": {
        "url": "memory/app-ctrl/archive",
        "params": {
            "mkey": {"type": "int", "required": "False"},
            "roll": {"type": "int", "required": "False"},
        },
    },
    "fortianalyzer_ips_archive": {
        "url": "fortianalyzer/ips/archive",
        "params": {
            "mkey": {"type": "int", "required": "False"},
            "roll": {"type": "int", "required": "False"},
        },
    },
    "fortianalyzer_app-ctrl_archive": {
        "url": "fortianalyzer/app-ctrl/archive",
        "params": {
            "mkey": {"type": "int", "required": "False"},
            "roll": {"type": "int", "required": "False"},
        },
    },
    "forticloud_ips_archive": {
        "url": "forticloud/ips/archive",
        "params": {
            "mkey": {"type": "int", "required": "False"},
            "roll": {"type": "int", "required": "False"},
        },
    },
    "forticloud_app-ctrl_archive": {
        "url": "forticloud/app-ctrl/archive",
        "params": {
            "mkey": {"type": "int", "required": "False"},
            "roll": {"type": "int", "required": "False"},
        },
    },
    "disk_ips_archive-download": {
        "url": "disk/ips/archive-download",
        "params": {
            "mkey": {"type": "int", "required": "False"},
            "roll": {"type": "int", "required": "False"},
            "filename": {"type": "string", "required": "False"},
        },
    },
    "disk_app-ctrl_archive-download": {
        "url": "disk/app-ctrl/archive-download",
        "params": {
            "mkey": {"type": "int", "required": "False"},
            "roll": {"type": "int", "required": "False"},
            "filename": {"type": "string", "required": "False"},
        },
    },
    "memory_ips_archive-download": {
        "url": "memory/ips/archive-download",
        "params": {
            "mkey": {"type": "int", "required": "False"},
            "roll": {"type": "int", "required": "False"},
            "filename": {"type": "string", "required": "False"},
        },
    },
    "memory_app-ctrl_archive-download": {
        "url": "memory/app-ctrl/archive-download",
        "params": {
            "mkey": {"type": "int", "required": "False"},
            "roll": {"type": "int", "required": "False"},
            "filename": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_ips_archive-download": {
        "url": "fortianalyzer/ips/archive-download",
        "params": {
            "mkey": {"type": "int", "required": "False"},
            "roll": {"type": "int", "required": "False"},
            "filename": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_app-ctrl_archive-download": {
        "url": "fortianalyzer/app-ctrl/archive-download",
        "params": {
            "mkey": {"type": "int", "required": "False"},
            "roll": {"type": "int", "required": "False"},
            "filename": {"type": "string", "required": "False"},
        },
    },
    "forticloud_ips_archive-download": {
        "url": "forticloud/ips/archive-download",
        "params": {
            "mkey": {"type": "int", "required": "False"},
            "roll": {"type": "int", "required": "False"},
            "filename": {"type": "string", "required": "False"},
        },
    },
    "forticloud_app-ctrl_archive-download": {
        "url": "forticloud/app-ctrl/archive-download",
        "params": {
            "mkey": {"type": "int", "required": "False"},
            "roll": {"type": "int", "required": "False"},
            "filename": {"type": "string", "required": "False"},
        },
    },
    "disk_virus_raw": {
        "url": "disk/virus/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "disk_webfilter_raw": {
        "url": "disk/webfilter/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "disk_waf_raw": {
        "url": "disk/waf/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "disk_ips_raw": {
        "url": "disk/ips/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "disk_anomaly_raw": {
        "url": "disk/anomaly/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "disk_app-ctrl_raw": {
        "url": "disk/app-ctrl/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "disk_cifs_raw": {
        "url": "disk/cifs/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "disk_emailfilter_raw": {
        "url": "disk/emailfilter/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "disk_dlp_raw": {
        "url": "disk/dlp/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "disk_voip_raw": {
        "url": "disk/voip/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "disk_gtp_raw": {
        "url": "disk/gtp/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "disk_dns_raw": {
        "url": "disk/dns/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "disk_ssh_raw": {
        "url": "disk/ssh/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "disk_ssl_raw": {
        "url": "disk/ssl/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "disk_file-filter_raw": {
        "url": "disk/file-filter/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "memory_virus_raw": {
        "url": "memory/virus/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "memory_webfilter_raw": {
        "url": "memory/webfilter/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "memory_waf_raw": {
        "url": "memory/waf/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "memory_ips_raw": {
        "url": "memory/ips/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "memory_anomaly_raw": {
        "url": "memory/anomaly/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "memory_app-ctrl_raw": {
        "url": "memory/app-ctrl/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "memory_cifs_raw": {
        "url": "memory/cifs/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "memory_emailfilter_raw": {
        "url": "memory/emailfilter/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "memory_dlp_raw": {
        "url": "memory/dlp/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "memory_voip_raw": {
        "url": "memory/voip/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "memory_gtp_raw": {
        "url": "memory/gtp/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "memory_dns_raw": {
        "url": "memory/dns/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "memory_ssh_raw": {
        "url": "memory/ssh/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "memory_ssl_raw": {
        "url": "memory/ssl/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "memory_file-filter_raw": {
        "url": "memory/file-filter/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_virus_raw": {
        "url": "fortianalyzer/virus/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_webfilter_raw": {
        "url": "fortianalyzer/webfilter/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_waf_raw": {
        "url": "fortianalyzer/waf/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_ips_raw": {
        "url": "fortianalyzer/ips/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_anomaly_raw": {
        "url": "fortianalyzer/anomaly/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_app-ctrl_raw": {
        "url": "fortianalyzer/app-ctrl/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_cifs_raw": {
        "url": "fortianalyzer/cifs/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_emailfilter_raw": {
        "url": "fortianalyzer/emailfilter/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_dlp_raw": {
        "url": "fortianalyzer/dlp/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_voip_raw": {
        "url": "fortianalyzer/voip/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_gtp_raw": {
        "url": "fortianalyzer/gtp/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_dns_raw": {
        "url": "fortianalyzer/dns/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_ssh_raw": {
        "url": "fortianalyzer/ssh/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_ssl_raw": {
        "url": "fortianalyzer/ssl/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_file-filter_raw": {
        "url": "fortianalyzer/file-filter/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "forticloud_virus_raw": {
        "url": "forticloud/virus/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "forticloud_webfilter_raw": {
        "url": "forticloud/webfilter/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "forticloud_waf_raw": {
        "url": "forticloud/waf/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "forticloud_ips_raw": {
        "url": "forticloud/ips/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "forticloud_anomaly_raw": {
        "url": "forticloud/anomaly/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "forticloud_app-ctrl_raw": {
        "url": "forticloud/app-ctrl/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "forticloud_cifs_raw": {
        "url": "forticloud/cifs/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "forticloud_emailfilter_raw": {
        "url": "forticloud/emailfilter/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "forticloud_dlp_raw": {
        "url": "forticloud/dlp/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "forticloud_voip_raw": {
        "url": "forticloud/voip/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "forticloud_gtp_raw": {
        "url": "forticloud/gtp/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "forticloud_dns_raw": {
        "url": "forticloud/dns/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "forticloud_ssh_raw": {
        "url": "forticloud/ssh/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "forticloud_ssl_raw": {
        "url": "forticloud/ssl/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "forticloud_file-filter_raw": {
        "url": "forticloud/file-filter/raw",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
        },
    },
    "disk_event_vpn": {
        "url": "disk/event/vpn",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "disk_event_user": {
        "url": "disk/event/user",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "disk_event_router": {
        "url": "disk/event/router",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "disk_event_wireless": {
        "url": "disk/event/wireless",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "disk_event_wad": {
        "url": "disk/event/wad",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "disk_event_endpoint": {
        "url": "disk/event/endpoint",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "disk_event_ha": {
        "url": "disk/event/ha",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "disk_event_compliance-check": {
        "url": "disk/event/compliance-check",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "disk_event_system": {
        "url": "disk/event/system",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "disk_event_connector": {
        "url": "disk/event/connector",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "disk_event_security-rating": {
        "url": "disk/event/security-rating",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "disk_event_fortiextender": {
        "url": "disk/event/fortiextender",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "disk_traffic_forward": {
        "url": "disk/traffic/forward",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "disk_traffic_local": {
        "url": "disk/traffic/local",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "disk_traffic_multicast": {
        "url": "disk/traffic/multicast",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "disk_traffic_sniffer": {
        "url": "disk/traffic/sniffer",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "disk_traffic_fortiview": {
        "url": "disk/traffic/fortiview",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "disk_traffic_threat": {
        "url": "disk/traffic/threat",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_event_vpn": {
        "url": "memory/event/vpn",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_event_user": {
        "url": "memory/event/user",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_event_router": {
        "url": "memory/event/router",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_event_wireless": {
        "url": "memory/event/wireless",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_event_wad": {
        "url": "memory/event/wad",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_event_endpoint": {
        "url": "memory/event/endpoint",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_event_ha": {
        "url": "memory/event/ha",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_event_compliance-check": {
        "url": "memory/event/compliance-check",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_event_system": {
        "url": "memory/event/system",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_event_connector": {
        "url": "memory/event/connector",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_event_security-rating": {
        "url": "memory/event/security-rating",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_event_fortiextender": {
        "url": "memory/event/fortiextender",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_traffic_forward": {
        "url": "memory/traffic/forward",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_traffic_local": {
        "url": "memory/traffic/local",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_traffic_multicast": {
        "url": "memory/traffic/multicast",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_traffic_sniffer": {
        "url": "memory/traffic/sniffer",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_traffic_fortiview": {
        "url": "memory/traffic/fortiview",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "memory_traffic_threat": {
        "url": "memory/traffic/threat",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_event_vpn": {
        "url": "fortianalyzer/event/vpn",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_event_user": {
        "url": "fortianalyzer/event/user",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_event_router": {
        "url": "fortianalyzer/event/router",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_event_wireless": {
        "url": "fortianalyzer/event/wireless",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_event_wad": {
        "url": "fortianalyzer/event/wad",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_event_endpoint": {
        "url": "fortianalyzer/event/endpoint",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_event_ha": {
        "url": "fortianalyzer/event/ha",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_event_compliance-check": {
        "url": "fortianalyzer/event/compliance-check",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_event_system": {
        "url": "fortianalyzer/event/system",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_event_connector": {
        "url": "fortianalyzer/event/connector",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_event_security-rating": {
        "url": "fortianalyzer/event/security-rating",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_event_fortiextender": {
        "url": "fortianalyzer/event/fortiextender",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_traffic_forward": {
        "url": "fortianalyzer/traffic/forward",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_traffic_local": {
        "url": "fortianalyzer/traffic/local",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_traffic_multicast": {
        "url": "fortianalyzer/traffic/multicast",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_traffic_sniffer": {
        "url": "fortianalyzer/traffic/sniffer",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_traffic_fortiview": {
        "url": "fortianalyzer/traffic/fortiview",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "fortianalyzer_traffic_threat": {
        "url": "fortianalyzer/traffic/threat",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_event_vpn": {
        "url": "forticloud/event/vpn",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_event_user": {
        "url": "forticloud/event/user",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_event_router": {
        "url": "forticloud/event/router",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_event_wireless": {
        "url": "forticloud/event/wireless",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_event_wad": {
        "url": "forticloud/event/wad",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_event_endpoint": {
        "url": "forticloud/event/endpoint",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_event_ha": {
        "url": "forticloud/event/ha",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_event_compliance-check": {
        "url": "forticloud/event/compliance-check",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_event_system": {
        "url": "forticloud/event/system",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_event_connector": {
        "url": "forticloud/event/connector",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_event_security-rating": {
        "url": "forticloud/event/security-rating",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_event_fortiextender": {
        "url": "forticloud/event/fortiextender",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_traffic_forward": {
        "url": "forticloud/traffic/forward",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_traffic_local": {
        "url": "forticloud/traffic/local",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_traffic_multicast": {
        "url": "forticloud/traffic/multicast",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_traffic_sniffer": {
        "url": "forticloud/traffic/sniffer",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_traffic_fortiview": {
        "url": "forticloud/traffic/fortiview",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
    "forticloud_traffic_threat": {
        "url": "forticloud/traffic/threat",
        "params": {
            "rows": {"type": "int", "required": "False"},
            "session_id": {"type": "int", "required": "False"},
            "serial_no": {"type": "string", "required": "False"},
            "is_ha_member": {"type": "boolean", "required": "False"},
            "filter": {"type": "string", "required": "False"},
            "extra": {"type": "string", "required": "False"},
        },
    },
}


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def validate_parameters(params, fos):
    # parameter validation will not block task, warning will be provided in case of parameters validation.
    selector = params["selector"]
    selector_params = params.get("params", {})

    if selector not in module_selectors_defs:
        return False, {"message": "unknown selector: " + selector}

    if selector_params:
        for param_key, param_value in selector_params.items():
            if not isinstance(param_value, (bool, int, str, list)):
                return False, {
                    "message": "value of param:%s must be atomic" % (param_key)
                }

    definition = module_selectors_defs.get(selector, {})
    if not params or len(params) == 0 or len(definition) == 0:
        return True, {}

    acceptable_param_names = list(module_selectors_defs[selector]["params"].keys())
    provided_param_names = list(selector_params.keys() if selector_params else [])

    params_valid = True
    for param_name in acceptable_param_names:
        # if param_name not in provided_param_names:
        if param_name not in provided_param_names and eval(
            module_selectors_defs[selector]["params"][param_name]["required"]
        ):
            params_valid = False
            break
    if params_valid:
        for param_name in provided_param_names:
            if param_name not in acceptable_param_names:
                params_valid = False
                break
    if not params_valid:
        param_summary = [
            "%s(%s, %s)"
            % (
                param_name,
                param["type"],
                "required" if param.get("required") else "optional",
            )
            for param_name, param in module_selectors_defs[selector]["params"].items()
        ]
        fos._module.warn(
            "selector:%s expects params:%s" % (selector, str(param_summary))
        )

    return True, {}


def fortios_log_fact(params, fos):
    valid, result = validate_parameters(params, fos)
    if not valid:
        return True, False, result

    selector = params["selector"]

    url_params = dict()
    if params["filters"] and len(params["filters"]):
        filter_body = quote(params["filters"][0])
        for filter_item in params["filters"][1:]:
            filter_body = "%s&filter=%s" % (filter_body, quote(filter_item))
        url_params["filter"] = filter_body
    if params["sorters"] and len(params["sorters"]):
        sorter_body = params["sorters"][0]
        for sorter_item in params["sorters"][1:]:
            sorter_body = "%s&sort=%s" % (sorter_body, sorter_item)
        url_params["sort"] = sorter_body
    if params["formatters"] and len(params["formatters"]):
        formatter_body = params["formatters"][0]
        for formatter_item in params["formatters"][1:]:
            formatter_body = "%s|%s" % (formatter_body, formatter_item)
        url_params["format"] = formatter_body
    if params["params"]:
        for selector_param_key, selector_param in params["params"].items():
            url_params[selector_param_key] = selector_param

    log_data = fos.log_get(module_selectors_defs[selector]["url"], url_params)

    return not is_successful_status(log_data), False, log_data


def main():
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "filters": {"required": False, "type": "list", "elements": "str"},
        "sorters": {"required": False, "type": "list", "elements": "str"},
        "formatters": {"required": False, "type": "list", "elements": "str"},
        "params": {"required": False, "type": "dict"},
        "selector": {
            "required": False,
            "type": "str",
            "choices": [
                "disk_virus_archive",
                "memory_virus_archive",
                "fortianalyzer_virus_archive",
                "forticloud_virus_archive",
                "disk_ips_archive",
                "disk_app-ctrl_archive",
                "memory_ips_archive",
                "memory_app-ctrl_archive",
                "fortianalyzer_ips_archive",
                "fortianalyzer_app-ctrl_archive",
                "forticloud_ips_archive",
                "forticloud_app-ctrl_archive",
                "disk_ips_archive-download",
                "disk_app-ctrl_archive-download",
                "memory_ips_archive-download",
                "memory_app-ctrl_archive-download",
                "fortianalyzer_ips_archive-download",
                "fortianalyzer_app-ctrl_archive-download",
                "forticloud_ips_archive-download",
                "forticloud_app-ctrl_archive-download",
                "disk_virus_raw",
                "disk_webfilter_raw",
                "disk_waf_raw",
                "disk_ips_raw",
                "disk_anomaly_raw",
                "disk_app-ctrl_raw",
                "disk_cifs_raw",
                "disk_emailfilter_raw",
                "disk_dlp_raw",
                "disk_voip_raw",
                "disk_gtp_raw",
                "disk_dns_raw",
                "disk_ssh_raw",
                "disk_ssl_raw",
                "disk_file-filter_raw",
                "memory_virus_raw",
                "memory_webfilter_raw",
                "memory_waf_raw",
                "memory_ips_raw",
                "memory_anomaly_raw",
                "memory_app-ctrl_raw",
                "memory_cifs_raw",
                "memory_emailfilter_raw",
                "memory_dlp_raw",
                "memory_voip_raw",
                "memory_gtp_raw",
                "memory_dns_raw",
                "memory_ssh_raw",
                "memory_ssl_raw",
                "memory_file-filter_raw",
                "fortianalyzer_virus_raw",
                "fortianalyzer_webfilter_raw",
                "fortianalyzer_waf_raw",
                "fortianalyzer_ips_raw",
                "fortianalyzer_anomaly_raw",
                "fortianalyzer_app-ctrl_raw",
                "fortianalyzer_cifs_raw",
                "fortianalyzer_emailfilter_raw",
                "fortianalyzer_dlp_raw",
                "fortianalyzer_voip_raw",
                "fortianalyzer_gtp_raw",
                "fortianalyzer_dns_raw",
                "fortianalyzer_ssh_raw",
                "fortianalyzer_ssl_raw",
                "fortianalyzer_file-filter_raw",
                "forticloud_virus_raw",
                "forticloud_webfilter_raw",
                "forticloud_waf_raw",
                "forticloud_ips_raw",
                "forticloud_anomaly_raw",
                "forticloud_app-ctrl_raw",
                "forticloud_cifs_raw",
                "forticloud_emailfilter_raw",
                "forticloud_dlp_raw",
                "forticloud_voip_raw",
                "forticloud_gtp_raw",
                "forticloud_dns_raw",
                "forticloud_ssh_raw",
                "forticloud_ssl_raw",
                "forticloud_file-filter_raw",
                "disk_event_vpn",
                "disk_event_user",
                "disk_event_router",
                "disk_event_wireless",
                "disk_event_wad",
                "disk_event_endpoint",
                "disk_event_ha",
                "disk_event_compliance-check",
                "disk_event_system",
                "disk_event_connector",
                "disk_event_security-rating",
                "disk_event_fortiextender",
                "disk_traffic_forward",
                "disk_traffic_local",
                "disk_traffic_multicast",
                "disk_traffic_sniffer",
                "disk_traffic_fortiview",
                "disk_traffic_threat",
                "memory_event_vpn",
                "memory_event_user",
                "memory_event_router",
                "memory_event_wireless",
                "memory_event_wad",
                "memory_event_endpoint",
                "memory_event_ha",
                "memory_event_compliance-check",
                "memory_event_system",
                "memory_event_connector",
                "memory_event_security-rating",
                "memory_event_fortiextender",
                "memory_traffic_forward",
                "memory_traffic_local",
                "memory_traffic_multicast",
                "memory_traffic_sniffer",
                "memory_traffic_fortiview",
                "memory_traffic_threat",
                "fortianalyzer_event_vpn",
                "fortianalyzer_event_user",
                "fortianalyzer_event_router",
                "fortianalyzer_event_wireless",
                "fortianalyzer_event_wad",
                "fortianalyzer_event_endpoint",
                "fortianalyzer_event_ha",
                "fortianalyzer_event_compliance-check",
                "fortianalyzer_event_system",
                "fortianalyzer_event_connector",
                "fortianalyzer_event_security-rating",
                "fortianalyzer_event_fortiextender",
                "fortianalyzer_traffic_forward",
                "fortianalyzer_traffic_local",
                "fortianalyzer_traffic_multicast",
                "fortianalyzer_traffic_sniffer",
                "fortianalyzer_traffic_fortiview",
                "fortianalyzer_traffic_threat",
                "forticloud_event_vpn",
                "forticloud_event_user",
                "forticloud_event_router",
                "forticloud_event_wireless",
                "forticloud_event_wad",
                "forticloud_event_endpoint",
                "forticloud_event_ha",
                "forticloud_event_compliance-check",
                "forticloud_event_system",
                "forticloud_event_connector",
                "forticloud_event_security-rating",
                "forticloud_event_fortiextender",
                "forticloud_traffic_forward",
                "forticloud_traffic_local",
                "forticloud_traffic_multicast",
                "forticloud_traffic_sniffer",
                "forticloud_traffic_fortiview",
                "forticloud_traffic_threat",
            ],
        },
        "selectors": {
            "required": False,
            "type": "list",
            "elements": "dict",
            "options": {
                "filters": {"required": False, "type": "list", "elements": "str"},
                "sorters": {"required": False, "type": "list", "elements": "str"},
                "formatters": {"required": False, "type": "list", "elements": "str"},
                "params": {"required": False, "type": "dict"},
                "selector": {
                    "required": True,
                    "type": "str",
                    "choices": [
                        "disk_virus_archive",
                        "memory_virus_archive",
                        "fortianalyzer_virus_archive",
                        "forticloud_virus_archive",
                        "disk_ips_archive",
                        "disk_app-ctrl_archive",
                        "memory_ips_archive",
                        "memory_app-ctrl_archive",
                        "fortianalyzer_ips_archive",
                        "fortianalyzer_app-ctrl_archive",
                        "forticloud_ips_archive",
                        "forticloud_app-ctrl_archive",
                        "disk_ips_archive-download",
                        "disk_app-ctrl_archive-download",
                        "memory_ips_archive-download",
                        "memory_app-ctrl_archive-download",
                        "fortianalyzer_ips_archive-download",
                        "fortianalyzer_app-ctrl_archive-download",
                        "forticloud_ips_archive-download",
                        "forticloud_app-ctrl_archive-download",
                        "disk_virus_raw",
                        "disk_webfilter_raw",
                        "disk_waf_raw",
                        "disk_ips_raw",
                        "disk_anomaly_raw",
                        "disk_app-ctrl_raw",
                        "disk_cifs_raw",
                        "disk_emailfilter_raw",
                        "disk_dlp_raw",
                        "disk_voip_raw",
                        "disk_gtp_raw",
                        "disk_dns_raw",
                        "disk_ssh_raw",
                        "disk_ssl_raw",
                        "disk_file-filter_raw",
                        "memory_virus_raw",
                        "memory_webfilter_raw",
                        "memory_waf_raw",
                        "memory_ips_raw",
                        "memory_anomaly_raw",
                        "memory_app-ctrl_raw",
                        "memory_cifs_raw",
                        "memory_emailfilter_raw",
                        "memory_dlp_raw",
                        "memory_voip_raw",
                        "memory_gtp_raw",
                        "memory_dns_raw",
                        "memory_ssh_raw",
                        "memory_ssl_raw",
                        "memory_file-filter_raw",
                        "fortianalyzer_virus_raw",
                        "fortianalyzer_webfilter_raw",
                        "fortianalyzer_waf_raw",
                        "fortianalyzer_ips_raw",
                        "fortianalyzer_anomaly_raw",
                        "fortianalyzer_app-ctrl_raw",
                        "fortianalyzer_cifs_raw",
                        "fortianalyzer_emailfilter_raw",
                        "fortianalyzer_dlp_raw",
                        "fortianalyzer_voip_raw",
                        "fortianalyzer_gtp_raw",
                        "fortianalyzer_dns_raw",
                        "fortianalyzer_ssh_raw",
                        "fortianalyzer_ssl_raw",
                        "fortianalyzer_file-filter_raw",
                        "forticloud_virus_raw",
                        "forticloud_webfilter_raw",
                        "forticloud_waf_raw",
                        "forticloud_ips_raw",
                        "forticloud_anomaly_raw",
                        "forticloud_app-ctrl_raw",
                        "forticloud_cifs_raw",
                        "forticloud_emailfilter_raw",
                        "forticloud_dlp_raw",
                        "forticloud_voip_raw",
                        "forticloud_gtp_raw",
                        "forticloud_dns_raw",
                        "forticloud_ssh_raw",
                        "forticloud_ssl_raw",
                        "forticloud_file-filter_raw",
                        "disk_event_vpn",
                        "disk_event_user",
                        "disk_event_router",
                        "disk_event_wireless",
                        "disk_event_wad",
                        "disk_event_endpoint",
                        "disk_event_ha",
                        "disk_event_compliance-check",
                        "disk_event_system",
                        "disk_event_connector",
                        "disk_event_security-rating",
                        "disk_event_fortiextender",
                        "disk_traffic_forward",
                        "disk_traffic_local",
                        "disk_traffic_multicast",
                        "disk_traffic_sniffer",
                        "disk_traffic_fortiview",
                        "disk_traffic_threat",
                        "memory_event_vpn",
                        "memory_event_user",
                        "memory_event_router",
                        "memory_event_wireless",
                        "memory_event_wad",
                        "memory_event_endpoint",
                        "memory_event_ha",
                        "memory_event_compliance-check",
                        "memory_event_system",
                        "memory_event_connector",
                        "memory_event_security-rating",
                        "memory_event_fortiextender",
                        "memory_traffic_forward",
                        "memory_traffic_local",
                        "memory_traffic_multicast",
                        "memory_traffic_sniffer",
                        "memory_traffic_fortiview",
                        "memory_traffic_threat",
                        "fortianalyzer_event_vpn",
                        "fortianalyzer_event_user",
                        "fortianalyzer_event_router",
                        "fortianalyzer_event_wireless",
                        "fortianalyzer_event_wad",
                        "fortianalyzer_event_endpoint",
                        "fortianalyzer_event_ha",
                        "fortianalyzer_event_compliance-check",
                        "fortianalyzer_event_system",
                        "fortianalyzer_event_connector",
                        "fortianalyzer_event_security-rating",
                        "fortianalyzer_event_fortiextender",
                        "fortianalyzer_traffic_forward",
                        "fortianalyzer_traffic_local",
                        "fortianalyzer_traffic_multicast",
                        "fortianalyzer_traffic_sniffer",
                        "fortianalyzer_traffic_fortiview",
                        "fortianalyzer_traffic_threat",
                        "forticloud_event_vpn",
                        "forticloud_event_user",
                        "forticloud_event_router",
                        "forticloud_event_wireless",
                        "forticloud_event_wad",
                        "forticloud_event_endpoint",
                        "forticloud_event_ha",
                        "forticloud_event_compliance-check",
                        "forticloud_event_system",
                        "forticloud_event_connector",
                        "forticloud_event_security-rating",
                        "forticloud_event_fortiextender",
                        "forticloud_traffic_forward",
                        "forticloud_traffic_local",
                        "forticloud_traffic_multicast",
                        "forticloud_traffic_sniffer",
                        "forticloud_traffic_fortiview",
                        "forticloud_traffic_threat",
                    ],
                },
            },
        },
    }

    module = AnsibleModule(argument_spec=fields, supports_check_mode=False)
    check_legacy_fortiosapi(module)

    if (
        module.params["selector"]
        and module.params["selectors"]
        or not module.params["selector"]
        and not module.params["selectors"]
    ):
        module.fail_json(msg="please use selector or selectors in a task.")

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_custom_option("access_token", module.params["access_token"])

        # Logging for fact module could be disabled/enabled.
        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)

        fos = FortiOSHandler(connection, module)

        if module.params["selector"]:
            is_error, has_changed, result = fortios_log_fact(module.params, fos)
        else:
            params = module.params
            selectors = params["selectors"]
            is_error = False
            has_changed = False
            result = []
            for selector_obj in selectors:
                per_selector = {
                    "vdom": params.get("vdom"),
                    # **selector_obj,
                }
                per_selector.update(selector_obj)
                is_error_local, has_changed_local, result_local = fortios_log_fact(
                    per_selector, fos
                )

                is_error = is_error or is_error_local
                has_changed = has_changed or has_changed_local
                result.append(result_local)
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and galaxy, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.exit_json(changed=has_changed, meta=result)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
