#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright 2020 Fortinet, Inc.
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
module: fortios_monitor
version_added: "2.0.0"
short_description: Ansible Module for FortiOS Monitor API
description:
    - Request FortiOS appliances to perform specific actions or procedures.
      This module contain all the FortiOS monitor API.
author:
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@fshen01)
notes:
    - Different selector may have different parameters, users are expected to look up them for a specific selector.
    - For some selectors, the objects are global, no params are allowed to appear.
    - Not all parameters are required for a selector.
    - This module is exclusivly for FortiOS monitor API.
    - The result of API request is stored in results.
requirements:
    - install galaxy collection fortinet.fortios >= 2.0.0.
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
    selector:
        description:
            - selector of the retrieved fortimanager facts
        type: str
        required: true
        choices:
         - 'check.endpoint-control.registration-password'
         - 'quarantine.endpoint-control.registration'
         - 'unquarantine.endpoint-control.registration'
         - 'block.endpoint-control.registration'
         - 'unblock.endpoint-control.registration'
         - 'deregister.endpoint-control.registration'
         - 'clear_counters.firewall.acl'
         - 'clear_counters.firewall.acl6'
         - 'reset.firewall.policy'
         - 'clear_counters.firewall.policy'
         - 'reset.firewall.policy6'
         - 'clear_counters.firewall.policy6'
         - 'clear_counters.firewall.proxy-policy'
         - 'clear_all.firewall.session'
         - 'close.firewall.session'
         - 'reset.firewall.shaper'
         - 'reset.firewall.per-ip-shaper'
         - 'cancel.fortiview.session'
         - 'upgrade.license.database'
         - 'reset.log.stats'
         - 'login.registration.forticloud'
         - 'create.registration.forticloud'
         - 'logout.registration.forticloud'
         - 'login.registration.forticare'
         - 'create.registration.forticare'
         - 'add-license.registration.forticare'
         - 'add-license.registration.vdom'
         - 'toggle-vdom-mode.system.admin'
         - 'generate-key.system.api-user'
         - 'update-comments.system.config-revision'
         - 'delete.system.config-revision'
         - 'save.system.config-revision'
         - 'system.disconnect-admins'
         - 'set.system.time'
         - 'reboot.system.os'
         - 'shutdown.system.os'
         - 'revoke.system.dhcp'
         - 'revoke.system.dhcp6'
         - 'upgrade.system.firmware'
         - 'start.system.fsck'
         - 'system.change-password'
         - 'system.password-policy-conform'
         - 'reset.system.modem'
         - 'connect.system.modem'
         - 'disconnect.system.modem'
         - 'update.system.modem'
         - 'restart.system.sniffer'
         - 'start.system.sniffer'
         - 'stop.system.sniffer'
         - 'test.system.automation-stitch'
         - 'update.switch-controller.managed-switch'
         - 'restart.switch-controller.managed-switch'
         - 'poe-reset.switch-controller.managed-switch'
         - 'factory-reset.switch-controller.managed-switch'
         - 'download.switch-controller.fsw-firmware'
         - 'push.switch-controller.fsw-firmware'
         - 'upload.switch-controller.fsw-firmware'
         - 'dhcp-renew.system.interface'
         - 'start.system.usb-log'
         - 'stop.system.usb-log'
         - 'eject.system.usb-device'
         - 'update.system.fortiguard'
         - 'clear-statistics.system.fortiguard'
         - 'test-availability.system.fortiguard'
         - 'config.system.fortimanager'
         - 'backup-action.system.fortimanager'
         - 'dump.system.com-log'
         - 'update.system.ha-peer'
         - 'disconnect.system.ha-peer'
         - 'run.system.compliance'
         - 'restore.system.config'
         - 'upload.system.vmlicense'
         - 'trigger.system.security-rating'
         - 'reset.extender-controller.extender'
         - 'validate-gcp-key.system.sdn-connector'
         - 'deauth.user.firewall'
         - 'clear_users.user.banned'
         - 'add_users.user.banned'
         - 'clear_all.user.banned'
         - 'activate.user.fortitoken'
         - 'refresh.user.fortitoken'
         - 'provision.user.fortitoken'
         - 'send-activation.user.fortitoken'
         - 'import-trial.user.fortitoken'
         - 'import-mobile.user.fortitoken'
         - 'import-seed.user.fortitoken'
         - 'refresh-server.user.fsso'
         - 'test-connect.user.radius'
         - 'test.user.tacacs-plus'
         - 'delete.webfilter.override'
         - 'reset.webfilter.category-quota'
         - 'tunnel_up.vpn.ipsec'
         - 'tunnel_down.vpn.ipsec'
         - 'tunnel_reset_stats.vpn.ipsec'
         - 'clear_tunnel.vpn.ssl'
         - 'delete.vpn.ssl'
         - 'import.vpn-certificate.ca'
         - 'import.vpn-certificate.crl'
         - 'import.vpn-certificate.local'
         - 'import.vpn-certificate.remote'
         - 'generate.vpn-certificate.csr'
         - 'reset.wanopt.history'
         - 'reset.wanopt.webcache'
         - 'reset.wanopt.peer_stats'
         - 'reset.webcache.stats'
         - 'set_status.wifi.managed_ap'
         - 'download.wifi.firmware'
         - 'push.wifi.firmware'
         - 'upload.wifi.firmware'
         - 'restart.wifi.managed_ap'
         - 'reset.wifi.euclid'
         - 'clear_all.wifi.rogue_ap'
         - 'set_status.wifi.rogue_ap'
         - 'reset.firewall.consolidated-policy'
         - 'clear_counters.firewall.consolidated-policy'
         - 'clear_counters.firewall.security-policy'
         - 'add.firewall.clearpass-address'
         - 'delete.firewall.clearpass-address'
         - 'delete.log.local-report'
         - 'migrate.registration.forticloud'
         - 'change-vdom-mode.system.admin'
         - 'delete.system.config-script'
         - 'run.system.config-script'
         - 'upload.system.config-script'
         - 'diagnose.extender-controller.extender'
         - 'upgrade.extender-controller.extender'
         - 'add.nsx.service'
         - 'update.system.sdn-connector'
         - 'import.web-ui.language'
         - 'create.web-ui.custom-language'
         - 'update.web-ui.custom-language'
         - 'email.user.guest'
         - 'sms.user.guest'
         - 'utm.rating-lookup'
         - 'connect.wifi.network'
         - 'scan.wifi.network'
         - 'upload.wifi.region-image'
         - 'refresh.azure.application-list'
         - 'verify-cert.endpoint-control.ems'
         - 'geoip.geoip-query'
         - 'transfer.registration.forticare'
         - 'register-device.registration.forticloud'
         - 'register-appliance.system.csf'
         - 'clear.system.sniffer'
         - 'webhook.system.automation-stitch'
         - 'format.system.logdisk'
         - 'speed-test-trigger.system.interface'
         - 'read-info.system.certificate'
         - 'provision-user.vpn.ssl'
         - 'upload.webproxy.pacfile'
         - 'disassociate.wifi.client'
         - 'start.wifi.spectrum'
         - 'keep-alive.wifi.spectrum'
         - 'stop.wifi.spectrum'
         - 'start.wifi.vlan-probe'
         - 'stop.wifi.vlan-probe'
         - 'generate-keys.wifi.ssid'
         - 'save.system.config'
         - 'led-blink.wifi.managed_ap'
         - 'auth.user.firewall'
         - 'remove.user.device'
         - 'clear.vpn.ike'
         - 'reset.firewall.multicast-policy'
         - 'reset.firewall.multicast-policy6'
         - 'clear_counters.firewall.multicast-policy'
         - 'clear_counters.firewall.multicast-policy6'
         - 'clear-soft-in.router.bgp'
         - 'clear-soft-out.router.bgp'
         - 'enable-app-bandwidth-tracking.system.traffic-history'
         - 'refresh.system.external-resource'
         - 'reset.firewall.central-snat-map'
         - 'clear-counters.firewall.central-snat-map'
         - 'reset.firewall.dnat'
         - 'clear-counters.firewall.dnat'
         - 'close-multiple.firewall.session'
         - 'close-multiple.firewall.session6'
         - 'close-all.firewall.session'
         - 'clear.system.crash-log'
         - 'backup.system.config'
         - 'abort.user.query'
         - 'create.vpn-certificate.local'
         - 'flush.firewall.gtp'
         - 'kill.system.process'
         - 'upload.system.hscalefw-license'
         - 'download.system.vmlicense'
         - 'start.network.debug-flow'
         - 'stop.network.debug-flow'
         - 'upload.system.lte-modem'
         - 'upgrade.system.lte-modem'
         - 'port-stats-reset.switch-controller.managed-switch'
         - 'bounce-port.switch-controller.managed-switch'
         - 'set-tier1.switch-controller.mclag-icl'
         - 'wake-on-lan.system.interface'
         - 'manual-update.system.fortiguard'
         - 'purdue-level.user.device'
         - 'deregister-device.registration.forticare'
         - 'soft-reset-neighbor.router.bgp'
         - 'download-eval.system.vmlicense'
         - 'dynamic.system.external-resource'
         - 'pse-config.switch-controller.recommendation'
         - 'update.switch-controller.isl-lockdown'
         - 'clear-counters.firewall.ztna-firewall-policy'
         - 'update.forticonverter.eligibility'
         - 'create.forticonverter.ticket'
         - 'update.forticonverter.sn-list'
         - 'upload.forticonverter.config'
         - 'update.forticonverter.intf-list'
         - 'forticonverter.set-source-sn'
         - 'submit.forticonverter.intf-mapping'
         - 'submit.forticonverter.mgmt-intf'
         - 'submit.forticonverter.notes'
         - 'submit.forticonverter.ticket'
         - 'update.forticonverter.submitted-info'
         - 'start.forticonverter.download'
         - 'trial.user.fortitoken-cloud'
         - 'unverify-cert.endpoint-control.ems'
         - 'update-global-label.firewall.policy'
         - 'update-global-label.firewall.security-policy'
         - 'set-tier-plus.switch-controller.mclag-icl'
         - 'user.password-policy-conform'
         - 'change-password.user.local'
         - 'report.sdwan.link-monitor-metrics'
         - 'generic-address.system.external-resource'
         - 'set.system.private-data-encryption'
         - 'create-default.wifi.ap-profile'

    params:
        description:
            - the parameter for each selector, see definition in above list.
        type: dict
        required: false
"""

EXAMPLES = """
- name: Activate FortiToken
  fortinet.fortios.fortios_monitor:
      vdom: "root"
      access_token: "your_own_value"
      selector: 'activate.user.fortitoken'
      params:
          tokens: '<token string>'

- name: Reboot This Device
  fortinet.fortios.fortios_monitor:
      vdom: "root"
      access_token: "you_own_value"
      selector: 'reboot.system.os'
      params:
          event_log_message: 'Reboot Request From Ansible'
"""

RETURN = """
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'GET'
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "firmware"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "system"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
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
ansible_facts:
  description: The list of fact subsets collected from the device
  returned: always
  type: dict

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

module_selectors_defs = {
    "check.endpoint-control.registration-password": {
        "url": "endpoint-control/registration-password/check",
        "params": {"password": {"type": "string", "required": "True"}},
    },
    "quarantine.endpoint-control.registration": {
        "url": "endpoint-control/registration/quarantine",
        "params": {
            "uid": {"type": "string", "required": "False"},
            "mac": {"type": "string", "required": "False"},
        },
    },
    "unquarantine.endpoint-control.registration": {
        "url": "endpoint-control/registration/unquarantine",
        "params": {
            "uid": {"type": "string", "required": "False"},
            "mac": {"type": "string", "required": "False"},
        },
    },
    "block.endpoint-control.registration": {
        "url": "endpoint-control/registration/block",
        "params": {
            "uid": {"type": "string", "required": "False"},
            "mac": {"type": "string", "required": "False"},
        },
    },
    "unblock.endpoint-control.registration": {
        "url": "endpoint-control/registration/unblock",
        "params": {
            "uid": {"type": "string", "required": "False"},
            "mac": {"type": "string", "required": "False"},
        },
    },
    "deregister.endpoint-control.registration": {
        "url": "endpoint-control/registration/deregister",
        "params": {
            "uid": {"type": "string", "required": "False"},
            "mac": {"type": "string", "required": "False"},
        },
    },
    "clear_counters.firewall.acl": {
        "url": "firewall/acl/clear_counters",
        "params": {"policy": {"type": "int", "required": "False"}},
    },
    "clear_counters.firewall.acl6": {
        "url": "firewall/acl6/clear_counters",
        "params": {"policy": {"type": "int", "required": "False"}},
    },
    "reset.firewall.policy": {"url": "firewall/policy/reset", "params": {}},
    "clear_counters.firewall.policy": {
        "url": "firewall/policy/clear_counters",
        "params": {"policy": {"type": "int", "required": "False"}},
    },
    "reset.firewall.policy6": {"url": "firewall/policy6/reset", "params": {}},
    "clear_counters.firewall.policy6": {
        "url": "firewall/policy6/clear_counters",
        "params": {"policy": {"type": "int", "required": "False"}},
    },
    "clear_counters.firewall.proxy-policy": {
        "url": "firewall/proxy-policy/clear_counters",
        "params": {"policy": {"type": "int", "required": "False"}},
    },
    "clear_all.firewall.session": {"url": "firewall/session/clear_all", "params": {}},
    "close.firewall.session": {
        "url": "firewall/session/close",
        "params": {
            "pro": {"type": "string", "required": "True"},
            "saddr": {"type": "string", "required": "True"},
            "daddr": {"type": "string", "required": "True"},
            "sport": {"type": "int", "required": "True"},
            "dport": {"type": "int", "required": "True"},
        },
    },
    "reset.firewall.shaper": {"url": "firewall/shaper/reset", "params": {}},
    "reset.firewall.per-ip-shaper": {
        "url": "firewall/per-ip-shaper/reset",
        "params": {},
    },
    "cancel.fortiview.session": {
        "url": "fortiview/session/cancel",
        "params": {
            "sessionid": {"type": "int", "required": "False"},
            "device": {"type": "string", "required": "False"},
            "report_by": {"type": "string", "required": "False"},
            "view_level": {"type": "string", "required": "False"},
        },
    },
    "upgrade.license.database": {
        "url": "license/database/upgrade",
        "params": {
            "db_name": {"type": "string", "required": "True"},
            "confirm_not_signed": {"type": "boolean", "required": "False"},
            "confirm_not_ga_certified": {"type": "boolean", "required": "False"},
            "file_id": {"type": "string", "required": "False"},
            "file_content": {"type": "string", "required": "False"},
        },
    },
    "reset.log.stats": {"url": "log/stats/reset", "params": {}},
    "login.registration.forticloud": {
        "url": "registration/forticloud/login",
        "params": {
            "email": {"type": "string", "required": "True"},
            "password": {"type": "string", "required": "True"},
            "send_logs": {"type": "boolean", "required": "False"},
            "domain": {"type": "string", "required": "False"},
        },
    },
    "create.registration.forticloud": {
        "url": "registration/forticloud/create",
        "params": {
            "email": {"type": "string", "required": "True"},
            "password": {"type": "string", "required": "True"},
            "send_logs": {"type": "boolean", "required": "False"},
        },
    },
    "logout.registration.forticloud": {
        "url": "registration/forticloud/logout",
        "params": {},
    },
    "login.registration.forticare": {
        "url": "registration/forticare/login",
        "params": {
            "serial": {"type": "string", "required": "False"},
            "email": {"type": "string", "required": "True"},
            "password": {"type": "string", "required": "True"},
            "reseller_name": {"type": "string", "required": "True"},
            "reseller_id": {"type": "int", "required": "True"},
            "agreement_accepted": {"type": "boolean", "required": "False"},
            "is_government": {"type": "boolean", "required": "False"},
        },
    },
    "create.registration.forticare": {
        "url": "registration/forticare/create",
        "params": {
            "email": {"type": "string", "required": "True"},
            "password": {"type": "string", "required": "True"},
            "first_name": {"type": "string", "required": "True"},
            "last_name": {"type": "string", "required": "True"},
            "title": {"type": "string", "required": "False"},
            "company": {"type": "string", "required": "True"},
            "address": {"type": "string", "required": "True"},
            "city": {"type": "string", "required": "True"},
            "country_code": {"type": "int", "required": "True"},
            "state": {"type": "string", "required": "True"},
            "state_code": {"type": "string", "required": "False"},
            "postal_code": {"type": "string", "required": "True"},
            "phone": {"type": "string", "required": "True"},
            "industry": {"type": "string", "required": "True"},
            "industry_id": {"type": "int", "required": "True"},
            "orgsize_id": {"type": "int", "required": "True"},
            "reseller_name": {"type": "string", "required": "True"},
            "reseller_id": {"type": "int", "required": "True"},
            "is_government": {"type": "boolean", "required": "False"},
        },
    },
    "add-license.registration.forticare": {
        "url": "registration/forticare/add-license",
        "params": {"registration_code": {"type": "string", "required": "True"}},
    },
    "add-license.registration.vdom": {
        "url": "registration/vdom/add-license",
        "params": {"license": {"type": "string", "required": "True"}},
    },
    "toggle-vdom-mode.system.admin": {
        "url": "system/admin/toggle-vdom-mode",
        "params": {},
    },
    "generate-key.system.api-user": {
        "url": "system/api-user/generate-key",
        "params": {
            "api-user": {"type": "string", "required": "True"},
            "expiry": {"type": "int", "required": "False"},
        },
    },
    "update-comments.system.config-revision": {
        "url": "system/config-revision/update-comments",
        "params": {
            "config_id": {"type": "int", "required": "False"},
            "comments": {"type": "string", "required": "False"},
        },
    },
    "delete.system.config-revision": {
        "url": "system/config-revision/delete",
        "params": {"config_ids": {"type": "array", "required": "True"}},
    },
    "save.system.config-revision": {
        "url": "system/config-revision/save",
        "params": {"comments": {"type": "string", "required": "False"}},
    },
    "system.disconnect-admins": {
        "url": "system/disconnect-admins/select",
        "params": {
            "id": {"type": "int", "required": "False"},
            "method": {"type": "string", "required": "False"},
            "admins": {"type": "array", "required": "True"},
        },
    },
    "set.system.time": {
        "url": "system/time/set",
        "params": {
            "year": {"type": "int", "required": "True"},
            "month": {"type": "int", "required": "True"},
            "day": {"type": "int", "required": "True"},
            "hour": {"type": "int", "required": "True"},
            "minute": {"type": "int", "required": "True"},
            "second": {"type": "int", "required": "True"},
        },
    },
    "reboot.system.os": {
        "url": "system/os/reboot",
        "params": {"event_log_message": {"type": "string", "required": "False"}},
    },
    "shutdown.system.os": {
        "url": "system/os/shutdown",
        "params": {"event_log_message": {"type": "string", "required": "False"}},
    },
    "revoke.system.dhcp": {
        "url": "system/dhcp/revoke",
        "params": {"ip": {"type": "array", "required": "False"}},
    },
    "revoke.system.dhcp6": {
        "url": "system/dhcp6/revoke",
        "params": {"ip": {"type": "array", "required": "False"}},
    },
    "upgrade.system.firmware": {
        "url": "system/firmware/upgrade",
        "params": {
            "source": {"type": "string", "required": "True"},
            "url": {"type": "string", "required": "False"},
            "passphrase": {"type": "string", "required": "False"},
            "force": {"type": "boolean", "required": "False"},
            "filename": {"type": "string", "required": "False"},
            "format_partition": {"type": "boolean", "required": "False"},
            "ignore_invalid_signature": {"type": "boolean", "required": "False"},
            "file_id": {"type": "string", "required": "False"},
            "ignore_admin_lockout_upon_downgrade": {
                "type": "boolean",
                "required": "False",
            },
            "file_content": {"type": "string", "required": "False"},
        },
    },
    "start.system.fsck": {"url": "system/fsck/start", "params": {}},
    "system.change-password": {
        "url": "system/change-password/select",
        "params": {
            "mkey": {"type": "string", "required": "False"},
            "old_password": {"type": "string", "required": "False"},
            "new_password": {"type": "string", "required": "True"},
        },
    },
    "system.password-policy-conform": {
        "url": "system/password-policy-conform/select",
        "params": {
            "mkey": {"type": "string", "required": "False"},
            "apply_to": {"type": "string", "required": "False"},
            "password": {"type": "string", "required": "False"},
            "old_password": {"type": "string", "required": "False"},
        },
    },
    "reset.system.modem": {"url": "system/modem/reset", "params": {}},
    "connect.system.modem": {"url": "system/modem/connect", "params": {}},
    "disconnect.system.modem": {"url": "system/modem/disconnect", "params": {}},
    "update.system.modem": {"url": "system/modem/update", "params": {}},
    "restart.system.sniffer": {
        "url": "system/sniffer/restart",
        "params": {"mkey": {"type": "int", "required": "True"}},
    },
    "start.system.sniffer": {
        "url": "system/sniffer/start",
        "params": {"mkey": {"type": "int", "required": "True"}},
    },
    "stop.system.sniffer": {
        "url": "system/sniffer/stop",
        "params": {"mkey": {"type": "int", "required": "True"}},
    },
    "test.system.automation-stitch": {
        "url": "system/automation-stitch/test",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "log": {"type": "string", "required": "False"},
        },
    },
    "update.switch-controller.managed-switch": {
        "url": "switch-controller/managed-switch/update",
        "params": {
            "mkey": {"type": "string", "required": "False"},
            "admin": {"type": "string", "required": "False"},
        },
    },
    "restart.switch-controller.managed-switch": {
        "url": "switch-controller/managed-switch/restart",
        "params": {"mkey": {"type": "string", "required": "True"}},
    },
    "poe-reset.switch-controller.managed-switch": {
        "url": "switch-controller/managed-switch/poe-reset",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "port": {"type": "string", "required": "True"},
        },
    },
    "factory-reset.switch-controller.managed-switch": {
        "url": "switch-controller/managed-switch/factory-reset",
        "params": {"mkey": {"type": "string", "required": "True"}},
    },
    "download.switch-controller.fsw-firmware": {
        "url": "switch-controller/fsw-firmware/download",
        "params": {"image_id": {"type": "string", "required": "True"}},
    },
    "push.switch-controller.fsw-firmware": {
        "url": "switch-controller/fsw-firmware/push",
        "params": {
            "switch_id": {"type": "string", "required": "True"},
            "image_id": {"type": "string", "required": "True"},
        },
    },
    "upload.switch-controller.fsw-firmware": {
        "url": "switch-controller/fsw-firmware/upload",
        "params": {
            "switch_ids": {"type": "string", "required": "False"},
            "file_content": {"type": "string", "required": "False"},
        },
    },
    "dhcp-renew.system.interface": {
        "url": "system/interface/dhcp-renew",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "ipv6": {"type": "boolean", "required": "False"},
        },
    },
    "start.system.usb-log": {"url": "system/usb-log/start", "params": {}},
    "stop.system.usb-log": {"url": "system/usb-log/stop", "params": {}},
    "eject.system.usb-device": {"url": "system/usb-device/eject", "params": {}},
    "update.system.fortiguard": {"url": "system/fortiguard/update", "params": {}},
    "clear-statistics.system.fortiguard": {
        "url": "system/fortiguard/clear-statistics",
        "params": {},
    },
    "test-availability.system.fortiguard": {
        "url": "system/fortiguard/test-availability",
        "params": {
            "protocol": {"type": "string", "required": "True"},
            "port": {"type": "int", "required": "True"},
            "service": {"type": "string", "required": "True"},
        },
    },
    "config.system.fortimanager": {
        "url": "system/fortimanager/config",
        "params": {
            "fortimanager_ip": {"type": "string", "required": "False"},
            "unregister": {"type": "boolean", "required": "False"},
        },
    },
    "backup-action.system.fortimanager": {
        "url": "system/fortimanager/backup-action",
        "params": {
            "operation": {"type": "string", "required": "True"},
            "objects": {"type": "array", "required": "True"},
        },
    },
    "dump.system.com-log": {"url": "system/com-log/dump", "params": {}},
    "update.system.ha-peer": {
        "url": "system/ha-peer/update",
        "params": {
            "serial_no": {"type": "string", "required": "True"},
            "vcluster_id": {"type": "int", "required": "False"},
            "priority": {"type": "int", "required": "False"},
            "hostname": {"type": "string", "required": "False"},
        },
    },
    "disconnect.system.ha-peer": {
        "url": "system/ha-peer/disconnect",
        "params": {
            "serial_no": {"type": "string", "required": "True"},
            "interface": {"type": "string", "required": "True"},
            "ip": {"type": "string", "required": "True"},
            "mask": {"type": "string", "required": "True"},
        },
    },
    "run.system.compliance": {"url": "system/compliance/run", "params": {}},
    "restore.system.config": {
        "url": "system/config/restore",
        "params": {
            "source": {"type": "string", "required": "True"},
            "usb_filename": {"type": "string", "required": "False"},
            "config_id": {"type": "int", "required": "False"},
            "password": {"type": "string", "required": "False"},
            "scope": {"type": "string", "required": "True"},
            "vdom": {"type": "string", "required": "False"},
            "confirm_password_mask": {"type": "boolean", "required": "False"},
            "file_content": {"type": "string", "required": "False"},
        },
    },
    "upload.system.vmlicense": {
        "url": "system/vmlicense/upload",
        "params": {"file_content": {"type": "string", "required": "False"}},
    },
    "trigger.system.security-rating": {
        "url": "system/security-rating/trigger",
        "params": {
            "report_type": {"type": "string", "required": "False"},
            "report_types": {"type": "array", "required": "False"},
        },
    },
    "reset.extender-controller.extender": {
        "url": "extender-controller/extender/reset",
        "params": {"id": {"type": "string", "required": "True"}},
    },
    "validate-gcp-key.system.sdn-connector": {
        "url": "system/sdn-connector/validate-gcp-key",
        "params": {"private-key": {"type": "string", "required": "True"}},
    },
    "deauth.user.firewall": {
        "url": "user/firewall/deauth",
        "params": {
            "user_type": {"type": "string", "required": "False"},
            "id": {"type": "int", "required": "False"},
            "ip": {"type": "string", "required": "False"},
            "ip_version": {"type": "string", "required": "False"},
            "method": {"type": "string", "required": "False"},
            "all": {"type": "boolean", "required": "False"},
            "users": {"type": "array", "required": "False"},
        },
    },
    "clear_users.user.banned": {
        "url": "user/banned/clear_users",
        "params": {"ip_addresses": {"type": "array", "required": "True"}},
    },
    "add_users.user.banned": {
        "url": "user/banned/add_users",
        "params": {
            "ip_addresses": {"type": "array", "required": "True"},
            "expiry": {"type": "int", "required": "False"},
        },
    },
    "clear_all.user.banned": {"url": "user/banned/clear_all", "params": {}},
    "activate.user.fortitoken": {
        "url": "user/fortitoken/activate",
        "params": {"tokens": {"type": "array", "required": "False"}},
    },
    "refresh.user.fortitoken": {
        "url": "user/fortitoken/refresh",
        "params": {"tokens": {"type": "array", "required": "False"}},
    },
    "provision.user.fortitoken": {
        "url": "user/fortitoken/provision",
        "params": {"tokens": {"type": "array", "required": "False"}},
    },
    "send-activation.user.fortitoken": {
        "url": "user/fortitoken/send-activation",
        "params": {
            "token": {"type": "string", "required": "True"},
            "method": {"type": "string", "required": "False"},
            "email": {"type": "string", "required": "False"},
            "sms_phone": {"type": "string", "required": "False"},
        },
    },
    "import-trial.user.fortitoken": {
        "url": "user/fortitoken/import-trial",
        "params": {},
    },
    "import-mobile.user.fortitoken": {
        "url": "user/fortitoken/import-mobile",
        "params": {"code": {"type": "string", "required": "True"}},
    },
    "import-seed.user.fortitoken": {
        "url": "user/fortitoken/import-seed",
        "params": {"file_content": {"type": "string", "required": "False"}},
    },
    "refresh-server.user.fsso": {"url": "user/fsso/refresh-server", "params": {}},
    "test-connect.user.radius": {
        "url": "user/radius/test-connect",
        "params": {
            "mkey": {"type": "string", "required": "False"},
            "ordinal": {"type": "string", "required": "False"},
            "server": {"type": "string", "required": "False"},
            "secret": {"type": "string", "required": "False"},
            "auth_type": {"type": "string", "required": "False"},
            "user": {"type": "string", "required": "False"},
            "password": {"type": "string", "required": "False"},
        },
    },
    "test.user.tacacs-plus": {
        "url": "user/tacacs-plus/test",
        "params": {
            "mkey": {"type": "string", "required": "False"},
            "ordinal": {"type": "string", "required": "False"},
            "server": {"type": "string", "required": "False"},
            "secret": {"type": "string", "required": "False"},
            "port": {"type": "int", "required": "False"},
            "source_ip": {"type": "string", "required": "False"},
        },
    },
    "delete.webfilter.override": {
        "url": "webfilter/override/delete",
        "params": {"mkey": {"type": "string", "required": "False"}},
    },
    "reset.webfilter.category-quota": {
        "url": "webfilter/category-quota/reset",
        "params": {
            "profile": {"type": "string", "required": "False"},
            "user": {"type": "string", "required": "False"},
        },
    },
    "tunnel_up.vpn.ipsec": {
        "url": "vpn/ipsec/tunnel_up",
        "params": {
            "p1name": {"type": "string", "required": "True"},
            "p2name": {"type": "string", "required": "True"},
            "p2serial": {"type": "int", "required": "False"},
        },
    },
    "tunnel_down.vpn.ipsec": {
        "url": "vpn/ipsec/tunnel_down",
        "params": {
            "p1name": {"type": "string", "required": "True"},
            "p2name": {"type": "string", "required": "True"},
            "p2serial": {"type": "int", "required": "False"},
        },
    },
    "tunnel_reset_stats.vpn.ipsec": {
        "url": "vpn/ipsec/tunnel_reset_stats",
        "params": {"p1name": {"type": "string", "required": "True"}},
    },
    "clear_tunnel.vpn.ssl": {"url": "vpn/ssl/clear_tunnel", "params": {}},
    "delete.vpn.ssl": {
        "url": "vpn/ssl/delete",
        "params": {
            "type": {"type": "string", "required": "True"},
            "index": {"type": "int", "required": "True"},
        },
    },
    "import.vpn-certificate.ca": {
        "url": "vpn-certificate/ca/import",
        "params": {
            "import_method": {"type": "string", "required": "True"},
            "scep_url": {"type": "string", "required": "False"},
            "scep_ca_id": {"type": "string", "required": "False"},
            "scope": {"type": "string", "required": "False"},
            "file_content": {"type": "string", "required": "False"},
        },
    },
    "import.vpn-certificate.crl": {
        "url": "vpn-certificate/crl/import",
        "params": {
            "scope": {"type": "string", "required": "False"},
            "file_content": {"type": "string", "required": "False"},
        },
    },
    "import.vpn-certificate.local": {
        "url": "vpn-certificate/local/import",
        "params": {
            "type": {"type": "string", "required": "True"},
            "certname": {"type": "string", "required": "False"},
            "password": {"type": "string", "required": "False"},
            "key_file_content": {"type": "string", "required": "False"},
            "scope": {"type": "string", "required": "False"},
            "acme_domain": {"type": "string", "required": "False"},
            "acme_email": {"type": "string", "required": "False"},
            "acme_ca_url": {"type": "string", "required": "False"},
            "acme_rsa_key_size": {"type": "int", "required": "False"},
            "acme_renew_window": {"type": "int", "required": "False"},
            "file_content": {"type": "string", "required": "False"},
        },
    },
    "import.vpn-certificate.remote": {
        "url": "vpn-certificate/remote/import",
        "params": {
            "scope": {"type": "string", "required": "False"},
            "file_content": {"type": "string", "required": "False"},
        },
    },
    "generate.vpn-certificate.csr": {
        "url": "vpn-certificate/csr/generate",
        "params": {
            "certname": {"type": "string", "required": "True"},
            "subject": {"type": "string", "required": "True"},
            "keytype": {"type": "string", "required": "True"},
            "keysize": {"type": "int", "required": "False"},
            "curvename": {"type": "string", "required": "False"},
            "orgunits": {"type": "array", "required": "False"},
            "org": {"type": "string", "required": "False"},
            "city": {"type": "string", "required": "False"},
            "state": {"type": "string", "required": "False"},
            "countrycode": {"type": "string", "required": "False"},
            "email": {"type": "string", "required": "False"},
            "subject_alt_name": {"type": "string", "required": "False"},
            "password": {"type": "string", "required": "False"},
            "scep_url": {"type": "string", "required": "False"},
            "scep_password": {"type": "string", "required": "False"},
            "scope": {"type": "string", "required": "False"},
        },
    },
    "reset.wanopt.history": {"url": "wanopt/history/reset", "params": {}},
    "reset.wanopt.webcache": {"url": "wanopt/webcache/reset", "params": {}},
    "reset.wanopt.peer_stats": {"url": "wanopt/peer_stats/reset", "params": {}},
    "reset.webcache.stats": {"url": "webcache/stats/reset", "params": {}},
    "set_status.wifi.managed_ap": {
        "url": "wifi/managed_ap/set_status",
        "params": {
            "wtpname": {"type": "string", "required": "False"},
            "admin": {"type": "string", "required": "False"},
        },
    },
    "download.wifi.firmware": {
        "url": "wifi/firmware/download",
        "params": {"image_id": {"type": "string", "required": "True"}},
    },
    "push.wifi.firmware": {
        "url": "wifi/firmware/push",
        "params": {
            "serial": {"type": "string", "required": "True"},
            "image_id": {"type": "string", "required": "True"},
        },
    },
    "upload.wifi.firmware": {
        "url": "wifi/firmware/upload",
        "params": {
            "serials": {"type": "string", "required": "False"},
            "file_content": {"type": "string", "required": "False"},
        },
    },
    "restart.wifi.managed_ap": {
        "url": "wifi/managed_ap/restart",
        "params": {"wtpname": {"type": "string", "required": "False"}},
    },
    "reset.wifi.euclid": {"url": "wifi/euclid/reset", "params": {}},
    "clear_all.wifi.rogue_ap": {"url": "wifi/rogue_ap/clear_all", "params": {}},
    "set_status.wifi.rogue_ap": {
        "url": "wifi/rogue_ap/set_status",
        "params": {
            "bssid": {"type": "array", "required": "False"},
            "ssid": {"type": "array", "required": "False"},
            "status": {"type": "string", "required": "False"},
        },
    },
    "reset.firewall.consolidated-policy": {
        "url": "firewall/consolidated-policy/reset",
        "params": {},
    },
    "clear_counters.firewall.consolidated-policy": {
        "url": "firewall/consolidated-policy/clear_counters",
        "params": {"policy": {"type": "int", "required": "False"}},
    },
    "clear_counters.firewall.security-policy": {
        "url": "firewall/security-policy/clear_counters",
        "params": {"policy": {"type": "int", "required": "False"}},
    },
    "add.firewall.clearpass-address": {
        "url": "firewall/clearpass-address/add",
        "params": {
            "endpoint_ip": {"type": "array", "required": "True"},
            "spt": {"type": "string", "required": "False"},
        },
    },
    "delete.firewall.clearpass-address": {
        "url": "firewall/clearpass-address/delete",
        "params": {
            "endpoint_ip": {"type": "array", "required": "True"},
            "spt": {"type": "string", "required": "False"},
        },
    },
    "delete.log.local-report": {
        "url": "log/local-report/delete",
        "params": {"mkeys": {"type": "array", "required": "True"}},
    },
    "migrate.registration.forticloud": {
        "url": "registration/forticloud/migrate",
        "params": {
            "email": {"type": "string", "required": "True"},
            "password": {"type": "string", "required": "True"},
        },
    },
    "change-vdom-mode.system.admin": {
        "url": "system/admin/change-vdom-mode",
        "params": {"vdom-mode": {"type": "string", "required": "True"}},
    },
    "delete.system.config-script": {
        "url": "system/config-script/delete",
        "params": {"id_list": {"type": "array", "required": "True"}},
    },
    "run.system.config-script": {
        "url": "system/config-script/run",
        "params": {"remote_script": {"type": "string", "required": "True"}},
    },
    "upload.system.config-script": {
        "url": "system/config-script/upload",
        "params": {
            "filename": {"type": "string", "required": "False"},
            "file_content": {"type": "string", "required": "False"},
        },
    },
    "diagnose.extender-controller.extender": {
        "url": "extender-controller/extender/diagnose",
        "params": {
            "id": {"type": "string", "required": "True"},
            "cmd": {"type": "string", "required": "True"},
        },
    },
    "upgrade.extender-controller.extender": {
        "url": "extender-controller/extender/upgrade",
        "params": {
            "id": {"type": "string", "required": "True"},
            "file_content": {"type": "string", "required": "False"},
        },
    },
    "add.nsx.service": {
        "url": "nsx/service/add",
        "params": {"mkey": {"type": "string", "required": "True"}},
    },
    "update.system.sdn-connector": {
        "url": "system/sdn-connector/update",
        "params": {"mkey": {"type": "string", "required": "True"}},
    },
    "import.web-ui.language": {
        "url": "web-ui/language/import",
        "params": {"file_content": {"type": "string", "required": "False"}},
    },
    "create.web-ui.custom-language": {
        "url": "web-ui/custom-language/create",
        "params": {
            "lang_name": {"type": "string", "required": "True"},
            "lang_comments": {"type": "string", "required": "False"},
            "file_content": {"type": "string", "required": "False"},
        },
    },
    "update.web-ui.custom-language": {
        "url": "web-ui/custom-language/update",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "lang_name": {"type": "string", "required": "False"},
            "lang_comments": {"type": "string", "required": "False"},
            "file_content": {"type": "string", "required": "False"},
        },
    },
    "email.user.guest": {
        "url": "user/guest/email",
        "params": {
            "group": {"type": "string", "required": "True"},
            "guest": {"type": "array", "required": "True"},
        },
    },
    "sms.user.guest": {
        "url": "user/guest/sms",
        "params": {
            "group": {"type": "string", "required": "True"},
            "guest": {"type": "array", "required": "True"},
        },
    },
    "utm.rating-lookup": {
        "url": "utm/rating-lookup/select",
        "params": {
            "url": {"type": "array", "required": "False"},
            "lang": {"type": "string", "required": "False"},
        },
    },
    "connect.wifi.network": {
        "url": "wifi/network/connect",
        "params": {"ssid": {"type": "string", "required": "True"}},
    },
    "scan.wifi.network": {"url": "wifi/network/scan", "params": {}},
    "upload.wifi.region-image": {
        "url": "wifi/region-image/upload",
        "params": {
            "region_name": {"type": "string", "required": "True"},
            "image_type": {"type": "string", "required": "True"},
            "file_content": {"type": "string", "required": "False"},
        },
    },
    "refresh.azure.application-list": {
        "url": "azure/application-list/refresh",
        "params": {"last_update_time": {"type": "int", "required": "False"}},
    },
    "verify-cert.endpoint-control.ems": {
        "url": "endpoint-control/ems/verify-cert",
        "params": {
            "ems_id": {"type": "int", "required": "True"},
            "scope": {"type": "string", "required": "False"},
            "fingerprint": {"type": "string", "required": "True"},
        },
    },
    "geoip.geoip-query": {
        "url": "geoip/geoip-query/select",
        "params": {"ip_addresses": {"type": "array", "required": "True"}},
    },
    "transfer.registration.forticare": {
        "url": "registration/forticare/transfer",
        "params": {
            "email": {"type": "string", "required": "True"},
            "password": {"type": "string", "required": "True"},
            "old_email": {"type": "string", "required": "True"},
            "old_password": {"type": "string", "required": "True"},
            "is_government": {"type": "boolean", "required": "False"},
        },
    },
    "register-device.registration.forticloud": {
        "url": "registration/forticloud/register-device",
        "params": {
            "serial": {"type": "string", "required": "False"},
            "email": {"type": "string", "required": "True"},
            "password": {"type": "string", "required": "True"},
            "reseller": {"type": "string", "required": "True"},
            "reseller_id": {"type": "int", "required": "True"},
            "country": {"type": "string", "required": "True"},
            "is_government": {"type": "boolean", "required": "False"},
            "agreement_accepted": {"type": "boolean", "required": "False"},
        },
    },
    "register-appliance.system.csf": {
        "url": "system/csf/register-appliance",
        "params": {
            "type": {"type": "string", "required": "True"},
            "mgmt_ip": {"type": "string", "required": "True"},
            "mgmt_port": {"type": "int", "required": "False"},
            "mgmt_url_parameters": {"type": "array", "required": "False"},
            "serial": {"type": "string", "required": "True"},
            "hostname": {"type": "string", "required": "False"},
        },
    },
    "clear.system.sniffer": {
        "url": "system/sniffer/clear",
        "params": {"mkey": {"type": "int", "required": "True"}},
    },
    "webhook.system.automation-stitch": {
        "url": "system/automation-stitch/webhook",
        "params": {"mkey": {"type": "string", "required": "True"}},
    },
    "format.system.logdisk": {
        "url": "system/logdisk/format",
        "params": {"raid": {"type": "string", "required": "True"}},
    },
    "speed-test-trigger.system.interface": {
        "url": "system/interface/speed-test-trigger",
        "params": {"mkey": {"type": "string", "required": "True"}},
    },
    "read-info.system.certificate": {
        "url": "system/certificate/read-info",
        "params": {"value": {"type": "string", "required": "True"}},
    },
    "provision-user.vpn.ssl": {
        "url": "vpn/ssl/provision-user",
        "params": {
            "host": {"type": "string", "required": "True"},
            "port": {"type": "int", "required": "True"},
            "vpn_name": {"type": "string", "required": "True"},
            "method": {"type": "string", "required": "False"},
            "email_list": {"type": "string", "required": "False"},
            "phone_user_list": {"type": "string", "required": "False"},
            "phone_number_list": {"type": "string", "required": "False"},
            "sms_method": {"type": "string", "required": "False"},
            "sms_server": {"type": "string", "required": "False"},
        },
    },
    "upload.webproxy.pacfile": {
        "url": "webproxy/pacfile/upload",
        "params": {
            "filename": {"type": "string", "required": "False"},
            "file_content": {"type": "string", "required": "False"},
        },
    },
    "disassociate.wifi.client": {
        "url": "wifi/client/disassociate",
        "params": {"mac": {"type": "string", "required": "True"}},
    },
    "start.wifi.spectrum": {
        "url": "wifi/spectrum/start",
        "params": {
            "wtp_id": {"type": "string", "required": "True"},
            "radio_id": {"type": "int", "required": "True"},
            "channels": {"type": "array", "required": "True"},
            "duration": {"type": "int", "required": "True"},
        },
    },
    "keep-alive.wifi.spectrum": {
        "url": "wifi/spectrum/keep-alive",
        "params": {
            "wtp_id": {"type": "string", "required": "True"},
            "radio_id": {"type": "int", "required": "True"},
            "duration": {"type": "int", "required": "True"},
        },
    },
    "stop.wifi.spectrum": {
        "url": "wifi/spectrum/stop",
        "params": {
            "wtp_id": {"type": "string", "required": "True"},
            "radio_id": {"type": "int", "required": "True"},
        },
    },
    "start.wifi.vlan-probe": {
        "url": "wifi/vlan-probe/start",
        "params": {
            "ap_interface": {"type": "int", "required": "True"},
            "wtp": {"type": "string", "required": "True"},
            "start_vlan_id": {"type": "int", "required": "True"},
            "end_vlan_id": {"type": "int", "required": "True"},
            "retries": {"type": "int", "required": "True"},
            "timeout": {"type": "int", "required": "True"},
        },
    },
    "stop.wifi.vlan-probe": {
        "url": "wifi/vlan-probe/stop",
        "params": {
            "ap_interface": {"type": "int", "required": "True"},
            "wtp": {"type": "string", "required": "True"},
        },
    },
    "generate-keys.wifi.ssid": {
        "url": "wifi/ssid/generate-keys",
        "params": {
            "mpsk_profile": {"type": "string", "required": "True"},
            "group": {"type": "string", "required": "True"},
            "prefix": {"type": "string", "required": "True"},
            "count": {"type": "int", "required": "True"},
            "key_length": {"type": "int", "required": "True"},
        },
    },
    "save.system.config": {"url": "system/config/save", "params": {}},
    "led-blink.wifi.managed_ap": {
        "url": "wifi/managed_ap/led-blink",
        "params": {
            "serials": {"type": "array", "required": "True"},
            "blink": {"type": "boolean", "required": "True"},
            "duration": {"type": "int", "required": "False"},
        },
    },
    "auth.user.firewall": {
        "url": "user/firewall/auth",
        "params": {
            "username": {"type": "string", "required": "True"},
            "ip": {"type": "string", "required": "True"},
            "server": {"type": "string", "required": "False"},
        },
    },
    "remove.user.device": {
        "url": "user/device/remove",
        "params": {"macs": {"type": "array", "required": "False"}},
    },
    "clear.vpn.ike": {
        "url": "vpn/ike/clear",
        "params": {"mkey": {"type": "string", "required": "True"}},
    },
    "reset.firewall.multicast-policy": {
        "url": "firewall/multicast-policy/reset",
        "params": {},
    },
    "reset.firewall.multicast-policy6": {
        "url": "firewall/multicast-policy6/reset",
        "params": {},
    },
    "clear_counters.firewall.multicast-policy": {
        "url": "firewall/multicast-policy/clear_counters",
        "params": {"policy": {"type": "int", "required": "False"}},
    },
    "clear_counters.firewall.multicast-policy6": {
        "url": "firewall/multicast-policy6/clear_counters",
        "params": {"policy": {"type": "int", "required": "False"}},
    },
    "clear-soft-in.router.bgp": {"url": "router/bgp/clear-soft-in", "params": {}},
    "clear-soft-out.router.bgp": {"url": "router/bgp/clear-soft-out", "params": {}},
    "enable-app-bandwidth-tracking.system.traffic-history": {
        "url": "system/traffic-history/enable-app-bandwidth-tracking",
        "params": {},
    },
    "refresh.system.external-resource": {
        "url": "system/external-resource/refresh",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "check_status_only": {"type": "boolean", "required": "False"},
            "last_connection_time": {"type": "int", "required": "False"},
        },
    },
    "reset.firewall.central-snat-map": {
        "url": "firewall/central-snat-map/reset",
        "params": {},
    },
    "clear-counters.firewall.central-snat-map": {
        "url": "firewall/central-snat-map/clear-counters",
        "params": {"policy": {"type": "int", "required": "False"}},
    },
    "reset.firewall.dnat": {"url": "firewall/dnat/reset", "params": {}},
    "clear-counters.firewall.dnat": {
        "url": "firewall/dnat/clear-counters",
        "params": {
            "id": {"type": "int", "required": "False"},
            "is_ipv6": {"type": "boolean", "required": "False"},
        },
    },
    "close-multiple.firewall.session": {
        "url": "firewall/session/close-multiple",
        "params": {
            "proto": {"type": "string", "required": "False"},
            "saddr": {"type": "string", "required": "False"},
            "daddr": {"type": "string", "required": "False"},
            "sport": {"type": "int", "required": "False"},
            "dport": {"type": "int", "required": "False"},
            "naddr": {"type": "string", "required": "False"},
            "nport": {"type": "int", "required": "False"},
            "policy": {"type": "int", "required": "False"},
        },
    },
    "close-multiple.firewall.session6": {
        "url": "firewall/session6/close-multiple",
        "params": {
            "proto": {"type": "string", "required": "False"},
            "saddr": {"type": "string", "required": "False"},
            "daddr": {"type": "string", "required": "False"},
            "sport": {"type": "int", "required": "False"},
            "dport": {"type": "int", "required": "False"},
            "policy": {"type": "int", "required": "False"},
        },
    },
    "close-all.firewall.session": {"url": "firewall/session/close-all", "params": {}},
    "clear.system.crash-log": {"url": "system/crash-log/clear", "params": {}},
    "backup.system.config": {
        "url": "system/config/backup",
        "params": {
            "destination": {"type": "string", "required": "False"},
            "usb_filename": {"type": "string", "required": "False"},
            "password": {"type": "string", "required": "False"},
            "scope": {"type": "string", "required": "True"},
            "vdom": {"type": "string", "required": "False"},
            "password_mask": {"type": "boolean", "required": "False"},
            "file_format": {"type": "string", "required": "False"},
        },
    },
    "abort.user.query": {
        "url": "user/query/abort",
        "params": {"query_id": {"type": "int", "required": "True"}},
    },
    "create.vpn-certificate.local": {
        "url": "vpn-certificate/local/create",
        "params": {
            "certname": {"type": "string", "required": "True"},
            "common_name": {"type": "string", "required": "True"},
            "scope": {"type": "string", "required": "True"},
        },
    },
    "flush.firewall.gtp": {
        "url": "firewall/gtp/flush",
        "params": {
            "scope": {"type": "string", "required": "False"},
            "gtp_profile": {"type": "string", "required": "False"},
            "version": {"type": "int", "required": "False"},
            "imsi": {"type": "string", "required": "False"},
            "msisdn": {"type": "string", "required": "False"},
            "ms_addr": {"type": "string", "required": "False"},
            "ms_addr6": {"type": "string", "required": "False"},
            "cteid": {"type": "int", "required": "False"},
            "cteid_addr": {"type": "string", "required": "False"},
            "cteid_addr6": {"type": "string", "required": "False"},
            "fteid": {"type": "int", "required": "False"},
            "fteid_addr": {"type": "string", "required": "False"},
            "fteid_addr6": {"type": "string", "required": "False"},
            "apn": {"type": "string", "required": "False"},
        },
    },
    "kill.system.process": {
        "url": "system/process/kill",
        "params": {
            "pid": {"type": "int", "required": "True"},
            "signal": {"type": "int", "required": "False"},
        },
    },
    "upload.system.hscalefw-license": {
        "url": "system/hscalefw-license/upload",
        "params": {"license_key": {"type": "string", "required": "True"}},
    },
    "download.system.vmlicense": {
        "url": "system/vmlicense/download",
        "params": {
            "token": {"type": "string", "required": "False"},
            "proxy_url": {"type": "string", "required": "False"},
        },
    },
    "start.network.debug-flow": {
        "url": "network/debug-flow/start",
        "params": {
            "num_packets": {"type": "int", "required": "True"},
            "ipv6": {"type": "boolean", "required": "True"},
            "negate": {"type": "boolean", "required": "False"},
            "addr_from": {"type": "string", "required": "False"},
            "addr_to": {"type": "string", "required": "False"},
            "daddr_from": {"type": "string", "required": "False"},
            "daddr_to": {"type": "string", "required": "False"},
            "saddr_from": {"type": "string", "required": "False"},
            "saddr_to": {"type": "string", "required": "False"},
            "port_from": {"type": "int", "required": "False"},
            "port_to": {"type": "int", "required": "False"},
            "dport_from": {"type": "int", "required": "False"},
            "dport_to": {"type": "int", "required": "False"},
            "sport_from": {"type": "int", "required": "False"},
            "sport_to": {"type": "int", "required": "False"},
            "proto": {"type": "int", "required": "False"},
        },
    },
    "stop.network.debug-flow": {"url": "network/debug-flow/stop", "params": {}},
    "upload.system.lte-modem": {
        "url": "system/lte-modem/upload",
        "params": {
            "filename": {"type": "string", "required": "False"},
            "file_content": {"type": "string", "required": "False"},
        },
    },
    "upgrade.system.lte-modem": {"url": "system/lte-modem/upgrade", "params": {}},
    "port-stats-reset.switch-controller.managed-switch": {
        "url": "switch-controller/managed-switch/port-stats-reset",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "ports": {"type": "array", "required": "False"},
        },
    },
    "bounce-port.switch-controller.managed-switch": {
        "url": "switch-controller/managed-switch/bounce-port",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "port": {"type": "string", "required": "True"},
            "duration": {"type": "int", "required": "False"},
            "stop": {"type": "boolean", "required": "False"},
        },
    },
    "set-tier1.switch-controller.mclag-icl": {
        "url": "switch-controller/mclag-icl/set-tier1",
        "params": {
            "fortilink": {"type": "string", "required": "True"},
            "peer1": {"type": "string", "required": "True"},
            "peer2": {"type": "string", "required": "True"},
        },
    },
    "wake-on-lan.system.interface": {
        "url": "system/interface/wake-on-lan",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "mac": {"type": "string", "required": "True"},
            "protocol_option": {"type": "string", "required": "False"},
            "port": {"type": "int", "required": "False"},
            "address": {"type": "string", "required": "False"},
            "secureon_password": {"type": "string", "required": "False"},
        },
    },
    "manual-update.system.fortiguard": {
        "url": "system/fortiguard/manual-update",
        "params": {"file_content": {"type": "string", "required": "False"}},
    },
    "purdue-level.user.device": {
        "url": "user/device/purdue-level",
        "params": {
            "mac": {"type": "string", "required": "True"},
            "ip": {"type": "string", "required": "False"},
            "level": {"type": "string", "required": "True"},
        },
    },
    "deregister-device.registration.forticare": {
        "url": "registration/forticare/deregister-device",
        "params": {
            "email": {"type": "string", "required": "True"},
            "password": {"type": "string", "required": "True"},
        },
    },
    "soft-reset-neighbor.router.bgp": {
        "url": "router/bgp/soft-reset-neighbor",
        "params": {"ip": {"type": "string", "required": "True"}},
    },
    "download-eval.system.vmlicense": {
        "url": "system/vmlicense/download-eval",
        "params": {
            "account_id": {"type": "string", "required": "True"},
            "account_password": {"type": "string", "required": "True"},
            "is_government": {"type": "boolean", "required": "False"},
        },
    },
    "dynamic.system.external-resource": {
        "url": "system/external-resource/dynamic",
        "params": {"commands": {"type": "array", "required": "True"}},
    },
    "pse-config.switch-controller.recommendation": {
        "url": "switch-controller/recommendation/pse-config",
        "params": {"fortilink": {"type": "string", "required": "True"}},
    },
    "update.switch-controller.isl-lockdown": {
        "url": "switch-controller/isl-lockdown/update",
        "params": {
            "fortilink": {"type": "string", "required": "True"},
            "status": {"type": "string", "required": "True"},
        },
    },
    "clear-counters.firewall.ztna-firewall-policy": {
        "url": "firewall/ztna-firewall-policy/clear-counters",
        "params": {"policy": {"type": "int", "required": "False"}},
    },
    "update.forticonverter.eligibility": {
        "url": "forticonverter/eligibility/update",
        "params": {},
    },
    "create.forticonverter.ticket": {
        "url": "forticonverter/ticket/create",
        "params": {},
    },
    "update.forticonverter.sn-list": {
        "url": "forticonverter/sn-list/update",
        "params": {},
    },
    "upload.forticonverter.config": {
        "url": "forticonverter/config/upload",
        "params": {
            "ticket_id": {"type": "string", "required": "True"},
            "file_content": {"type": "string", "required": "False"},
        },
    },
    "update.forticonverter.intf-list": {
        "url": "forticonverter/intf-list/update",
        "params": {},
    },
    "forticonverter.set-source-sn": {
        "url": "forticonverter/set-source-sn/select",
        "params": {
            "source_sn": {"type": "string", "required": "True"},
            "ticket_id": {"type": "string", "required": "True"},
        },
    },
    "submit.forticonverter.intf-mapping": {
        "url": "forticonverter/intf-mapping/submit",
        "params": {
            "intf_mapping": {"type": "object", "required": "True"},
            "ticket_id": {"type": "string", "required": "True"},
        },
    },
    "submit.forticonverter.mgmt-intf": {
        "url": "forticonverter/mgmt-intf/submit",
        "params": {
            "intf_details": {"type": "object", "required": "True"},
            "ticket_id": {"type": "string", "required": "True"},
        },
    },
    "submit.forticonverter.notes": {
        "url": "forticonverter/notes/submit",
        "params": {
            "ticket_id": {"type": "string", "required": "True"},
            "contact_name": {"type": "string", "required": "True"},
            "contact_email": {"type": "string", "required": "True"},
            "contact_phone": {"type": "string", "required": "True"},
            "notes": {"type": "string", "required": "False"},
        },
    },
    "submit.forticonverter.ticket": {
        "url": "forticonverter/ticket/submit",
        "params": {"ticket_id": {"type": "string", "required": "True"}},
    },
    "update.forticonverter.submitted-info": {
        "url": "forticonverter/submitted-info/update",
        "params": {},
    },
    "start.forticonverter.download": {
        "url": "forticonverter/download/start",
        "params": {
            "ticket_id": {"type": "string", "required": "True"},
            "extension": {"type": "string", "required": "True"},
        },
    },
    "trial.user.fortitoken-cloud": {"url": "user/fortitoken-cloud/trial", "params": {}},
    "unverify-cert.endpoint-control.ems": {
        "url": "endpoint-control/ems/unverify-cert",
        "params": {
            "ems_id": {"type": "int", "required": "True"},
            "scope": {"type": "string", "required": "False"},
        },
    },
    "update-global-label.firewall.policy": {
        "url": "firewall/policy/update-global-label",
        "params": {
            "policyid": {"type": "string", "required": "True"},
            "current-label": {"type": "string", "required": "False"},
            "new-label": {"type": "string", "required": "False"},
        },
    },
    "update-global-label.firewall.security-policy": {
        "url": "firewall/security-policy/update-global-label",
        "params": {
            "policyid": {"type": "string", "required": "True"},
            "current-label": {"type": "string", "required": "False"},
            "new-label": {"type": "string", "required": "False"},
        },
    },
    "set-tier-plus.switch-controller.mclag-icl": {
        "url": "switch-controller/mclag-icl/set-tier-plus",
        "params": {
            "fortilink": {"type": "string", "required": "True"},
            "parent_peer1": {"type": "string", "required": "True"},
            "parent_peer2": {"type": "string", "required": "True"},
            "peer1": {"type": "string", "required": "True"},
            "peer2": {"type": "string", "required": "True"},
            "isl_port_group": {"type": "string", "required": "True"},
        },
    },
    "user.password-policy-conform": {
        "url": "user/password-policy-conform/select",
        "params": {
            "username": {"type": "string", "required": "False"},
            "password": {"type": "string", "required": "True"},
        },
    },
    "change-password.user.local": {
        "url": "user/local/change-password",
        "params": {
            "username": {"type": "string", "required": "True"},
            "new_password": {"type": "string", "required": "True"},
        },
    },
    "report.sdwan.link-monitor-metrics": {
        "url": "sdwan/link-monitor-metrics/report",
        "params": {
            "agent_ip": {"type": "string", "required": "True"},
            "application_name": {"type": "string", "required": "True"},
            "application_id": {"type": "int", "required": "True"},
            "latency": {"type": "double", "required": "True"},
            "jitter": {"type": "double", "required": "True"},
            "packet_loss": {"type": "double", "required": "True"},
            "ntt": {"type": "double", "required": "False"},
            "srt": {"type": "double", "required": "False"},
            "application_error": {"type": "double", "required": "False"},
        },
    },
    "generic-address.system.external-resource": {
        "url": "system/external-resource/generic-address",
        "params": {
            "mkey": {"type": "string", "required": "True"},
            "data": {"type": "object", "required": "True"},
        },
    },
    "set.system.private-data-encryption": {
        "url": "system/private-data-encryption/set",
        "params": {
            "enable": {"type": "boolean", "required": "True"},
            "password": {"type": "string", "required": "False"},
        },
    },
    "create-default.wifi.ap-profile": {
        "url": "wifi/ap-profile/create-default",
        "params": {"platform": {"type": "string", "required": "True"}},
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


def validate_parameters(fos):
    # parameter validation will not block task, warning will be provided in case of parameters validation.
    mod_params = fos._module.params
    selector = mod_params["selector"]
    params = mod_params["params"]

    if params:
        for param_key, param_value in params.items():
            if not isinstance(param_value, (bool, int, str, list)):
                return False, {
                    "message": "value of param:%s must be atomic" % (param_key)
                }

    acceptable_param_names = list(module_selectors_defs[selector]["params"].keys())
    provided_param_names = list(params.keys() if params else [])

    params_valid = True
    for param_name in acceptable_param_names:
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
                "required" if eval(param["required"]) else "optional",
            )
            for param_name, param in module_selectors_defs[selector]["params"].items()
        ]
        fos._module.warn(
            "selector:%s expects params:%s" % (selector, str(param_summary))
        )
    return True, {}


def fortios_monitor(fos):
    valid, result = validate_parameters(fos)
    if not valid:
        return True, False, result

    params = fos._module.params

    selector = params["selector"]
    selector_params = params["params"]

    resp = fos.monitor_post(
        module_selectors_defs[selector]["url"],
        vdom=params["vdom"],
        data=selector_params,
    )

    return not is_successful_status(resp), False, resp


def main():
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "params": {"required": False, "type": "dict"},
        "selector": {
            "required": True,
            "type": "str",
            "choices": [
                "check.endpoint-control.registration-password",
                "quarantine.endpoint-control.registration",
                "unquarantine.endpoint-control.registration",
                "block.endpoint-control.registration",
                "unblock.endpoint-control.registration",
                "deregister.endpoint-control.registration",
                "clear_counters.firewall.acl",
                "clear_counters.firewall.acl6",
                "reset.firewall.policy",
                "clear_counters.firewall.policy",
                "reset.firewall.policy6",
                "clear_counters.firewall.policy6",
                "clear_counters.firewall.proxy-policy",
                "clear_all.firewall.session",
                "close.firewall.session",
                "reset.firewall.shaper",
                "reset.firewall.per-ip-shaper",
                "cancel.fortiview.session",
                "upgrade.license.database",
                "reset.log.stats",
                "login.registration.forticloud",
                "create.registration.forticloud",
                "logout.registration.forticloud",
                "login.registration.forticare",
                "create.registration.forticare",
                "add-license.registration.forticare",
                "add-license.registration.vdom",
                "toggle-vdom-mode.system.admin",
                "generate-key.system.api-user",
                "update-comments.system.config-revision",
                "delete.system.config-revision",
                "save.system.config-revision",
                "system.disconnect-admins",
                "set.system.time",
                "reboot.system.os",
                "shutdown.system.os",
                "revoke.system.dhcp",
                "revoke.system.dhcp6",
                "upgrade.system.firmware",
                "start.system.fsck",
                "system.change-password",
                "system.password-policy-conform",
                "reset.system.modem",
                "connect.system.modem",
                "disconnect.system.modem",
                "update.system.modem",
                "restart.system.sniffer",
                "start.system.sniffer",
                "stop.system.sniffer",
                "test.system.automation-stitch",
                "update.switch-controller.managed-switch",
                "restart.switch-controller.managed-switch",
                "poe-reset.switch-controller.managed-switch",
                "factory-reset.switch-controller.managed-switch",
                "download.switch-controller.fsw-firmware",
                "push.switch-controller.fsw-firmware",
                "upload.switch-controller.fsw-firmware",
                "dhcp-renew.system.interface",
                "start.system.usb-log",
                "stop.system.usb-log",
                "eject.system.usb-device",
                "update.system.fortiguard",
                "clear-statistics.system.fortiguard",
                "test-availability.system.fortiguard",
                "config.system.fortimanager",
                "backup-action.system.fortimanager",
                "dump.system.com-log",
                "update.system.ha-peer",
                "disconnect.system.ha-peer",
                "run.system.compliance",
                "restore.system.config",
                "upload.system.vmlicense",
                "trigger.system.security-rating",
                "reset.extender-controller.extender",
                "validate-gcp-key.system.sdn-connector",
                "deauth.user.firewall",
                "clear_users.user.banned",
                "add_users.user.banned",
                "clear_all.user.banned",
                "activate.user.fortitoken",
                "refresh.user.fortitoken",
                "provision.user.fortitoken",
                "send-activation.user.fortitoken",
                "import-trial.user.fortitoken",
                "import-mobile.user.fortitoken",
                "import-seed.user.fortitoken",
                "refresh-server.user.fsso",
                "test-connect.user.radius",
                "test.user.tacacs-plus",
                "delete.webfilter.override",
                "reset.webfilter.category-quota",
                "tunnel_up.vpn.ipsec",
                "tunnel_down.vpn.ipsec",
                "tunnel_reset_stats.vpn.ipsec",
                "clear_tunnel.vpn.ssl",
                "delete.vpn.ssl",
                "import.vpn-certificate.ca",
                "import.vpn-certificate.crl",
                "import.vpn-certificate.local",
                "import.vpn-certificate.remote",
                "generate.vpn-certificate.csr",
                "reset.wanopt.history",
                "reset.wanopt.webcache",
                "reset.wanopt.peer_stats",
                "reset.webcache.stats",
                "set_status.wifi.managed_ap",
                "download.wifi.firmware",
                "push.wifi.firmware",
                "upload.wifi.firmware",
                "restart.wifi.managed_ap",
                "reset.wifi.euclid",
                "clear_all.wifi.rogue_ap",
                "set_status.wifi.rogue_ap",
                "reset.firewall.consolidated-policy",
                "clear_counters.firewall.consolidated-policy",
                "clear_counters.firewall.security-policy",
                "add.firewall.clearpass-address",
                "delete.firewall.clearpass-address",
                "delete.log.local-report",
                "migrate.registration.forticloud",
                "change-vdom-mode.system.admin",
                "delete.system.config-script",
                "run.system.config-script",
                "upload.system.config-script",
                "diagnose.extender-controller.extender",
                "upgrade.extender-controller.extender",
                "add.nsx.service",
                "update.system.sdn-connector",
                "import.web-ui.language",
                "create.web-ui.custom-language",
                "update.web-ui.custom-language",
                "email.user.guest",
                "sms.user.guest",
                "utm.rating-lookup",
                "connect.wifi.network",
                "scan.wifi.network",
                "upload.wifi.region-image",
                "refresh.azure.application-list",
                "verify-cert.endpoint-control.ems",
                "geoip.geoip-query",
                "transfer.registration.forticare",
                "register-device.registration.forticloud",
                "register-appliance.system.csf",
                "clear.system.sniffer",
                "webhook.system.automation-stitch",
                "format.system.logdisk",
                "speed-test-trigger.system.interface",
                "read-info.system.certificate",
                "provision-user.vpn.ssl",
                "upload.webproxy.pacfile",
                "disassociate.wifi.client",
                "start.wifi.spectrum",
                "keep-alive.wifi.spectrum",
                "stop.wifi.spectrum",
                "start.wifi.vlan-probe",
                "stop.wifi.vlan-probe",
                "generate-keys.wifi.ssid",
                "save.system.config",
                "led-blink.wifi.managed_ap",
                "auth.user.firewall",
                "remove.user.device",
                "clear.vpn.ike",
                "reset.firewall.multicast-policy",
                "reset.firewall.multicast-policy6",
                "clear_counters.firewall.multicast-policy",
                "clear_counters.firewall.multicast-policy6",
                "clear-soft-in.router.bgp",
                "clear-soft-out.router.bgp",
                "enable-app-bandwidth-tracking.system.traffic-history",
                "refresh.system.external-resource",
                "reset.firewall.central-snat-map",
                "clear-counters.firewall.central-snat-map",
                "reset.firewall.dnat",
                "clear-counters.firewall.dnat",
                "close-multiple.firewall.session",
                "close-multiple.firewall.session6",
                "close-all.firewall.session",
                "clear.system.crash-log",
                "backup.system.config",
                "abort.user.query",
                "create.vpn-certificate.local",
                "flush.firewall.gtp",
                "kill.system.process",
                "upload.system.hscalefw-license",
                "download.system.vmlicense",
                "start.network.debug-flow",
                "stop.network.debug-flow",
                "upload.system.lte-modem",
                "upgrade.system.lte-modem",
                "port-stats-reset.switch-controller.managed-switch",
                "bounce-port.switch-controller.managed-switch",
                "set-tier1.switch-controller.mclag-icl",
                "wake-on-lan.system.interface",
                "manual-update.system.fortiguard",
                "purdue-level.user.device",
                "deregister-device.registration.forticare",
                "soft-reset-neighbor.router.bgp",
                "download-eval.system.vmlicense",
                "dynamic.system.external-resource",
                "pse-config.switch-controller.recommendation",
                "update.switch-controller.isl-lockdown",
                "clear-counters.firewall.ztna-firewall-policy",
                "update.forticonverter.eligibility",
                "create.forticonverter.ticket",
                "update.forticonverter.sn-list",
                "upload.forticonverter.config",
                "update.forticonverter.intf-list",
                "forticonverter.set-source-sn",
                "submit.forticonverter.intf-mapping",
                "submit.forticonverter.mgmt-intf",
                "submit.forticonverter.notes",
                "submit.forticonverter.ticket",
                "update.forticonverter.submitted-info",
                "start.forticonverter.download",
                "trial.user.fortitoken-cloud",
                "unverify-cert.endpoint-control.ems",
                "update-global-label.firewall.policy",
                "update-global-label.firewall.security-policy",
                "set-tier-plus.switch-controller.mclag-icl",
                "user.password-policy-conform",
                "change-password.user.local",
                "report.sdwan.link-monitor-metrics",
                "generic-address.system.external-resource",
                "set.system.private-data-encryption",
                "create-default.wifi.ap-profile",
            ],
        },
    }

    module = AnsibleModule(argument_spec=fields, supports_check_mode=False)
    check_legacy_fortiosapi(module)

    is_error = False
    has_changed = False
    result = None

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        # Checking system status prevents upload.system.vmlicense from uploading a licence to a newly installed machine.
        connection.set_custom_option("check_system_status", False)

        if "access_token" in module.params:
            connection.set_custom_option("access_token", module.params["access_token"])

        # Logging for fact module could be disabled/enabled.
        if "enable_log" in module.params:
            connection.set_custom_option("enable_log", module.params["enable_log"])
        else:
            connection.set_custom_option("enable_log", False)

        fos = FortiOSHandler(connection, module)

        is_error, has_changed, result = fortios_monitor(fos)
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
