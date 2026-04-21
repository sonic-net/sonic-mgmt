#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_syslog_remote_dest
short_description: Manage Syslog Remote Destinations (syslog:RemoteDest)
description:
- Manage remote destinations for syslog messages within an existing syslog group object.
options:
  admin_state:
    description:
    - Administrative state of the syslog remote destination
    type: str
    choices: [ enabled, disabled ]
  description:
    description:
    - Description of the remote destination
    type: str
  destination:
    description:
    - Hostname or IP address to send syslog messages to
    type: str
  format:
    description:
    - Format of the syslog messages
    type: str
    choices: [ aci, nxos ]
  facility:
    description:
    - Forwarding facility for syslog messages
    type: str
    choices: [ local0, local1, local2, local3, local4, local5, local6, local7 ]
  group:
    description:
    - Name of an existing syslog group
    type: str
    aliases: [ syslog_group, syslog_group_name ]
  mgmt_epg:
    description:
    - Name of a management EPG to send syslog messages from
    type: str
  name:
    description:
    - Name of the syslog remote destination
    type: str
    aliases: [ remote_destination_name, remote_destination ]
  severity:
    description:
    - Severity of messages to send to remote syslog
    type: str
    choices: [ alerts, critical, debugging, emergencies, error, information, notifications, warnings]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  syslog_port:
    description:
    - UDP port to send syslog messages to
    type: int
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(syslog:RemoteDest).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Create a syslog remote destination
  cisco.aci.aci_syslog_remote_dest:
    host: apic
    username: admin
    password: SomeSecretPassword
    group: my_syslog_group
    facility: local7
    destination: 10.20.30.40
    syslog_port: 5678
    mgmt_epg: oob-default
    state: present
  delegate_to: localhost

- name: Delete syslog remote destination
  cisco.aci.aci_syslog_remote_dest:
    host: apic
    username: admin
    password: SomeSecretPassword
    group: my_syslog_group
    destination: 10.20.30.40
    state: absent
  delegate_to: localhost

- name: Query a syslog remote destination
  cisco.aci.aci_syslog_remote_dest:
    host: apic
    username: admin
    password: SomeSecretPassword
    group: my_syslog_group
    destination: 10.20.30.40
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all syslog remote destinations
  cisco.aci.aci_syslog_remote_dest:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result
"""

RETURN = r"""
current:
  description: The existing configuration from the APIC after the module has finished
  returned: success
  type: list
  sample:
    [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production environment",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
error:
  description: The error information as returned from the APIC
  returned: failure
  type: dict
  sample:
    {
        "code": "122",
        "text": "unknown managed object class foo"
    }
raw:
  description: The raw output returned by the APIC REST API (xml or json)
  returned: parse error
  type: str
  sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class foo"/></imdata>'
sent:
  description: The actual/minimal configuration pushed to the APIC
  returned: info
  type: list
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment"
            }
        }
    }
previous:
  description: The original configuration from the APIC before the module has started
  returned: info
  type: list
  sample:
    [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
proposed:
  description: The assembled configuration from the user-provided parameters
  returned: info
  type: dict
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment",
                "name": "production"
            }
        }
    }
filter_string:
  description: The filter string used for the request
  returned: failure or debug
  type: str
  sample: ?rsp-prop-include=config-only
method:
  description: The HTTP method used for the request to the APIC
  returned: failure or debug
  type: str
  sample: POST
response:
  description: The HTTP response from the APIC
  returned: failure or debug
  type: str
  sample: OK (30 bytes)
status:
  description: The HTTP status from the APIC
  returned: failure or debug
  type: int
  sample: 200
url:
  description: The HTTP url used for the request to the APIC
  returned: failure or debug
  type: str
  sample: https://10.11.12.13/api/mo/uni/tn-production.json
"""

from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        name=dict(type="str", aliases=["remote_destination_name", "remote_destination"]),
        format=dict(type="str", choices=["aci", "nxos"]),
        admin_state=dict(type="str", choices=["enabled", "disabled"]),
        description=dict(type="str"),
        destination=dict(type="str"),
        facility=dict(type="str", choices=["local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"]),
        group=dict(type="str", aliases=["syslog_group", "syslog_group_name"]),
        mgmt_epg=dict(type="str"),
        syslog_port=dict(type="int"),
        severity=dict(type="str", choices=["alerts", "critical", "debugging", "emergencies", "error", "information", "notifications", "warnings"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["group", "destination"]],
            ["state", "present", ["group", "destination"]],
        ],
    )

    aci = ACIModule(module)

    name = module.params.get("name")
    format = module.params.get("format")
    admin_state = module.params.get("admin_state")
    description = module.params.get("description")
    destination = module.params.get("destination")
    facility = module.params.get("facility")
    group = module.params.get("group")
    syslog_port = module.params.get("syslog_port")
    severity = module.params.get("severity")
    state = module.params.get("state")
    mgmt_epg = module.params.get("mgmt_epg")

    aci.construct_url(
        root_class=dict(
            aci_class="syslogGroup",
            aci_rn="fabric/slgroup-{0}".format(group),
            module_object=group,
            target_filter={"name": group},
        ),
        subclass_1=dict(
            aci_class="syslogRemoteDest",
            aci_rn="rdst-{0}".format(destination),
            module_object=destination,
            target_filter={"host": destination},
        ),
        child_classes=["fileRsARemoteHostToEpg"],
    )

    aci.get_existing()

    if state == "present":
        child_configs = []
        if mgmt_epg:
            child_configs.append(
                dict(
                    fileRsARemoteHostToEpg=dict(
                        attributes=dict(tDn=("uni/tn-mgmt/mgmtp-default/{0}".format(mgmt_epg))),
                    ),
                )
            )
        aci.payload(
            aci_class="syslogRemoteDest",
            class_config=dict(
                adminState=admin_state,
                descr=description,
                format=format,
                forwardingFacility=facility,
                host=destination,
                name=name,
                port=syslog_port,
                severity=severity,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class="syslogRemoteDest")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
