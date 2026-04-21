#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Manuel Widmer <mawidmer@cisco.com>
# Copyright: (c) 2021, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# Copyright: (c) 2023, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: aci_vmm_controller
short_description: Manage VMM Controller for virtual domains profiles (vmm:CtrlrP)
description:
- Manage vCenter virtual domains on Cisco ACI fabrics.
options:
  name:
    description:
    - Name of VMM Controller.
    type: str
    aliases: []
  controller_hostname:
    description:
    - Hostname or IP of the controller.
    type: str
    aliases: []
  dvs_version:
    description:
    - Version of the VMware DVS.
    type: str
    aliases: []
    choices: [ 'unmanaged', '5.1', '5.5', '6.0', '6.5', '6.6', '7.0', '8.0' ]
  stats_collection:
    description:
    - Whether stats collection is enabled.
    type: str
    choices: [ 'enabled', 'disabled' ]
    default: disabled
    aliases: []
  domain:
    description:
    - Name of the virtual domain profile.
    type: str
    aliases: [ domain_name, domain_profile ]
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
  credentials:
    description:
    - Name of the VMM credentials to be used
    type: str
  inband_management_epg:
    description:
    - Name of the management EPG to be used by the controller. Only supports in-band management EPGs for now.
    type: str
  name_alias:
    description:
    - The alias for the current object. This relates to the nameAlias field in ACI.
    type: str
  datacenter:
    description:
    - Name of the data center, as seen in vCenter
    type: str
  vm_provider:
    description:
    - The VM platform for VMM Domains.
    - Support for Kubernetes was added in ACI v3.0.
    - Support for CloudFoundry, OpenShift and Red Hat was added in ACI v3.1.
    type: str
    choices: [ cloudfoundry, kubernetes, microsoft, openshift, openstack, redhat, vmware, nutanix ]
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation

seealso:
- module: cisco.aci.aci_domain
- module: cisco.aci.aci_vmm_credential
- name: APIC Management Information Model reference
  description: More information about the internal APIC classes B(vmm:DomP)
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Manuel Widmer (@lumean)
- Anvitha Jain (@anvitha-jain)
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Add controller to VMware VMM domain
  cisco.aci.aci_vmm_controller:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: vmware_dom
    name: vCenter1
    controller_hostname: 10.1.1.1
    dvs_version: unmanaged
    vm_provider: vmware
    credentials: vCenterCredentials1
    datacenter: DC1
    state: present

- name: Remove controller from VMware VMM domain
  cisco.aci.aci_vmm_controller:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: vmware_dom
    name: vCenter1
    vm_provider: vmware
    state: absent

- name: Query a specific VMware VMM controller
  cisco.aci.aci_vmm_controller:
    host: apic
    username: admin
    password: SomeSecretPassword
    domain: vmware_dom
    name: vCenter1
    vm_provider: vmware
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all VMware VMM controller
  cisco.aci.aci_vmm_controller:
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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec
from ansible_collections.cisco.aci.plugins.module_utils.constants import VM_PROVIDER_MAPPING, VM_SCOPE_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(
        name=dict(type="str"),
        controller_hostname=dict(type="str"),
        dvs_version=dict(type="str", choices=["unmanaged", "5.1", "5.5", "6.0", "6.5", "6.6", "7.0", "8.0"]),
        stats_collection=dict(type="str", default="disabled", choices=["enabled", "disabled"]),
        domain=dict(type="str", aliases=["domain_name", "domain_profile"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
        credentials=dict(type="str"),
        inband_management_epg=dict(type="str"),
        name_alias=dict(type="str"),
        datacenter=dict(type="str"),
        vm_provider=dict(type="str", choices=list(VM_PROVIDER_MAPPING)),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["domain", "vm_provider", "name"]],
            ["state", "present", ["domain", "vm_provider", "name"]],
        ],
    )

    name = module.params.get("name")
    controller_hostname = module.params.get("controller_hostname")
    dvs_version = module.params.get("dvs_version")
    stats_collection = module.params.get("stats_collection")
    domain = module.params.get("domain")
    state = module.params.get("state")
    credentials = module.params.get("credentials")
    inband_management_epg = module.params.get("inband_management_epg")
    name_alias = module.params.get("name_alias")
    datacenter = module.params.get("datacenter")
    vm_provider = module.params.get("vm_provider")

    controller_class = "vmmCtrlrP"

    aci = ACIModule(module)

    child_classes = ["vmmRsMgmtEPg", "vmmRsAcc"]

    aci.construct_url(
        root_class=dict(
            aci_class="vmmProvP",
            aci_rn="vmmp-{0}".format(VM_PROVIDER_MAPPING.get(vm_provider)),
            module_object=vm_provider,
            target_filter={"name": vm_provider},
        ),
        subclass_1=dict(
            aci_class="vmmDomP",
            aci_rn="dom-{0}".format(domain),
            module_object=domain,
            target_filter={"name": domain},
        ),
        subclass_2=dict(
            aci_class="vmmCtrlrP",
            aci_rn="ctrlr-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=child_classes,
    )

    # vmmProvP is not allowed to execute a query with rsp-subtree set in the filter_string
    # due to complicated url construction logic which should be refactored creating a temporary fix inside module
    # TODO refactor url construction logic if more occurences of rsp-subtree not supported problem appear
    # check if the url is pointing towards the vmmProvP class and rsp-subtree is set in the filter_string
    if aci.url.split("/")[-1].startswith("vmmp-") and "rsp-subtree" in aci.filter_string:
        if name:
            aci.url = "{0}/api/class/vmmCtrlrP.json".format(aci.base_url)
            aci.filter_string = '?query-target-filter=eq(vmmCtrlrP.name,"{0}")&rsp-subtree=full&rsp-subtree-class={1}'.format(name, ",".join(child_classes))
        else:
            aci.url = "{0}/api/mo/uni/vmmp-{1}.json".format(aci.base_url, VM_PROVIDER_MAPPING.get(vm_provider))
            aci.filter_string = ""

    aci.get_existing()

    if state == "present":
        children = list()
        if inband_management_epg is not None:
            children.append(dict(vmmRsMgmtEPg=dict(attributes=dict(tDn="uni/tn-mgmt/mgmtp-default/inb-{0}".format(inband_management_epg)))))

        if credentials is not None:
            children.append(
                dict(vmmRsAcc=dict(attributes=dict(tDn="uni/vmmp-{0}/dom-{1}/usracc-{2}".format(VM_PROVIDER_MAPPING.get(vm_provider), domain, credentials))))
            )

        aci.payload(
            aci_class=controller_class,
            class_config=dict(
                name=name,
                hostOrIp=controller_hostname,
                dvsVersion=dvs_version,
                statsMode=stats_collection,
                rootContName=datacenter,
                nameAlias=name_alias,
                scope=VM_SCOPE_MAPPING.get(vm_provider),
            ),
            child_configs=children,
        )

        aci.get_diff(aci_class=controller_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
