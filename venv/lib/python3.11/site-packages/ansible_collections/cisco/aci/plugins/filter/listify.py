#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Ramses Smeyers <rsmeyers@cisco.com>
# Copyright: (c) 2023, Shreyas Srish <ssrish@cisco.com>
# Copyright: (c) 2024, Akini Ross <akinross@cisco.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
    name: aci_listify
    short_description: Flattens the nested dictionaries representing the ACI model data.
    description:
      - This filter flattens and transforms the input data into a list.
      - See the Examples section below.
    options:
      data:
        description: This option represents the ACI model data which is a list of dictionaries or a dictionary with any level of nesting data.
        type: raw
        required: True
      keys:
        description: Comma separated keys of type string denoting the ACI objects.
        required: True
"""

EXAMPLES = r"""
- name: Set vars
  ansible.builtin.set_fact:
    data:
      tenant:
        - name: ansible_test
          description: Created using listify
          app:
            - name: app_test
              epg:
                - name: web
                  bd: web_bd
                - name: app
                  bd: app_bd
          bd:
            - name: bd_test
              subnet:
                - name: 10.10.10.1
                  mask: 24
                  scope:
                    - public
                    - shared
              vrf: vrf_test
            - name: bd_test2
              subnet:
                - name: 20.20.20.1
                  mask: 24
                  scope: public
              vrf: vrf_test
          vrf:
            - name: vrf_test
          policies:
            protocol:
              bfd:
                - name: BFD-ON
                  description: Enable BFD
                  admin_state: enabled
                  detection_multiplier: 3
                  min_tx_interval: 50
                  min_rx_interval: 50
                  echo_rx_interval: 50
                  echo_admin_state: enabled
                  sub_interface_optimization_state: enabled
              ospf:
                interface:
                  - name: OSPF-P2P-IntPol
                    network_type: p2p
                    priority: 1
                  - name: OSPF-Broadcast-IntPol
                    network_type: bcast
                    priority: 1

- name: Create tenants
  cisco.aci.aci_tenant:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: '{{ item.tenant_name }}'
    description: '{{ item.tenant_description }}'
  with_items: '{{ data|cisco.aci.aci_listify("tenant") }}'

- name: Create VRFs
  cisco.aci.aci_vrf:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: '{{ item.tenant_name }}'
    vrf_name: '{{ item.tenant_vrf_name }}'
  with_items: '{{ data|cisco.aci.aci_listify("tenant","vrf") }}'

- name: Create BDs
  cisco.aci.aci_bd:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: '{{ item.tenant_name }}'
    vrf: '{{ item.tenant_bd_vrf }}'
    bd: '{{ item.tenant_bd_name }}'
    enable_routing: 'yes'
  with_items: '{{ data|cisco.aci.aci_listify("tenant","bd") }}'

- name: Create BD subnets
  cisco.aci.aci_bd_subnet:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: '{{ item.tenant_name }}'
    bd: '{{ item.tenant_bd_name }}'
    gateway: '{{ item.tenant_bd_subnet_name }}'
    mask: '{{ item.tenant_bd_subnet_mask }}'
    scope: '{{ item.tenant_bd_subnet_scope }}'
  with_items: '{{ data|cisco.aci.aci_listify("tenant","bd","subnet") }}'

- name: Create APs
  cisco.aci.aci_ap:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: '{{ item.tenant_name }}'
    app_profile: '{{ item.tenant_app_name }}'
  with_items: '{{ data|cisco.aci.aci_listify("tenant","app") }}'

- name: Create EPGs
  cisco.aci.aci_epg:
    host: apic
    username: admin
    password: SomeSecretPassword
    tenant: '{{ item.tenant_name }}'
    app_profile: '{{ item.tenant_app_name }}'
    epg: '{{ item.tenant_app_epg_name }}'
    bd: '{{ item.tenant_app_epg_bd }}'
  with_items: '{{ data|cisco.aci.aci_listify("tenant","app","epg") }}'
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


# This function takes a dictionary and a series of keys,
# and returns a list of dictionaries using recursive helper function 'listify_worker'
def listify(d, *keys):
    return list(listify_worker(d, keys, 0, {}, ""))


# This function walks through a dictionary 'd', depth-first,
# using the keys provided, and generates a new dictionary for each key:value pair encountered
def listify_worker(d, keys, depth, cache, prefix):
    # The prefix in the code is used to store the path of keys traversed in the nested dictionary,
    # which helps to generate unique keys for each value when flattening the dictionary.
    prefix += keys[depth] + "_"

    if keys[depth] in d:
        for item in d[keys[depth]]:
            cache_work = cache.copy()
            if isinstance(item, dict):
                for k, v in item.items():
                    if isinstance(v, list) and all(isinstance(x, (str, int, float, bool, bytes)) for x in v) or not isinstance(v, (dict, list)):
                        # The cache in this code is a temporary storage that holds key-value pairs as the function navigates through the nested dictionary.
                        # It helps to generate the final output by remembering the traversed path in each recursive call.
                        cache_key = prefix + k
                        cache_value = v
                        cache_work[cache_key] = cache_value
                # If we're at the deepest level of keys
                if len(keys) - 1 == depth:
                    yield cache_work
                else:
                    for k, v in item.items():
                        if k == keys[depth + 1] and isinstance(v, (dict, list)):
                            yield from listify_worker({k: v}, keys, depth + 1, cache_work, prefix)
            # Conditional to support nested dictionaries which are detected by item is string
            elif isinstance(item, str) and isinstance(d[keys[depth]], dict):
                yield from listify_worker({item: d[keys[depth]][item]}, keys, depth + 1, cache_work, prefix)


class FilterModule(object):
    """Ansible core jinja2 filters"""

    def filters(self):
        return {
            "aci_listify": listify,
        }
