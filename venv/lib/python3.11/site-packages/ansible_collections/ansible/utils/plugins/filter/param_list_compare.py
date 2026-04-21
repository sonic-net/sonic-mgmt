from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    name: param_list_compare
    author: Rohit Thakur (@rohitthakur2590)
    version_added: "2.4.0"
    short_description: Generate the final param list combining/comparing base and provided parameters.
    description:
        - Generate the final list of parameters after comparing with base list and provided/target list of params/bangs.
    options:
      base:
        description: Specify the base list.
        type: list
        elements: str
      target:
        description: Specify the target list.
        type: list
        elements: str
"""

EXAMPLES = r"""
- set_fact:
    base: ['1', '2', '3', '4', ' 5']

- set_fact:
    target: ['!all', '2', '4']

- name: Get final list of parameters
  register: result
  set_fact:
    final_params: "{{ base | param_list_compare(target) }}"

# TASK [Target list] **********************************************************
# ok: [localhost] => {
#     "msg": {
#         "actionable": [
#             "2",
#             "4"
#         ],
#         "unsupported": []
#     }
# }

- set_fact:
    base: ['1', '2', '3', '4', '5']

- name: Get final list of parameters
  register: result
  set_fact:
    final_params: "{{ base|param_list_compare(target=['2', '7', '8']) }}"

# TASK [Get final list of parameters] ********************************************
# ok: [localhost] => {
#     "ansible_facts": {
#         "final_params": {
#             "actionable": [
#                 "2"
#             ],
#             "unsupported": [
#                 "7",
#                 "8"
#             ]
#         }
#     },
#     "changed": false
# }

# Network Specific Example
# -----------
- set_fact:
    ios_resources:
      - "acl_interfaces"
      - "acls"
      - "bgp_address_family"
      - "bgp_global"
      - "interfaces"
      - "l2_interfaces"
      - "l3_interfaces"
      - "lacp"
      - "lacp_interfaces"
      - "lag_interfaces"
      - "lldp_global"
      - "lldp_interfaces"
      - "logging_global"
      - "ospf_interfaces"
      - "ospfv2"
      - "ospfv3"
      - "prefix_lists"
      - "route_maps"
      - "static_routes"
      - "vlans"

- set_fact:
    target_resources:
      - '!all'
      - 'vlan'
      - 'bgp_global'

- name: Get final list of target resources/params
  register: result
  set_fact:
    network_resources: "{{ ios_resources|param_list_compare(target_resources) }}"

- name: Target list of network resources
  debug:
    msg: "{{ network_resources }}"

# TASK [Target list of network resources] *******************************************************************************************************************
# ok: [localhost] => {
#     "msg": {
#         "actionable": [
#             "bgp_global",
#             "vlans"
#         ],
#         "unsupported": []
#     }
# }

- name: Get final list of target resources/params
  register: result
  set_fact:
    network_resources: "{{ ios_resources|param_list_compare(target=['vla', 'ntp_global', 'logging_global']) }}"

- name: Target list of network resources
  debug:
    msg: "{{ network_resources }}"

# TASK [Target list of network resources] ************************************************
# ok: [localhost] => {
#     "msg": {
#         "actionable": [
#             "logging_global"
#         ],
#         "unsupported": [
#             "vla",
#             "ntp_global"
#         ]
#     }
# }
"""

RETURN = """
  actionable:
    description: list of combined params
    type: list

  unsupported:
    description: list of unsupported params
    type: list

"""

from ansible.errors import AnsibleFilterError

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    check_argspec,
)


ARGSPEC_CONDITIONALS = {}


def param_list_compare(*args, **kwargs):
    params = ["base", "target"]
    data = dict(zip(params, args))
    data.update(kwargs)

    if len(data) < 2:
        raise AnsibleFilterError(
            "Missing either 'base' or 'other value in filter input,"
            "refer 'ansible.utils.param_list_compare' filter plugin documentation for details",
        )

    valid, argspec_result, updated_params = check_argspec(
        DOCUMENTATION,
        "param_list_compare filter",
        schema_conditionals=ARGSPEC_CONDITIONALS,
        **data,
    )
    if not valid:
        raise AnsibleFilterError(
            "{argspec_result} with errors: {argspec_errors}".format(
                argspec_result=argspec_result.get("msg"),
                argspec_errors=argspec_result.get("errors"),
            ),
        )
    base = data["base"]
    other = data["target"]
    combined = []
    alls = [x for x in other if x == "all"]
    bangs = [x[1:] for x in other if x.startswith("!")]
    rbangs = [x for x in other if x.startswith("!")]
    remain = [x for x in other if x not in alls and x not in rbangs and x in base]
    unsupported = [x for x in other if x not in alls and x not in rbangs and x not in base]

    if alls:
        combined = base
    for entry in bangs:
        if entry in combined:
            combined.remove(entry)
    for entry in remain:
        if entry not in combined:
            combined.append(entry)
    combined.sort()
    output = {"actionable": combined, "unsupported": unsupported}
    return output


class FilterModule(object):
    """param_list_compare"""

    def filters(self):
        """a mapping of filter names to functions"""
        return {"param_list_compare": param_list_compare}
