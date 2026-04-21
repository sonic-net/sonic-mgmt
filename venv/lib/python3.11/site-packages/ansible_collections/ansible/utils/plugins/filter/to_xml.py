#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#


"""
The to_xml filter plugin
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    name: to_xml
    author: Ashwini Mhatre (@amhatre)
    version_added: "2.0.2"
    short_description: Convert given JSON string to XML
    description:
        - This plugin converts the JSON string to XML.
        - Using the parameters below- C(data|ansible.utils.to_xml)
    options:
      data:
        description:
        - The input JSON string .
        - This option represents the JSON value that is passed to the filter plugin in pipe format.
        - For example C(config_data|ansible.utils.to_xml), in this case C(config_data) represents this option.
        type: dict
        required: True
      engine:
        description:
        - Conversion library to use within the filter plugin.
        type: str
        default: xmltodict
      indent:
        description:
        - The character used for indentation (defaults to tabs).
        type: str
        default: tabs
        choices: ["tabs", "spaces"]
      indent_width:
        description:
        - The number of spaces to use to indent output data.
        - This option is only used when indent="spaces", otherwise it is ignored.
        - When indent="tabs", a single tab is always used for indentation.
        type: int
        default: 4
      full_document:
        description:
        - The option to disable xml declaration(defaults to True).
        type: bool
        default: True
"""

EXAMPLES = r"""

#### Simple examples with out any engine. plugin will use default value as xmltodict

- name: Define JSON data
  ansible.builtin.set_fact:
      data:
          "interface-configurations":
              "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XR-ifmgr-cfg"
              "interface-configuration":
- debug:
      msg: "{{ data | ansible.utils.to_xml }}"

# TASK [Define JSON data ] *************************************************************************
# task path: /Users/amhatre/ansible-collections/playbooks/test_utils_json_to_xml.yaml:5
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": {
#             "interface-configurations": {
#                 "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XR-ifmgr-cfg",
#                 "interface-configuration": null
#             }
#         }
#     },
#     "changed": false
# }
#
# TASK [debug] ***********************************************************************************************************
# task path: /Users/amhatre/ansible-collections/playbooks/test_utils_json_to_xml.yaml:13
# Loading collection ansible.utils from /Users/amhatre/ansible-collections/collections/ansible_collections/ansible/utils
# ok: [localhost] => {
#     "msg": "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<interface-configurations xmlns=\"http://cisco.com/ns/yang/
#     Cisco-IOS-XR-ifmgr-cfg\">\n\t<interface-configuration></interface-configuration>\n</interface-configurations>"
# }

#### example2 with engine=xmltodict

- name: Define JSON data
  ansible.builtin.set_fact:
      data:
          "interface-configurations":
              "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XR-ifmgr-cfg"
              "interface-configuration":
- debug:
      msg: "{{ data | ansible.utils.to_xml('xmltodict') }}"

# TASK [Define JSON data ] *************************************************************************
# task path: /Users/amhatre/ansible-collections/playbooks/test_utils_json_to_xml.yaml:5
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": {
#             "interface-configurations": {
#                 "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XR-ifmgr-cfg",
#                 "interface-configuration": null
#             }
#         }
#     },
#     "changed": false
# }
# TASK [debug] ***********************************************************************************************************
# task path: /Users/amhatre/ansible-collections/playbooks/test_utils_json_to_xml.yaml:13
# Loading collection ansible.utils from /Users/amhatre/ansible-collections/collections/ansible_collections/ansible/utils
# ok: [localhost] => {
#     "msg": "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<interface-configurations xmlns=\"http://cisco.com/ns/yang/
#     Cisco-IOS-XR-ifmgr-cfg\">\n\t<interface-configuration></interface-configuration>\n</interface-configurations>"
# }

#### example3 with indent='spaces' and indent_width=2

- name: Define JSON data
  ansible.builtin.set_fact:
      data:
          "interface-configurations":
              "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XR-ifmgr-cfg"
              "interface-configuration":
- debug:
      msg: "{{ data | ansible.utils.to_xml(indent='spaces', indent_width=2) }}"

# TASK [Define JSON data ] *************************************************************************
# task path: /Users/amhatre/ansible-collections/playbooks/test_utils_json_to_xml.yaml:5
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": {
#             "interface-configurations": {
#                 "@xmlns": "http://cisco.com/ns/yang/Cisco-IOS-XR-ifmgr-cfg",
#                 "interface-configuration": null
#             }
#         }
#     },
#     "changed": false
# }
# TASK [debug] ***********************************************************************************************************
# task path: /Users/amhatre/ansible-collections/playbooks/test_utils_json_to_xml.yaml:13
# Loading collection ansible.utils from /Users/amhatre/ansible-collections/collections/ansible_collections/ansible/utils
# ok: [localhost] => {
#     "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<interface-configurations xmlns=\"http://cisco.com/ns/yang/
#     Cisco-IOS-XR-ifmgr-cfg\">\n  <interface-configuration></interface-configuration>\n</interface-configurations>"
# }
"""

from ansible.errors import AnsibleFilterError

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)
from ansible_collections.ansible.utils.plugins.plugin_utils.to_xml import to_xml


try:
    from jinja2.filters import pass_environment
except ImportError:
    from jinja2.filters import environmentfilter as pass_environment


@pass_environment
def _to_xml(*args, **kwargs):
    """Convert the given data from json to xml."""
    keys = ["data", "engine", "indent", "indent_width"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="to_xml")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return to_xml(**updated_data)


class FilterModule(object):
    """to_xml"""

    def filters(self):
        """a mapping of filter names to functions"""
        return {"to_xml": _to_xml}
