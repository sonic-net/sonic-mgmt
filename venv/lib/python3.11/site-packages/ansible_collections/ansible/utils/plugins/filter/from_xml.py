#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The from_xml filter plugin
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    name: from_xml
    author: Ashwini Mhatre (@amhatre)
    version_added: "2.0.2"
    short_description: Convert given XML string to native python dictionary.
    description:
        - This plugin converts the XML string to a native python dictionary.
        - Using the parameters below- C(data|ansible.utils.from_xml)
    options:
      data:
        description:
        - The input XML string.
        - This option represents the XML value that is passed to the filter plugin in pipe format.
        - For example C(config_data|ansible.utils.from_xml), in this case C(config_data) represents this option.
        type: str
        required: True
      engine:
        description:
        - Conversion library to use within the filter plugin.
        type: str
        default: xmltodict
"""

EXAMPLES = r"""

#### Simple examples with out any engine. plugin will use default value as xmltodict


- name: convert given XML to native python dictionary
  ansible.builtin.set_fact:
    data: ' <netconf-state xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"><schemas><schema/></schemas></netconf-state> '
- debug:
    msg: '{{ data|ansible.utils.from_xml }}'

# TASK######
# TASK [convert given XML to native python dictionary] *****************************************************************************************************
# task path: /Users/amhatre/ansible-collections/playbooks/test_utils.yaml:5
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": " <netconf-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring\"><schemas><schema/></schemas></netconf-state> "
#     },
#     "changed": false
# }
#
# TASK [debug] *************************************************************************************************************************
# task path: /Users/amhatre/ansible-collections/playbooks/test_utils.yaml:13
# Loading collection ansible.utils from /Users/amhatre/ansible-collections/collections/ansible_collections/ansible/utils
# ok: [localhost] => {
#     "msg": {
#         "netconf-state": {
#             "@xmlns": "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring",
#             "schemas": {
#                 "schema": null
#             }
#         }
#     }
# }

#### example2 with engine=xmltodict

- name: convert given XML to native python dictionary
  ansible.builtin.set_fact:
    data: ' <netconf-state xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"><schemas><schema/></schemas></netconf-state> '
- debug:
    msg: '{{ data|ansible.utils.from_xml(''xmltodict'') }}'

# TASK######
# TASK [convert given XML to native python dictionary] *****************************************************************************************************
# task path: /Users/amhatre/ansible-collections/playbooks/test_utils.yaml:5
# ok: [localhost] => {
#     "ansible_facts": {
#         "data": " <netconf-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring\"><schemas><schema/></schemas></netconf-state> "
#     },
#     "changed": false
# }
#
# TASK [debug] *************************************************************************************************************************
# task path: /Users/amhatre/ansible-collections/playbooks/test_utils.yaml:13
# Loading collection ansible.utils from /Users/amhatre/ansible-collections/collections/ansible_collections/ansible/utils
# ok: [localhost] => {
#     "msg": {
#         "netconf-state": {
#             "@xmlns": "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring",
#             "schemas": {
#                 "schema": null
#             }
#         }
#     }
# }
"""

from ansible.errors import AnsibleFilterError

from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)
from ansible_collections.ansible.utils.plugins.plugin_utils.from_xml import from_xml


try:
    from jinja2.filters import pass_environment
except ImportError:
    from jinja2.filters import environmentfilter as pass_environment


@pass_environment
def _from_xml(*args, **kwargs):
    """Convert the given data from xml to json."""

    keys = ["data", "engine"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="from_xml")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return from_xml(**updated_data)


class FilterModule(object):
    """from_xml"""

    def filters(self):
        """a mapping of filter names to functions"""
        return {"from_xml": _from_xml}
