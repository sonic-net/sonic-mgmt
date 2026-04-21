#
# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The parse_xml filter plugin
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
name: parse_xml
author: Ganesh Nalawade (@ganeshrn)
version_added: "1.0.0"
short_description: The parse_xml filter plugin.
description:
  - This filter will load the spec file and pass the command output
    through it, returning JSON output.
  - The YAML spec file defines how to parse the CLI output.
  - This plugin is deprecated and will be removed in a future release after 2027-02-01, please Use ansible.utils.cli_parse instead.
notes:
  - To convert the XML output of a network device command into structured JSON output.
options:
  output:
    description:
    - This source xml on which parse_xml invokes.
    type: raw
    required: True
  tmpl:
    description:
    - The spec file should be valid formatted YAML.
      It defines how to parse the XML output and return JSON data.
    - For example C(xml_data | ansible.netcommon.parse_xml(template.yml)),
      in this case C(xml_data) represents xml data option.
    type: str
"""

EXAMPLES = r"""
# Using parse_xml

# example_output.xml

# <?xml version="1.0" encoding="UTF-8"?>
# <rpc-reply message-id="urn:uuid:0cadb4e8-5bba-47f4-986e-72906227007f">
# 	<data>
# 		<ntp>
# 			<nodes>
# 				<node>
# 					<node>0/0/CPU0</node>
# 					<associations>
# 						<is-ntp-enabled>true</is-ntp-enabled>
# 						<sys-leap>ntp-leap-no-warning</sys-leap>
# 						<peer-summary-info>
# 							<peer-info-common>
# 								<host-mode>ntp-mode-client</host-mode>
# 								<is-configured>true</is-configured>
# 								<address>10.1.1.1</address>
# 								<reachability>0</reachability>
# 							</peer-info-common>
# 							<time-since>-1</time-since>
# 						</peer-summary-info>
# 						<peer-summary-info>
# 							<peer-info-common>
# 								<host-mode>ntp-mode-client</host-mode>
# 								<is-configured>true</is-configured>
# 								<address>172.16.252.29</address>
# 								<reachability>255</reachability>
# 							</peer-info-common>
# 							<time-since>991</time-since>
# 						</peer-summary-info>
# 					</associations>
# 				</node>
# 			</nodes>
# 		</ntp>
# 	</data>
# </rpc-reply>

# parse_xml.yml

# ---
# vars:
#   ntp_peers:
#     address: "{{ item.address }}"
#     reachability: "{{ item.reachability}}"
# keys:
#   result:
#     value: "{{ ntp_peers }}"
#     top: data/ntp/nodes/node/associations
#     items:
#       address: peer-summary-info/peer-info-common/address
#       reachability: peer-summary-info/peer-info-common/reachability


- name: Facts setup
  ansible.builtin.set_fact:
    xml: "{{ lookup('file', 'example_output.xml') }}"

- name: Parse xml invocation
  ansible.builtin.debug:
    msg: "{{ xml | ansible.netcommon.parse_xml('parse_xml.yml') }}"


# Task Output
# -----------
#
# TASK [set xml Data]
# ok: [host] => changed=false
#   ansible_facts:
#     xml: |-
#       <?xml version="1.0" encoding="UTF-8"?>
#       <rpc-reply message-id="urn:uuid:0cadb4e8-5bba-47f4-986e-72906227007f">
#               <data>
#                       <ntp>
#                               <nodes>
#                                       <node>
#                                               <node>0/0/CPU0</node>
#                                               <associations>
#                                                       <is-ntp-enabled>true</is-ntp-enabled>
#                                                       <sys-leap>ntp-leap-no-warning</sys-leap>
#                                                       <peer-summary-info>
#                                                               <peer-info-common>
#                                                                       <host-mode>ntp-mode-client</host-mode>
#                                                                       <is-configured>true</is-configured>
#                                                                       <address>10.1.1.1</address>
#                                                                       <reachability>0</reachability>
#                                                               </peer-info-common>
#                                                               <time-since>-1</time-since>
#                                                       </peer-summary-info>
#                                                       <peer-summary-info>
#                                                               <peer-info-common>
#                                                                       <host-mode>ntp-mode-client</host-mode>
#                                                                       <is-configured>true</is-configured>
#                                                                       <address>172.16.252.29</address>
#                                                                       <reachability>255</reachability>
#                                                               </peer-info-common>
#                                                               <time-since>991</time-since>
#                                                       </peer-summary-info>
#                                               </associations>
#                                       </node>
#                               </nodes>
#                       </ntp>
#               </data>
#       </rpc-reply>

# TASK [Parse Data]
# ok: [host] => changed=false
#   ansible_facts:
#     output:
#       result:
#       - address:
#         - 10.1.1.1
#         - 172.16.252.29
#         reachability:
#         - '0'
#         - '255'
"""

from ansible.errors import AnsibleFilterError
from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)

from ansible_collections.ansible.netcommon.plugins.plugin_utils.parse_xml import parse_xml


try:
    from jinja2.filters import pass_environment
except ImportError:
    from jinja2.filters import environmentfilter as pass_environment

from ansible.utils.display import Display


@pass_environment
def _parse_xml(*args, **kwargs):
    """parse xml"""

    display = Display()
    display.warning(
        "The 'parse_xml' filter is deprecated and will be removed in a future release "
        "after 2027-02-01. Use 'ansible.utils.cli_parse' instead."
    )
    keys = ["output", "tmpl"]
    data = dict(zip(keys, args[1:]))
    data.update(kwargs)
    aav = AnsibleArgSpecValidator(data=data, schema=DOCUMENTATION, name="parse_xml")
    valid, errors, updated_data = aav.validate()
    if not valid:
        raise AnsibleFilterError(errors)
    return parse_xml(**updated_data)


class FilterModule(object):
    """parse_xml"""

    def filters(self):
        """a mapping of filter names to functions"""
        return {"parse_xml": _parse_xml}
