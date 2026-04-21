# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
name: nios_lookup
short_description: Query Infoblox NIOS objects
version_added: "1.0.0"
description:
  - Uses the Infoblox WAPI API to fetch NIOS specified objects.  This lookup
    supports adding additional keywords to filter the return data and specify
    the desired set of returned fields.
requirements:
  - infoblox-client

options:
    _terms:
      description:
        - The name of the network object to be returned from the Infoblox appliance.
      required: True
      type: str
    return_fields:
      description: The list of field names to return for the specified object.
      type: list
      elements: str
    filter:
      description: A dict object that is used to filter the returned objects.
      type: dict
    extattrs:
      description: A dict object that is used to filter based on extensible attributes.
      type: dict
'''

EXAMPLES = """
- name: fetch all networkview objects
  ansible.builtin.set_fact:
    networkviews: "{{ lookup('infoblox.nios_modules.nios_lookup', 'networkview', provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"

- name: fetch the default dns view
  ansible.builtin.set_fact:
    dns_views: "{{ lookup('infoblox.nios_modules.nios_lookup', 'view', filter={'name': 'default'},
                   provider={'host': 'nios01', 'username': 'admin', 'password': 'password'}) }}"

# all of the examples below use credentials that are  set using env variables
# export INFOBLOX_HOST=nios01
# export INFOBLOX_USERNAME=admin
# export INFOBLOX_PASSWORD=admin

- name: fetch all host records and include extended attributes
  ansible.builtin.set_fact:
    host_records: "{{ lookup('infoblox.nios_modules.nios_lookup', 'record:host', return_fields=['extattrs', 'name', 'view', 'comment']}) }}"


- name: use env variables to pass credentials
  ansible.builtin.set_fact:
    networkviews: "{{ lookup('infoblox.nios_modules.nios_lookup', 'networkview') }}"

- name: get a host record
  ansible.builtin.set_fact:
    host: "{{ lookup('infoblox.nios_modules.nios_lookup', 'record:host', filter={'name': 'hostname.ansible.com'}) }}"

- name: get the authoritative zone from a non default dns view
  ansible.builtin.set_fact:
    host: "{{ lookup('infoblox.nios_modules.nios_lookup', 'zone_auth', filter={'fqdn': 'ansible.com', 'view': 'ansible-dns'}) }}"
"""

RETURN = """
obj_type:
  description:
    - The object type specified in the terms argument
  returned: always
  type: list
  contains:
    obj_field:
      description:
      - One or more obj_type fields as specified by return_fields argument or
        the default set of fields as per the object type
"""

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
from ..module_utils.api import WapiLookup
from ..module_utils.api import normalize_extattrs, flatten_extattrs


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        try:
            obj_type = terms[0]
        except IndexError:
            raise AnsibleError('the object_type must be specified')

        return_fields = kwargs.pop('return_fields', None)
        filter_data = kwargs.pop('filter', {})
        extattrs = normalize_extattrs(kwargs.pop('extattrs', {}))
        provider = kwargs.pop('provider', {})
        wapi = WapiLookup(provider)
        res = wapi.get_object(obj_type, filter_data, return_fields=return_fields, extattrs=extattrs)
        if res is not None:
            for obj in res:
                if 'extattrs' in obj:
                    obj['extattrs'] = flatten_extattrs(obj['extattrs'])
        else:
            res = []
        return res
