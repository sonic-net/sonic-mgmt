from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright © 2020 Infoblox Inc
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#


import json
import os
import copy
from functools import partial
from ansible.module_utils._text import to_native
from ansible.module_utils.six import iteritems
from ansible.module_utils._text import to_text
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.common.validation import check_type_dict, safe_eval

try:
    from infoblox_client.connector import Connector
    from infoblox_client.exceptions import InfobloxException
    HAS_INFOBLOX_CLIENT = True
except ImportError:
    HAS_INFOBLOX_CLIENT = False

# defining nios constants
NIOS_DNS_VIEW = 'view'
NIOS_NETWORK_VIEW = 'networkview'
NIOS_HOST_RECORD = 'record:host'
NIOS_IPV4_NETWORK = 'network'
NIOS_RANGE = 'range'
NIOS_IPV6_NETWORK = 'ipv6network'
NIOS_ZONE = 'zone_auth'
NIOS_PTR_RECORD = 'record:ptr'
NIOS_A_RECORD = 'record:a'
NIOS_AAAA_RECORD = 'record:aaaa'
NIOS_CNAME_RECORD = 'record:cname'
NIOS_MX_RECORD = 'record:mx'
NIOS_SRV_RECORD = 'record:srv'
NIOS_NAPTR_RECORD = 'record:naptr'
NIOS_TXT_RECORD = 'record:txt'
NIOS_NSGROUP = 'nsgroup'
NIOS_IPV4_FIXED_ADDRESS = 'fixedaddress'
NIOS_IPV6_FIXED_ADDRESS = 'ipv6fixedaddress'
NIOS_NEXT_AVAILABLE_IP = 'func:nextavailableip'
NIOS_IPV4_NETWORK_CONTAINER = 'networkcontainer'
NIOS_IPV6_NETWORK_CONTAINER = 'ipv6networkcontainer'
NIOS_MEMBER = 'member'
NIOS_DTC_SERVER = 'dtc:server'
NIOS_DTC_POOL = 'dtc:pool'
NIOS_DTC_LBDN = 'dtc:lbdn'
NIOS_NSGROUP_FORWARDSTUBSERVER = 'nsgroup:forwardstubserver'
NIOS_NSGROUP_FORWARDINGMEMBER = 'nsgroup:forwardingmember'
NIOS_NSGROUP_DELEGATION = 'nsgroup:delegation'
NIOS_NSGROUP_STUBMEMBER = 'nsgroup:stubmember'
NIOS_DTC_MONITOR_HTTP = 'dtc:monitor:http'
NIOS_DTC_MONITOR_ICMP = 'dtc:monitor:icmp'
NIOS_DTC_MONITOR_PDP = 'dtc:monitor:pdp'
NIOS_DTC_MONITOR_SIP = 'dtc:monitor:sip'
NIOS_DTC_MONITOR_SNMP = 'dtc:monitor:snmp'
NIOS_DTC_MONITOR_TCP = 'dtc:monitor:tcp'
NIOS_DTC_TOPOLOGY = 'dtc:topology'
NIOS_EXTENSIBLE_ATTRIBUTE = 'extensibleattributedef'
NIOS_VLAN = 'vlan'
NIOS_ADMINUSER = 'adminuser'

NIOS_PROVIDER_SPEC = {
    'host': dict(fallback=(env_fallback, ['INFOBLOX_HOST'])),
    'username': dict(fallback=(env_fallback, ['INFOBLOX_USERNAME'])),
    'password': dict(fallback=(env_fallback, ['INFOBLOX_PASSWORD']), no_log=True),
    'cert': dict(fallback=(env_fallback, ['INFOBLOX_CERT'])),
    'key': dict(fallback=(env_fallback, ['INFOBLOX_KEY']), no_log=True),
    'validate_certs': dict(type='bool', default=False, fallback=(env_fallback, ['INFOBLOX_SSL_VERIFY']), aliases=['ssl_verify']),
    'silent_ssl_warnings': dict(type='bool', default=True),
    'http_request_timeout': dict(type='int', default=10, fallback=(env_fallback, ['INFOBLOX_HTTP_REQUEST_TIMEOUT'])),
    'http_pool_connections': dict(type='int', default=10),
    'http_pool_maxsize': dict(type='int', default=10),
    'max_retries': dict(type='int', default=3, fallback=(env_fallback, ['INFOBLOX_MAX_RETRIES'])),
    'wapi_version': dict(default='2.12.3', fallback=(env_fallback, ['INFOBLOX_WAPI_VERSION'])),
    'max_results': dict(type='int', default=1000, fallback=(env_fallback, ['INFOBLOX_MAX_RESULTS']))
}


def get_connector(*args, **kwargs):
    ''' Returns an instance of infoblox_client.connector.Connector
    :params args: positional arguments are silently ignored
    :params kwargs: dict that is passed to Connector init
    :returns: Connector
    '''
    if not HAS_INFOBLOX_CLIENT:
        raise Exception('infoblox-client is required but does not appear '
                        'to be installed.  It can be installed using the '
                        'command `pip install infoblox-client`')

    if not set(kwargs.keys()).issubset(list(NIOS_PROVIDER_SPEC.keys()) + ['ssl_verify']):
        raise Exception('invalid or unsupported keyword argument for connector')
    for key, value in iteritems(NIOS_PROVIDER_SPEC):
        if key not in kwargs:
            # apply default values from NIOS_PROVIDER_SPEC since we cannot just
            # assume the provider values are coming from AnsibleModule
            if 'default' in value:
                kwargs[key] = value['default']

            # override any values with env variables unless they were
            # explicitly set
            env = ('INFOBLOX_%s' % key).upper()
            if env in os.environ:
                if NIOS_PROVIDER_SPEC[key].get('type') == 'bool':
                    kwargs[key] = eval(os.environ.get(env).title())
                elif NIOS_PROVIDER_SPEC[key].get('type') == 'int':
                    kwargs[key] = eval(os.environ.get(env))
                else:
                    kwargs[key] = os.environ.get(env)

    if 'validate_certs' in kwargs.keys():
        kwargs['ssl_verify'] = kwargs['validate_certs']
        kwargs.pop('validate_certs', None)

    return Connector(kwargs)


def normalize_extattrs(value):
    ''' Normalize extattrs field to expected format
    The module accepts extattrs as key/value pairs.  This method will
    transform the key/value pairs into a structure suitable for
    sending across WAPI in the format of:
        extattrs: {
            key: {
                value: <value>
            }
        }
    '''
    return dict([(k, {'value': v}) for k, v in iteritems(value)])


def flatten_extattrs(value):
    ''' Flatten the key/value struct for extattrs
    WAPI returns extattrs field as a dict in form of:
        extattrs: {
            key: {
                value: <value>
            }
        }
    This method will flatten the structure to:
        extattrs: {
            key: value
        }
    '''
    return dict([(k, v['value']) for k, v in iteritems(value)])


def member_normalize(member_spec):
    ''' Transforms the member module arguments into a valid WAPI struct
    This function will transform the arguments into a structure that
    is a valid WAPI structure in the format of:
        {
            key: <value>,
        }
    It will remove any arguments that are set to None since WAPI will error on
    that condition.
    The remainder of the value validation is performed by WAPI
    Some parameters in ib_spec are passed as a list in order to pass the validation for elements.
    In this function, they are converted to dictionary.
    '''
    member_elements = ['vip_setting', 'ipv6_setting', 'lan2_port_setting', 'mgmt_port_setting',
                       'pre_provisioning', 'network_setting', 'v6_network_setting',
                       'ha_port_setting', 'lan_port_setting', 'lan2_physical_setting',
                       'lan_ha_port_setting', 'mgmt_network_setting', 'v6_mgmt_network_setting']
    for key in list(member_spec.keys()):
        if key in member_elements and member_spec[key] is not None:
            member_spec[key] = member_spec[key][0]
        if isinstance(member_spec[key], dict):
            member_spec[key] = member_normalize(member_spec[key])
        elif isinstance(member_spec[key], list):
            for x in member_spec[key]:
                if isinstance(x, dict):
                    x = member_normalize(x)
        elif member_spec[key] is None:
            del member_spec[key]
    return member_spec


def convert_members_to_struct(member_spec):
    ''' Transforms the members list of the Network module arguments into a
    valid WAPI struct. This function will change arguments into the valid
    wapi structure of the format:
        {
            network: 10.1.1.0/24
            members:
                [
                    {'_struct': 'dhcpmember', 'name': 'member_name1'},
                    {'_struct': 'dhcpmember', 'name': 'member_name2'}
                    {'_struct': 'dhcpmember', 'name': '...'}
                ]
        }
    '''
    if 'members' in member_spec.keys():
        member_spec['members'] = [{'_struct': 'dhcpmember', 'name': k['name']} for k in member_spec['members']]
    return member_spec


def convert_ea_list_to_struct(member_spec):
    ''' Transforms the list of the values into a valid WAPI struct.
    '''
    if 'list_values' in member_spec.keys():
        if all(isinstance(item, dict) for item in member_spec['list_values']):
            member_spec['list_values'] = [item['value'] for item in member_spec['list_values']]
        member_spec['list_values'] = [{'_struct': 'extensibleattributedef:listvalues', 'value': v} for v in member_spec['list_values']]
    return member_spec


def normalize_ib_spec(ib_spec):
    result = {}
    for arg in ib_spec:
        result[arg] = dict([(k, v)
                            for k, v in iteritems(ib_spec[arg])
                            if k not in ('ib_req', 'transform', 'update')])
    return result


class WapiBase(object):
    ''' Base class for implementing Infoblox WAPI API '''
    provider_spec = {'provider': dict(type='dict', options=NIOS_PROVIDER_SPEC)}

    def __init__(self, provider):
        self.connector = get_connector(**provider)

    def __getattr__(self, name):
        try:
            return self.__dict__[name]
        except KeyError:
            if name.startswith('_'):
                raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, name))
            return partial(self._invoke_method, name)

    def _invoke_method(self, name, *args, **kwargs):
        try:
            method = getattr(self.connector, name)
            return method(*args, **kwargs)
        except InfobloxException as exc:
            if hasattr(self, 'handle_exception'):
                self.handle_exception(name, exc)
            else:
                raise


class WapiLookup(WapiBase):
    ''' Implements WapiBase for lookup plugins '''
    def handle_exception(self, method_name, exc):
        if ('text' in exc.response):
            raise Exception(exc.response['text'])
        else:
            raise Exception(exc)


class WapiInventory(WapiBase):
    ''' Implements WapiBase for dynamic inventory script '''
    pass


class AnsibleError(Exception):
    '''Implements raising exceptions'''
    pass


class WapiModule(WapiBase):
    ''' Implements WapiBase for executing a NIOS module '''
    def __init__(self, module):
        self.module = module
        provider = module.params['provider']
        try:
            super(WapiModule, self).__init__(provider)
        except Exception as exc:
            self.module.fail_json(msg=to_text(exc))

    def handle_exception(self, method_name, exc):
        ''' Handles any exceptions raised
        This method will be called if an InfobloxException is raised for
        any call to the instance of Connector and also, in case of generic
        exception. This method will then gracefully fail the module.
        :args exc: instance of InfobloxException
        '''
        if ('text' in exc.response):
            self.module.fail_json(
                msg=exc.response['text'],
                type=exc.response['Error'].split(':')[0],
                code=exc.response.get('code'),
                operation=method_name
            )
        else:
            self.module.fail_json(msg=to_native(exc))

    def clean_empty_keys(self, current_object, proposed_object):
        """
        Removes keys from the proposed_object that are empty and do not exist in current_object.
        :param current_object: The current object to compare with.
        :param proposed_object: The proposed object to clean up.
        :return: Cleaned a proposed_object.
        """
        keys_to_remove = []

        for key, proposed_item in iteritems(proposed_object):
            # Check if the key is empty (None, empty string, empty list, etc.)
            if proposed_item in [None, '', [], {}, set()]:  # Add more empty checks if needed
                # If the key doesn't exist in current_object, mark it for removal
                if key not in current_object:
                    keys_to_remove.append(key)

        # Remove the identified keys from proposed_object
        for key in keys_to_remove:
            del proposed_object[key]

        return proposed_object

    def run(self, ib_obj_type, ib_spec):
        ''' Runs the module and perform configuration tasks
        :args ib_obj_type: the WAPI object type to operate against
        :args ib_spec: the specification for the WAPI object as a dict
        :returns:  result dict
        '''

        update = new_name = None
        state = self.module.params['state']
        if state not in ('present', 'absent'):
            self.module.fail_json(msg='state must be one of `present`, `absent`, got `%s`' % state)

        result = {'changed': False}

        obj_filter = dict([(k, self.module.params[k]) for k, v in iteritems(ib_spec) if v.get('ib_req')])
        # get object reference
        ib_obj_ref, update, new_name = self.get_object_ref(self.module, ib_obj_type, obj_filter, ib_spec)

        # When a range update is defined, check for a range that matches the target range definition as well
        # to allows for idempotence
        if ib_obj_type == NIOS_RANGE and len(ib_obj_ref) == 0 and \
                (True for v in ('new_start_addr', 'new_end_addr') if v in ib_spec.keys()):
            if self.module.params.get('new_start_addr'):
                obj_filter['start_addr'] = self.module.params.get('new_start_addr')
            if self.module.params.get('new_end_addr'):
                obj_filter['end_addr'] = self.module.params.get('new_end_addr')
            ib_obj_ref, update, new_name = self.get_object_ref(self.module, ib_obj_type, obj_filter, ib_spec)

        proposed_object = {}
        for key, value in iteritems(ib_spec):
            if self.module.params[key] is not None:
                if 'transform' in value:
                    proposed_object[key] = value['transform'](self.module)
                else:
                    proposed_object[key] = self.module.params[key]

        # If configure_by_dns is set to False and view is 'default', then delete the default dns
        if not proposed_object.get('configure_for_dns') and proposed_object.get('view') == 'default' \
                and ib_obj_type == NIOS_HOST_RECORD:
            del proposed_object['view']
        if ib_obj_ref:
            if len(ib_obj_ref) > 1:
                for each in ib_obj_ref:
                    # To check for existing A_record with same name with input A_record by IP
                    if each.get('ipv4addr') and each.get('ipv4addr') == proposed_object.get('ipv4addr'):
                        current_object = each
                        break
                    # To check for existing Host_record with same name with input Host_record by IP
                    elif each.get('ipv4addrs') and each.get('ipv4addrs')[0].get('ipv4addr') \
                            == proposed_object.get('ipv4addrs')[0].get('ipv4addr'):
                        current_object = each
                    # Else set the current_object with input value
                    else:
                        current_object = obj_filter
                        ref = None
            else:
                current_object = ib_obj_ref[0]
            if 'extattrs' in current_object:
                current_object['extattrs'] = flatten_extattrs(current_object['extattrs'])
            if current_object.get('_ref'):
                ref = current_object.pop('_ref')
        else:
            current_object = obj_filter
            ref = None
        # checks if the object type is member to normalize the attributes being passed
        if (ib_obj_type == NIOS_MEMBER):
            proposed_object = member_normalize(proposed_object)
            # The WAPI API will never return the "create_token" field that causes a difference
            # with the defaults of the module. To prevent this we remove the "create_token" option
            # if it has not been set to true.
            if (proposed_object.get("create_token") is not True):
                proposed_object.pop("create_token")

        if (ib_obj_type == NIOS_IPV4_NETWORK or ib_obj_type == NIOS_IPV6_NETWORK):
            proposed_object = convert_members_to_struct(proposed_object)

        if ib_obj_type in {NIOS_IPV4_NETWORK_CONTAINER, NIOS_IPV6_NETWORK_CONTAINER, NIOS_IPV4_NETWORK, NIOS_IPV6_NETWORK, NIOS_RANGE}:

            # Iterate over each option and remove the 'num' key
            if current_object.get('options') or proposed_object.get('options'):
                if proposed_object.get('options'):
                    # remove use_options false from proposed_object
                    proposed_object['options'] = [option for option in proposed_object['options'] if option.get('use_option', True)]

                if current_object.get('options'):
                    # remove use_options false from current_object
                    current_object['options'] = [option for option in current_object['options'] if option.get('use_option', True)]

        if (ib_obj_type == NIOS_RANGE):
            if proposed_object.get('new_start_addr'):
                proposed_object['start_addr'] = proposed_object.get('new_start_addr')
                del proposed_object['new_start_addr']
            if proposed_object.get('new_end_addr'):
                proposed_object['end_addr'] = proposed_object.get('new_end_addr')
                del proposed_object['new_end_addr']

        if (ib_obj_type == NIOS_EXTENSIBLE_ATTRIBUTE):
            proposed_object = convert_ea_list_to_struct(proposed_object)
            current_object = convert_ea_list_to_struct(current_object)
            # Convert 'default_value' to string in both proposed_object and current_object if it exists
            for obj in (proposed_object, current_object):
                if 'default_value' in obj:
                    obj['default_value'] = str(obj['default_value'])

        if ib_obj_type == NIOS_VLAN and ib_obj_ref:
            if 'parent' in current_object:
                current_object['parent'] = current_object['parent']['_ref']

        # checks if the 'text' field has to be updated for the TXT Record
        if (ib_obj_type == NIOS_TXT_RECORD):
            text_obj = proposed_object["text"]
            if text_obj.startswith("{"):
                try:
                    text_obj = json.loads(text_obj)
                    txt = text_obj['new_text']
                except Exception:
                    (result, exc) = safe_eval(text_obj, dict(), include_exceptions=True)
                    if exc is not None:
                        raise TypeError('unable to evaluate string as dictionary')
                    txt = result['new_text']
                proposed_object['text'] = txt

        # checks if the name's field has been updated
        if update and new_name:
            if (ib_obj_type == NIOS_MEMBER):
                proposed_object['host_name'] = new_name
            else:
                proposed_object['name'] = new_name

        check_remove = []
        if (ib_obj_type == NIOS_HOST_RECORD):
            if 'ipv4addrs' in proposed_object and sum(addr.get('use_for_ea_inheritance', False) for addr in proposed_object['ipv4addrs']) > 1:
                raise AnsibleError('Only one address allowed to be used for extensible attributes inheritance')
            # this check is for idempotency, as if the same ip address shall be passed
            # add param will be removed, and the same exists true for the remove case as well.
            if 'ipv4addrs' in [current_object and proposed_object]:
                for each in current_object['ipv4addrs']:
                    if each['ipv4addr'] == proposed_object['ipv4addrs'][0]['ipv4addr']:
                        if 'add' in proposed_object['ipv4addrs'][0]:
                            del proposed_object['ipv4addrs'][0]['add']
                            break
                    check_remove += each.values()
                if proposed_object['ipv4addrs'][0]['ipv4addr'] not in check_remove:
                    if 'remove' in proposed_object['ipv4addrs'][0]:
                        del proposed_object['ipv4addrs'][0]['remove']

        # Checks if 'new_ipv4addr' param exists in ipv4addr args
        proposed_object = self.check_for_new_ipv4addr(proposed_object)

        res = None
        if ib_obj_type == NIOS_VLAN:
            # Removes keys from the proposed_object that are empty and do not exist in current_object.
            # Fix the issue to update the optional fields of the object with default empty values
            proposed_object = self.clean_empty_keys(current_object, proposed_object)
        modified = not self.compare_objects(current_object, proposed_object, ib_obj_type)
        if 'extattrs' in proposed_object:
            proposed_object['extattrs'] = normalize_extattrs(proposed_object['extattrs'])

        # Checks if nios_next_ip param is passed in ipv4addrs/ipv4addr args
        proposed_object = self.check_if_nios_next_ip_exists(proposed_object)

        if state == 'present':
            if ref is None:
                if not self.module.check_mode:
                    self.create_object(ib_obj_type, proposed_object)
                result['changed'] = True
            # Check if NIOS_MEMBER and the flag to call function create_token is set
            elif (ib_obj_type == NIOS_MEMBER) and (proposed_object.get("create_token") is True):
                proposed_object = None
                # the function creates a token that can be used by a pre-provisioned member to join the grid
                result['api_results'] = self.call_func('create_token', ref, proposed_object)
                result['changed'] = True
            elif modified:
                if 'ipv4addrs' in proposed_object:
                    if ('add' not in proposed_object['ipv4addrs'][0]) and ('remove' not in proposed_object['ipv4addrs'][0]):
                        self.check_if_recordname_exists(obj_filter, ib_obj_ref, ib_obj_type, current_object, proposed_object)

                if (ib_obj_type in (NIOS_HOST_RECORD, NIOS_NETWORK_VIEW, NIOS_DNS_VIEW)):
                    run_update = True
                    proposed_object = self.on_update(proposed_object, ib_spec)
                    if 'ipv4addrs' in proposed_object:
                        if ('add' or 'remove') in proposed_object['ipv4addrs'][0]:
                            run_update, proposed_object = self.check_if_add_remove_ip_arg_exists(proposed_object)
                            if run_update:
                                res = self.update_object(ref, proposed_object)
                                result['changed'] = True
                            else:
                                res = ref

                if (ib_obj_type in (NIOS_A_RECORD, NIOS_AAAA_RECORD, NIOS_PTR_RECORD, NIOS_SRV_RECORD, NIOS_NAPTR_RECORD)):
                    # popping 'view' key as update of 'view' is not supported with respect to a:record/aaaa:record/srv:record/ptr:record/naptr:record
                    proposed_object = self.on_update(proposed_object, ib_spec)
                    del proposed_object['view']
                    if not self.module.check_mode:
                        res = self.update_object(ref, proposed_object)
                    result['changed'] = True
                if (ib_obj_type in (NIOS_ZONE)):
                    # popping 'zone_format' key as update of 'zone_format' is not supported with respect to zone_auth
                    proposed_object = self.on_update(proposed_object, ib_spec)
                    del proposed_object['zone_format']
                    self.update_object(ref, proposed_object)
                    result['changed'] = True
                elif 'network_view' in proposed_object and (ib_obj_type not in (NIOS_IPV4_FIXED_ADDRESS, NIOS_IPV6_FIXED_ADDRESS, NIOS_RANGE)):
                    proposed_object.pop('network_view')
                    if ib_obj_type in (NIOS_IPV4_NETWORK_CONTAINER, NIOS_IPV6_NETWORK_CONTAINER):
                        proposed_object.pop('network')
                    result['changed'] = True
                if not self.module.check_mode and res is None:
                    proposed_object = self.on_update(proposed_object, ib_spec)
                    if ib_obj_type == NIOS_HOST_RECORD and 'ipv4addrs' in proposed_object:
                        # Remove 'use_for_ea_inheritance' from each dictionary in 'ipv4addrs'
                        update_proposed = copy.deepcopy(proposed_object)
                        update_proposed['ipv4addrs'] = [
                            {k: v for k, v in addr.items() if k != 'use_for_ea_inheritance'}
                            for addr in proposed_object['ipv4addrs']
                        ]
                        res = self.update_object(ref, update_proposed)
                    else:
                        res = self.update_object(ref, proposed_object)
                    result['changed'] = True

                    if ib_obj_type == NIOS_HOST_RECORD and res:
                        # WAPI always reset the use_for_ea_inheritance for each update operation
                        # Handle use_for_ea_inheritance flag changes for IPv4addr in a host record
                        # Fetch the updated reference of host to avoid drift.
                        host_ref = self.connector.get_object(obj_type=str(res), return_fields=['ipv4addrs'])
                        if host_ref and 'ipv4addrs' in host_ref:
                            # Create a dictionary for quick lookups
                            ref_dict = {obj['ipv4addr']: obj['_ref'] for obj in host_ref['ipv4addrs']}
                            sorted_ipv4addrs = sorted(proposed_object['ipv4addrs'], key=lambda x: x.get('use_for_ea_inheritance', False))
                            for proposed in sorted_ipv4addrs:
                                ipv4addr = proposed['ipv4addr']
                                if ipv4addr in ref_dict and 'use_for_ea_inheritance' in proposed:
                                    self.update_object(ref_dict[ipv4addr], {'use_for_ea_inheritance': proposed['use_for_ea_inheritance']})
        elif state == 'absent':
            if ref is not None:
                if 'ipv4addrs' in proposed_object:
                    if 'remove' in proposed_object['ipv4addrs'][0]:
                        self.check_if_add_remove_ip_arg_exists(proposed_object)
                        self.update_object(ref, proposed_object)
                        result['changed'] = True
                elif not self.module.check_mode:
                    self.delete_object(ref)
                    result['changed'] = True

        return result

    def check_if_recordname_exists(self, obj_filter, ib_obj_ref, ib_obj_type, current_object, proposed_object):
        ''' Send POST request if host record input name and retrieved ref name is same,
            but input IP and retrieved IP is different'''

        if 'name' in (obj_filter and ib_obj_ref[0]) and ib_obj_type == NIOS_HOST_RECORD:
            obj_host_name = obj_filter['name']
            ref_host_name = ib_obj_ref[0]['name']
            if 'ipv4addrs' in (current_object and proposed_object):
                current_ip_addr = current_object['ipv4addrs'][0]['ipv4addr']
                proposed_ip_addr = proposed_object['ipv4addrs'][0]['ipv4addr']
            elif 'ipv6addrs' in (current_object and proposed_object):
                current_ip_addr = current_object['ipv6addrs'][0]['ipv6addr']
                proposed_ip_addr = proposed_object['ipv6addrs'][0]['ipv6addr']

            if obj_host_name == ref_host_name and current_ip_addr != proposed_ip_addr:
                self.create_object(ib_obj_type, proposed_object)

    def get_network_view(self, proposed_object):
        ''' Check for the associated network view with
            the given dns_view'''
        try:
            network_view_ref = self.get_object('view', {"name": proposed_object['view']}, return_fields=['network_view'])
            if network_view_ref:
                network_view = network_view_ref[0].get('network_view')
                return network_view
        except Exception:
            raise Exception("object with dns_view: %s not found" % (proposed_object['view']))

    def check_if_nios_next_ip_exists(self, proposed_object):
        ''' Check if nios_next_ip argument is passed in ipaddr while creating
            host record, if yes then format proposed object ipv4addrs and pass
            func:nextavailableip and ipaddr range to create hostrecord with next
             available ip in one call to avoid any race condition '''

        if 'ipv4addrs' in proposed_object:
            if 'nios_next_ip' in proposed_object['ipv4addrs'][0]['ipv4addr']:
                ip_range = check_type_dict(proposed_object['ipv4addrs'][0]['ipv4addr'])['nios_next_ip']
                proposed_object['ipv4addrs'][0]['ipv4addr'] = NIOS_NEXT_AVAILABLE_IP + ':' + ip_range
        elif 'ipv4addr' in proposed_object:
            if 'nios_next_ip' in proposed_object['ipv4addr']:
                ip_range = check_type_dict(proposed_object['ipv4addr'])['nios_next_ip']
                net_view = self.get_network_view(proposed_object)
                proposed_object['ipv4addr'] = NIOS_NEXT_AVAILABLE_IP + ':' + ip_range + ',' + net_view

        return proposed_object

    def check_for_new_ipv4addr(self, proposed_object):
        ''' Checks if new_ipv4addr parameter is passed in the argument
            while updating the record with new ipv4addr with static allocation'''
        if 'ipv4addr' in proposed_object:
            if 'new_ipv4addr' in proposed_object['ipv4addr']:
                new_ipv4 = check_type_dict(proposed_object['ipv4addr'])['new_ipv4addr']
                proposed_object['ipv4addr'] = new_ipv4

        return proposed_object

    def check_if_add_remove_ip_arg_exists(self, proposed_object):
        '''
            This function shall check if add/remove param is set to true and
            is passed in the args, then we will update the proposed dictionary
            to add/remove IP to existing host_record, if the user passes false
            param with the argument nothing shall be done.
            :returns: True if param is changed based on add/remove, and also the
            changed proposed_object.
        '''
        update = False
        if 'add' in proposed_object['ipv4addrs'][0]:
            if proposed_object['ipv4addrs'][0]['add']:
                proposed_object['ipv4addrs+'] = proposed_object['ipv4addrs']
                del proposed_object['ipv4addrs']
                del proposed_object['ipv4addrs+'][0]['add']
                update = True
            else:
                del proposed_object['ipv4addrs'][0]['add']
        elif 'remove' in proposed_object['ipv4addrs'][0]:
            if proposed_object['ipv4addrs'][0]['remove']:
                proposed_object['ipv4addrs-'] = proposed_object['ipv4addrs']
                del proposed_object['ipv4addrs']
                del proposed_object['ipv4addrs-'][0]['remove']
                update = True
            else:
                del proposed_object['ipv4addrs'][0]['remove']
        return update, proposed_object

    def check_next_ip_status(self, obj_filter):
        ''' Checks if nios next ip argument exists if True returns true
            else returns false'''
        if 'ipv4addr' in obj_filter:
            if 'nios_next_ip' in obj_filter['ipv4addr']:
                return True
        return False

    def issubset(self, item, objects):
        ''' Checks if item is a subset of objects
        :args item: the subset item to validate
        :args objects: superset list of objects to validate against
        :returns: True if item is a subset of one entry in objects otherwise
            this method will return None
        '''
        for obj in objects:
            if isinstance(item, dict):
                # Normalize MAC address for comparison
                if 'mac' in item:
                    item['mac'] = item['mac'].replace('-', ':').lower()
                elif 'duid' in item:
                    item['duid'] = item['duid'].replace('-', ':').lower()
                if all(entry in obj.items() for entry in item.items()):
                    return True
            else:
                if item in obj:
                    return True

    def compare_extattrs(self, current_extattrs, proposed_extattrs):
        '''Compare current extensible attributes to given extensible
           attribute, if length is not equal returns false , else
           checks the value of keys in proposed extattrs'''
        if len(current_extattrs) != len(proposed_extattrs):
            return False
        else:
            for key, proposed_item in iteritems(proposed_extattrs):
                current_item = current_extattrs.get(key)
                if current_item != proposed_item:
                    return False
            return True

    def verify_list_order(self, proposed_data, current_data):
        return len(proposed_data) == len(current_data) and all(a == b for a, b in zip(proposed_data, current_data))

    def compare_objects(self, current_object, proposed_object, ib_obj_type=None):
        for key, proposed_item in iteritems(proposed_object):
            current_item = current_object.get(key)

            # if proposed has a key that current doesn't, then the objects are
            # not equal and False will be immediately returned
            if current_item is None:
                return False

            elif isinstance(proposed_item, list):
                if key == 'aliases':
                    if set(current_item) != set(proposed_item):
                        return False
                # If the lists are of a different length, the objects cannot be
                # equal, and False will be returned before comparing the list items
                # this code part will work for members' assignment

                if key in ('members', 'options', 'delegate_to', 'forwarding_servers', 'stub_members', 'ssh_keys', 'vlans') \
                        and len(proposed_item) != len(current_item):
                    return False

                # Validate the Sequence of the List data
                if key in ('external_servers', 'list_values') and not self.verify_list_order(proposed_item, current_item):
                    return False

                for subitem in proposed_item:
                    if not isinstance(subitem, dict):
                        continue  # Skip non-dict items

                    if ib_obj_type == NIOS_HOST_RECORD and key == 'ipv4addrs':
                        current_config = current_item[0]
                        dhcp_flag = current_config.get('configure_for_dhcp', False)
                        # Host IPv4addrs wont contain use_nextserver and nextserver
                        # If DHCP is false.
                        use_nextserver = subitem.get('use_nextserver', False)

                        if not dhcp_flag:
                            try:
                                subitem.pop('use_nextserver')
                                subitem.pop('nextserver')
                            except KeyError:
                                pass
                        elif dhcp_flag and not use_nextserver:
                            try:
                                subitem.pop('nextserver')
                            except KeyError:
                                pass

                    if not self.issubset(subitem, current_item):
                        return False

                if key == 'logic_filter_rules' and proposed_item != current_item:
                    return False

            elif isinstance(proposed_item, dict):
                # Compare the items of the dict to see if they are equal. A
                # difference stops the comparison and returns false. If they
                # are equal, move on to the next item

                # Checks if extattrs existing in proposed object
                if key == 'extattrs':
                    current_extattrs = current_object.get(key)
                    proposed_extattrs = proposed_object.get(key)
                    if not self.compare_extattrs(current_extattrs, proposed_extattrs):
                        return False

                if self.compare_objects(current_item, proposed_item, ib_obj_type) is False:
                    return False
                else:
                    continue

            else:
                if current_item != proposed_item:
                    return False

        return True

    def get_object_ref(self, module, ib_obj_type, obj_filter, ib_spec):
        ''' this function gets the reference object of pre-existing nios objects '''
        update = False
        old_name = new_name = None
        old_ipv4addr_exists = old_text_exists = False
        next_ip_exists = False

        if ib_obj_type == NIOS_VLAN:
            obj_filter.update({'parent': ib_spec['parent']['transform'](self.module)})

        if ('name' in obj_filter):
            # gets and returns the current object based on name/old_name passed
            try:
                name_obj = check_type_dict(obj_filter['name'])
                # check if network_view allows searching and updating with camelCase
                if (ib_obj_type == NIOS_NETWORK_VIEW):
                    old_name = name_obj['old_name']
                    new_name = name_obj['new_name']
                else:
                    old_name = name_obj['old_name'].lower()
                    new_name = name_obj['new_name'].lower()
            except TypeError:
                name = obj_filter['name']

            return_fields = list(ib_spec.keys())

            if (ib_obj_type == NIOS_ADMINUSER):
                if 'password' in return_fields:
                    return_fields.remove('password')

            if old_name and new_name:
                if (ib_obj_type == NIOS_HOST_RECORD):
                    # to check only by old_name if dns bypassing is set
                    if not obj_filter['configure_for_dns']:
                        test_obj_filter = dict([('name', old_name)])
                    else:
                        test_obj_filter = dict([('name', old_name), ('view', obj_filter['view'])])
                # if there are multiple records with the same name and different ip
                elif (ib_obj_type == NIOS_A_RECORD):
                    test_obj_filter = dict([('name', old_name), ('ipv4addr', obj_filter['ipv4addr'])])
                    try:
                        ipaddr_obj = check_type_dict(obj_filter['ipv4addr'])
                        ipaddr = ipaddr_obj.get('old_ipv4addr')
                        old_ipv4addr_exists = True if ipaddr else False
                    except TypeError:
                        ipaddr = test_obj_filter['ipv4addr']
                    if old_ipv4addr_exists:
                        test_obj_filter['ipv4addr'] = ipaddr
                    else:
                        del test_obj_filter['ipv4addr']
                elif ib_obj_type == NIOS_VLAN:
                    test_obj_filter = dict([
                        ('name', old_name), ('id', obj_filter['id']), ('parent', obj_filter['parent'])])
                else:
                    test_obj_filter = dict([('name', old_name)])
                # get the object reference
                ib_obj = self.get_object(ib_obj_type, test_obj_filter, return_fields=return_fields)
                if ib_obj:
                    obj_filter['name'] = new_name
                elif old_ipv4addr_exists and (len(ib_obj) == 0):
                    raise Exception(
                        "object with name: '%s', ipv4addr: '%s' is not found" % (old_name, test_obj_filter['ipv4addr']))
                else:
                    raise Exception("object with name: '%s' is not found" % (old_name))
                update = True
                return ib_obj, update, new_name
            if (ib_obj_type == NIOS_HOST_RECORD):
                # to fix the sanity issue
                name = obj_filter['name']
                # to check only by name if dns bypassing is set
                if not obj_filter['configure_for_dns']:
                    test_obj_filter = dict([('name', name)])
                else:
                    test_obj_filter = dict([('name', name), ('view', obj_filter['view'])])
            elif (ib_obj_type == NIOS_IPV4_FIXED_ADDRESS and 'mac' in obj_filter):
                test_obj_filter = dict([['mac', obj_filter['mac']]])
            elif (ib_obj_type == NIOS_IPV6_FIXED_ADDRESS and 'duid' in obj_filter):
                test_obj_filter = dict([['duid', obj_filter['duid']]])
            elif (ib_obj_type == NIOS_CNAME_RECORD):
                test_obj_filter = dict([('name', obj_filter['name']), ('view', obj_filter['view'])])
            elif (ib_obj_type == NIOS_A_RECORD):
                # resolves issue where a_record with uppercase name was returning null and was failing
                test_obj_filter = obj_filter
                test_obj_filter['name'] = test_obj_filter['name'].lower()
                # resolves issue where multiple a_records with same name and different IP address
                try:
                    ipaddr_obj = check_type_dict(obj_filter['ipv4addr'])
                    ipaddr = ipaddr_obj.get('old_ipv4addr')
                    old_ipv4addr_exists = True if ipaddr else False
                    if not old_ipv4addr_exists:
                        next_ip_exists = self.check_next_ip_status(test_obj_filter)
                except TypeError:
                    ipaddr = obj_filter['ipv4addr']
                if old_ipv4addr_exists:
                    test_obj_filter['ipv4addr'] = ipaddr
                # resolve issue if nios_next_ip exists which is not searchable attribute
                if next_ip_exists:
                    del test_obj_filter['ipv4addr']
            elif (ib_obj_type == NIOS_TXT_RECORD):
                # resolves issue where multiple txt_records with same name and different text
                test_obj_filter = obj_filter
                try:
                    text_obj = obj_filter['text']
                    if text_obj.startswith("{"):
                        try:
                            text_obj = json.loads(text_obj)
                            txt = text_obj['old_text']
                            old_text_exists = True
                        except Exception:
                            (result, exc) = safe_eval(text_obj, dict(), include_exceptions=True)
                            if exc is not None:
                                raise TypeError('unable to evaluate string as dictionary')
                            txt = result['old_text']
                            old_text_exists = True
                    else:
                        txt = text_obj
                except TypeError:
                    txt = obj_filter['text']
                test_obj_filter['text'] = txt

            # removing Port param from get params for NIOS_DTC_MONITOR_TCP
            elif (ib_obj_type == NIOS_DTC_MONITOR_TCP):
                test_obj_filter = dict([('name', obj_filter['name'])])

            # check if test_obj_filter is empty copy passed obj_filter
            else:
                test_obj_filter = obj_filter

            if ib_obj_type == NIOS_HOST_RECORD:
                ipv4addrs_return = [
                    'ipv4addrs.ipv4addr', 'ipv4addrs.mac', 'ipv4addrs.configure_for_dhcp', 'ipv4addrs.host',
                    'ipv4addrs.nextserver', 'ipv4addrs.use_nextserver', 'ipv4addrs.use_for_ea_inheritance'
                ]
                ipv6addrs_return = [
                    'ipv6addrs.ipv6addr', 'ipv6addrs.duid', 'ipv6addrs.configure_for_dhcp', 'ipv6addrs.host'
                ]
                return_fields.extend(ipv4addrs_return)
                return_fields.extend(ipv6addrs_return)

            ib_obj = self.get_object(ib_obj_type, test_obj_filter.copy(), return_fields=return_fields)

            # prevents creation of a new A record with 'new_ipv4addr' when A record with a particular 'old_ipv4addr' is not found
            if old_ipv4addr_exists and (ib_obj is None or len(ib_obj) == 0):
                raise Exception("A Record with ipv4addr: '%s' is not found" % (ipaddr))
            # prevents creation of a new TXT record with 'new_text' when TXT record with a particular 'old_text' is not found
            if old_text_exists and ib_obj is None:
                raise Exception("TXT Record with text: '%s' is not found" % (txt))
        elif (ib_obj_type == NIOS_A_RECORD):
            # resolves issue where multiple a_records with same name and different IP address
            test_obj_filter = obj_filter
            try:
                ipaddr_obj = check_type_dict(obj_filter['ipv4addr'])
                ipaddr = ipaddr_obj.get('old_ipv4addr')
                old_ipv4addr_exists = True if ipaddr else False
            except TypeError:
                ipaddr = obj_filter['ipv4addr']
            test_obj_filter['ipv4addr'] = ipaddr
            ib_obj = self.get_object(ib_obj_type, test_obj_filter.copy(), return_fields=list(ib_spec.keys()))
            # prevents creation of a new A record with 'new_ipv4addr' when A record with a particular 'old_ipv4addr' is not found
            if old_ipv4addr_exists and ib_obj is None:
                raise Exception("A Record with ipv4addr: '%s' is not found" % (ipaddr))
        elif (ib_obj_type == NIOS_TXT_RECORD):
            # resolves issue where multiple txt_records with same name and different text
            test_obj_filter = obj_filter
            try:
                text_obj = obj_filter(['text'])
                if text_obj.startswith("{"):
                    try:
                        text_obj = json.loads(text_obj)
                        txt = text_obj['old_text']
                        old_text_exists = True
                    except Exception:
                        (result, exc) = safe_eval(text_obj, dict(), include_exceptions=True)
                        if exc is not None:
                            raise TypeError('unable to evaluate string as dictionary')
                        txt = result['old_text']
                        old_text_exists = True
                else:
                    txt = text_obj
            except TypeError:
                txt = obj_filter['text']
            test_obj_filter['text'] = txt
            ib_obj = self.get_object(ib_obj_type, test_obj_filter.copy(), return_fields=list(ib_spec.keys()))
            # prevents creation of a new TXT record with 'new_text' when TXT record with a particular 'old_text' is not found
            if old_text_exists and ib_obj is None:
                raise Exception("TXT Record with text: '%s' is not found" % (txt))
        elif (ib_obj_type == NIOS_ZONE):
            # del key 'restart_if_needed' as nios_zone get_object fails with the key present
            temp = ib_spec['restart_if_needed']
            del ib_spec['restart_if_needed']
            ib_obj = self.get_object(ib_obj_type, obj_filter.copy(), return_fields=list(ib_spec.keys()))
            # reinstate restart_if_needed if ib_obj is none, meaning there's no existing nios_zone ref
            if not ib_obj:
                ib_spec['restart_if_needed'] = temp
        elif (ib_obj_type == NIOS_MEMBER):
            # gets and returns current_object as per old_name/host_name passed
            test_obj_filter = obj_filter
            try:
                name_obj = check_type_dict(test_obj_filter['host_name'])
                old_name = name_obj['old_name']
                new_name = name_obj['new_name']
            except TypeError:
                host_name = obj_filter['host_name']

            if old_name and new_name:
                test_obj_filter['host_name'] = old_name
                temp = ib_spec['create_token']
                del ib_spec['create_token']
                ib_obj = self.get_object(ib_obj_type, test_obj_filter.copy(), return_fields=list(ib_spec.keys()))
                if temp:
                    # reinstate 'create_token' key
                    ib_spec['create_token'] = temp
                if ib_obj:
                    obj_filter['host_name'] = new_name
                else:
                    raise Exception("object with name: '%s' is not found" % (old_name))
                update = True
            else:
                # del key 'create_token' as nios_member get_object fails with the key present
                temp = ib_spec['create_token']
                del ib_spec['create_token']
                ib_obj = self.get_object(ib_obj_type, obj_filter.copy(), return_fields=list(ib_spec.keys()))
                if temp:
                    # reinstate 'create_token' key
                    ib_spec['create_token'] = temp
        elif (ib_obj_type in (NIOS_IPV4_NETWORK, NIOS_IPV6_NETWORK, NIOS_IPV4_NETWORK_CONTAINER, NIOS_IPV6_NETWORK_CONTAINER)):
            # del key 'template' as nios_network get_object fails with the key present
            temp = ib_spec['template']
            del ib_spec['template']

            if (ib_obj_type in (NIOS_IPV4_NETWORK_CONTAINER, NIOS_IPV6_NETWORK_CONTAINER)):
                # del key 'members' as nios_network get_object fails with the key present
                # Don't reinstate the field after as it is not valid for network containers
                del ib_spec['members']
                del ib_spec['vlans']

            ib_obj = self.get_object(ib_obj_type, obj_filter.copy(), return_fields=list(ib_spec.keys()))
            # reinstate the 'template' and 'members' key
            if temp:
                ib_spec['template'] = temp

        elif (ib_obj_type in (NIOS_RANGE)):
            # Delete the update keys to find the original range object
            new_start = ib_spec.get('new_start_addr')
            new_end = ib_spec.get('new_end_addr')
            del ib_spec['new_start_addr']
            del ib_spec['new_end_addr']
            new_start_arg = self.module.params.get('new_start_addr')
            new_end_arg = self.module.params.get('new_end_addr')
            ib_obj = self.get_object(ib_obj_type, obj_filter.copy(), return_fields=list(ib_spec.keys()))
            # Restore the keys to the object.
            if new_start:
                ib_spec['new_start_addr'] = new_start
            if new_end:
                ib_spec['new_end_addr'] = new_end

            # throws exception if start_addr and end_addr doesn't exists for updating range
            if (new_start_arg and new_end_arg):
                if not ib_obj:
                    raise Exception(
                        'Specified range %s-%s not found' % (obj_filter['start_addr'], obj_filter['end_addr']))
        else:
            ib_obj = self.get_object(ib_obj_type, obj_filter.copy(), return_fields=list(ib_spec.keys()))
        return ib_obj, update, new_name

    def on_update(self, proposed_object, ib_spec):
        ''' Event called before the update is sent to the API endpoing
        This method will allow the final proposed object to be changed
        and/or keys filtered before it is sent to the API endpoint to
        be processed.
        :args proposed_object: A dict item that will be encoded and sent
            the API endpoint with the updated data structure
        :returns: updated object to be sent to API endpoint
        '''
        keys = set()
        for key, value in iteritems(proposed_object):
            update = ib_spec[key].get('update', True)
            if not update:
                keys.add(key)
        return dict([(k, v) for k, v in iteritems(proposed_object) if k not in keys])
