# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c) 2018, Laurent Nicolas <laurentn@netapp.com>
# All rights reserved.
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

''' Support class for NetApp ansible modules '''

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from copy import deepcopy
import re
import traceback
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils

ZAPI_ONLY_DEPRECATION_MESSAGE = "This module only supports ZAPI and is deprecated.   "\
                                "After upgrading to ONTAP 9.14 and beyond, ONTAPI (ZAPI) remains active for 30 days.  "\
                                "If no calls are detected, it will be automatically disabled but can be re-enabled via CLI command."


def cmp(obj1, obj2):
    """
    Python 3 does not have a cmp function, this will do the cmp.
    :param obj1: first object to check
    :param obj2: second object to check
    :return:
    """
    # convert to lower case for string comparison.
    if obj1 is None:
        return -1
    if isinstance(obj1, str) and isinstance(obj2, str):
        obj1 = obj1.lower()
        obj2 = obj2.lower()
    # if list has string element, convert string to lower case.
    if isinstance(obj1, list) and isinstance(obj2, list):
        obj1 = [x.lower() if isinstance(x, str) else x for x in obj1]
        obj2 = [x.lower() if isinstance(x, str) else x for x in obj2]
        obj1.sort()
        obj2.sort()
    return (obj1 > obj2) - (obj1 < obj2)


class NetAppModule(object):
    '''
    Common class for NetApp modules
    set of support functions to derive actions based
    on the current state of the system, and a desired state
    '''

    def __init__(self, module=None):
        # we can call this with module set to self or self.module
        # self is a NetApp module, while self.module is the AnsibleModule object
        self.netapp_module = None
        self.ansible_module = module
        if module and getattr(module, 'module', None) is not None:
            self.netapp_module = module
            self.ansible_module = module.module
        # When using self or self.module, this gives access to:
        #       self.ansible_module.fail_json
        # When using self, this gives access to:
        #       self.netapp_module.rest_api.log_debug
        self.log = []
        self.changed = False
        self.parameters = {'name': 'not initialized'}
        self.zapi_string_keys = {}
        self.zapi_bool_keys = {}
        self.zapi_list_keys = {}
        self.zapi_int_keys = {}
        self.zapi_required = {}
        self.params_to_rest_api_keys = {}

    def module_deprecated(self, module):
        module.warn(ZAPI_ONLY_DEPRECATION_MESSAGE)

    def module_replaces(self, new_module, module):
        self.module_deprecated(module)
        module.warn('netapp.ontap.%s should be used instead.' % new_module)

    def set_parameters(self, ansible_params):
        self.parameters = {}
        for param in ansible_params:
            if ansible_params[param] is not None:
                self.parameters[param] = ansible_params[param]
        return self.parameters

    def fall_back_to_zapi(self, module, msg, parameters):
        if parameters['use_rest'].lower() == 'always':
            module.fail_json(msg='Error: %s' % msg)
        if parameters['use_rest'].lower() == 'auto':
            module.warn('Falling back to ZAPI: %s' % msg)
            return False

    def check_and_set_parameters(self, module):
        self.parameters = {}
        check_for_none = netapp_utils.has_feature(module, 'check_required_params_for_none')
        if check_for_none:
            required_keys = [key for key, value in module.argument_spec.items() if value.get('required')]
        for param in module.params:
            if module.params[param] is not None:
                self.parameters[param] = module.params[param]
            elif check_for_none and param in required_keys:
                module.fail_json(msg="%s requires a value, got: None" % param)
        return self.parameters

    @staticmethod
    def type_error_message(type_str, key, value):
        return "expecting '%s' type for %s: %s, got: %s" % (type_str, repr(key), repr(value), type(value))

    def get_value_for_bool(self, from_zapi, value, key=None):
        """
        Convert boolean values to string or vice-versa
        If from_zapi = True, value is converted from string (as it appears in ZAPI) to boolean
        If from_zapi = False, value is converted from boolean to string
        For get() method, from_zapi = True
        For modify(), create(), from_zapi = False
        :param from_zapi: convert the value from ZAPI or to ZAPI acceptable type
        :param value: value of the boolean attribute
        :param key: if present, force error checking to validate type, and accepted values
        :return: string or boolean
        """
        if value is None:
            return None
        if from_zapi:
            if key is not None and not isinstance(value, str):
                raise TypeError(self.type_error_message('str', key, value))
            if key is not None and value not in ('true', 'false'):
                raise ValueError('Unexpected value: %s received from ZAPI for boolean attribute: %s' % (repr(value), repr(key)))
            return value == 'true'
        if key is not None and not isinstance(value, bool):
            raise TypeError(self.type_error_message('bool', key, value))
        return 'true' if value else 'false'

    def get_value_for_int(self, from_zapi, value, key=None):
        """
        Convert integer values to string or vice-versa
        If from_zapi = True, value is converted from string (as it appears in ZAPI) to integer
        If from_zapi = False, value is converted from integer to string
        For get() method, from_zapi = True
        For modify(), create(), from_zapi = False
        :param from_zapi: convert the value from ZAPI or to ZAPI acceptable type
        :param value: value of the integer attribute
        :param key: if present, force error checking to validate type
        :return: string or integer
        """
        if value is None:
            return None
        if from_zapi:
            if key is not None and not isinstance(value, str):
                raise TypeError(self.type_error_message('str', key, value))
            return int(value)
        if key is not None and not isinstance(value, int):
            raise TypeError(self.type_error_message('int', key, value))
        return str(value)

    def get_value_for_list(self, from_zapi, zapi_parent, zapi_child=None, data=None):
        """
        Convert a python list() to NaElement or vice-versa
        If from_zapi = True, value is converted from NaElement (parent-children structure) to list()
        If from_zapi = False, value is converted from list() to NaElement
        :param zapi_parent: ZAPI parent key or the ZAPI parent NaElement
        :param zapi_child: ZAPI child key
        :param data: list() to be converted to NaElement parent-children object
        :param from_zapi: convert the value from ZAPI or to ZAPI acceptable type
        :return: list() or NaElement
        """
        if from_zapi:
            if zapi_parent is None:
                return []
            return [zapi_child.get_content() for zapi_child in zapi_parent.get_children()]

        zapi_parent = netapp_utils.zapi.NaElement(zapi_parent)
        for item in data:
            zapi_parent.add_new_child(zapi_child, item)
        return zapi_parent

    def get_cd_action(self, current, desired):
        ''' takes a desired state and a current state, and return an action:
            create, delete, None
            eg:
            is_present = 'absent'
            some_object = self.get_object(source)
            if some_object is not None:
                is_present = 'present'
            action = cd_action(current=is_present, desired = self.desired.state())
        '''
        desired_state = desired['state'] if 'state' in desired else 'present'
        if current is None and desired_state == 'absent':
            return None
        if current is not None and desired_state == 'present':
            return None
        # change in state
        self.changed = True
        return 'create' if current is None else 'delete'

    @staticmethod
    def check_keys(current, desired):
        ''' TODO: raise an error if keys do not match
            with the exception of:
            new_name, state in desired
        '''

    @staticmethod
    def compare_lists(current, desired, get_list_diff):
        ''' compares two lists and return a list of elements that are either the desired elements or elements that are
            modified from the current state depending on the get_list_diff flag
            :param: current: current item attribute in ONTAP
            :param: desired: attributes from playbook
            :param: get_list_diff: specifies whether to have a diff of desired list w.r.t current list for an attribute
            :return: list of attributes to be modified
            :rtype: list
        '''
        current_copy = deepcopy(current)
        desired_copy = deepcopy(desired)

        # get what in desired and not in current
        desired_diff_list = []
        for item in desired:
            if item in current_copy:
                current_copy.remove(item)
            else:
                desired_diff_list.append(item)

        # get what in current but not in desired
        current_diff_list = []
        for item in current:
            if item in desired_copy:
                desired_copy.remove(item)
            else:
                current_diff_list.append(item)

        if desired_diff_list or current_diff_list:
            # there are changes
            return desired_diff_list if get_list_diff else desired
        else:
            return None

    def get_modified_attributes(self, current, desired, get_list_diff=False):
        ''' takes two dicts of attributes and return a dict of attributes that are
            not in the current state
            It is expected that all attributes of interest are listed in current and
            desired.
            :param: current: current attributes in ONTAP
            :param: desired: attributes from playbook
            :param: get_list_diff: specifies whether to have a diff of desired list w.r.t current list for an attribute
            :return: dict of attributes to be modified
            :rtype: dict

            NOTE: depending on the attribute, the caller may need to do a modify or a
            different operation (eg move volume if the modified attribute is an
            aggregate name)
        '''
        # if the object does not exist,  we can't modify it
        modified = {}
        if current is None:
            return modified

        if not isinstance(desired, dict):
            raise TypeError("Expecting dict, got: %s with current: %s" % (desired, current))
        # error out if keys do not match
        self.check_keys(current, desired)

        # collect changed attributes
        for key, value in current.items():
            # if self.netapp_module:
            #     self.netapp_module.rest_api.log_debug('KDV', "%s:%s:%s" % (key, desired.get(key), value))
            if desired.get(key) is not None:
                modified_value = None
                if isinstance(value, list):
                    modified_value = self.compare_lists(value, desired[key], get_list_diff)  # get modified list from current and desired
                elif isinstance(value, dict):
                    modified_value = self.get_modified_attributes(value, desired[key]) or None
                else:
                    try:
                        result = cmp(value, desired[key])
                    except TypeError as exc:
                        raise TypeError("%s, key: %s, value: %s, desired: %s" % (repr(exc), key, repr(value), repr(desired[key])))
                    # if self.netapp_module:
                    #     self.netapp_module.rest_api.log_debug('RESULT', result)
                    if result != 0:
                        modified_value = desired[key]
                if modified_value is not None:
                    modified[key] = modified_value

        if modified:
            self.changed = True
        return modified

    def is_rename_action(self, source, target):
        ''' takes a source and target object, and returns True
            if a rename is required
            eg:
            source = self.get_object(source_name)
            target = self.get_object(target_name)
            action = is_rename_action(source, target)
            :return: None for error, True for rename action, False otherwise

            I'm not sure we need this function any more.
            I think a better way to do it is to:
            1. look if a create is required (eg the target resource does not exist and state==present)
            2. consider that a create can be fullfilled by different actions: rename, create from scratch, move, ...
            So for rename:
            cd_action = self.na_helper.get_cd_action(current, self.parameters)
            if cd_action == 'create' and self.parameters.get('from_name'):
                # creating new subnet by renaming
                current = self.get_subnet(self.parameters['from_name'])
                if current is None:
                    self.module.fail_json(msg="Error renaming: subnet %s does not exist" %
                                          self.parameters['from_name'])
                rename = True
                cd_action = None
        '''
        if source is None and target is None:
            # error, do nothing
            # cannot rename a non existent resource
            return None
        if target is None:
            # source is not None and target is None:
            # rename is in order
            self.changed = True
            return True
        # target is not None, so do nothing as the destination exists
        # if source is None, maybe we already renamed
        # if source is not None, maybe a new resource was created after being renamed
        return False

    @staticmethod
    def sanitize_wwn(initiator):
        ''' igroup initiator may or may not be using WWN format: eg 20:00:00:25:B5:00:20:01
            if format is matched, convert initiator to lowercase, as this is what ONTAP is using '''
        wwn_format = r'[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){7}'
        initiator = initiator.strip()
        if re.match(wwn_format, initiator):
            initiator = initiator.lower()
        return initiator

    def safe_get(self, an_object, key_list, allow_sparse_dict=True):
        ''' recursively traverse a dictionary or a any object supporting get_item or indexing
            (in our case, python dicts and NAElement responses, and lists)
            It is expected that some keys can be missing, this is controlled with allow_sparse_dict

            return value if the key chain is exhausted
            return None if a key is not found and allow_sparse_dict is True
            raise KeyError is a key is not found and allow_sparse_dict is False (looking for exact match)
            raise TypeError if an intermediate element cannot be indexed,
              unless the element is None and allow_sparse_dict is True
        '''
        if not key_list:
            # we've exhausted the keys, good!
            return an_object
        key_list = list(key_list)   # preserve original values
        key = key_list.pop(0)
        try:
            return self.safe_get(an_object[key], key_list, allow_sparse_dict=allow_sparse_dict)
        except (KeyError, IndexError) as exc:
            # error, key or index not found
            if allow_sparse_dict:
                return None
            raise exc
        except TypeError as exc:
            # error, we were expecting a dict or NAElement
            if allow_sparse_dict and an_object is None:
                return None
            raise exc

    def convert_value(self, value, convert_to):
        if convert_to is None:
            return value, None
        if not isinstance(value, str):
            return None, ('Unexpected type: %s for %s' % (type(value), str(value)))
        if convert_to == str:
            return value, None
        if convert_to == int:
            try:
                return int(value), None
            except ValueError as exc:
                return None, ('Unexpected value for int: %s, %s' % (str(value), str(exc)))
        if convert_to == bool:
            if value not in ('true', 'false'):
                return None, 'Unexpected value: %s received from ZAPI for boolean attribute' % value
            return value == 'true', None
        if convert_to == 'bool_online':
            return value == 'online', None
        self.ansible_module.fail_json(msg='Error: Unexpected value for convert_to: %s' % convert_to)

    def zapi_get_value(self, na_element, key_list, required=False, default=None, convert_to=None):
        """ read a value from na_element using key_list

            If required is True, an error is reported if a key in key_list is not found.
            If required is False and the value is not found, uses default as the value.
            If convert_to is set to str, bool, int, the ZAPI value is converted from str to the desired type.
                suported values: None, the python types int, str, bool, special 'bool_online'

        Errors: fail_json is called for:
            - a key is not found and required=True,
            - a format conversion error
        """

        # keep a copy, as the list is mutated
        saved_key_list = list(key_list)
        try:
            value = self.safe_get(na_element, key_list, allow_sparse_dict=not required)
        except (KeyError, TypeError) as exc:
            error = exc
        else:
            value, error = self.convert_value(value, convert_to) if value is not None else (default, None)
        if error:
            self.ansible_module.fail_json(msg='Error reading %s from %s: %s' % (saved_key_list, na_element.to_string(), error))
        return value

    def zapi_get_attrs(self, na_element, attr_dict, result):
        """ Retrieve a list of attributes from na_elements
        see na_ontap_volume for an example.
        na_element: xml element as returned by ZAPI.
        attr_dict:
            A dict of dict, with format:
                key: dict(key_list, required=False, default=None, convert_to=None, omitnone=False)
            The keys are used to index a result dictionary, values are read from a ZAPI object indexed by key_list.
            If required is True, an error is reported if a key in key_list is not found.
            If required is False and the value is not found, uses default as the value.
            If convert_to is set to str, bool, int, the ZAPI value is converted from str to the desired type.
            I'm not sure there is much value in omitnone, but it preserves backward compatibility.
            When the value is None, if omitnone is False, a None value is recorded, if True, the key is not set.
        result: an existing dictionary.  keys are added or updated based on attrs.

        Errors: fail_json is called for:
            - a key is not found and required=True,
            - a format conversion error
        """
        for key, kwargs in attr_dict.items():
            omitnone = kwargs.pop('omitnone', False)
            value = self.zapi_get_value(na_element, **kwargs)
            if value is not None or not omitnone:
                result[key] = value

    def _filter_out_none_entries_from_dict(self, adict, allow_empty_list_or_dict):
        """take a dict as input and return a dict without keys whose values are None
           return empty dicts or lists if allow_empty_list_or_dict otherwise skip empty dicts or lists.
        """
        result = {}
        for key, value in adict.items():
            if isinstance(value, (list, dict)):
                sub = self.filter_out_none_entries(value, allow_empty_list_or_dict)
                if sub or allow_empty_list_or_dict:
                    # allow empty dict or list if allow_empty_list_or_dict is set.
                    # skip empty dict or list otherwise
                    result[key] = sub
            elif value is not None:
                # skip None value
                result[key] = value
        return result

    def _filter_out_none_entries_from_list(self, alist, allow_empty_list_or_dict):
        """take a list as input and return a list without elements whose values are None
           return empty dicts or lists if allow_empty_list_or_dict otherwise skip empty dicts or lists.
        """
        result = []
        for item in alist:
            if isinstance(item, (list, dict)):
                sub = self.filter_out_none_entries(item, allow_empty_list_or_dict)
                if sub or allow_empty_list_or_dict:
                    # allow empty dict or list if allow_empty_list_or_dict is set.
                    # skip empty dict or list otherwise
                    result.append(sub)
            elif item is not None:
                # skip None value
                result.append(item)
        return result

    def filter_out_none_entries(self, list_or_dict, allow_empty_list_or_dict=False):
        """take a dict or list as input and return a dict/list without keys/elements whose values are None
           return empty dicts or lists if allow_empty_list_or_dict otherwise skip empty dicts or lists.
        """

        if isinstance(list_or_dict, dict):
            return self._filter_out_none_entries_from_dict(list_or_dict, allow_empty_list_or_dict)

        if isinstance(list_or_dict, list):
            return self._filter_out_none_entries_from_list(list_or_dict, allow_empty_list_or_dict)

        raise TypeError('unexpected type %s' % type(list_or_dict))

    @staticmethod
    def get_caller(depth):
        '''return the name of:
             our caller if depth is 1
             the caller of our caller if depth is 2
             the caller of the caller of our caller if depth is 3
             ...
        '''
        # one more caller in the stack
        depth += 1
        frames = traceback.extract_stack(limit=depth)
        try:
            function_name = frames[0].name
        except AttributeError:
            # python 2.7 does not have named attributes for frames
            try:
                function_name = frames[0][2]
            except Exception as exc:                                   # pylint: disable=broad-except
                function_name = 'Error retrieving function name: %s - %s' % (str(exc), repr(frames))
        return function_name

    def fail_on_error(self, error, api=None, stack=False, depth=1, previous_errors=None):
        '''depth identifies how far is the caller in the call stack'''
        if error is None:
            return
        # one more caller to account for this function
        depth += 1
        if api is not None:
            error = 'calling api: %s: %s' % (api, error)
        results = dict(msg='Error in %s: %s' % (self.get_caller(depth), error))
        if stack:
            results['stack'] = traceback.format_stack()
        if previous_errors:
            results['previous_errors'] = ' - '.join(previous_errors)
        if getattr(self, 'ansible_module', None) is not None:
            self.ansible_module.fail_json(**results)
        raise AttributeError('Expecting self.ansible_module to be set when reporting %s' % repr(results))

    def compare_chmod_value(self, current_permissions, desired_permissions):
        """
        compare current unix_permissions to desired unix_permissions.
        :return: True if the same, False it not the same or desired unix_permissions is not valid.
        """
        if current_permissions is None:
            return False
        if desired_permissions.isdigit():
            return int(current_permissions) == int(desired_permissions)
        # ONTAP will throw error as invalid field if the length is not 9 or 12.
        if len(desired_permissions) not in [12, 9]:
            return False
        desired_octal_value = ''
        # if the length is 12, first three character sets userid('s'), groupid('s') and sticky('t') attributes
        if len(desired_permissions) == 12:
            if desired_permissions[0] not in ['s', '-'] or desired_permissions[1] not in ['s', '-']\
                    or desired_permissions[2] not in ['t', '-']:
                return False
            desired_octal_value += str(self.char_to_octal(desired_permissions[:3]))
        # if the len is 9, start from 0 else start from 3.
        start_range = len(desired_permissions) - 9
        for i in range(start_range, len(desired_permissions), 3):
            if desired_permissions[i] not in ['r', '-'] or desired_permissions[i + 1] not in ['w', '-']\
                    or desired_permissions[i + 2] not in ['x', '-']:
                return False
            group_permission = self.char_to_octal(desired_permissions[i:i + 3])
            desired_octal_value += str(group_permission)
        return int(current_permissions) == int(desired_octal_value)

    def char_to_octal(self, chars):
        """
        :param chars: Characters to be converted into octal values.
        :return: octal value of the individual group permission.
        """
        total = 0
        if chars[0] in ['r', 's']:
            total += 4
        if chars[1] in ['w', 's']:
            total += 2
        if chars[2] in ['x', 't']:
            total += 1
        return total

    def ignore_missing_vserver_on_delete(self, error, vserver_name=None):
        """ When a resource is expected to be absent, it's OK if the containing vserver is also absent.
            This function expects self.parameters('vserver') to be set or the vserver_name argument to be passed.
            error is an error returned by rest_generic.get_xxxx.
        """
        if self.parameters.get('state') != 'absent':
            return False
        if vserver_name is None:
            if self.parameters.get('vserver') is None:
                self.ansible_module.fail_json(
                    msg='Internal error, vserver name is required, when processing error: %s' % error, exception=traceback.format_exc())
            vserver_name = self.parameters['vserver']
        if isinstance(error, str):
            pass
        elif isinstance(error, dict):
            if 'message' in error:
                error = error['message']
            else:
                self.ansible_module.fail_json(
                    msg='Internal error, error should contain "message" key, found: %s' % error, exception=traceback.format_exc())
        else:
            self.ansible_module.fail_json(
                msg='Internal error, error should be str or dict, found: %s, %s' % (type(error), error), exception=traceback.format_exc())
        return 'SVM "%s" does not exist.' % vserver_name in error

    def remove_hal_links(self, records):
        """ Remove all _links entries """
        if isinstance(records, dict):
            records.pop('_links', None)
            for record in records.values():
                self.remove_hal_links(record)
        if isinstance(records, list):
            for record in records:
                self.remove_hal_links(record)
