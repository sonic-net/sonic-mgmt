#!/usr/bin/python

# (c) 2018-2023, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_license
'''
from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''

module: na_ontap_license

short_description: NetApp ONTAP protocol and feature license packages
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap
version_added: 2.6.0
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>

description:
  - Add or remove license packages on NetApp ONTAP.
  - Note that the module is asymmetrical.
  - It requires license codes to add packages and the package name is not visible.
  - It requires package names and as serial number to remove packages.

options:
  state:
    description:
      - Whether the specified license packages should be installed or removed.
    choices: ['present', 'absent']
    type: str
    default: present

  remove_unused:
    description:
      - Remove license packages that have no controller affiliation in the cluster.
      - Not supported with REST.
    type: bool

  remove_expired:
    description:
      - Remove license packages that have expired in the cluster.
      - Not supported with REST.
    type: bool

  serial_number:
    description:
      - Serial number of the node or cluster associated with the license package.
      - This parameter is required when removing a license package.
      - With REST, '*' is accepted and matches any serial number.
    type: str

  license_names:
    type: list
    elements: str
    description:
      - List of license package names to remove.
    suboptions:
      base:
        description:
          - Cluster Base License
      nfs:
        description:
          - NFS License
      cifs:
        description:
          - CIFS License
      iscsi:
        description:
          - iSCSI License
      fcp:
        description:
          - FCP License
      cdmi:
        description:
          - CDMI License
      snaprestore:
        description:
          - SnapRestore License
      snapmirror:
        description:
          - SnapMirror License
      flexclone:
        description:
          - FlexClone License
      snapvault:
        description:
          - SnapVault License
      snaplock:
        description:
          - SnapLock License
      snapmanagersuite:
        description:
          - SnapManagerSuite License
      snapprotectapps:
        description:
          - SnapProtectApp License
      v_storageattach:
        description:
          - Virtual Attached Storage License

  license_codes:
    description:
      - List of license codes to be installed.
    type: list
    elements: str

notes:
  - Partially supports check_mode - some changes cannot be detected until an add or remove action is performed.
  - Supports 28 character key licenses with ZAPI and REST.
  - Supports NetApp License File Version 2 (NLFv2) with REST.
  - NetApp License File Version 1 (NLFv1) with REST is not supported at present but may work.
  - Ansible attempts to reformat license files as the contents are python-like.
    Use the string filter in case of problem to disable this behavior.
  - This module requires the python ast and json packages when the string filter is not used.
  - This module requires the json package to check for idempotency, and to remove licenses using a NLFv2 file.
  - This module requires the deepdiff package to check for idempotency.
  - None of these packages are required when the string filter is used, but the module will not be idempotent.
'''


EXAMPLES = """
- name: Add licenses - 28 character keys
  netapp.ontap.na_ontap_license:
    state: present
    serial_number: #################
    license_codes: CODE1,CODE2

- name: Remove licenses
  netapp.ontap.na_ontap_license:
    state: absent
    remove_unused: false
    remove_expired: true
    serial_number: #################
    license_names: nfs,cifs

- name: Add NLF licenses
  netapp.ontap.na_ontap_license:
    state: present
    license_codes:
      - "{{ lookup('file', nlf_filepath) | string }}"

- name: Remove NLF license bundle - using license file
  netapp.ontap.na_ontap_license:
    state: absent
    license_codes:
      - "{{ lookup('file', nlf_filepath) | string }}"

- name: Remove NLF license bundle - using bundle name
  netapp.ontap.na_ontap_license:
    state: absent
    remove_unused: false
    remove_expired: true
    serial_number: #################
    license_names: "Enterprise Edition"
"""

RETURN = """
updated_licenses:
    description: return list of updated package names
    returned: always
    type: dict
    sample: "['nfs']"
"""

HAS_AST = True
HAS_DEEPDIFF = True
HAS_JSON = True
IMPORT_ERRORS = []

try:
    import ast
except ImportError as exc:
    HAS_AST = False
    IMPORT_ERRORS.append(exc)

try:
    from deepdiff import DeepDiff
except (ImportError, SyntaxError) as exc:
    # With Ansible 2.9, python 2.6 reports a SyntaxError
    HAS_DEEPDIFF = False
    IMPORT_ERRORS.append(exc)

try:
    import json
except ImportError as exc:
    HAS_JSON = False
    IMPORT_ERRORS.append(exc)

import re
import sys
import time
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_generic


if sys.version_info < (3, 5):
    # not defined in earlier versions
    RecursionError = RuntimeError


def local_cmp(a, b):
    """
        compares with only values and not keys, keys should be the same for both dicts
        :param a: dict 1
        :param b: dict 2
        :return: difference of values in both dicts
        """
    return [key for key in a if a[key] != b[key]]


class NetAppOntapLicense:
    '''ONTAP license class'''

    def __init__(self):
        self.argument_spec = netapp_utils.na_ontap_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            serial_number=dict(required=False, type='str'),
            remove_unused=dict(default=None, type='bool'),
            remove_expired=dict(default=None, type='bool'),
            license_codes=dict(default=None, type='list', elements='str'),
            license_names=dict(default=None, type='list', elements='str'),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
            required_if=[
                ('state', 'absent', ['license_codes', 'license_names'], True)],
            required_together=[
                ('serial_number', 'license_names')],
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.license_status = {}
        # list of tuples - original licenses (license_code or NLF contents), and dict of NLF contents (empty dict for legacy codes)
        self.nlfs = []
        # when using REST, just keep a list as returned by GET to use with deepdiff
        self.previous_records = []

        # Set up REST API
        self.rest_api = OntapRestAPI(self.module)
        unsupported_rest_properties = ['remove_unused', 'remove_expired']
        self.use_rest = self.rest_api.is_rest_supported_properties(self.parameters, unsupported_rest_properties)
        if not self.use_rest:
            if not netapp_utils.has_netapp_lib():
                self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
            else:
                self.server = netapp_utils.setup_na_ontap_zapi(module=self.module)
        self.validate_nlfs()

    def get_licensing_status(self):
        """
            Check licensing status

            :return: package (key) and licensing status (value)
            :rtype: dict
        """
        if self.use_rest:
            return self.get_licensing_status_rest()
        license_status = netapp_utils.zapi.NaElement(
            'license-v2-status-list-info')
        result = None
        try:
            result = self.server.invoke_successfully(license_status,
                                                     enable_tunneling=False)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error checking license status: %s" %
                                  to_native(error), exception=traceback.format_exc())

        return_dictionary = {}
        license_v2_status = result.get_child_by_name('license-v2-status')
        if license_v2_status:
            for license_v2_status_info in license_v2_status.get_children():
                package = license_v2_status_info.get_child_content('package')
                status = license_v2_status_info.get_child_content('method')
                return_dictionary[package] = status
        return return_dictionary, None

    def get_licensing_status_rest(self):
        api = 'cluster/licensing/licenses'
        # By default, the GET method only returns licensed packages.
        # To retrieve all the available package state details, below query is used.
        query = {'state': 'compliant, noncompliant, unlicensed, unknown'}
        fields = 'name,state,licenses'
        records, error = rest_generic.get_0_or_more_records(self.rest_api, api, query, fields)
        if error:
            self.module.fail_json(msg=error)
        current = {'installed_licenses': {}}
        if records:
            for package in records:
                current[package['name']] = package['state']
                if 'licenses' in package:
                    for license in package['licenses']:
                        installed_license = license.get('installed_license')
                        serial_number = license.get('serial_number')
                        if serial_number and installed_license:
                            if serial_number not in current:
                                current['installed_licenses'][serial_number] = set()
                            current['installed_licenses'][serial_number].add(installed_license)
        return current, records

    def remove_licenses(self, package_name, nlf_dict=None):
        """
        Remove requested licenses
        :param:
          package_name: Name of the license to be deleted
        """
        if self.use_rest:
            return self.remove_licenses_rest(package_name, nlf_dict or {})
        license_delete = netapp_utils.zapi.NaElement('license-v2-delete')
        license_delete.add_new_child('serial-number', self.parameters['serial_number'])
        license_delete.add_new_child('package', package_name)
        try:
            self.server.invoke_successfully(license_delete,
                                            enable_tunneling=False)
            return True
        except netapp_utils.zapi.NaApiError as error:
            # Error 15661 - Object not found
            if to_native(error.code) == "15661":
                return False
            else:
                self.module.fail_json(msg="Error removing license %s" %
                                      to_native(error), exception=traceback.format_exc())

    def remove_licenses_rest(self, package_name, nlf_dict):
        """
        This is called either with a package name or a NLF dict
        We already validated product and serialNumber are present in nlf_dict
        """
        p_serial_number = self.parameters.get('serial_number')
        n_serial_number = nlf_dict.get('serialNumber')
        n_product = nlf_dict.get('product')
        serial_number = n_serial_number or p_serial_number
        if not serial_number:
            self.module.fail_json(msg='Error: serial_number is required to delete a license.')
        if n_product:
            error = self.remove_one_license_rest(None, n_product, serial_number)
        elif package_name.endswith(('Bundle', 'Edition')):
            error = self.remove_one_license_rest(None, package_name, serial_number)
        else:
            error = self.remove_one_license_rest(package_name, None, serial_number)
            if error and "entry doesn't exist" in error:
                return False
        if error:
            self.module.fail_json(msg="Error removing license for serial number %s and %s: %s"
                                  % (serial_number, n_product or package_name, error))
        return True

    def remove_one_license_rest(self, package_name, product, serial_number):
        api = 'cluster/licensing/licenses'
        query = {'serial_number': serial_number}
        if product:
            query['licenses.installed_license'] = product.replace(' ', '*')
            # since this is a query, we need to specify state, or only active licenses are removed
            query['state'] = '*'
        dummy, error = rest_generic.delete_async(self.rest_api, api, package_name, query)
        return error

    def remove_unused_licenses(self):
        """
        Remove unused licenses
        """
        remove_unused = netapp_utils.zapi.NaElement('license-v2-delete-unused')
        try:
            self.server.invoke_successfully(remove_unused,
                                            enable_tunneling=False)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error removing unused licenses: %s" %
                                  to_native(error), exception=traceback.format_exc())

    def remove_expired_licenses(self):
        """
        Remove expired licenses
        """
        remove_expired = netapp_utils.zapi.NaElement(
            'license-v2-delete-expired')
        try:
            self.server.invoke_successfully(remove_expired,
                                            enable_tunneling=False)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error removing expired licenses: %s" %
                                  to_native(error), exception=traceback.format_exc())

    def add_licenses(self):
        """
        Add licenses
        """
        if self.use_rest:
            return self.add_licenses_rest()
        license_add = netapp_utils.zapi.NaElement('license-v2-add')
        codes = netapp_utils.zapi.NaElement('codes')
        for code in self.parameters['license_codes']:
            codes.add_new_child('license-code-v2', str(code.strip().lower()))
        license_add.add_child_elem(codes)
        try:
            self.server.invoke_successfully(license_add,
                                            enable_tunneling=False)
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error adding licenses: %s" %
                                  to_native(error), exception=traceback.format_exc())

    def add_licenses_rest(self):
        api = 'cluster/licensing/licenses'
        body = {'keys': [x[0] for x in self.nlfs]}
        headers = None
        if self.rest_api.meets_rest_minimum_version(self.use_rest, 9, 9, 1):
            # request nested errors
            headers = {'X-Dot-Error-Arguments': 'true'}
        dummy, error = rest_generic.post_async(self.rest_api, api, body, headers=headers)
        if error:
            error = self.format_post_error(error, body)
            if 'conflicts' in error:
                return error
            self.module.fail_json(msg="Error adding license: %s - previous license status: %s" % (error, self.license_status))
        return None

    def compare_license_status(self, previous_license_status):
        changed_keys = []
        for __ in range(5):
            error = None
            new_license_status, records = self.get_licensing_status()
            try:
                changed_keys = local_cmp(previous_license_status, new_license_status)
                break
            except KeyError as exc:
                # when a new license is added, it seems REST may not report all licenses
                # wait for things to stabilize
                error = exc
                time.sleep(5)
        if error:
            self.module.fail_json(msg='Error: mismatch in license package names: %s.  Expected: %s, found: %s.'
                                  % (error, previous_license_status.keys(), new_license_status.keys()))
        if 'installed_licenses' in changed_keys:
            changed_keys.remove('installed_licenses')
        if records and self.previous_records:
            deep_changed_keys = self.deep_compare(records)
            for key in deep_changed_keys:
                if key not in changed_keys:
                    changed_keys.append(key)
        return changed_keys

    def deep_compare(self, records):
        """ look for any change in license details, capacity, expiration, ...
            this is run after apply, so we don't know for sure in check_mode
        """
        if not HAS_DEEPDIFF:
            self.module.warn('deepdiff is required to identify detailed changes')
            return []
        diffs = DeepDiff(self.previous_records, records)
        self.rest_api.log_debug('diffs', diffs)
        roots = set(re.findall(r'root\[(\d+)\]', str(diffs)))
        result = [records[int(index)]['name'] for index in roots]
        self.rest_api.log_debug('deep_changed_keys', result)
        return result

    def reformat_nlf(self, license_code):
        # Ansible converts double quotes into single quotes if the input is python-like
        # and we can't use json loads with single quotes!
        if not HAS_AST or not HAS_JSON:
            return None, "ast and json packages are required to install NLF license files.  Import error(s): %s." % IMPORT_ERRORS
        try:
            nlf_dict = ast.literal_eval(license_code)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError) as exc:
            return None, "malformed input: %s, exception: %s" % (license_code, exc)
        try:
            license_code = json.dumps(nlf_dict, separators=(',', ':'))
        except Exception as exc:
            return None, "unable to encode input: %s - evaluated as %s, exception: %s" % (license_code, nlf_dict, exc)
        return license_code, None

    def get_nlf_dict(self, license_code):
        nlf_dict = {}
        is_nlf = False
        if '"statusResp"' in license_code:
            if license_code.count('"statusResp"') > 1:
                self.module.fail_json(msg="Error: NLF license files with multiple licenses are not supported, found %d in %s."
                                      % (license_code.count('"statusResp"'), license_code))
            if license_code.count('"serialNumber"') > 1:
                self.module.fail_json(msg="Error: NLF license files with multiple serial numbers are not supported, found %d in %s."
                                      % (license_code.count('"serialNumber"'), license_code))
            is_nlf = True
            if not HAS_JSON:
                return nlf_dict, is_nlf, "the json package is required to process NLF license files.  Import error(s): %s." % IMPORT_ERRORS
            try:
                nlf_dict = json.loads(license_code)
            except Exception as exc:
                return nlf_dict, is_nlf, "the license contents cannot be read.  Unable to decode input: %s - exception: %s." % (license_code, exc)
        return nlf_dict, is_nlf, None

    def scan_license_codes_for_nlf(self, license_code):
        more_info = "You %s seeing this error because the original NLF contents were modified by Ansible.  You can use the string filter to keep the original."
        transformed = False
        original_license_code = license_code

        if "'statusResp'" in license_code:
            license_code, error = self.reformat_nlf(license_code)
            if error:
                error = 'Error: %s  %s' % (error, more_info % 'are')
                self.module.fail_json(msg=error)
            transformed = True

        # For an NLF license, extract fields, to later collect serial number and bundle name (product)
        nlf_dict, is_nlf, error = self.get_nlf_dict(license_code)
        if error and transformed:
            error = 'Error: %s.  Ansible input: %s  %s' % (error, original_license_code, more_info % 'may be')
            self.module.fail_json(msg=error)

        if error:
            msg = "The license " + (
                  "will be installed without checking for idempotency." if self.parameters['state'] == 'present' else "cannot be removed.")
            msg += "  You are seeing this warning because " + error
            self.module.warn(msg)

        return license_code, nlf_dict, is_nlf

    def split_nlf(self, license_code):
        """ A NLF file may contain several licenses
            One license per line
            Return a list of 1 or more licenses
        """
        licenses = license_code.count('"statusResp"')
        if licenses <= 1:
            return [license_code]
        nlfs = license_code.splitlines()
        if len(nlfs) != licenses:
            self.module.fail_json(msg="Error: unexpected format found %d entries and %d lines in %s"
                                  % (licenses, len(nlfs), license_code))
        return nlfs

    def split_nlfs(self):
        """ A NLF file may contain several licenses
            Return a flattened list of license codes
        """
        license_codes = []
        for license in self.parameters.get('license_codes', []):
            license_codes.extend(self.split_nlf(license))
        return license_codes

    def validate_nlfs(self):
        self.parameters['license_codes'] = self.split_nlfs()
        nlf_count = 0
        for license in self.parameters['license_codes']:
            nlf, nlf_dict, is_nlf = self.scan_license_codes_for_nlf(license)
            if is_nlf and not self.use_rest:
                self.module.fail_json(msg="Error: NLF license format is not supported with ZAPI.")
            self.nlfs.append((nlf, nlf_dict))
            if is_nlf:
                nlf_count += 1
        if nlf_count and nlf_count != len(self.parameters['license_codes']):
            self.module.fail_json(msg="Error: cannot mix legacy licenses and NLF licenses; found %d NLF licenses out of %d license_codes."
                                  % (nlf_count, len(self.parameters['license_codes'])))

    def get_key(self, error, body):
        needle = r'Failed to install the license at index (\d+)'
        matched = re.search(needle, error)
        if matched:
            index = int(matched.group(1))
            return body['keys'][index]
        return None

    def format_post_error(self, error, body):
        if 'The system received a licensing request with an invalid digital signature.' in error:
            key = self.get_key(error, body)
            if key and "'statusResp'" in key:
                error = 'Original NLF contents were modified by Ansible.  Make sure to use the string filter.  REST error: %s' % error
        return error

    def nlf_is_installed(self, nlf_dict):
        """ return True if NLF with same SN, product (bundle) name and package list is present
            return False otherwise
            Even when present, the NLF may not be active, so this is only useful for delete
        """
        n_serial_number, n_product = self.get_sn_and_product(nlf_dict)
        if not n_product or not n_serial_number:
            return False
        if 'installed_licenses' not in self.license_status:
            # nothing is installed
            return False
        if n_serial_number == '*' and self.parameters['state'] == 'absent':
            # force a delete
            return True
        if n_serial_number not in self.license_status['installed_licenses']:
            return False
        return n_product in self.license_status['installed_licenses'][n_serial_number]

    def get_sn_and_product(self, nlf_dict):
        # V2 and V1 formats
        n_serial_number = self.na_helper.safe_get(nlf_dict, ['statusResp', 'serialNumber'])\
            or self.na_helper.safe_get(nlf_dict, ['statusResp', 'licenses', 'serialNumber'])
        n_product = self.na_helper.safe_get(nlf_dict, ['statusResp', 'product'])\
            or self.na_helper.safe_get(nlf_dict, ['statusResp', 'licenses', 'product'])
        return n_serial_number, n_product

    def validate_delete_action(self, nlf_dict):
        """ make sure product and serialNumber are set at the top level (V2 format) """
        # product is required for delete
        n_serial_number, n_product = self.get_sn_and_product(nlf_dict)
        if nlf_dict and not n_product:
            self.module.fail_json(msg='Error: product not found in NLF file %s.' % nlf_dict)
        # if serial number is not present in the NLF, we could use a module parameter
        p_serial_number = self.parameters.get('serial_number')
        if p_serial_number and n_serial_number and p_serial_number != n_serial_number:
            self.module.fail_json(msg='Error: mismatch is serial numbers %s vs %s' % (p_serial_number, n_serial_number))
        if nlf_dict and not n_serial_number and not p_serial_number:
            self.module.fail_json(msg='Error: serialNumber not found in NLF file.  It can be set in the module parameter.')
        nlf_dict['serialNumber'] = n_serial_number or p_serial_number
        nlf_dict['product'] = n_product

    def get_delete_actions(self):
        packages_to_delete = []
        if self.parameters.get('license_names') is not None:
            for package in list(self.parameters['license_names']):
                if 'installed_licenses' in self.license_status and self.parameters['serial_number'] != '*'\
                   and self.parameters['serial_number'] in self.license_status['installed_licenses']\
                   and package in self.license_status['installed_licenses'][self.parameters['serial_number']]:
                    packages_to_delete.append(package)
                if package in self.license_status:
                    packages_to_delete.append(package)

        for dummy, nlf_dict in self.nlfs:
            if nlf_dict:
                self.validate_delete_action(nlf_dict)
        nlfs_to_delete = [
            nlf_dict
            for dummy, nlf_dict in self.nlfs
            if self.nlf_is_installed(nlf_dict)
        ]
        return bool(nlfs_to_delete) or bool(self.parameters.get('license_names')), packages_to_delete, nlfs_to_delete

    def get_add_actions(self):
        """ add licenses unconditionally
            for legacy licenses we don't know if they are already installed
            for NLF licenses we don't know if some details have changed (eg capacity, expiration date)
        """
        return bool(self.nlfs), [license_code for license_code, dummy in self.nlfs]

    def get_actions(self):
        changed = False
        licenses_to_add = []
        nlfs_to_delete = []
        remove_license = False
        packages_to_delete = []
        nlfs_to_delete = []
        # Add / Update licenses.
        self.license_status, self.previous_records = self.get_licensing_status()
        if self.parameters['state'] == 'absent':  # delete
            changed, packages_to_delete, nlfs_to_delete = self.get_delete_actions()
        else:  # add or update
            changed, licenses_to_add = self.get_add_actions()
            if self.parameters.get('remove_unused') is not None:
                remove_license = True
                changed = True
            if self.parameters.get('remove_expired') is not None:
                remove_license = True
                changed = True
        return changed, licenses_to_add, remove_license, packages_to_delete, nlfs_to_delete

    def apply(self):
        '''Call add, delete or modify methods'''
        changed, licenses_to_add, remove_license, packages_to_delete, nlfs_to_delete = self.get_actions()
        error, changed_keys = None, []
        if changed and not self.module.check_mode:
            if self.parameters['state'] == 'present':  # execute create
                if licenses_to_add:
                    error = self.add_licenses()
                if self.parameters.get('remove_unused') is not None:
                    self.remove_unused_licenses()
                if self.parameters.get('remove_expired') is not None:
                    self.remove_expired_licenses()
                # not able to detect that a new license is required until we try to install it.
                if licenses_to_add or remove_license:
                    changed_keys = self.compare_license_status(self.license_status)
            # delete actions
            else:
                if nlfs_to_delete:
                    changed_keys.extend([nlf_dict.get("product") for nlf_dict in nlfs_to_delete if self.remove_licenses(None, nlf_dict)])
                if packages_to_delete:
                    changed_keys.extend([package for package in self.parameters['license_names'] if self.remove_licenses(package)])
            if not changed_keys:
                changed = False

        if error:
            error = 'Error: ' + (
                'some licenses were updated, but others were in conflict: '
                if changed_keys
                else 'adding licenses: '
            ) + error
            self.module.fail_json(msg=error, changed=changed, updated_licenses=changed_keys)
        self.module.exit_json(changed=changed, updated_licenses=changed_keys)


def main():
    '''Apply license operations'''
    obj = NetAppOntapLicense()
    obj.apply()


if __name__ == '__main__':
    main()
