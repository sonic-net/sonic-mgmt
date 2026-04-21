#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2021 IBM CORPORATION
# Author(s): Shilpi Jain <shilpi.jain1@ibm.com>
#            Lavanya C R <lavanya.c.r1@ibm.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_initial_setup
short_description: This module allows users to manage the initial setup configuration on IBM Storage Virtualize family systems
version_added: "1.7.0"
description:
  - Ansible interface to perform various initial system configuration
options:
    clustername:
        description:
            - The hostname or management IP of the Storage Virtualize system.
        required: true
        type: str
    domain:
        description:
            - Domain for the Storage Virtualize system.
            - Valid when hostname is used for the parameter I(clustername).
        type: str
    username:
        description:
            - REST API username for the Storage Virtualize system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    password:
        description:
            - REST API password for the Storage Virtualize system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    token:
        description:
            - The authentication token to verify a user on the Storage Virtualize system.
            - To generate a token, use the M(ibm.storage_virtualize.ibm_svc_auth) module.
        type: str
    log_path:
        description:
            - Path of debug log file.
        type: str
    validate_certs:
        description:
            - Validates certification.
        default: false
        type: bool
    system_name:
        description:
            - Specifies system name.
        type: str
    dnsname:
        description:
            - Specifies a unique name for the system DNS server being created.
            - Maximum two DNS servers can be configured. User needs to provide the complete list of DNS servers that are required to be configured.
        type: list
        elements: str
    dnsip:
        description:
            - Specifies the DNS server Internet Protocol (IP) address.
        type: list
        elements: str
    ntpip:
        description:
            - Specifies the IPv4 address or fully qualified domain name (FQDN) for the Network Time Protocol (NTP) server.
            - To remove an already configured NTP IP, user must specify 0.0.0.0.
        type: str
    time:
        description:
            - Specifies the time to which the system must be set.
            - This value must be in the following format MMDDHHmmYYYY (where M is month, D is day, H is hour, m is minute, and Y is year).
        type: str
    timezone:
        description:
            - Specifies the time zone to set for the system.
        type: str
    vdiskprotectiontime:
        description:
            - Specifies the volume protection time (in minutes).
        type: int
        version_added: 2.7.0
    vdiskprotectionenabled:
        description:
            - Specifies whether the volume protection is enabled or disabled.
        type: str
        version_added: 2.7.0
        choices: [ 'yes', 'no' ]
    iscsiauthmethod:
        description:
            - Specify the authentication method for iSCSI communications on the system.
        type: str
        version_added: 2.7.0
        choices: [ 'none', 'chap' ]
    chapsecret:
        description:
            - Specify the CHAP secret to authenticate the system using iSCSI.
            - Required when I(iscsiauthmethod=chap), to modify a CHAP secret.
            - If I(chapsecret) is specified as an empty string (""), it is treated as nochapsecret, which clears current chapsecret.
        type: str
        version_added: 2.7.0
    license_key:
        description:
            - Provides the license key to activate a feature that contains 16 hexadecimal characters organized in four groups
              of four numbers with each group separated by a hyphen (such as 0123-4567-89AB-CDEF).
        type: list
        elements: str
    remote:
        description:
            - Changes system licensing for remote-copy functions such as Metro Mirror, Global Mirror, and HyperSwap.
            - Depending on the type of system, specify a capacity value in terabytes (TB) or specify the total number of
              internal and external enclosures that user has licensed on the system.
              There must be an enclosure license for all enclosures.
        type: int
    virtualization:
        description:
            - Changes system licensing for the Virtualization function.
            - Depending on the type of system, specify a capacity value in terabytes (TB) or specify the total number of
              storage capacity units (SCUs) that user is licensed to virtualize across tiers of storage on the system or
              specify the number of enclosures of external storage that user is authorized to use.
        type: int
    compression:
        description:
            - Changes system licensing for the compression function.
            - Depending on the type of system, specify a capacity value in terabytes (TB) or specify the total number of
              storage capacity units (SCUs) that user is licensed to virtualize across tiers of storage on the system or
              specify the total number of internal and external enclosures that user has licensed on the system.
        type: int
    flash:
        description:
            - Changes system licensing for the FlashCopy function.
            - Depending on the type of system, specify a capacity value in terabytes (TB) or specify the total number of
              internal and external enclosures for the FlashCopy function.
        type: int
    cloud:
        description:
            - Specifies the number of enclosures for the transparent cloud tiering function.
        type: int
    easytier:
        description:
            - Specifies the number of enclosures on which user can run Easy Tier.
        type: int
    physical_flash:
        description:
            - For physical disk licensing, this parameter enables or disables the FlashCopy function.
        type: str
        choices: [ 'on', 'off' ]
        default: 'off'
    encryption:
        description:
            - Specifies whether the encryption license function is enabled or disabled.
        type: str
        choices: [ 'on', 'off' ]
    flashcopydefaultgrainsize:
        description:
            - Allow a user to change the FC grainsize to be one of either 64K or 256K.
        type: int
        version_added: 2.6.0
    storageinsightscontrolaccess:
        description:
            - Indicates whether the storage insights control access for the system is enabled or disabled.
        type: str
        version_added: 2.6.0
        choices: [ 'yes', 'no' ]
author:
    - Shilpi Jain (@Shilpi-J)
    - Lavanya C R (@lavanyacr)
notes:
    - This module supports C(check_mode).
    - Error Considerations
        - CMMVC5708E A parameter is missing a value.
        - CMMVC5713E Some parameters are mutually exclusive.
        - CMMVC7218E The provided license key is not valid.
'''

EXAMPLES = '''
- name: Initial configuration on FlashSystem 9200
  ibm.storage_virtualize.ibm_svc_initial_setup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    system_name: cluster_test_0
    time: 101009142021
    timezone: 200
    remote: 50
    virtualization: 50
    flash: 50
    license_key:
      - 0123-4567-89AB-CDEF
      - 8921-4567-89AB-GHIJ
- name: Add DNS servers
  ibm.storage_virtualize.ibm_svc_initial_setup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    system_name: cluster_test_
    dnsname:
      - dns_01
      - dns_02
    dnsip:
      - '1.1.1.1'
      - '2.2.2.2'
- name: Delete dns_02 server
  ibm.storage_virtualize.ibm_svc_initial_setup:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    system_name: cluster_test_
    dnsname:
      - dns_01
    dnsip:
      - '1.1.1.1'
- name: Change flashcopydefaultgrainsize to 64 and storageinsightscontrolaccess to no.
  ibm.storage_virtualize.ibm_svc_initial_setup:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    flashcopydefaultgrainsize: 64
    storageinsightscontrolaccess: "no"
- name: Change vdiskprotectiontime to 20 and vdiskprotectionenabled to yes.
  ibm.storage_virtualize.ibm_svc_initial_setup:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    vdiskprotectiontime: 20
    vdiskprotectionenabled: "yes"
- name: Change iscsiauthmethod to chap and set chapsecret.
  ibm.storage_virtualize.ibm_svc_initial_setup:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    iscsiauthmethod: chap
    chapsecret: "test_cs"
- name: Change iscsiauthmethod to none and clear chapsecret.
  ibm.storage_virtualize.ibm_svc_initial_setup:
    clustername: "{{ clustername }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/playbook.debug
    iscsiauthmethod: none
    chapsecret: ""
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils._text import to_native


class IBMSVCInitialSetup(object):
    def __init__(self):
        argument_spec = svc_argument_spec()

        argument_spec.update(
            dict(
                system_name=dict(type='str'),
                ntpip=dict(type='str'),
                time=dict(type='str'),
                timezone=dict(type='str'),
                vdiskprotectiontime=dict(type='int'),
                vdiskprotectionenabled=dict(type='str', choices=['yes', 'no']),
                iscsiauthmethod=dict(type='str', choices=['none', 'chap']),
                chapsecret=dict(type='str', no_log=True),
                flashcopydefaultgrainsize=dict(type='int'),
                storageinsightscontrolaccess=dict(type='str', choices=['yes', 'no']),
                dnsname=dict(type='list', elements='str'),
                dnsip=dict(type='list', elements='str'),
                license_key=dict(type='list', elements='str', no_log=True),
                flash=dict(type='int'),
                remote=dict(type='int'),
                virtualization=dict(type='int'),
                compression=dict(type='int'),
                physical_flash=dict(type='str', default='off', choices=['on', 'off']),
                easytier=dict(type='int'),
                encryption=dict(type='str', choices=['on', 'off']),
                cloud=dict(type='int'),
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        self.changed = False
        self.message = ""

        # system related parameters
        self.systemname = self.module.params.get('system_name', '')
        self.ntpip = self.module.params.get('ntpip', '')
        self.time = self.module.params.get('time', '')
        self.timezone = self.module.params.get('timezone', '')
        self.vdiskprotectiontime = self.module.params.get('vdiskprotectiontime', '')
        self.vdiskprotectionenabled = self.module.params.get('vdiskprotectionenabled', '')
        self.iscsiauthmethod = self.module.params.get('iscsiauthmethod', '')
        self.chapsecret = self.module.params.get('chapsecret', '')
        self.flashcopydefaultgrainsize = self.module.params.get('flashcopydefaultgrainsize', '')
        self.storageinsightscontrolaccess = self.module.params.get('storageinsightscontrolaccess', '')

        # dns related parameter
        self.dnsname = self.module.params.get('dnsname', '')
        self.dnsip = self.module.params.get('dnsip', '')

        # license related parameters
        self.license_key = self.module.params.get('license_key', '')
        self.flash = self.module.params.get('flash', '')
        self.remote = self.module.params.get('remote', '')
        self.virtualization = self.module.params.get('virtualization', '')
        self.compression = self.module.params.get('compression', '')
        self.physical_flash = self.module.params.get('physical_flash', '')
        self.easytier = self.module.params.get('easytier', '')
        self.cloud = self.module.params.get('cloud', '')
        self.encryption = self.module.params.get('encryption', '')

        self.restapi = IBMSVCRestApi(
            module=self.module,
            clustername=self.module.params['clustername'],
            domain=self.module.params['domain'],
            username=self.module.params['username'],
            password=self.module.params['password'],
            validate_certs=self.module.params['validate_certs'],
            log_path=log_path,
            token=self.module.params['token']
        )

    def basic_checks(self):

        mutually_exclusive = (
            ('time', 'ntpip'),
        )
        for param1, param2 in mutually_exclusive:
            if getattr(self, param1) and getattr(self, param2):
                self.module.fail_json(
                    msg='CMMVC5713E Mutually exclusive parameters: [{0}, {1}]'.format(param1, param2)
                )

        if self.iscsiauthmethod == "chap" and not self.chapsecret:
            self.module.fail_json(msg='CMMVC5708E Parameter [chapsecret] is missing a value.')

        if self.dnsname and self.dnsip:
            if len(self.dnsname) != len(self.dnsip):
                self.module.fail_json(msg='To configure DNS, number of DNS IP(s) must match the number of DNS server name(s).')
            for dnsname, dnsip in zip(self.dnsname, self.dnsip):
                if dnsname == "":
                    self.module.fail_json(msg='CMMVC5708E Parameter [dnsname] is missing a value.')
                if dnsip == "":
                    self.module.fail_json(msg='CMMVC5708E Parameter [dnsip] is missing a value.')

        if self.license_key:
            for key in self.license_key:
                if key == "":
                    self.module.fail_json(msg='CMMVC5708E Parameter [licensekey] is missing a value.')
                if len(key) != 19:  # SVC throw
                    self.module.fail_json(msg='CMMVC7218E An invalid license key was specified.')

    def get_system_info(self):
        self.log("Entering function get_system_info")
        system_data = self.restapi.svc_obj_info(cmd='lssystem', cmdopts=None, cmdargs=None)
        return system_data

    def get_license_info(self):
        self.log("Entering function get_license_info")
        license_data = self.restapi.svc_obj_info(cmd='lslicense', cmdopts=None, cmdargs=None)
        return license_data

    def get_dnsserver_info(self):
        self.log("Entering function get_dnsserver_info")
        merged_result = []

        dnsserver_data = self.restapi.svc_obj_info(cmd='lsdnsserver', cmdopts=None, cmdargs=None)

        if isinstance(dnsserver_data, list):
            for d in dnsserver_data:
                merged_result.append(d)
        else:
            merged_result = dnsserver_data

        return merged_result

    def get_feature_info(self):
        self.log("Entering function get_feature_info")
        feature_data = self.restapi.svc_obj_info('lsfeature', cmdopts=None, cmdargs=None)
        return feature_data

    def system_probe(self, data):
        props = []

        field_mappings = (
            ('systemname', data.get('name', '')),
            ('ntpip', data.get('cluster_ntp_IP_address', '')),
            ('vdiskprotectiontime', int(data.get('vdisk_protection_time', 0))),
            ('vdiskprotectionenabled', data.get('vdisk_protection_enabled', '')),
            ('iscsiauthmethod', data.get('iscsi_auth_method', '')),
            ('flashcopydefaultgrainsize', int(data.get('flashcopy_default_grainsize', 0))),
            ('storageinsightscontrolaccess', data.get('storage_insights_control_access', '')),
        )

        for field, existing_value in field_mappings:
            new_value = getattr(self, field, None)
            if new_value is not None and new_value != existing_value:
                props.append(field)

        if self.chapsecret is not None:
            if self.chapsecret != "" and self.chapsecret != data['iscsi_chap_secret']:
                props.append('chapsecret')
            elif self.chapsecret == "" and data['iscsi_chap_secret'] != "":
                self.nochapsecret = True
                props.append('nochapsecret')

        if self.time and data['cluster_ntp_IP_address'] != "":
            props.append('ntpip')

        if self.time:
            props.append('time')

        if self.timezone and (self.timezone != (data['time_zone'].split(" ", 1)[0] if data['time_zone'] else None)):
            props.append('timezone')

        self.log("system_probe props='%s'", props)
        return props

    def systemtime_update(self):
        cmd = 'setsystemtime'
        cmdopts = {}
        cmdopts['time'] = self.time

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log("Properties: Time %s updated", self.time)

    def timezone_update(self):
        cmd = 'settimezone'
        cmdopts = {}
        cmdopts['timezone'] = self.timezone

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log("Properties: Time zone %s updated", self.timezone)

    def system_update(self, modify, data):

        self.log("updating system '%s'", self.systemname)
        if self.module.check_mode:
            self.changed = True
            return

        cmd = 'chsystem'
        cmdopts = {}

        system_name_required = False
        time_change_required = False

        if 'systemname' in modify:
            cmdopts['name'] = self.systemname
            system_name_required = True
            modify.remove('systemname')

        if 'ntpip' in modify:
            cmdopts['ntpip'] = self.ntpip if self.ntpip else '0.0.0.0'
            modify.remove('ntpip')

        if 'time' in modify:
            time_change_required = True
            modify.remove('time')

        if 'timezone' in modify:
            self.timezone_update()
            self.changed = True
            modify.remove('timezone')

        for param in modify:
            cmdopts[param] = getattr(self, param)

        if 'iscsiauthmethod' in modify and self.iscsiauthmethod == 'chap':
            cmdopts['chapsecret'] = self.chapsecret if 'chapsecret' in modify else data['iscsi_chap_secret']

        cmdoptsList = cmdopts.keys()
        if cmdopts:
            self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
            self.changed = True
            self.log("Properties updated: %s", cmdoptsList)

        if time_change_required:
            self.systemtime_update()
            self.changed = True

        if cmdopts:
            if system_name_required:
                self.message += "System [{0}] has been successfully renamed to [{1}]{2}".format(
                    data['name'],
                    self.systemname,
                    ' and other parameters updated.' if (len(cmdoptsList) > 1) else '.'
                )
            else:
                self.message += "System %s updated" % data['name']

    def dns_configure(self, data):
        existing_dns = {}
        existing_dns_server = []
        existing_dns_ip = []

        if self.module.check_mode:
            self.changed = True
            return

        if self.dnsip and self.dnsname:
            for server in data:
                existing_dns_server.append(server['name'])
                existing_dns_ip.append(server['IP_address'])
                existing_dns[server['name']] = server['IP_address']

            for name, ip in zip(self.dnsname, self.dnsip):  # To modify existing name or ip
                if name in existing_dns and existing_dns[name] != ip:
                    self.log("update, diff IP.")
                    self.restapi.svc_run_command(
                        'chdnsserver', {'ip': ip}, [name]
                    )
                    self.changed = True
                    self.message += "DNS %s modified." % name

            if (set(existing_dns_server)).symmetric_difference(set(self.dnsname)):

                dnsserver_to_remove = list(set(existing_dns_server) - set(self.dnsname))
                if dnsserver_to_remove:
                    for item in dnsserver_to_remove:
                        self.restapi.svc_run_command(
                            'rmdnsserver', None,
                            [item]
                        )
                    self.message += " DNS server %s removed." % dnsserver_to_remove

                dnsservername_to_add = list(set(self.dnsname) - set(existing_dns_server))
                dnsserverid_to_add = list(set(self.dnsip) - set(existing_dns_ip))
                if dnsservername_to_add:
                    for dns_name, dns_ip in zip(dnsservername_to_add, dnsserverid_to_add):
                        self.log('%s %s', dns_name, dns_ip)
                        self.restapi.svc_run_command(
                            'mkdnsserver',
                            {'name': dns_name, 'ip': dns_ip}, cmdargs=None
                        )
                    self.message += " DNS server %s added." % dnsservername_to_add
                self.changed = True

    def license_probe(self, data, sys_data):
        props = []

        field_mappings = (
            ('flash', int(data.get('license_flash', 0))),
            ('remote', int(data.get('license_remote', 0))),
            ('virtualization', int(data.get('license_virtualization', 0))),
            ('physical_flash', data.get('license_physical_flash', '')),
            ('easytier', int(data.get('license_easy_tier', 0))),
            ('cloud', int(data.get('license_cloud_enclosures', 0))),
        )

        for field, existing_value in field_mappings:
            new_value = getattr(self, field, None)
            if new_value is not None and new_value != existing_value:
                props.append(field)

        if self.compression:
            if (sys_data['product_name'] == "IBM Storwize V7000") or (sys_data['product_name'] == "IBM FlashSystem 7200"):
                if (int(data['license_compression_enclosures']) != self.compression):
                    self.log("license_compression_enclosure=%d", int(data['license_compression_enclosures']))
                    props.append('compression')
            else:
                if (int(data['license_compression_capacity']) != self.compression):
                    self.log("license_compression_capacity=%d", int(data['license_compression_capacity']))
                    props.append('compression')

        self.log("license_probe props: %s", props)
        return props

    def license_update(self, modify):
        self.log("updating license of '%s'", self.systemname)
        if self.module.check_mode:
            self.changed = True
            return

        for license in modify:
            cmdopts = {}
            cmdopts[license] = getattr(self, license)
            self.restapi.svc_run_command('chlicense', cmdopts, cmdargs=None)

        if self.encryption:
            self.restapi.svc_run_command('chlicense', {'encryption': self.encryption}, cmdargs=None)

        self.changed = True
        self.log("Licensed functions %s updated", modify)
        self.message += " Licensed functions %s updated." % modify

    def license_key_update(self, data):
        existing_license_keys = []
        existing_license_id_pairs = {}

        if self.module.check_mode:
            self.changed = True
            return

        for feature in data:
            existing_license_keys.append(feature['license_key'])
            existing_license_id_pairs[feature['license_key']] = feature['id']
        self.log("existing licenses=%s, license_id_pairs=%s", existing_license_keys, existing_license_id_pairs)

        if (set(existing_license_keys)).symmetric_difference(set(self.license_key)):
            activate_license_keys = list(set(self.license_key) - set(existing_license_keys))
            deactivate_license_keys = list(set(existing_license_keys) - set(self.license_key))

            if deactivate_license_keys:
                for key in deactivate_license_keys:
                    if key:
                        self.restapi.svc_run_command(
                            'deactivatefeature', None, [existing_license_id_pairs[key]]
                        )
                        self.changed = True
                        self.log('%s deactivated', deactivate_license_keys)
                self.message += " License %s deactivated." % deactivate_license_keys

            if activate_license_keys:
                for key in activate_license_keys:
                    if key:
                        self.restapi.svc_run_command(
                            'activatefeature', {'licensekey': key}, None
                        )
                        self.changed = True
                        self.log('%s activated', key)
                self.message += " License %s activated." % activate_license_keys
        else:
            self.message += " No license Changes."

    def apply(self):
        msg = None
        modify = []

        self.basic_checks()

        # System Configuration
        system_data = self.get_system_info()
        modify = self.system_probe(system_data)
        if modify:
            self.system_update(modify, system_data)

        # DNS configuration
        if self.dnsname and self.dnsip:
            dns_data = self.get_dnsserver_info()
            self.dns_configure(dns_data)

        # For honour based licenses
        license_data = self.get_license_info()
        modify = self.license_probe(license_data, system_data)
        if modify:
            self.license_update(modify)

        # For key based licenses
        if self.license_key:
            feature_data = self.get_feature_info()
            self.license_key_update(feature_data)

        if self.changed:
            if self.module.check_mode:
                msg = "skipping changes due to check mode."
            else:
                msg = self.message
        else:
            msg = "No modifications required. Exiting with no changes."

        self.module.exit_json(msg=msg, changed=self.changed)


def main():
    v = IBMSVCInitialSetup()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
