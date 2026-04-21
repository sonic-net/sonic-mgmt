#!/usr/bin/python3

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import sys
import yaml

import ovirtsdk4 as sdk
from ovirtsdk4 import types

from bcolors import bcolors
from configparser import ConfigParser


INFO = bcolors.OKGREEN
INPUT = bcolors.OKGREEN
WARN = bcolors.WARNING
FAIL = bcolors.FAIL
END = bcolors.ENDC
PREFIX = "[Validate Mapping File] "


class ValidateMappingFile:

    def_var_file = "../examples/disaster_recovery_vars.yml"
    default_main_file = "../defaults/main.yml"
    var_file = ""
    running_vms = "dr_running_vms"
    cluster_map = 'dr_cluster_mappings'
    domain_map = 'dr_import_storages'
    role_map = 'dr_role_mappings'
    aff_group_map = 'dr_affinity_group_mappings'
    aff_label_map = 'dr_affinity_label_mappings'
    network_map = 'dr_network_mappings'

    def run(self, conf_file):
        print("%s%sValidate variable mapping file "
              "for oVirt ansible disaster recovery%s"
              % (INFO, PREFIX, END))
        self._set_dr_conf_variables(conf_file)
        print("%s%sVar File: '%s'%s" % (INFO, PREFIX, self.var_file, END))

        python_vars = self._read_var_file()
        if (not self._validate_lists_in_mapping_file(python_vars)
                or not self._validate_duplicate_keys(python_vars)
                or not self._entity_validator(python_vars)
                or not self._validate_failback_leftovers()):
            self._print_finish_error()
            sys.exit()

        if not self._validate_hosted_engine(python_vars):
            self._print_finish_error()
            sys.exit()

        if not self._validate_export_domain(python_vars):
            self._print_finish_error()
            sys.exit()
        self._print_finish_success()

    def _validate_lists_in_mapping_file(self, mapping_vars):
        return self._is_list(mapping_vars, self.cluster_map) and self._is_list(
            mapping_vars, self.domain_map) and self._is_list(
            mapping_vars, self.role_map) and self._is_list(
            mapping_vars, self.aff_group_map) and self._is_list(
            mapping_vars, self.aff_label_map) and self._is_list(
            mapping_vars, self.network_map)

    def _is_list(self, mapping_vars, mapping):
        map_file = mapping_vars.get(mapping)
        if not isinstance(map_file, list) and map_file is not None:
            print("%s%s%s is not a list: '%s'."
                  " Please check your mapping file%s"
                  % (FAIL, PREFIX, mapping, map_file, END))
            return False
        return True

    def _print_finish_error(self):
        print("%s%sFailed to validate variable mapping file "
              "for oVirt ansible disaster recovery%s"
              % (FAIL, PREFIX, END))

    def _print_finish_success(self):
        print("%s%sFinished validation of variable mapping file "
              "for oVirt ansible disaster recovery%s"
              % (INFO, PREFIX, END))

    def _read_var_file(self):
        with open(self.var_file, 'r') as info:
            info_dict = yaml.safe_load(info)
        return info_dict

    def _set_dr_conf_variables(self, conf_file):
        _SECTION = 'validate_vars'
        _VAR_FILE = 'var_file'

        # Get default location of the yml var file.
        settings = ConfigParser()
        settings.read(conf_file)
        if _SECTION not in settings.sections():
            settings.add_section(_SECTION)
        if not settings.has_option(_SECTION, _VAR_FILE):
            settings.set(_SECTION, _VAR_FILE, '')
        var_file = settings.get(_SECTION, _VAR_FILE,
                                vars=DefaultOption(settings,
                                                   _SECTION,
                                                   site=self.def_var_file))
        var_file = os.path.expanduser(var_file)

        while not os.path.isfile(var_file):
            var_file = input("%s%sVar file '%s' does not exist. Please "
                             "provide the location of the var file (%s): %s"
                             % (WARN, PREFIX, var_file, self.def_var_file, END)
                             ) or self.def_var_file
            var_file = os.path.expanduser(var_file)
        self.var_file = var_file

        self.primary_pwd = input(
            "%s%sPlease provide password for the primary setup: %s"
            % (INPUT, PREFIX, END))
        self.second_pwd = input(
            "%s%sPlease provide password for the secondary setup: %s"
            % (INPUT, PREFIX, END))

    def _print_duplicate_keys(self, duplicates, keys):
        ret_val = False
        for key in keys:
            if len(duplicates[key]) > 0:
                print("%s%sFound the following duplicate keys in %s: %s%s" %
                      (FAIL, PREFIX, key, list(duplicates[key]), END))
                ret_val = True
        return ret_val

    def _entity_validator(self, python_vars):
        ovirt_setups = ConnectSDK(
            python_vars,
            self.primary_pwd,
            self.second_pwd)
        isValid = ovirt_setups.validate_primary()
        isValid = ovirt_setups.validate_secondary() and isValid
        if isValid:
            primary_conn, second_conn = '', ''
            try:
                primary_conn = ovirt_setups.connect_primary()
                if primary_conn is None:
                    return False
                isValid = self._validate_entities_in_setup(
                    primary_conn, 'primary', python_vars) and isValid
                second_conn = ovirt_setups.connect_secondary()
                if second_conn is None:
                    return False
                isValid = self._validate_entities_in_setup(
                    second_conn, 'secondary', python_vars) and isValid
                cluster_mapping = python_vars.get(self.cluster_map)
                isValid = isValid and self._validate_vms_for_failback(
                    primary_conn,
                    "primary")
                isValid = isValid and self._validate_vms_for_failback(
                    second_conn,
                    "secondary")
                isValid = isValid and self._is_compatible_versions(
                    primary_conn,
                    second_conn,
                    cluster_mapping)
            finally:
                # Close the connections.
                if primary_conn:
                    primary_conn.close()
                if second_conn:
                    second_conn.close()

        return isValid

    def _validate_failback_leftovers(self):
        valid = {"yes": True, "y": True, "ye": True,
                 "no": False, "n": False}
        with open(self.default_main_file, 'r') as stream:
            try:
                info_dict = yaml.safe_load(stream)
                running_vms_file = info_dict.get(self.running_vms)
                if os.path.isfile(running_vms_file):
                    ans = input(
                        "%s%sFile with running vms info already exists from "
                        "previous failback operation. Do you want to "
                        "delete it (yes,no)?: %s" %
                        (WARN, PREFIX, END))
                    ans = ans.lower()
                    if ans in valid and valid[ans]:
                        os.remove(running_vms_file)
                        print("%s%sFile '%s' has been deleted successfully%s" %
                              (INFO, PREFIX, running_vms_file, END))
                    else:
                        print("%s%sFile '%s' has not been deleted."
                              " It will be used in the next failback"
                              " operation%s" %
                              (INFO, PREFIX, running_vms_file, END))

            except yaml.YAMLError as exc:
                print("%s%syaml file '%s' could not be loaded%s"
                      % (FAIL, PREFIX, self.default_main_file, END))
                print(exc)
                return False
            except OSError as ex:
                print("%s%sFail to validate failback running vms file '%s'%s"
                      % (FAIL, PREFIX, self.default_main_file, END))
                print(ex)
                return False
        return True

    def _validate_entities_in_setup(self, conn, setup, python_vars):
        dcs_service = conn.system_service().data_centers_service()
        dcs_list = dcs_service.list()
        clusters = []
        affinity_groups = set()
        for dc in dcs_list:
            dc_service = dcs_service.data_center_service(dc.id)
            clusters_service = dc_service.clusters_service()
            attached_clusters_list = clusters_service.list()
            for cluster in attached_clusters_list:
                clusters.append(cluster.name)
                cluster_service = clusters_service.cluster_service(cluster.id)
                affinity_groups.update(
                    self._fetch_affinity_groups(cluster_service))
        aff_labels = self._get_affinity_labels(conn)
        aaa_domains = self._get_aaa_domains(conn)
        # TODO: Remove once vnic profile is validated.
        networks = self._get_vnic_profile_mapping(conn)
        isValid = self._validate_networks(
            python_vars,
            networks,
            setup)
        isValid = self._validate_entity_exists(
            clusters,
            python_vars,
            self.cluster_map,
            setup) and isValid
        isValid = self._validate_entity_exists(
            list(affinity_groups),
            python_vars,
            self.aff_group_map,
            setup) and isValid
        isValid = self._validate_entity_exists(
            aff_labels,
            python_vars,
            self.aff_label_map,
            setup) and isValid
        return isValid

    def _fetch_affinity_groups(self, cluster_service):
        affinity_groups = set()
        affinity_groups_service = cluster_service.affinity_groups_service()
        for affinity_group in affinity_groups_service.list():
            affinity_groups.add(affinity_group.name)
        return list(affinity_groups)

    def _get_affinity_labels(self, conn):
        affinity_labels = set()
        affinity_labels_service = \
            conn.system_service().affinity_labels_service()
        for affinity_label in affinity_labels_service.list():
            affinity_labels.add(affinity_label.name)
        return list(affinity_labels)

    def _get_aaa_domains(self, conn):
        domains = []
        domains_service = conn.system_service().domains_service()
        domains_list = domains_service.list()
        for domain in domains_list:
            domains.append(domain.name)
        return domains

    def _get_vnic_profile_mapping(self, conn):
        networks = []
        vnic_profiles_service = conn.system_service().vnic_profiles_service()
        vnic_profile_list = vnic_profiles_service.list()
        for vnic_profile_item in vnic_profile_list:
            mapped_network = {}
            networks_list = conn.system_service().networks_service().list()
            network_name = ''
            for network_item in networks_list:
                if network_item.id == vnic_profile_item.network.id:
                    network_name = network_item.name
                    dc_name = conn.system_service().data_centers_service(). \
                        data_center_service(network_item.data_center.id). \
                        get()._name
                    break
            mapped_network['network_name'] = network_name
            # TODO: 'dc_name' might be referenced before assignment.
            mapped_network['network_dc'] = dc_name
            mapped_network['profile_name'] = vnic_profile_item.name
            networks.append(mapped_network)
        return networks

    def _key_setup(self, setup, key):
        if setup == 'primary':
            if key == 'dr_import_storages':
                return 'dr_primary_name'
            if key == 'dr_network_mappings':
                return ['primary_profile_name',
                        'primary_network_name',
                        'primary_network_dc']
            return 'primary_name'
        elif setup == 'secondary':
            if key == 'dr_import_storages':
                return 'dr_secondary_name'
            if key == 'dr_network_mappings':
                return ['secondary_profile_name',
                        'secondary_network_name',
                        'secondary_network_dc']
            return 'secondary_name'

    def _validate_networks(self, var_file, networks_setup, setup):
        dups = self._get_network_dups(networks_setup)
        _mappings = var_file.get(self.network_map)
        keys = self._key_setup(setup, self.network_map)
        for mapping in _mappings:
            map_key = mapping[keys[0]] + \
                "_" + mapping[keys[1]] + \
                "_" + (mapping[keys[2]] if keys[2] in mapping else "")
            if map_key in dups:
                if keys[2] not in mapping:
                    print(
                        "%s%sVnic profile name '%s' and network name '%s'"
                        " are related to multiple data centers in the"
                        " %s setup. Please specify the data center name in"
                        " the mapping var file.%s" %
                        (FAIL,
                         PREFIX,
                         mapping[keys[0]],
                         mapping[keys[1]],
                         setup,
                         END))
                    return False
                # TODO: Add check whether the data center exists in the setup
        print("%s%sFinished validation for 'dr_network_mappings' for "
              "%s setup with success.%s" %
              (INFO, PREFIX, setup, END))
        return True

    def _get_network_dups(self, networks_setup):
        attributes = [attr['profile_name']
                      + "_"
                      + attr['network_name']
                      + "_"
                      + attr['network_dc'] for attr in networks_setup]
        dups = [x for n, x in enumerate(attributes) if x in attributes[:n]]
        return dups

    def _validate_entity_exists(self, _list, var_file, key, setup):
        isValid = True
        key_setup = self._key_setup(setup, key)
        _mapping = var_file.get(key)
        if _mapping is None:
            return isValid
        for x in _mapping:
            if key_setup not in x.keys():
                print(
                    "%s%sdictionary key '%s' is not included in %s[%s].%s" %
                    (FAIL,
                     PREFIX,
                     key_setup,
                     key,
                     x.keys(),
                     END))
                isValid = False
            if isValid and x[key_setup] not in _list:
                print(
                    "%s%s%s entity '%s':'%s' does not exist in the "
                    "setup.\n%sThe entities which exists in the setup "
                    "are: %s.%s" %
                    (FAIL,
                     PREFIX,
                     key,
                     key_setup,
                     x[key_setup],
                     PREFIX,
                     _list,
                     END))
                isValid = False
        if isValid:
            print(
                "%s%sFinished validation for '%s' for key name "
                "'%s' with success.%s" %
                (INFO, PREFIX, key, key_setup, END))
        return isValid

    def _validate_hosted_engine(self, var_file):
        domains = var_file[self.domain_map]
        hosted = 'hosted_storage'
        for domain in domains:
            primary = domain['dr_primary_name']
            secondary = domain['dr_secondary_name']
            if primary == hosted or secondary == hosted:
                print("%s%sHosted storage domains are not supported.%s"
                      % (FAIL, PREFIX, END))
                return False
        return True

    def _validate_export_domain(self, var_file):
        domains = var_file[self.domain_map]
        for domain in domains:
            domain_type = domain['dr_storage_domain_type']
            if domain_type == 'export':
                print("%s%sExport storage domain is not supported.%s"
                      % (FAIL, PREFIX, END))
                return False
        return True

    def _validate_duplicate_keys(self, var_file):
        clusters = 'clusters'
        domains = 'domains'
        roles = 'roles'
        aff_groups = 'aff_groups'
        aff_labels = 'aff_labels'
        network = 'network'
        key1 = 'primary_name'
        key2 = 'secondary_name'
        dr_primary_name = 'dr_primary_name'
        dr_secondary_name = 'dr_secondary_name'

        duplicates = self._get_dups(
            var_file, [
                [clusters, self.cluster_map, key1, key2],
                [domains, self.domain_map, dr_primary_name, dr_secondary_name],
                [roles, self.role_map, key1, key2],
                [aff_groups, self.aff_group_map, key1, key2],
                [aff_labels, self.aff_label_map, key1, key2]])
        duplicates[network] = self._get_dup_network(var_file)
        return not self._print_duplicate_keys(
            duplicates,
            [clusters, domains, roles, aff_groups, aff_labels, network])

    def _validate_vms_for_failback(self, setup_conn, setup_type):
        vms_in_preview = []
        vms_delete_protected = []
        service_setup = setup_conn.system_service().vms_service()
        for vm in service_setup.list():
            vm_service = service_setup.vm_service(vm.id)
            if vm.delete_protected:
                vms_delete_protected.append(vm.name)
            snapshots_service = vm_service.snapshots_service()
            for snapshot in snapshots_service.list():
                if snapshot.snapshot_status == types.SnapshotStatus.IN_PREVIEW:
                    vms_in_preview.append(vm.name)
        if len(vms_in_preview) > 0:
            print("%s%sFailback process does not support VMs in preview."
                  " The '%s' setup contains the following previewed vms:"
                  " '%s'%s"
                  % (FAIL, PREFIX, setup_type, vms_in_preview, END))
            return False
        if len(vms_delete_protected) > 0:
            print("%s%sFailback process does not support delete protected"
                  " VMs. The '%s' setup contains the following vms:"
                  " '%s'%s"
                  % (FAIL, PREFIX, setup_type, vms_delete_protected, END))
            return False
        return True

    def _is_compatible_versions(self,
                                primary_conn,
                                second_conn,
                                cluster_mapping):
        """ Validate cluster versions """
        service_primary = primary_conn.system_service().clusters_service()
        service_sec = second_conn.system_service().clusters_service()
        for cluster_map in cluster_mapping:
            search_prime = "name=%s" % cluster_map['primary_name']
            search_sec = "name=%s" % cluster_map['secondary_name']
            cluster_prime = service_primary.list(search=search_prime)[0]
            cluster_sec = service_sec.list(search=search_sec)[0]
            prime_ver = cluster_prime.version
            sec_ver = cluster_sec.version
            if (prime_ver.major != sec_ver.major
                    or prime_ver.minor != sec_ver.minor):
                print("%s%sClusters have incompatible versions. "
                      "primary setup ('%s' %s.%s) not equal to "
                      "secondary setup ('%s' %s.%s)%s"
                      % (FAIL,
                         PREFIX,
                         cluster_prime.name,
                         prime_ver.major,
                         prime_ver.minor,
                         cluster_sec.name,
                         sec_ver.major,
                         sec_ver.minor,
                         END))
                return False
        return True

    def _get_dups(self, var_file, mappings):
        duplicates = {}
        for mapping in mappings:
            _return_set = set()
            _mapping = var_file.get(mapping[1])
            if _mapping is None or len(_mapping) < 1:
                print("%s%smapping %s is empty in var file%s"
                      % (WARN, PREFIX, mapping[1], END))
                duplicates[mapping[0]] = _return_set
                continue
            _primary = set()
            _second = set()
            _return_set.update(
                set(x[mapping[2]]
                    for x in _mapping
                    if x[mapping[2]]
                    in _primary or _primary.add(x[mapping[2]])))
            _return_set.update(
                set(x[mapping[3]]
                    for x in _mapping
                    if x[mapping[3]]
                    in _second or _second.add(x[mapping[3]])))
            duplicates[mapping[0]] = _return_set
        return duplicates

    def _get_dup_network(self, var_file):
        _return_set = set()
        # TODO: Add data center also
        _mapping = var_file.get(self.network_map)
        if _mapping is None or len(_mapping) < 1:
            print("%s%sNetwork has not been initialized in var file%s"
                  % (WARN, PREFIX, END))
            return _return_set

        # Check for profile + network name duplicates in primary
        _primary1 = set()
        key1_a = 'primary_profile_name'
        key1_b = 'primary_network_name'
        key1_c = 'primary_network_dc'
        for x in _mapping:
            if x[key1_a] is None or x[key1_b] is None:
                print("%s%sNetwork '%s' is not initialized in map %s %s%s"
                      % (FAIL,
                         PREFIX,
                         x,
                         x[key1_a],
                         x[key1_b],
                         END))
                sys.exit()
            primary_dc_name = ''
            if key1_c in x:
                primary_dc_name = x[key1_c]
            map_key = x[key1_a] + "_" + x[key1_b] + "_" + primary_dc_name
            if map_key in _primary1:
                _return_set.add(map_key)
            else:
                _primary1.add(map_key)

        # Check for profile + network name duplicates in secondary
        _second1 = set()
        val1_a = 'secondary_profile_name'
        val1_b = 'secondary_network_name'
        val1_c = 'secondary_network_dc'
        for x in _mapping:
            if x[val1_a] is None or x[val1_b] is None:
                print("%s%sThe following network mapping is not "
                      "initialized in var file mapping:\n"
                      "  %s:'%s'\n  %s:'%s'%s"
                      % (FAIL,
                         PREFIX,
                         val1_a,
                         x[val1_a],
                         val1_b,
                         x[val1_b],
                         END))
                sys.exit()
            secondary_dc_name = ''
            if val1_c in x:
                secondary_dc_name = x[val1_c]
            map_key = x[val1_a] + "_" + x[val1_b] + "_" + secondary_dc_name
            if map_key in _second1:
                _return_set.add(map_key)
            else:
                _second1.add(map_key)

        return _return_set


class DefaultOption(dict):

    def __init__(self, config, section, **kv):
        self._config = config
        self._section = section
        dict.__init__(self, **kv)

    def items(self):
        _items = []
        for option in self:
            if not self._config.has_option(self._section, option):
                _items.append((option, self[option]))
            else:
                value_in_config = self._config.get(self._section, option)
                _items.append((option, value_in_config))
        return _items


class ConnectSDK:
    primary_url, primary_user, primary_ca = '', '', ''
    second_url, second_user, second_ca = '', '', ''
    prefix = ''
    error_msg = "%s%s The '%s' field in the %s setup is not " \
                "initialized in var file mapping.%s"

    def __init__(self, var_file, primary_pwd, second_pwd):
        """
        ---
        dr_sites_primary_url: http://xxx.xx.xx.xxx:8080/ovirt-engine/api
        dr_sites_primary_username: admin@internal
        dr_sites_primary_ca_file: /etc/pki/ovirt-engine/ca.pem

        # Please fill in the following properties for the secondary site:
        dr_sites_secondary_url: http://yyy.yy.yy.yyy:8080/ovirt-engine/api
        dr_sites_secondary_username: admin@internal
        dr_sites_secondary_ca_file: /etc/pki/ovirt-engine_secondary/ca.pem
        """
        self.primary_url = var_file.get('dr_sites_primary_url')
        self.primary_user = var_file.get('dr_sites_primary_username')
        self.primary_ca = var_file.get('dr_sites_primary_ca_file')
        self.second_url = var_file.get('dr_sites_secondary_url')
        self.second_user = var_file.get('dr_sites_secondary_username')
        self.second_ca = var_file.get('dr_sites_secondary_ca_file')
        self.primary_pwd = primary_pwd
        self.second_pwd = second_pwd

    def validate_primary(self):
        isValid = True
        if self.primary_url is None:
            print(self.error_msg % (
                  FAIL,
                  PREFIX,
                  "url",
                  "primary",
                  END))
            isValid = False
        if self.primary_user is None:
            print(self.error_msg % (
                  FAIL,
                  PREFIX,
                  "username",
                  "primary",
                  END))
            isValid = False
        if self.primary_ca is None:
            print(self.error_msg % (
                  FAIL,
                  PREFIX,
                  "ca",
                  "primary",
                  END))
            isValid = False
        return isValid

    def validate_secondary(self):
        isValid = True
        if self.second_url is None:
            print(self.error_msg % (
                  FAIL,
                  PREFIX,
                  "url",
                  "secondary",
                  END))
            isValid = False
        if self.second_user is None:
            print(self.error_msg % (
                  FAIL,
                  PREFIX,
                  "username",
                  "secondary",
                  END))
            isValid = False
        if self.second_ca is None:
            print(self.error_msg % (
                  FAIL,
                  PREFIX,
                  "ca",
                  "secondary",
                  END))
            isValid = False
        return isValid

    def _validate_connection(self, url, username, password, ca):
        conn = None
        try:
            conn = self._connect_sdk(url, username, password, ca)
            dcs_service = conn.system_service().data_centers_service()
            dcs_service.list()
        except Exception:
            print(
                "%s%sConnection to setup has failed."
                " Please check your credentials: "
                "\n%s URL: %s"
                "\n%s user: %s"
                "\n%s CA file: %s%s" %
                (FAIL,
                 PREFIX,
                 PREFIX,
                 url,
                 PREFIX,
                 username,
                 PREFIX,
                 ca,
                 END))
            if conn:
                conn.close()
            return None
        return conn

    def connect_primary(self):
        return self._validate_connection(self.primary_url,
                                         self.primary_user,
                                         self.primary_pwd,
                                         self.primary_ca)

    def connect_secondary(self):
        return self._validate_connection(self.second_url,
                                         self.second_user,
                                         self.second_pwd,
                                         self.second_ca)

    def _connect_sdk(self, url, username, password, ca):
        connection = sdk.Connection(
            url=url,
            username=username,
            password=password,
            ca_file=ca,
        )
        return connection


if __name__ == "__main__":
    ValidateMappingFile().run('dr.conf')
