#!/usr/bin/python3

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import sys
import getopt
import logging

import ovirtsdk4 as sdk
import ovirtsdk4.types as otypes

# TODO: log file location is currently in the same folder
logging.basicConfig(level=logging.DEBUG, filename='generator.log')


# Documentation: We only support attached storage domains in the var generator.
def main(argv):
    url, username, password, ca, file_ = _init_vars(argv)
    connection = _connect_sdk(url, username, password, ca, logging.getLogger())
    host_storages = _get_host_storages_for_external_lun_disks(connection)
    external_disks = _get_external_lun_disks(connection)
    affinity_labels = _get_affinity_labels(connection)
    domains = _get_aaa_domains(connection)
    networks = _get_vnic_profile_mapping(connection)

    f = open(file_, 'w')
    _write_file_header(f, url, username, ca)
    clusters, affinity_groups = _handle_dc_properties(f, connection)
    _write_clusters(f, clusters)
    _write_affinity_groups(f, affinity_groups)
    _write_affinity_labels(f, affinity_labels)
    _write_aaa_domains(f, domains)
    _write_roles(f)
    _write_vnic_profiles(f, networks)
    _write_external_lun_disks(f, external_disks, host_storages)
    connection.close()


def _init_vars(argv):
    url, username, password, ca, file_ = '', '', '', '', ''
    try:
        opts, args = getopt.getopt(
            argv,
            "a:u:p:f:c:", ["a=", "u=", "p=", "f=", "c="])
    except getopt.GetoptError:
        print(
            '''
            -a <http://127.0.0.1:8080/ovirt-engine/api>\n
            -u <admin@portal>\n
            -p <password>\n
            -c </etc/pki/ovirt-engine/ca.pem>\n
            -f <disaster_recovery_vars.yml>
            ''')
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print(
                '''
                generate_mapping.py
                -a <http://127.0.0.1:8080/ovirt-engine/api>\n
                -u <admin@portal>\n
                -p <password>\n
                -c </etc/pki/ovirt-engine/ca.pem>\n
                -f <disaster_recovery_vars.yml>
                ''')
            sys.exit()
        elif opt in ("-a", "--url"):
            url = arg
        elif opt in ("-u", "--username"):
            username = arg
        elif opt in ("-p", "--password"):
            password = arg
        elif opt in ("-c", "--ca"):
            ca = arg
        elif opt in ("-f", "--file"):
            file_ = arg
    return url, username, password, ca, file_


def _connect_sdk(url, username, password, ca, log_):
    connection = sdk.Connection(
        url=url,
        username=username,
        password=password,
        ca_file=ca,
        debug=True,
        log=log_,
    )
    return connection


def _write_file_header(f, url, username, ca):
    """
    Add header for paramter file, for example:
       dr_sites_primary_url: "http://engine1.redhat.com:8080/ovirt-engine/api"
       dr_sites_primary_username: "admin@internal"
       dr_sites_primary_ca_file: "ovirt-share/etc/pki/ovirt-engine/ca.pem"

       dr_sites_secondary_url:
       dr_sites_secondary_username:
       dr_sites_secondary_ca_file:
     """
    f.write("---\n")
    f.write("dr_sites_primary_url: %s\n" % url)
    f.write("dr_sites_primary_username: %s\n" % username)
    f.write("dr_sites_primary_ca_file: %s\n\n" % ca)

    f.write("# Please fill in the following properties "
            "for the secondary site: \n")
    f.write("dr_sites_secondary_url: # %s\n" % url)
    f.write("dr_sites_secondary_username: # %s\n" % username)
    f.write("dr_sites_secondary_ca_file: # %s\n\n" % ca)


def _handle_dc_properties(f, connection):
    f.write("dr_import_storages:\n")
    dcs_service = connection.system_service().data_centers_service()
    dcs_list = dcs_service.list()
    clusters = []
    affinity_groups = []
    for dc in dcs_list:
        dc_service = dcs_service.data_center_service(dc.id)
        _write_attached_storage_domains(f, dc_service, dc)
        _add_clusters_and_aff_groups_for_dc(dc_service,
                                            clusters,
                                            affinity_groups)
    return clusters, affinity_groups


def _get_host_storages_for_external_lun_disks(connection):
    host_storages = {}
    hosts_service = connection.system_service().hosts_service()
    hosts_list = hosts_service.list(search='status=up')

    # The reason we go over each active Host in the DC is that there might
    # be a Host which fail to connect to a certain device but still be active.
    for host in hosts_list:
        host_storages_service = hosts_service.host_service(host.id) \
            .storage_service().list()
        for host_storage in host_storages_service:
            if host_storage.id not in host_storages.keys():
                host_storages[host_storage.id] = host_storage
    return host_storages


def _get_external_lun_disks(connection):
    external_disks = []
    disks_service = connection.system_service().disks_service()
    disks_list = disks_service.list()
    for disk in disks_list:
        if otypes.DiskStorageType.LUN == disk.storage_type:
            external_disks.append(disk)
    return external_disks


def _get_affinity_labels(connection):
    affinity_labels = []
    affinity_labels_service = \
        connection.system_service().affinity_labels_service()
    affinity_labels_list = affinity_labels_service.list()
    for affinity_label in affinity_labels_list:
        affinity_labels.append(affinity_label.name)
    return affinity_labels


def _get_aaa_domains(connection):
    domains = []
    domains_service = connection.system_service().domains_service()
    domains_list = domains_service.list()
    for domain in domains_list:
        domains.append(domain.name)
    return domains


def _get_vnic_profile_mapping(connection):
    networks = []
    vnic_profiles_service = connection.system_service().vnic_profiles_service()
    vnic_profile_list = vnic_profiles_service.list()
    for vnic_profile_item in vnic_profile_list:
        mapped_network = {}
        networks_list = connection.system_service().networks_service().list()
        network_name = ''
        for network_item in networks_list:
            if network_item.id == vnic_profile_item.network.id:
                network_name = network_item.name
                dc_name = connection.system_service().data_centers_service(). \
                    data_center_service(network_item.data_center.id). \
                    get()._name
                break
        mapped_network['network_name'] = network_name
        mapped_network['network_dc'] = dc_name
        mapped_network['profile_name'] = vnic_profile_item.name
        mapped_network['profile_id'] = vnic_profile_item.id
        networks.append(mapped_network)
    return networks


def _add_clusters_and_aff_groups_for_dc(dc_service, clusters, affinity_groups):
    clusters_service = dc_service.clusters_service()
    attached_clusters_list = clusters_service.list()
    for cluster in attached_clusters_list:
        clusters.append(cluster.name)
        cluster_service = clusters_service.cluster_service(cluster.id)
        _add_affinity_groups_for_cluster(cluster_service, affinity_groups)


def _add_affinity_groups_for_cluster(cluster_service, affinity_groups):
    affinity_groups_service = cluster_service.affinity_groups_service()
    for affinity_group in affinity_groups_service.list():
        affinity_groups.append(affinity_group.name)


def _write_attached_storage_domains(f, dc_service, dc):
    """
    Add all the attached storage domains to the var file
    """
    # Locate the service that manages the storage domains that are attached
    # to the data centers:
    attached_sds_service = dc_service.storage_domains_service()
    attached_sds_list = attached_sds_service.list()
    for attached_sd in attached_sds_list:
        if attached_sd.name == 'hosted_storage':
            f.write("# Hosted storage should not be part of the "
                    "recovery process! Comment it out.\n")
            f.write("#- dr_domain_type: %s\n" % attached_sd.storage.type)
            f.write("#  dr_primary_name: %s\n" % attached_sd.name)
            f.write("#  dr_primary_dc_name: %s\n\n" % dc.name)
            continue

        if attached_sd.type == otypes.StorageDomainType.EXPORT:
            f.write("# Export storage domain should not be part of the "
                    "recovery process!\n")
            f.write("# Please note that a data center with an export "
                    "storage domain might reflect on the failback process.\n")
            f.write("#- dr_domain_type: %s\n" % attached_sd.storage.type)
            f.write("#  dr_primary_name: %s\n" % attached_sd.name)
            f.write("#  dr_primary_dc_name: %s\n\n" % dc.name)
            continue

        f.write("- dr_domain_type: %s\n" % attached_sd.storage.type)
        f.write("  dr_wipe_after_delete: %s\n" % attached_sd.wipe_after_delete)
        f.write("  dr_backup: %s\n" % attached_sd.backup)
        f.write("  dr_critical_space_action_blocker: %s\n"
                % attached_sd.critical_space_action_blocker)
        f.write("  dr_storage_domain_type: %s\n" % attached_sd.type)
        f.write("  dr_warning_low_space: %s\n"
                % attached_sd.warning_low_space_indicator)
        f.write("  dr_primary_name: %s\n" % attached_sd.name)
        f.write("  dr_primary_master_domain: %s\n" % attached_sd.master)
        f.write("  dr_primary_dc_name: %s\n" % dc.name)
        is_fcp = attached_sd._storage.type == otypes.StorageType.FCP
        is_scsi = attached_sd.storage.type == otypes.StorageType.ISCSI
        if not is_fcp and not is_scsi:
            f.write("  dr_primary_path: %s\n" % attached_sd.storage.path)
            f.write("  dr_primary_address: %s\n" % attached_sd.storage.address)
            if attached_sd._storage.type == otypes.StorageType.POSIXFS:
                f.write("  dr_primary_vfs_type: %s\n"
                        % attached_sd.storage.vfs_type)
            _add_secondary_mount(f, dc.name, attached_sd)
        else:
            f.write("  dr_discard_after_delete: %s\n"
                    % attached_sd.discard_after_delete)
            f.write("  dr_domain_id: %s\n" % attached_sd.id)
            if attached_sd._storage._type == otypes.StorageType.ISCSI:
                f.write("  dr_primary_address: %s\n" %
                        attached_sd.storage.volume_group
                        .logical_units[0].address)
                f.write("  dr_primary_port: %s\n" %
                        attached_sd.storage.volume_group.logical_units[0].port)
                targets = set(lun_unit.target for lun_unit in
                              attached_sd.storage.volume_group.logical_units)
                f.write("  dr_primary_target: [%s]\n" %
                        ','.join(['"' + target + '"' for target in targets]))
                _add_secondary_scsi(f, dc.name, attached_sd, targets)
            else:
                _add_secondary_fcp(f, dc.name, attached_sd)
        f.write("\n")


def _add_secondary_mount(f, dc_name, attached):
    f.write("  # Fill in the empty properties related to the secondary site\n")
    f.write("  dr_secondary_name: # %s\n" % attached.name)
    f.write("  dr_secondary_master_domain: # %s\n" % attached.master)
    f.write("  dr_secondary_dc_name: # %s\n" % dc_name)
    f.write("  dr_secondary_path: # %s\n" % attached.storage.path)
    f.write("  dr_secondary_address: # %s\n" % attached.storage.address)
    if attached._storage.type == otypes.StorageType.POSIXFS:
        f.write("  dr_secondary_vfs_type: # %s\n" % attached.storage.vfs_type)


def _add_secondary_scsi(f, dc_name, attached, targets):
    f.write("  # Fill in the empty properties related to the secondary site\n")
    f.write("  dr_secondary_name: # %s\n" % attached.name)
    f.write("  dr_secondary_master_domain: # %s\n" % attached.master)
    f.write("  dr_secondary_dc_name: # %s\n" % dc_name)
    f.write("  dr_secondary_address: # %s\n" % attached.storage.volume_group
            .logical_units[0].address)
    f.write("  dr_secondary_port: # %s\n" % attached.storage.volume_group
            .logical_units[0].port)
    f.write("  # target example: [\"target1\",\"target2\",\"target3\"]\n")
    f.write("  dr_secondary_target: # [%s]\n" %
            ','.join(['"' + target + '"' for target in targets]))


def _add_secondary_fcp(f, dc_name, attached):
    f.write("  # Fill in the empty properties related to the secondary site\n")
    f.write("  dr_secondary_name: # %s\n" % attached.name)
    f.write("  dr_secondary_master_domain: # %s\n" % attached.master)
    f.write("  dr_secondary_dc_name: # %s\n" % dc_name)


def _write_clusters(f, clusters):
    f.write("# Mapping for cluster\n")
    f.write("dr_cluster_mappings:\n")
    for cluster_name in clusters:
        f.write("- primary_name: %s\n" % cluster_name)
        f.write("  # Fill the correlated cluster name in the "
                "secondary site for cluster '%s'\n" % cluster_name)
        f.write("  secondary_name: # %s\n\n" % cluster_name)


def _write_affinity_groups(f, affinity_groups):
    f.write("\n# Mapping for affinity group\n")
    f.write("dr_affinity_group_mappings:\n")
    for affinity_group in affinity_groups:
        f.write("- primary_name: %s\n" % affinity_group)
        f.write("  # Fill the correlated affinity group name in the "
                "secondary site for affinity '%s'\n" % affinity_group)
        f.write("  secondary_name: # %s\n\n" % affinity_group)


def _write_affinity_labels(f, affinity_labels):
    f.write("\n# Mapping for affinity label\n")
    f.write("dr_affinity_label_mappings:\n")
    for affinity_label in affinity_labels:
        f.write("- primary_name: %s\n" % affinity_label)
        f.write("  # Fill the correlated affinity label name in the "
                "secondary site for affinity label '%s'\n" % affinity_label)
        f.write("  secondary_name: # %s\n\n" % affinity_label)


def _write_aaa_domains(f, domains):
    f.write("\n# Mapping for domain\n")
    f.write("dr_domain_mappings: \n")
    for domain in domains:
        f.write("- primary_name: %s\n" % domain)
        f.write("  # Fill in the correlated domain in the "
                "secondary site for domain '%s'\n" % domain)
        f.write("  secondary_name: # %s\n\n" % domain)


def _write_roles(f):
    f.write("\n# Mapping for role\n")
    f.write("# Fill in any roles which should be mapped between sites.\n")
    f.write("dr_role_mappings: \n")
    f.write("- primary_name: \n")
    f.write("  secondary_name: \n\n")


def _write_vnic_profiles(f, networks):
    f.write("dr_network_mappings:\n")
    for network in networks:
        f.write("- primary_network_name: %s\n" % network['network_name'])
        f.write("# Data Center name is relevant when multiple vnic profiles"
                " are maintained.\n")
        f.write("# please uncomment it in case you have more than one DC.\n")
        f.write("# primary_network_dc: %s\n" % network['network_dc'])
        f.write("  primary_profile_name: %s\n" % network['profile_name'])
        f.write("  primary_profile_id: %s\n" % network['profile_id'])
        f.write("  # Fill in the correlated vnic profile properties in the "
                "secondary site for profile '%s'\n" % network['profile_name'])
        f.write("  secondary_network_name: # %s\n" % network['network_name'])
        f.write("# Data Center name is relevant when multiple vnic profiles"
                " are maintained.\n")
        f.write("# please uncomment it in case you have more than one DC.\n")
        f.write("# secondary_network_dc: %s\n" % network['network_dc'])
        f.write("  secondary_profile_name: # %s\n" % network['profile_name'])
        f.write("  secondary_profile_id: # %s\n\n" % network['profile_id'])


def _write_external_lun_disks(f, external_disks, host_storages):
    f.write("\n# Mapping for external LUN disks\n")
    f.write("dr_lun_mappings:")
    for disk in external_disks:
        disk_id = disk.lun_storage.logical_units[0].id
        f.write("\n- logical_unit_alias: %s\n" % disk.alias)
        f.write("  logical_unit_description: %s\n" % disk.description)
        f.write("  wipe_after_delete: %s\n" % disk.wipe_after_delete)
        f.write("  shareable: %s\n" % disk.shareable)
        f.write("  primary_logical_unit_id: %s\n" % disk_id)
        disk_storage_type = ''
        if host_storages.get(disk_id) is not None:
            disk_storage_type = host_storages.get(disk_id).type
            disk_storage = host_storages.get(disk_id).logical_units[0]
            f.write("  primary_storage_type: %s\n" % disk_storage_type)
            if disk_storage_type == otypes.StorageType.ISCSI:
                portal = ''
                if disk_storage.portal is not None:
                    splitted = disk_storage.portal.split(',')
                    if len(splitted) > 0:
                        portal = splitted[1]
                f.write("  primary_logical_unit_address: %s\n"
                        "  primary_logical_unit_port: %s\n"
                        "  primary_logical_unit_portal: \"%s\"\n"
                        "  primary_logical_unit_target: %s\n"
                        % (disk_storage.address,
                           disk_storage.port,
                           portal,
                           disk_storage.target))
                if disk_storage.username is not None:
                    f.write("  primary_logical_unit_username: %s\n"
                            "  primary_logical_unit_password: "
                            "PLEASE_SET_PASSWORD_HERE\n"
                            % disk_storage.username)

        f.write("  # Fill in the following properties of the external LUN "
                "disk in the secondary site\n")
        f.write(
            "  secondary_storage_type: %s\n" % (
                disk_storage_type
                if disk_storage_type != ''
                else "STORAGE TYPE COULD NOT BE FETCHED!"
            )
        )
        f.write("  secondary_logical_unit_id: # %s\n" % disk_id)
        if disk_storage_type == otypes.StorageType.ISCSI:
            f.write("  secondary_logical_unit_address: # %s\n"
                    "  secondary_logical_unit_port: # %s\n"
                    "  secondary_logical_unit_portal: # \"%s\"\n"
                    "  secondary_logical_unit_target: # %s\n"
                    % (disk_storage.address,
                       disk_storage.port,
                       portal,
                       disk_storage.target))
            if disk_storage.username is not None:
                f.write("  secondary_logical_unit_username: # %s\n"
                        "  secondary_logical_unit_password:"
                        "PLEASE_SET_PASSWORD_HERE\n"
                        % disk_storage.username)


if __name__ == "__main__":
    main(sys.argv[1:])
