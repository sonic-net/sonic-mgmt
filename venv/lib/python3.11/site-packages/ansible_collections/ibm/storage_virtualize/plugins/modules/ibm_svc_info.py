#!/usr/bin/python
# Copyright (C) 2024 IBM CORPORATION
# Author(s): Peng Wang <wangpww@cn.ibm.com>
#            Sreshtant Bohidar <sreshtant.bohidar@ibm.com>
#            Sanjaikumaar M <sanjaikumaar.m@ibm.com>
#            Sumit Kumar Gupta <sumit.gupta16@ibm.com>
#            Sandip Gulab Rajbanshi <sandip.rajbanshi@ibm.com>
#            Rahul Pawar <rahul.p@ibm.com>
#            Lavanya C R <lavanya.c.r1@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_info
short_description: This module gathers various information from the IBM Storage Virtualize family systems
version_added: "1.0.0"
description:
- Gathers the list of specified IBM Storage Virtualize family system
  entities. These include the list of nodes, pools, volumes, hosts,
  host clusters, FC ports, iSCSI ports, target port FC, FC consistgrp,
  vdiskcopy, I/O groups, FC map, FC connectivity, NVMe fabric,
  array, and system.
author:
    - Peng Wang (@wangpww)
    - Sumit Kumar Gupta (@sumitguptaibm)
    - Sandip Gulab Rajbanshi (@Sandip-Rajbanshi)
    - Lavanya C R (@Lavanya-C-R1)
options:
  clustername:
    description:
    - The hostname or management IP of the
      Storage Virtualize system.
    type: str
    required: true
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
    - To generate a token, use the ibm_svc_auth module.
    type: str
    version_added: '1.5.0'
  log_path:
    description:
    - Path of debug log file.
    type: str
  validate_certs:
    description:
    - Validates certification.
    default: false
    type: bool
  objectname:
    description:
    - If specified, only the instance with the I(objectname) is returned. If not specified, all the instances are returned.
    - If I(objectname:"all") specified, display detailed output of all instances of all objects that are specified
      in gather_subset and command_list.
    - For entities that require objectname as a mandatory parameter, I(objectname:"all") will throw error.
    type: str
  filtervalue:
    description:
    - Specifies (key=value) combination that helps in returning a subset of objects satisfying the condition.
    type: str
  gather_subset:
    type: list
    elements: str
    description:
    - List of string variables to specify the Storage Virtualize entities
      for which information is required.
    - all - list of all Storage Virtualize entities
            supported by the module.
    - vol - lists information for VDisks.
    - pool - lists information for mdiskgrps.
    - node - lists information for nodes.
    - iog - lists information for I/O groups.
    - host - lists information for hosts.
    - hostvdiskmap - lists all VDisks mapped to host 'objectname'
    - vdiskhostmap - lists all hosts VDisk 'objectname' is mapped to
    - hc - lists information for host clusters.
    - fc - lists information for FC connectivity.
    - fcport - lists information for FC ports.
    - fabricport -  list the FDMI information that is discovered by the system.
    - targetportfc - lists information for WWPN which is required to set up
                     FC zoning and to display the current failover status
                     of host I/O ports.
    - fcmap - lists information for FC maps.
    - rcrelationship - lists information for remote copy relationships.
    - fcconsistgrp - displays a concise list or a detailed
                     view of flash copy consistency groups.
    - rcconsistgrp - displays a concise list or a detailed
                     view of remote copy consistency groups.
    - iscsiport - lists information for iSCSI ports.
    - vdiskcopy - lists information for volume copy.
    - array - lists information for array MDisks.
    - system - displays the storage system information.
    - cloudaccount - lists all the configured cloud accounts.
    - cloudaccountusage - lists the usage information about the configured cloud storage accounts.
    - cloudimportcandidate - lists information about systems that have data that is stored in the cloud accounts.
    - ldapserver - lists the most recent details for all configured Lightweight Directory Access Protocol (LDAP) servers.
    - drive - lists the configuration information and drive vital product data (VPD).
    - user - lists all the users that are created on the system.
    - usergroup - lists the user groups that is created on the system.
    - ownershipgroup - displays the ownership groups that are available in the system.
    - partnership - lists all the clustered systems (systems) that are associated with the local system.
    - replicationpolicy - lists all the replication policies on the system.
    - cloudbackup - lists the volumes that have cloud snapshot enabled and volumes that have cloud snapshots in the cloud account.
    - cloudbackupgeneration - lists any volume snapshots available on the specified volume. I(objectname) is a mandatory parameter.
    - snapshotpolicy - lists all the snapshot policies on the system.
    - snapshotpolicyschedule - lists all snapshot schedules on the system.
    - volumegroup - lists all volume groups on the system.
    - volumepopulation - list the population information about volumes of type clone or thinclone.
    - volumegrouppopulation - list the information about volume groups of type clone or thinclone.
    - volumegroupsnapshotpolicy - lists the snapshot policy attributes associated with a volume group on the system.
    - volumesnapshot - lists all volume snapshots.
    - dnsserver - lists the information for any Domain Name System (DNS) servers in the system.
    - systemcertificate - lists the information about the current system Secure Sockets Layer (SSL) certificate.
    - truststore - lists the current certificate stores.
    - sra - command to check both secure remote assistance status and the time of the last login.
    - syslogserver - lists the syslog servers that are configured on the clustered system.
    - emailserver - lists the email servers that are configured on the system.
    - emailuser - lists the Email event notification settings for all Email recipients,
                  an individual Email recipient, or a specified type (local or support) of an Email recipient.
    - provisioningpolicy - lists the provisioning policies available on the system.
    - volumegroupsnapshot - lists the snapshot objects available on the system.
    - callhome - displays the status of the Call Home information that is sent to a server in the Cloud.
    - ip - lists the currently configured IP addresses.
    - portset - lists the currently configured portset on the system.
    - safeguardedpolicy - lists the Safeguarded policies available on the system.
    - mdisk - displays a concise list or a detailed view of managed disks (MDisks) visible to the system.
    - safeguardedpolicyschedule - displays the Safeguarded backup schedule that is associated with Safeguarded policies.
    - eventlog - displays the concise view of system event log
    - enclosurestats - lists the most recent values (averaged) of all enclosure statistics.
    - enclosurestatshistory - lists the history values of all enclosure statistics including power consumed,
                              temperature in fahrenheit and temperature in celsius.
    - driveclass - lists all drive classes in the system
    - security - display the current system Secure Sockets Layer (SSL) or Transport Layer Security (TLS) security and
      password rules settings
    - partition - display all the storage partitions information related to storage.
    - volumegroupreplication - displays all the replication information for the volume group.
    - plugin - display the information of registered plugins.
    - quorum - display all the quorum devices that the system uses to store quorum data.
    - enclosure - displays a summary of the enclosures.
    - snmpserver -  display a concise list or a detailed view of SNMP servers that are configured on the system
    - testldapserver - tests a Lightweight Directory Access Protocol (LDAP) server.
    - availablepatch - display the patches that are compatible with the SVC version.
    - patch - displays a list of all the patches on a specific node.
    - systempatches - displays patches installed on all the nodes in the system.
    - flashgrid - displays the summarized view of flashsystem grid.
    - flashgridmembers - displays the summarized view of flashsystem grid members.
    - flashgridsystem - displays the information about all systems in the flashsystem grid.
    - flashgridpartition - displays the information about all partitions in the flashsystem grid.
    choices: [vol, pool, node, iog, host, hostvdiskmap, vdiskhostmap, hc, fcport
              , fabricport, iscsiport, fc, fcmap, fcconsistgrp, rcrelationship, rcconsistgrp
              , vdiskcopy, targetportfc, array, system, 'cloudaccount', 'cloudaccountusage',
               'ldapserver', 'drive', 'user', 'usergroup', 'ownershipgroup',
               'partnership', 'replicationpolicy', 'cloudbackup', 'enclosurestats',
               'cloudbackupgeneration', 'snapshotpolicy', 'snapshotpolicyschedule',
               'volumegroup', 'volumepopulation', 'volumegrouppopulation', 'volumegroupsnapshotpolicy', 'volumesnapshot',
               'dnsserver', 'systemcertificate', 'sra', 'syslogserver', 'enclosurestatshistory',
               'emailserver', 'emailuser', 'provisioningpolicy', 'volumegroupsnapshot',
               'truststore', 'callhome', 'ip', 'portset', 'safeguardedpolicy',
               'mdisk', 'safeguardedpolicyschedule', 'cloudimportcandidate', 'eventlog', 'driveclass', 'security', 'partition',
               'volumegroupreplication', 'plugin', 'quorum', 'enclosure', 'snmpserver', 'testldapserver', 'availablepatch',
               'patch', 'systempatches', 'flashgrid', 'flashgridmembers', 'flashgridsystem', 'flashgridpartition', all]
  command_list:
    type: list
    elements: str
    description:
    - Specify to get information regarding any Storage Virtualize entities other than choices of gather_subset.
    - Exact command has to be specified to use command_list (i.e. lssystemcert, lstimezones, lsportset etc.).
    - Output will be stored in this way (i.e. lssystemcert -> Systemcert, lstimezones -> Timezones etc.).
notes:
    - This module supports C(check_mode).
    - If both I(gather_subset) and I(command_list) are not specified, ibm_svc_info will list information about I(default) objects.
    - I(lsroute) and I(lsarraylba) commands are not covered.
'''

EXAMPLES = '''
- name: Get volume info
  ibm.storage_virtualize.ibm_svc_info:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/ansible.log
    gather_subset: vol
- name: Get volume info
  ibm.storage_virtualize.ibm_svc_info:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/ansible.log
    objectname: volumename
    gather_subset: vol
- name: Get pool info
  ibm.storage_virtualize.ibm_svc_info:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/ansible.log
    gather_subset: pool
- name: Get population information about volumes and volumegroups of type clone or thinclone
  ibm.storage_virtualize.ibm_svc_info:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/ansible.log
    gather_subset: ['volumepopulation', 'volumegrouppopulation']
- name: Get all info related to volume 'Volume1'
  ibm.storage_virtualize.ibm_svc_info:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/ansible.log
    gather_subset: vol
    objectname: Volume1
- name: Get detailed info of all volumes.
  ibm.storage_virtualize.ibm_svc_info:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/ansible.log
    gather_subset: vol
    objectname: all
- name: Get detailed info for objects returned by lsvdiskcopy using command_list.
  ibm.storage_virtualize.ibm_svc_info:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/ansible.log
    command_list: lsvdiskcopy
    objectname: all
- name: Get detailed info of multiple objects using gather_subset and command_list.
  ibm.storage_virtualize.ibm_svc_info:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/ansible.log
    gather_subset: [vol, host]
    command_list: [lsvdiskcopy, lssite]
    objectname: all
- name: Get list of candidate drives info using filtervale and gather_subset.
  ibm.storage_virtualize.ibm_svc_info:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/ansible.log
    gather_subset: drive
    filtervalue: "use=candidate"
- name: Get list of replication type portsets info using filtervalue and command_list.
  ibm.storage_virtualize.ibm_svc_info:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    log_path: /tmp/ansible.log
    command_list: lsportset
    filtervalue: "type=replication"
'''

RETURN = '''
Array:
    description:
        - Data will be populated when I(gather_subset=array) or I(gather_subset=all)
        - Lists information for array MDisks
    returned: success
    type: list
    elements: dict
    sample: [{...}]
CallHome:
    description:
        - Data will be populated when I(gather_subset=callhome) or I(gather_subset=all)
        - Displays the status of the Call Home information that is sent to a server in the Cloud
    returned: success
    type: list
    elements: dict
    sample: [{...}]
CloudAccount:
    description:
        - Data will be populated when I(gather_subset=cloudaccount) or I(gather_subset=all)
        - Lists all the configured cloud accounts
    returned: success
    type: list
    elements: dict
    sample: [{...}]
CloudAccountUsage:
    description:
        - Data will be populated when I(gather_subset=cloudaccountusage) or I(gather_subset=all)
        - Lists the usage information about the configured cloud storage accounts
    returned: success
    type: list
    elements: dict
    sample: [{...}]
CloudBackup:
    description:
        - Data will be populated when I(gather_subset=cloudbackup) or I(gather_subset=all)
        - Lists the volumes that have cloud snapshot that enabled and volumes that have cloud snapshots in the cloud account
    returned: success
    type: list
    elements: dict
    sample: [{...}]
CloudBackupGeneration:
    description:
        - Data will be populated when I(gather_subset=cloudbackupgeneration)
        - List any volume snapshots available on the specified volume
    returned: success
    type: list
    elements: dict
    sample: [{...}]
CloudImportCandidate:
    description:
        - Data will be populated when I(gather_subset=cloudimportcandidate) or I(gather_subset=all)
        - Lists information about systems that have data that is stored in the cloud accounts
    returned: success
    type: list
    elements: dict
    sample: [{...}]
DnsServer:
    description:
        - Data will be populated when I(gather_subset=dnsserver) or I(gather_subset=all)
        - Lists the information for any Domain Name System (DNS) servers in the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Drive:
    description:
        - Data will be populated when I(gather_subset=drive) or I(gather_subset=all)
        - Lists the configuration information and drive vital product data (VPD)
    returned: success
    type: list
    elements: dict
    sample: [{...}]
EmailServer:
    description:
        - Data will be populated when I(gather_subset=emailserver) or I(gather_subset=all)
        - Lists the Email servers that are configured on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
EmailUser:
    description:
        - Data will be populated when I(gather_subset=emailuser) or I(gather_subset=all)
        - Lists the Email event notification settings for all Email recipients,
          an individual Email recipient, or a specified type (local or support) of Email recipient
    returned: success
    type: list
    elements: dict
    sample: [{...}]
FCConnectivity:
    description:
        - Data will be populated when I(gather_subset=fc) or I(gather_subset=all)
        - Lists information for FC connectivity
    returned: success
    type: list
    elements: dict
    sample: [{...}]
FCConsistgrp:
    description:
        - Data will be populated when I(gather_subset=fcconsistgrp) or I(gather_subset=all)
        - Displays a concise list or a detailed view of flash copy consistency groups
    returned: success
    type: list
    elements: dict
    sample: [{...}]
FCMap:
    description:
        - Data will be populated when I(gather_subset=fcmap) or I(gather_subset=all)
        - Lists information for FC maps
    returned: success
    type: list
    elements: dict
    sample: [{...}]
FCPort:
    description:
        - Data will be populated when I(gather_subset=fcport) or I(gather_subset=all)
        - Lists information for FC ports
    returned: success
    type: list
    elements: dict
    sample: [{...}]
FabricPort:
    description:
        - Data will be populated when I(gather_subset=fabricport) or I(gather_subset=all)
        - List the FDMI information that is discovered by the system.
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Host:
    description:
        - Data will be populated when I(gather_subset=host) or I(gather_subset=all)
        - Lists information for hosts
    returned: success
    type: list
    elements: dict
    sample: [{...}]
HostCluster:
    description:
        - Data will be populated when I(gather_subset=hc) or I(gather_subset=all)
        - Lists information for host clusters
    returned: success
    type: list
    elements: dict
    sample: [{...}]
HostVdiskMap:
    description:
        - Data will be populated when I(gather_subset=hostvdiskmap) or I(gather_subset=all)
        - Lists all VDisks mapped to host 'objectname'
    returned: success
    type: list
    elements: dict
    sample: [{...}]
IOGroup:
    description:
        - Data will be populated when I(gather_subset=iog) or I(gather_subset=all)
        - Lists information for I/O groups
    returned: success
    type: list
    elements: dict
    sample: [{...}]
IP:
    description:
        - Data will be populated when I(gather_subset=ip) or I(gather_subset=all)
        - Lists the currently configured IP addresses
    returned: success
    type: list
    elements: dict
    sample: [{...}]
LdapServer:
    description:
        - Data will be populated when I(gather_subset=ldapserver) or I(gather_subset=all)
        - Lists the most recent details for all configured Lightweight Directory Access Protocol (LDAP) servers
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Mdisk:
    description:
        - Data will be populated when I(gather_subset=mdisk) or I(gather_subset=all)
        - Displays a concise list or a detailed view of managed disks (MDisks) visible to the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Node:
    description:
        - Data will be populated when I(gather_subset=node) or I(gather_subset=all)
        - Lists information for nodes
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Ownershipgroup:
    description:
        - Data will be populated when I(gather_subset=ownershipgroup) or I(gather_subset=all)
        - Displays the ownership groups that are available in the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Partnership:
    description:
        - Data will be populated when I(gather_subset=partnership) or I(gather_subset=all)
        - Lists all the clustered systems (systems) that are associated with the local system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Pool:
    description:
        - Data will be populated when I(gather_subset=pool) or I(gather_subset=all)
        - Lists information for mdiskgrps
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Portset:
    description:
        - Data will be populated when I(gather_subset=portset) or I(gather_subset=all)
        - Lists the currently configured portset on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
ProvisioningPolicy:
    description:
        - Data will be populated when I(gather_subset=provisioningpolicy) or I(gather_subset=all)
        - Lists the provisioning policies available on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
RCConsistgrp:
    description:
        - Data will be populated when I(gather_subset=rcconsistgrp) or I(gather_subset=all)
        - Displays a concise list or a detailed view of remote copy consistency groups
    returned: success
    type: list
    elements: dict
    sample: [{...}]
RemoteCopy:
    description:
        - Data will be populated when I(gather_subset=rcrelationship) or I(gather_subset=all)
        - Lists information for remote copy relationships
    returned: success
    type: list
    elements: dict
    sample: [{...}]
ReplicationPolicy:
    description:
        - Data will be populated when I(gather_subset=replicationpolicy) or I(gather_subset=all)
        - Lists all the replication policies on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
SafeguardedPolicy:
    description:
        - Data will be populated when I(gather_subset=safeguardedpolicy) or I(gather_subset=all)
        - Lists the Safeguarded policies available on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
SafeguardedSchedule:
    description:
        - Data will be populated when I(gather_subset=safeguardedpolicyschedule) or I(gather_subset=all)
        - Displays the Safeguarded backup schedule that is associated with Safeguarded policies
    returned: success
    type: list
    elements: dict
    sample: [{...}]
SnapshotPolicy:
    description:
        - Data will be populated when I(gather_subset=snapshotpolicy) or I(gather_subset=all)
        - Lists all the snapshot policies on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
SnapshotSchedule:
    description:
        - Data will be populated when I(gather_subset=snapshotpolicyschedule) or I(gather_subset=all)
        - Lists all snapshot schedules on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Sra:
    description:
        - Data will be populated when I(gather_subset=sra) or I(gather_subset=all)
        - Command to check both secure remote assistance status and the time of the last login
    returned: success
    type: list
    elements: dict
    sample: [{...}]
SysLogServer:
    description:
        - Data will be populated when I(gather_subset=syslogserver) or I(gather_subset=all)
        - Lists the syslog servers that are configured on the clustered system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
System:
    description:
        - Data will be populated when I(gather_subset=system) or I(gather_subset=all)
        - Displays the storage system information
    returned: success
    type: list
    elements: dict
    sample: [{...}]
SystemCert:
    description:
        - Data will be populated when I(gather_subset=systemcertificate) or I(gather_subset=all)
        - Lists the information about the current system Secure Sockets Layer (SSL) certificate
    returned: success
    type: list
    elements: dict
    sample: [{...}]
TargetPortFC:
    description:
        - Data will be populated when I(gather_subset=targetportfc) or I(gather_subset=all)
        - Lists information for WWPN which is required to set up FC zoning and to display
          the current failover status of host I/O ports
    returned: success
    type: list
    elements: dict
    sample: [{...}]
TrustStore:
    description:
        - Data will be populated when I(gather_subset=truststore) or I(gather_subset=all)
        - Lists the current certificate stores
    returned: success
    type: list
    elements: dict
    sample: [{...}]
User:
    description:
        - Data will be populated when I(gather_subset=user) or I(gather_subset=all)
        - Lists all the users that are created on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
UserGrp:
    description:
        - Data will be populated when I(gather_subset=usergroup) or I(gather_subset=all)
        - Lists the user groups that is created on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
VdiskCopy:
    description:
        - Data will be populated when I(gather_subset=vdiskcopy) or I(gather_subset=all)
        - Lists information for volume copy
    returned: success
    type: list
    elements: dict
    sample: [{...}]
VdiskHostMap:
    description:
        - Data will be populated when I(gather_subset=vdiskhostmap) or I(gather_subset=all)
        - Lists all hosts the VDisk 'objectname' is mapped to
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Volume:
    description:
        - Data will be populated when I(gather_subset=vol) or I(gather_subset=all)
        - Lists information for VDisks
    returned: success
    type: list
    elements: dict
    sample: [{...}]
VolumeGroup:
    description:
        - Data will be populated when I(gather_subset=volumegroup) or I(gather_subset=all)
        - Lists all volume groups on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
VolumePopulation:
    description:
        - Data will be populated when I(gather_subset=volumepopulation) or I(gather_subset=all)
        - Lists information about volumes of type clone or thinclone
    returned: success
    type: list
    elements: dict
    sample: [{...}]
VolumeGroupPopulation:
    description:
        - Data will be populated when I(gather_subset=volumegrouppopulation) or I(gather_subset=all)
        - Lists information about volume groups of type clone or thinclone including source and in-progress restore
    returned: success
    type: list
    elements: dict
    sample: [{...}]
VolumeGroupSnapshot:
    description:
        - Data will be populated when I(gather_subset=volumegroupsnapshot) or I(gather_subset=all)
        - Lists the snapshot objects available on the system based on volume group
    returned: success
    type: list
    elements: dict
    sample: [{...}]
VolumeGroupSnapshotPolicy:
    description:
        - Data will be populated when I(gather_subset=volumegroupsnapshotpolicy) or I(gather_subset=all)
        - Lists view snapshot objects on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
VolumeSnapshot:
    description:
        - Data will be populated when I(gather_subset=volumesnapshot) or I(gather_subset=all)
        - Lists all volume snapshots
    returned: success
    type: list
    elements: dict
    sample: [{...}]
iSCSIPort:
    description:
        - Data will be populated when I(gather_subset=iscsiport) or I(gather_subset=all)
        - Lists information for iSCSI ports
    returned: success
    type: list
    elements: dict
    sample: [{...}]
EventLog:
    description:
        - Data will be populated when I(gather_subset=eventlog) or I(gather_subset=all)
        - Lists information about the system event log
    returned: success
    type: list
    elements: dict
    sample: [{...}]
EnclosureStats:
    description:
        - Data will be populated when I(gather_subset=enclosurestats) or I(gather_subset=all)
        - Lists the most recent values (averaged) of all enclosure statistics.
    returned: success
    type: list
    elements: dict
    sample: [{...}]
EnclosureStatsHistory:
    description:
        - Data will be populated when I(gather_subset=enclosurestatshistory) or I(gather_subset=all)
        - Lists the history values of all enclosure statistics including power consumed,
          temperature in fahrenheit and temperature in celsius.
    returned: success
    type: list
    elements: dict
    sample: [{...}]
DriveClass:
    description:
        - Data will be populated when I(gather_subset=driveclass) or I(gather_subset=all)
        - List all drive classes in the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Security:
    description:
        - Data will be populated when I(gather_subset=security) or I(gather_subset=all)
        - Displays current security settings of the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Partition:
    description:
        - Data will be populated when I(gather_subset=partition) or I(gather_subset=all)
        - Displays all storage partitions
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Plugin:
    description:
        - Data will be populated when I(gather_subset=plugin) or I(gather_subset=all)
        - Displays all registered plugins
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Volumegroupreplication:
    description:
        - Data will be populated when I(gather_subset=volumegroupreplication) or I(gather_subset=all)
        - Displays all replication for the volumegroup
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Quorum:
    description:
        - Data will be populated when I(gather_subset=quorum) or I(gather_subset=all)
        - list the quorum devices that the system uses to store quorum data.
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Enclosure:
    description:
        - Data will be populated when I(gather_subset=enclosure) or I(gather_subset=all)
        - Displays a summary of the enclosures.
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Snmpserver:
    description:
        - Data will be populated when I(gather_subset=snmpserver) or I(gather_subset=all)
        - Display a concise list or a detailed view of SNMP servers that are configured on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Testldapserver:
    description:
        - Data will be populated when I(gather_subset=testldapserver)
        - Tests a Lightweight Directory Access Protocol (LDAP) server.
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Availablepatch:
    description:
        - Data will be populated when I(gather_subset=availablepatch) or I(gather_subset=all)
        - Display the patches that are compatible with the SVC version on the users system.
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Patch:
    description:
        - Data will be populated when I(gather_subset=patch) or I(gather_subset=all)
        - Displays a list of all the patches on a specific node in the system.
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Systempatches:
    description:
        - Data will be populated when I(gather_subset=systempatches) or I(gather_subset=all)
        - Displays patches installed on all the nodes in the system
    returned: success
    type: list
    elements: dict
FlashsystemGrid:
    description:
        - Data will be populated when I(gather_subset=flashgrid) or I(gather_subset=all)
        - Displays summarized view of flashsystem grid.
    returned: success
    type: list
    elements: dict
FlashsystemGridMembers:
    description:
        - Data will be populated when I(gather_subset=flashgridmembers) or I(gather_subset=all)
        - Displays summarized view of flashsystem grid members.
    returned: success
    type: list
    elements: dict
FlashsystemGridSystem:
    description:
        - Data will be populated when I(gather_subset=flashgridsystem) or I(gather_subset=all)
        - Displays the information about all systems in the flashsystem grid.
    returned: success
    type: list
    elements: dict
FlashsystemGridPartition:
    description:
        - Data will be populated when I(gather_subset=flashgridpartition) or I(gather_subset=all)
        - Displays the information about all partitions in the flashsystem grid.
    returned: success
    type: list
    elements: dict
'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils._text import to_native


class IBMSVCGatherInfo(object):
    def __init__(self):
        argument_spec = svc_argument_spec()

        argument_spec.update(
            dict(
                objectname=dict(type='str'),
                filtervalue=dict(type='str'),
                gather_subset=dict(type='list', elements='str', required=False,
                                   choices=['vol',
                                            'pool',
                                            'node',
                                            'iog',
                                            'host',
                                            'hostvdiskmap',
                                            'vdiskhostmap',
                                            'hc',
                                            'fc',
                                            'fcport',
                                            'fabricport',
                                            'targetportfc',
                                            'iscsiport',
                                            'fcmap',
                                            'rcrelationship',
                                            'fcconsistgrp',
                                            'rcconsistgrp',
                                            'vdiskcopy',
                                            'array',
                                            'system',
                                            'cloudaccount',
                                            'cloudaccountusage',
                                            'cloudimportcandidate',
                                            'ldapserver',
                                            'drive',
                                            'user',
                                            'usergroup',
                                            'ownershipgroup',
                                            'partnership',
                                            'replicationpolicy',
                                            'cloudbackup',
                                            'cloudbackupgeneration',
                                            'snapshotpolicy',
                                            'snapshotpolicyschedule',
                                            'volumegroup',
                                            'volumepopulation',
                                            'volumegrouppopulation',
                                            'volumegroupsnapshotpolicy',
                                            'volumesnapshot',
                                            'dnsserver',
                                            'systemcertificate',
                                            'truststore',
                                            'sra',
                                            'syslogserver',
                                            'emailserver',
                                            'emailuser',
                                            'provisioningpolicy',
                                            'volumegroupsnapshot',
                                            'callhome',
                                            'ip',
                                            'portset',
                                            'safeguardedpolicy',
                                            'mdisk',
                                            'safeguardedpolicyschedule',
                                            'eventlog',
                                            'enclosurestats',
                                            'enclosurestatshistory',
                                            'driveclass',
                                            'security',
                                            'partition',
                                            'plugin',
                                            'volumegroupreplication',
                                            'quorum',
                                            'enclosure',
                                            'snmpserver',
                                            'testldapserver',
                                            'availablepatch',
                                            'patch',
                                            'systempatches',
                                            'flashgrid',
                                            'flashgridmembers',
                                            'flashgridsystem',
                                            'flashgridpartition',
                                            'all'
                                            ]),
                command_list=dict(type='list', elements='str', required=False)
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # logging setup
        log_path = self.module.params['log_path']
        self.log = get_logger(self.__class__.__name__, log_path)
        self.subset = self.module.params['gather_subset']
        self.objectname = self.module.params['objectname']
        self.filtervalue = self.module.params['filtervalue']
        self.command_list = self.module.params['command_list']

        self.basic_checks()

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
        if self.command_list == ["all"]:
            self.module.fail_json(msg="command_list parameter cannot be specified as 'all'")
        if self.subset == ["all"] and self.objectname == "all":
            self.module.fail_json(msg="gather_subset and objectname both cannot be specified as 'all' at the same time.")
        if not self.subset and not self.command_list and self.objectname:
            self.module.fail_json(msg="objectname(%s) is specified while gather_subset or command_list is not "
                                  "specified" % (self.objectname))
        if self.filtervalue:
            if (self.subset and self.command_list) or (not self.subset and not self.command_list):
                self.module.fail_json(msg="filtervalue must be accompanied with a single object either in gather_subset or command_list")
            elif self.subset:
                if len(self.subset) != 1:
                    self.module.fail_json(msg="filtervalue must be accompanied with a single object either in gather_subset or command_list")
                elif self.subset[0] == "all":
                    self.module.fail_json(msg="filtervalue is not supported when gather_subset is specified as 'all'")
            elif self.command_list:
                if len(self.command_list) != 1:
                    self.module.fail_json(msg="filtervalue must be accompanied with a single object either in gather_subset or command_list")

    def validate(self, subset):
        if not self.objectname:
            self.module.fail_json(msg='Following parameter is mandatory to execute {0}: objectname'.format(subset))
        if self.objectname == "all":
            self.module.fail_json(msg="Objectname specified as 'all' which is invalid for the gather_subset [%s]" % subset)

    @property
    def cloudbackupgeneration(self):
        return self.restapi.svc_obj_info(
            cmd='lsvolumebackupgeneration',
            cmdopts={'volume': self.objectname},
            cmdargs=None
        )

    @property
    def enclosurestatshistory(self):
        return self.restapi.svc_obj_info(
            cmd='lsenclosurestats',
            cmdopts={'history': 'power_w:temp_c:temp_f'},
            cmdargs=[self.objectname]
        )

    def filter_value_out(self, cmd, cmdargs):
        op_key = self.restapi.svc_obj_info(
            cmd=cmd,
            cmdopts={'filtervalue': self.filtervalue},
            cmdargs=cmdargs
        )
        return op_key

    def get_list(self, subset, op_key, cmd, validate):
        try:
            svc_obj_out = None
            output = {}
            if validate is True:
                self.validate(subset)
            elif validate == "check":
                svc_obj_out = self.restapi.svc_obj_info(cmd=cmd,
                                                        cmdopts=None,
                                                        cmdargs=None)
                if not svc_obj_out:
                    output[op_key] = None
                    return output
                if "CMMVC5707E" in str(svc_obj_out):
                    self.module.fail_json(msg="CMMVC5707E Required parameters for command [%s] are missing or "
                                          "specified parameters are invalid" % cmd)
                elif "CMMVC5767E" in str(svc_obj_out):
                    self.module.fail_json(msg="CMMVC5767E One or more of the parameters specified are invalid or "
                                          "a parameter is missing for commamd [%s]." % cmd)
                elif svc_obj_out == 404 or "CMMVC7205E" in str(svc_obj_out):
                    self.module.fail_json(msg="Command [%s] not found or "
                                          "CMMVC7205E command [%s] is not supported on current svc version." % cmd)
                '''
                Handle these errors internally
                error-codes:
                    CMMVC5707E - Required parameters are missing.
                    CMMVC5767E - One or more of the parameters specified are invalid or a parameter is missing.
                    CMMVC7205E - The command failed because it is not supported.
                '''
            exceptions = {'cloudbackupgeneration', 'enclosurestatshistory'}
            if subset in exceptions:
                output[op_key] = getattr(self, subset)
            else:
                cmdargs = None
                op_key_list = []
                if self.objectname:
                    if self.filtervalue:
                        output[op_key] = self.filter_value_out(cmd, [self.objectname])
                        return output
                    if self.objectname == "all":
                        if cmd == "lsdumps":
                            all_node_info = self.restapi.svc_obj_info(cmd="lsnodecanister",
                                                                      cmdopts=None,
                                                                      cmdargs=None)
                            for node in all_node_info:
                                op_key_list.append(self.restapi.svc_obj_info(cmd=cmd,
                                                                             cmdopts=None,
                                                                             cmdargs=[node["id"]]))
                            output[op_key] = op_key_list
                            return output
                        elif cmd == "lscurrentuser":
                            output[op_key] = svc_obj_out
                            return output
                        else:
                            if svc_obj_out:
                                get_all_objects = svc_obj_out
                            else:
                                get_all_objects = self.restapi.svc_obj_info(cmd=cmd,
                                                                            cmdopts=None,
                                                                            cmdargs=None)
                            try:
                                id_name = str(list(get_all_objects[0])[0])
                                '''
                                To get name of 1st column of svc_obj_info output which contain objectname i.e. id/name,
                                generally 1st column is id
                                '''
                            except Exception as e:
                                id_name = None
                            if id_name:
                                list_object = []  # Getting all ID's in list_object
                                for obj in get_all_objects:
                                    list_object.append(obj[id_name])
                                if len(list_object) == len(set(list_object)):  # Those commands in which all ids are unique (ex. lsmdisk, lsvdisk etc)
                                    cnt = 0
                                    for object_id in list_object:
                                        op_key_list.append(self.restapi.svc_obj_info(cmd=cmd,
                                                                                     cmdopts=None,
                                                                                     cmdargs=[object_id]))
                                        if cnt == 0:
                                            cnt += 1
                                            '''
                                            Checking in first iteration only,
                                            whether id can be specifed with command or not (lscommand <id>)
                                            '''
                                            first_object = op_key_list[0]
                                            if not first_object:
                                                output[op_key] = get_all_objects
                                                '''
                                                If output is None (i.e. lscommand <id> is invalid), return concise output,
                                                No need to iterate over loop (ex. lscompatibilitymode, lscopystatus,
                                                lsfcmapcandidate, lsfcportcandidate, lsfeature, lsiogrpcandidate,
                                                lsrcrelationshipcandidate, lssite, lssystemlimits,  lstimezones,
                                                lsvdiskanalysisprogress etc.)
                                                '''
                                                return output
                                            elif len(get_all_objects[0]) == len(first_object):
                                                output[op_key] = get_all_objects
                                                '''
                                                If output is equal to concise output, then break the loop and return concise output,
                                                further iteration not required (ex. lsfcportsetmember, lsportset,
                                                lsprovisioningpolicy, lsquorum, lssystemsupportcenter, lstargetportfc,
                                                lstruststore, lsusergrp, lsvolumegrouppopulation, lsvolumegroupsnapshotpolicy,
                                                lsvolumegroupsnapshotschedule etc.)
                                                '''
                                                return output

                                    output[op_key] = op_key_list
                                else:
                                    output[op_key] = get_all_objects
                                    '''
                                    When multiple objects have same id, return concise output.
                                    (ex. lsarraymember, lsarraymembergoals, lsenclosurecanister, lsenclosurefanmodule,
                                    lsenclosurepsu, lsenclosureslot, lsenclosurestats, lsfabric, lsnodestats, lsportethernet,
                                    lsportip, lssnapshotschedule, lsvdiskaccess, lsvolumesnapshot etc.)
                                    '''
                                    return output
                            else:
                                output[op_key] = get_all_objects
                                '''
                                In few cases id is not mentioned or id is invalid with command lscommand <id>.
                                (ex. lsauthmultifactorduo, lsauthmultifactorverify, lsauthsinglesignon, lscloudcallhome,
                                lsencryption, lskeyserverisklm, lsldap, lslicense, lsnodestatus, lsproxy, lssecurity, lssra,
                                lssystem, lssystemcert, lssystemethernet, lsflashgrid, lsflashgridmembers etc.)
                                '''
                                return output
                    else:
                        output[op_key] = self.restapi.svc_obj_info(cmd=cmd,
                                                                   cmdopts=None,
                                                                   cmdargs=[self.objectname])
                        return output
                else:
                    if self.filtervalue:
                        output[op_key] = self.filter_value_out(cmd, None)
                        return output
                    output[op_key] = self.restapi.svc_obj_info(cmd=cmd,
                                                               cmdopts=None,
                                                               cmdargs=cmdargs)
                    return output
            self.log.info('Successfully listed %d %s info '
                          'from cluster %s', len(subset), subset,
                          self.module.params['clustername'])
            return output
        except Exception as e:
            msg = 'Getting %s info from cluster %s failed with error %s ' % \
                  (subset, self.module.params['clustername'], str(e))
            self.log.error(msg)
            self.module.fail_json(msg=msg)

    def apply(self):
        subset = self.subset
        command_list = self.command_list
        if command_list:
            if subset:
                subset += command_list
            else:
                subset = command_list
        if not subset:
            subset = ['all']
        if len(subset) == 0 or 'all' in subset:
            self.log.info("The default value for gather_subset is all")

        result = {
            'Volume': [],
            'Pool': [],
            'Node': [],
            'IOGroup': [],
            'Host': [],
            'HostVdiskMap': [],
            'VdiskHostMap': [],
            'HostCluster': [],
            'FCConnectivity': [],
            'FCConsistgrp': [],
            'RCConsistgrp': [],
            'VdiskCopy': [],
            'FCPort': [],
            'FabricPort': [],
            'TargetPortFC': [],
            'iSCSIPort': [],
            'FCMap': [],
            'RemoteCopy': [],
            'Array': [],
            'System': [],
            'CloudAccount': [],
            'CloudAccountUsage': [],
            'CloudImportCandidate': [],
            'LdapServer': [],
            'Drive': [],
            'User': [],
            'Partnership': [],
            'ReplicationPolicy': [],
            'SnapshotPolicy': [],
            'VolumeGroup': [],
            'VolumePopulation': [],
            'VolumeGroupPopulation': [],
            'SnapshotSchedule': [],
            'VolumeGroupSnapshotPolicy': [],
            'VolumeSnapshot': [],
            'DnsServer': [],
            'SystemCert': [],
            'TrustStore': [],
            'Sra': [],
            'SysLogServer': [],
            'UserGrp': [],
            'EmailServer': [],
            'EmailUser': [],
            'CloudBackup': [],
            'CloudBackupGeneration': [],
            'ProvisioningPolicy': [],
            'VolumeGroupSnapshot': [],
            'CallHome': [],
            'IP': [],
            'Ownershipgroup': [],
            'Portset': [],
            'SafeguardedPolicy': [],
            'Mdisk': [],
            'SafeguardedSchedule': [],
            'EventLog': [],
            'DriveClass': [],
            'Security': [],
            'Partition': [],
            'Plugin': [],
            'Volumegroupreplication': [],
            'Quorum': [],
            'Enclosure': [],
            'Snmpserver': [],
            'Testldapserver': [],
            'Availablepatch': [],
            'Patch': [],
            'FlashsystemGrid': [],
            'FlashsystemGridMembers': [],
            'FlashsystemGridSystem': [],
            'FlashsystemGridPartition': [],
            'Systempatches': []
        }

        cmd_mappings = {
            'vol': ('Volume', 'lsvdisk', False, None),
            'pool': ('Pool', 'lsmdiskgrp', False, None),
            'node': ('Node', 'lsnode', False, None),
            'iog': ('IOGroup', 'lsiogrp', False, None),
            'host': ('Host', 'lshost', False, None),
            'hostvdiskmap': ('HostVdiskMap', 'lshostvdiskmap', False, None),
            'vdiskhostmap': ('VdiskHostMap', 'lsvdiskhostmap', True, None),
            'hc': ('HostCluster', 'lshostcluster', False, '7.7.1.0'),
            'fc': ('FCConnectivity', 'lsfabric', False, None),
            'fcport': ('FCPort', 'lsportfc', False, None),
            'fabricport': ('FabricPort', 'lsfabricport', False, '8.6.0.0'),
            'iscsiport': ('iSCSIPort', 'lsportip', False, None),
            'fcmap': ('FCMap', 'lsfcmap', False, None),
            'rcrelationship': ('RemoteCopy', 'lsrcrelationship', False, None),
            'fcconsistgrp': ('FCConsistgrp', 'lsfcconsistgrp', False, None),
            'rcconsistgrp': ('RCConsistgrp', 'lsrcconsistgrp', False, None),
            'vdiskcopy': ('VdiskCopy', 'lsvdiskcopy', False, None),
            'targetportfc': ('TargetPortFC', 'lstargetportfc', False, '7.7.0.0'),
            'array': ('Array', 'lsarray', False, None),
            'system': ('System', 'lssystem', False, '6.3.0.0'),
            'cloudaccount': ('CloudAccount', 'lscloudaccount', False, '7.8.0.0'),
            'cloudaccountusage': ('CloudAccountUsage', 'lscloudaccountusage', False, '7.8.0.0'),
            'cloudimportcandidate': ('CloudImportCandidate', 'lscloudaccountimportcandidate', False, '7.8.0.0'),
            'ldapserver': ('LdapServer', 'lsldapserver', False, '6.3.0.0'),
            'drive': ('Drive', 'lsdrive', False, None),
            'user': ('User', 'lsuser', False, None),
            'usergroup': ('UserGrp', 'lsusergrp', False, None),
            'ownershipgroup': ('Ownershipgroup', 'lsownershipgroup', False, '8.3.0.0'),
            'partnership': ('Partnership', 'lspartnership', False, '6.3.0.0'),
            'replicationpolicy': ('ReplicationPolicy', 'lsreplicationpolicy', False, '8.5.2.0'),
            'cloudbackup': ('CloudBackup', 'lsvolumebackup', False, '7.8.0.0'),
            'cloudbackupgeneration': ('CloudBackupGeneration', 'lsvolumebackupgeneration', True, '7.8.0.0'),
            'snapshotpolicy': ('SnapshotPolicy', 'lssnapshotpolicy', False, '8.5.1.0'),
            'snapshotpolicyschedule': ('SnapshotSchedule', 'lssnapshotschedule', False, '8.5.1.0'),
            'volumegroup': ('VolumeGroup', 'lsvolumegroup', False, '7.8.0.0'),
            'volumepopulation': ('VolumePopulation', 'lsvolumepopulation', False, '8.5.1.0'),
            'volumegrouppopulation': ('VolumeGroupPopulation', 'lsvolumegrouppopulation', False, '8.5.1.0'),
            'volumegroupsnapshotpolicy': ('VolumeGroupSnapshotPolicy', 'lsvolumegroupsnapshotpolicy', False, '8.5.1.0'),
            'volumesnapshot': ('VolumeSnapshot', 'lsvolumesnapshot', False, '8.5.1.0'),
            'dnsserver': ('DnsServer', 'lsdnsserver', False, '7.8.0.0'),
            'systemcertificate': ('SystemCert', 'lssystemcert', False, '7.6.0.0'),
            'truststore': ('TrustStore', 'lstruststore', False, '8.5.1.0'),
            'sra': ('Sra', 'lssra', False, '7.7.0.0'),
            'syslogserver': ('SysLogServer', 'lssyslogserver', False, None),
            'emailserver': ('EmailServer', 'lsemailserver', False, None),
            'emailuser': ('EmailUser', 'lsemailuser', False, None),
            'provisioningpolicy': ('ProvisioningPolicy', 'lsprovisioningpolicy', False, '8.4.1.0'),
            'volumegroupsnapshot': ('VolumeGroupSnapshot', 'lsvolumegroupsnapshot', False, '8.5.1.0'),
            'callhome': ('CallHome', 'lscloudcallhome', False, '8.2.1.0'),
            'ip': ('IP', 'lsip', False, '8.4.2.0'),
            'portset': ('Portset', 'lsportset', False, '8.4.2.0'),
            'safeguardedpolicy': ('SafeguardedPolicy', 'lssafeguardedpolicy', False, '8.4.2.0'),
            'mdisk': ('Mdisk', 'lsmdisk', False, None),
            'safeguardedpolicyschedule': ('SafeguardedSchedule', 'lssafeguardedschedule', False, '8.4.2.0'),
            'eventlog': ('EventLog', 'lseventlog', False, None),
            'enclosurestats': ('EnclosureStats', 'lsenclosurestats', False, None),
            'enclosurestatshistory': ('EnclosureStatsHistory', 'lsenclosurestats -history power_w:temp_c:temp_f', True, None),
            'driveclass': ('DriveClass', 'lsdriveclass', False, '7.6.0.0'),
            'security': ('Security', 'lssecurity', False, '7.4.0.0'),
            'partition': ('Partition', 'lspartition', False, '8.6.1.0'),
            'plugin': ('Plugin', 'lsplugin', False, '8.6.0.0'),
            'volumegroupreplication': ('Volumegroupreplication', 'lsvolumegroupreplication', False, '8.5.2.0'),
            'quorum': ('Quorum', 'lsquorum', False, None),
            'enclosure': ('Enclosure', 'lsenclosure', False, None),
            'snmpserver': ('Snmpserver', 'lssnmpserver', False, None),
            'testldapserver': ('Testldapserver', 'testldapserver', False, '6.3.0.0'),
            'availablepatch': ('Availablepatch', 'lsavailablepatch', False, '8.7.0.0'),
            'patch': ('Patch', 'lspatch', False, '8.5.4.0'),
            'systempatches': ('Systempatches', 'lssystempatches', False, '8.5.4.0'),
            'flashgrid': ('FlashsystemGrid', 'lsflashgrid', False, '8.7.1.0'),
            'flashgridmembers': ('FlashsystemGridMembers', 'lsflashgridmembers', False, '8.7.2.0'),
            'flashgridsystem': ('FlashsystemGridSystem', 'lsflashgridsystem', False, '8.7.3.0'),
            'flashgridpartition': ('FlashsystemGridPartition', 'lsflashgridpartition', False, '8.7.2.0')
        }
        if command_list:
            for cmd in command_list:
                if cmd[:2] == "ls":
                    op_key = cmd[2:].capitalize()
                else:
                    op_key = cmd.capitalize()
                cmd_mappings[cmd] = (op_key, cmd, "check")

        if subset == ['all']:
            current_set = cmd_mappings.keys()
        else:
            current_set = subset
        build_version = ''
        for key in current_set:
            value_tuple = cmd_mappings[key]
            if subset == ['all']:
                version = value_tuple[3]
                if value_tuple[2]:
                    continue
                elif not version:
                    pass
                else:
                    if build_version == '':
                        system_info = self.restapi.svc_obj_info(cmd='lssystem', cmdargs=[], cmdopts=None)
                        build_version = (system_info['code_level'].split(" ")[0]).split(".")
                    version = value_tuple[3].split('.')
                    flag = True
                    for idx in range(4):
                        if int(version[idx]) > int(build_version[idx]):
                            flag = False
                        elif int(version[idx]) < int(build_version[idx]):
                            break
                    if not flag:
                        continue
            op = self.get_list(key, *value_tuple[:3])
            result.update(op)

        self.module.exit_json(**result)


def main():
    v = IBMSVCGatherInfo()
    try:
        v.apply()
    except Exception as e:
        v.log.debug("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
