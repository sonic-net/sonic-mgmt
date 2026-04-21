oVirt Infra
===========

The `infra` role enables you to set up oVirt infrastructure including: mac pools, data centers, clusters, networks, hosts, users, and groups.

Target machine
--------------
In case you use this role to do user management, it will use `ovirt-aaa-jdbc-tool`, which is located on engine machine,
so you must execute the role on engine machine.


Role Variables
--------------

### Datacenter
To setup/cleanup datacenter you can use following variables:

| Name                     | Default value         | Description                          |
|--------------------------|-----------------------|--------------------------------------|
| data_center_name         | UNDEF                 | Name of the data center.              |
| data_center_description  | UNDEF                 | Description of the data center.       |
| data_center_local        | false                 | Specify whether the data center is shared or local. |
| compatibility_version    | UNDEF                 | Compatibility version of data center. |
| data_center_state        | present               | Specify whether the datacenter should be present or absent. |
| recursive_cleanup        | false                 | Specify whether to recursively remove all entities inside DC. Valid only when state == absent. |
| format_storages          | false                 | Specify whether to format ALL the storages that are going to be removed as part of the DC. Valid only when data_center_state == absent and recursive_cleanup == true. |

### MAC pools
To setup MAC pools you can define list variable called `mac_pools`.
The items in `mac_pools` list variable can contain the following parameters:

| Name                      | Default value         | Description                                                       |
|---------------------------|-----------------------|-------------------------------------------------------------------|
| mac_pool_name             | UNDEF                 | Name of the the MAC pool to manage.                               |
| mac_pool_ranges           | UNDEF                 | List of MAC ranges. The from and to should be splitted by comma. For example: 00:1a:4a:16:01:51,00:1a:4a:16:01:61 |
| mac_pool_allow_duplicates | UNDEF                 | If (true) allow a MAC address to be used multiple times in a pool. Default value is set by oVirt engine to false. |

### Clusters
To setup clusters you can define list variable called `clusters`.
The items in `clusters` list variable can contain the following parameters:

| Name                              | Default value       | Description                              |
|-----------------------------------|---------------------|------------------------------------------|
| name                              | UNDEF (Required)    | Name of the cluster.                     |
| state                             | present             | State of the cluster.                    |
| cpu_type                          | Intel Conroe Family | CPU type of the cluster.                 |
| profile                           | UNDEF               | The cluster profile. You can choose a predefined cluster profile, see the tables below. |
| ballooning                        | UNDEF               | If True enable memory balloon optimization. Memory balloon is used to re-distribute / reclaim the host memory based on VM needs in a dynamic way. |
| description                       | UNDEF               | Description of the cluster. |
| ksm                               | UNDEF               | I True MoM enables to run Kernel Same-page Merging KSM when necessary and when it can yield a memory saving benefit that outweighs its CPU cost. |
| ksm_numa                          | UNDEF               | If True enables KSM ksm for best berformance inside NUMA nodes. |
| vm_reason                         | UNDEF               | If True enable an optional reason field when a virtual machine is shut down from the Manager, allowing the administrator to provide an explanation for the maintenance. |
| host_reason                       | UNDEF               | If True enable an optional reason field when a host is placed into maintenance mode from the Manager, allowing the administrator to provide an explanation for the maintenance. |
| memory_policy<br/>alias: <i>performance_preset</i>                     | UNDEF               | <ul><li>disabled - Disables memory page sharing.</li><li>server - Sets the memory page sharing threshold to 150% of the system memory on each host.</li><li>desktop - Sets the memory page sharing threshold to 200% of the system memory on each host.</li></ul> |
| migration_policy                  | UNDEF               | A migration policy defines the conditions for live migrating virtual machines in the event of host failure. Following policies are supported:<ul><li>legacy - Legacy behavior of 3.6 version.</li><li>minimal_downtime - Virtual machines should not experience any significant downtime.</li><li>suspend_workload - Virtual machines may experience a more significant downtime.</li><li>post_copy - Virtual machines should not experience any significant downtime. If the VM migration is not converging for a long time, the migration will be switched to post-copy</li></ul> |
| scheduling_policy                 | UNDEF               | The scheduling policy used by the cluster. |
| ha_reservation                    | UNDEF               | If True enable the oVirt/RHV to monitor cluster capacity for highly available virtual machines. |
| fence_enabled                     | UNDEF               | If True, enables fencing on the cluster. |
| fence_connectivity_threshold | UNDEF          | The threshold used by <i>fence_skip_if_connectivity_broken</i>. |
| fence_skip_if_connectivity_broken | UNDEF               | If True, fencing will be temporarily disabled if the percentage of hosts in the cluster that are experiencing connectivity issues is greater than or equal to the defined threshold. |
| fence_skip_if_sd_active           | UNDEF               | If True, any hosts in the cluster that are Non Responsive and still connected to storage will not be fenced. |
| mac_pool                          | UNDEF               | Mac pool name. |
| comment               | UNDEF                 | Comment of the cluster. |
| migration_bandwidth          | UNDEF          | The bandwidth settings define the maximum bandwidth of both outgoing and incoming migrations per host.<br/>Following bandwidth options are supported:<br/><ul><li>auto - Bandwidth is copied from the rate limit [Mbps] setting in the data center host network QoS.</li><li>hypervisor_default - Bandwidth is controlled by local VDSM setting on sending host.</li><li>custom - Defined by user (in Mbps).</li></ul> |
| migration_bandwidth_limit    | UNDEF          | Set the custom migration bandwidth limit. |
| network             | UNDEF                   | Management network of cluster to access cluster hosts. |
| resilience_policy   | UNDEF                   | The resilience policy defines how the virtual machines are prioritized in the migration.<br/>Following values are supported:<br/><ul><li>do_not_migrate - Prevents virtual machines from being migrated.</li><li>migrate - Migrates all virtual machines in order of their defined priority.</li><li>migrate_highly_available - Migrates only highly available virtual machines to prevent overloading other hosts.</li></ul> |
| rng_sources         | UNDEF                   | List that specify the random number generator devices that all hosts in the cluster will use. Supported generators are: <i>hwrng</i> and <i>random</i>. |
| serial_policy       | UNDEF                   | Specify a serial number policy for the virtual machines in the cluster.<br/>Following options are supported:<br/><ul><li>vm - Sets the virtual machine's UUID as its serial number.</li><li>host - Sets the host's UUID as the virtual machine's serial number.</li><li>custom - Allows you to specify a custom serial number in serial_policy_value.</li></ul> |
| serial_policy_value | UNDEF                   | Allows you to specify a custom serial number. This parameter is used only when <i>serial_policy</i> is custom. |
| spice_proxy         | UNDEF                   | The proxy by which the SPICE client will connect to virtual machines. The address must be in the following format: protocol://[host]:[port] |
| switch_type         | UNDEF                   | Type of switch to be used by all networks in given cluster. Either legacy which is using linux brigde or ovs using Open vSwitch. |
| threads_as_cores    | UNDEF                   | If True the exposed host threads would be treated as cores which can be utilized by virtual machines. |
| trusted_service     | UNDEF                   | If True enable integration with an OpenAttestation server.|
| virt                | UNDEF                   | If True, hosts in this cluster will be used to run virtual machines. Default is true. |
| gluster                      | UNDEF          | If True, hosts in this cluster will be used as Gluster Storage server nodes, and not for running virtual machines. |
| external_network_providers   | UNDEF          |  List that specify the external network providers available in the cluster. |

More information about the parameters can be found in the [ovirt_cluster](http://docs.ansible.com/ansible/ovirt_cluster_module.html) module documentation.

#### Cluster Profile
Possible `profile` options of cluster are `development` and `production`, their default values are described below:

##### Development
The `development` profile of the cluster have predefined following vaules:

| Parameter        | Value         |
|------------------|---------------|
| ballooning       | true          |
| ksm              | true          |
| host_reason      | false         |
| vm_reason        | false         |
| memory_policy    | server        |
| migration_policy | post_copy     |

##### Production
The `production` profile of the cluster have predefined following vaules:

| Parameter                         | Value              |
|-----------------------------------|--------------------|
| ballooning                        | false              |
| ksm                               | false              |
| host_reason                       | true               |
| vm_reason                         | true               |
| memory_policy                     | disabled           |
| migration_policy                  | suspend_workload   |
| scheduling_policy                 | evenly_distributed |
| ha_reservation                    | true               |
| fence_enabled                     | true               |
| fence_skip_if_connectivity_broken | true               |
| fence_skip_if_sd_active           | true               |

### Hosts
To setup hosts you can define list variable called `hosts`.
The items in `hosts` list variable can contain the following parameters:

| Name          | Default value    | Description                           |
|---------------|------------------|---------------------------------------|
| name          | UNDEF (Required) | Name of the host.                      |
| state         | present          | Specifies whether the host is `present` or `absent`.  |
| address       | UNDEF            | IP address or FQDN of the host.   |
| password      | UNDEF            | The host's root password. Required if <i>public_key</i> is false. |
| public_key    | UNDEF            | If <i>true</i> the public key should be used to authenticate to host. |
| cluster       | UNDEF (Required) | The cluster that the host must connect to.    |
| timeout       | 1800             | Maximum wait time for the host to be in an UP state.  |
| poll_interval | 20               | Polling interval to check the host status. |
| hosted_engine | UNDEF            | Specifies if the host is 'deploy' as hosted engine. |
| power_management | UNDEF            | The power managment. You can choose a predefined variables, see the tables below. |

In case you cannot use `hosts` variable for whatever reason in your playbook, you can change this variable's name
by overriding value of `hosts_var_name` variable. Example:
```yaml
- name: Set up oVirt infrastructure
  hosts: engine

  roles:
    - role: ovirt.ovirt.infra
      vars:
        hosts_var_name: ovirt_hosts
        ovirt_hosts:
          - name: host_0
            state: present
            address: 1.2.3.4
            password: 123456
            cluster: Default
```

##### Host power managment
The `power_management` have predefined following vaules:

| Name          | Default value    | Description                           |
|---------------|------------------|---------------------------------------|
| address       | UNDEF            | Address of the power management interface. |
| state         | present          | Should the host power managment be present/absent.  |
| username      | UNDEF            | Username to be used to connect to power management interface.      |
| password      | UNDEF            | Password of the user specified in C(username) parameter. |
| type          | UNDEF            | Type of the power management. oVirt/RHV predefined values are drac5, ipmilan, rsa, bladecenter, alom, apc, apc_snmp, eps, wti, rsb, cisco_ucs, drac7, hpblade, ilo, ilo2, ilo3, ilo4, ilo_ssh, but user can have defined custom type. |
| options       | UNDEF            | Dictionary of additional fence agent options (including Power Management slot). Additional information about options can be found at https://github.com/ClusterLabs/fence-agents/blob/master/doc/FenceAgentAPI.md. |
| port          | UNDEF            | Power management interface port. |

### Networks

##### Logical networks
To setup logical networks you can define list variable called `logical_networks`.
The `logical_networks` list can contain following parameters:

| Name          | Default value  | Description                           |
|---------------|----------------|---------------------------------------|
| name          | UNDEF          | Name of the network.                   |
| state         | present        | Specifies whether the network state is `present` or `absent`. |
| vlan_tag      | UNDEF          | Specify VLAN tag.                |
| vm_network    | True           | If True network will be marked as network for VM.             |
| mtu           | UNDEF          | Maximum transmission unit (MTU) of the network.    |
| description   | UNDEF          | Description of the network.  |
| clusters      | UNDEF          | List of dictionaries describing how the network is managed in specific cluster. |
| external_provider      | UNDEF          | Name of external network provider. At first it tries to import the network when not found it will create network in external provider. |
| label         | UNDEF          | Name of the label to assign to the network. |

More information about the parameters can be found in the [ovirt_network](http://docs.ansible.com/ansible/ovirt_network_module.html) module documentation.

##### Host networks
To setup host networks you can define list variable called `host_networks`.
The `host_networks` list can contain following parameters:

| Name          | Default value  | Description                           |
|---------------|----------------|---------------------------------------|
| name          | UNDEF          | Name of the host.                      |
| state         | UNDEF          | Specifies whether the network state is `present` or `absent`.            |
| check         | UNDEF          | If true, verifies the connection between the host and engine. |
| save          | UNDEF          | If true, the network configuration will be persistent, by default it is temporary. |
| bond          | UNDEF          | Dictionary describing the network bond. |
| networks      | UNDEF          | Dictionary describing the networks to be attached to the interface or bond. |
| labels        | UNDEF          | List of names of the network label to be assigned to the bond or interface. |
| interface     | UNDEF          | Name of the network interface where the logical network should be attached. |

More information about the parameters can be found in the [ovirt_host_network](http://docs.ansible.com/ansible/ovirt_host_network_module.html) module documentation.

### Storages
To setup storages you can define dictionary variable called `storages`.
In case of more than one connection, the storage connection update of this domain will be skipped.
The value of item in `storages` dictionary can contain following parameters (the key is always a name of the storage):

| Name            | Default value  | Description                           |
|-----------------|----------------|---------------------------------------|
| master          | false          | If true, the storage will be added as the first storage, meaning it will be the master storage. |
| domain_function | data           | The function of the storage domain. Possible values are: <ul><li>iso</li><li>export</li><li>data</li></ul>. |
| localfs         | UNDEF          | Dictionary defining local storage. |
| nfs             | UNDEF          | Dictionary defining NFS storage. |
| iscsi           | UNDEF          | Dictionary defining iSCSI storage. |
| posixfs         | UNDEF          | Dictionary defining PosixFS storage. |
| fcp             | UNDEF          | Dictionary defining FCP storage. |
| glusterfs       | UNDEF          | Dictionary defining glusterFS storage. |
| discard_after_delete  | UNDEF    | If True storage domain blocks will be discarded upon deletion. Enabled by default. This parameter is relevant only for block based storage domains. |

More information about the parameters can be found in the [ovirt_storage_domain](http://docs.ansible.com/ansible/ovirt_storage_domain_module.html) module documentation.

### AAA JDBC
##### Users
To setup users in AAA JDBC provider you can define dictionary variable called `users`.
The items in `users` list can contain the following parameters:

| Name          | Default value  | Description                           |
|---------------|----------------|---------------------------------------|
| state         | present        | Specifies whether the user is `present` or `absent`. |
| name          | UNDEF          | Name of the user.                      |
| authz_name    | UNDEF          | Authorization provider of the user.    |
| password      | UNDEF          | Password of the user.                  |
| valid_to      | UNDEF          | Specifies the date that the account remains valid. |
| attributes    | UNDEF          | A dict of attributes related to the user. Available attributes: <ul><li>department</li><li>description</li><li>displayName</li><li>email</li><li>firstName</li><li>lasName</li><li>title</li></ul>|

##### User groups
To setup user groups in AAA JDBC provider you can define dictionary variable called `user_groups`.
The items in `user_groups` list can contain the following parameters:

| Name          | Default value  | Description                           |
|---------------|----------------|---------------------------------------|
| state         | present        | Specifies whether the group is `present` or `absent`. |
| name          | UNDEF          | Name of the group.                     |
| authz_name    | UNDEF          | Authorization provider of the group.   |
| users         | UNDEF          | List of users that belong to this group. |

### Permissions
To setup permissions of users or groups you can define dictionary variable called `permissions`.
The items in `permissions` list variable can contain following parameters:

| Name          | Default value  | Description                |
|---------------|----------------|----------------------------|
| state         | present        | Specifies whether the state of the permission is `present` or `absent`.    |
| user_name     | UNDEF          | The user to manage the permission for. |
| group_name    | UNDEF          | Name of the group to manage the permission for. |
| authz_name    | UNDEF          | Name of the authorization provider of the group or user. |
| role          | UNDEF          | The role to be assigned to the user or group. |
| object_type   | UNDEF          | The object type which should be used to assign the permission. Possible object types are:<ul><li>data_center</li><li>cluster</li><li>host</li><li>storage_domain</li><li>network</li><li>disk</li><li>vm</li><li>vm_pool</li><li>template</li><li>cpu_profile</li><li>disk_profile</li><li>vnic_profile</li><li>system</li></ul> |
| object_name   | UNDEF          | Name of the object where the permission should be assigned. |

### External providers
To setup external providers you can define dictionary variable called `external_providers`.
The items in `external_providers` list variable can contain following parameters:

| Name                   | Default value       | Description                                                                      |
|------------------------|---------------------|----------------------------------------------------------------------------------|
| name                   | UNDEF (Required)    | Name of the external provider.                                                   |
| state                  | present             | State of the external provider. Values can be: <ul><li>present</li><li>absent</li></ul>|
| type                   | UNDEF (Required)    | Type of the external provider. Values can be: <ul><li>os_image</li><li>network</li><li>os_volume</li><li>foreman</li></ul>|
| url                    | UNDEF               | URL where external provider is hosted. Required if state is present.            |
| username               | UNDEF               | Username to be used for login to external provider. Applicable for all types.   |
| password               | UNDEF               | Password of the user specified in username parameter. Applicable for all types. |
| tenant                 | UNDEF               | Name of the tenant. |
| auth_url               | UNDEF               | Keystone authentication URL of the openstack provider. Required for: <ul><li>os_image</li><li>network</li><li>os_volume</li></ul>|
| data_center            | UNDEF               | Name of the data center where provider should be attached. Applicable for type <i>os_volume</i>. |
| authentication_keys    | UNDEF               | List of authentication keys. Each key is represented by dict like {'uuid': 'my-uuid', 'value': 'secret value'}. Added in ansible 2.6.  Applicable for type <i>os_volume</i>. |

More information about the parameters can be found in the [ovirt_external_provider](http://docs.ansible.com/ansible/ovirt_external_provider_module.html) module documentation.

Example Playbook
----------------

```yaml
---
- name: oVirt infra
  hosts: localhost
  connection: local
  gather_facts: false

  vars:
     engine_fqdn: ovirt-engine.example.com
     engine_user: admin@internal
     engine_password: 123456
     engine_cafile: /etc/pki/ovirt-engine/ca.pem
     data_center_name: mydatacenter
     compatibility_version: 4.4

     mac_pools:
      - mac_pool_name: "Default"
        mac_pool_ranges:
          - "00:1a:4a:16:01:51,00:1a:4a:16:01:61"

     clusters:
      - name: production
        cpu_type: Intel Conroe Family
        profile: production

     hosts:
      - name: myhost
        address: 1.2.3.4
        cluster: production
        password: 123456
      - name: myhost1
        address: 5.6.7.8
        cluster: production
        password: 123456
        power_management:
          address: 9.8.7.6
          username: root
          password: password
          type: ipmilan
          options:
            myoption1: x
            myoption2: y
            slot: myslot

     storages:
       mynfsstorage:
         master: true
         state: present
         nfs:
           address: 10.11.12.13
           path: /the_path
       myiscsistorage:
         state: present
         iscsi:
           target: iqn.2014-07.org.ovirt:storage
           port: 3260
           address: 100.101.102.103
           username: username
           password: password
           lun_id: 3600140551fcc8348ea74a99b6760fbb4
       mytemplates:
         domain_function: export
         nfs:
           address: 100.101.102.104
           path: /exports/nfs/exported
       myisostorage:
         domain_function: iso
         nfs:
           address: 100.101.102.105
           path: /exports/nfs/iso

     logical_networks:
       - name: mynetwork
         clusters:
           - name: production
             assigned: yes
             required: no
             display: no
             migration: yes
             gluster: no

     host_networks:
       - name: myhost1
         check: true
         save: true
         bond:
           name: bond0
           mode: 2
           interfaces:
             - eth2
             - eth3
         networks:
           - name: mynetwork
             boot_protocol: dhcp

     users:
      - name: john.doe
        authz_name: internal-authz
        password: 123456
        valid_to: "2018-01-01 00:00:00Z"
      - name: joe.doe
        authz_name: internal-authz
        password: 123456
        valid_to: "2018-01-01 00:00:00Z"

     user_groups:
      - name: admins
        authz_name: internal-authz
        users:
         - john.doe
         - joe.doe

     permissions:
      - state: present
        user_name: john.doe
        authz_name: internal-authz
        role: UserROle
        object_type: cluster
        object_name: production

      - state: present
        group_name: admins
        authz_name: internal-authz
        role: UserVmManager
        object_type: cluster
        object_name: production

     external_providers:
       - name: myglance
         type: os_image
         state: present
         url: http://externalprovider.example.com:9292
         username: admin
         password: secret
         tenant: admin
         auth_url: http://externalprovider.example.com:35357/v2.0/

  pre_tasks:
    - name: Login to oVirt
      ovirt_auth:
        hostname: "{{ engine_fqdn }}"
        username: "{{ engine_user }}"
        password: "{{ engine_password }}"
        ca_file: "{{ engine_cafile | default(omit) }}"
        insecure: "{{ engine_insecure | default(true) }}"
      tags:
        - always

  roles:
    - ovirt.ovirt.infra

  post_tasks:
    - name: Logout from oVirt
      ovirt_auth:
        state: absent
        ovirt_auth: "{{ ovirt_auth }}"
      tags:
        - always
```

[![asciicast](https://asciinema.org/a/112415.png)](https://asciinema.org/a/112415)
