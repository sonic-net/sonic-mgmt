oVirt Clusters
==============

The `clusters` role is used set up oVirt clusters.

Role Variables
--------------

| Name                  | Default value         |  Description                            |
|-----------------------|-----------------------|-----------------------------------------|
| clusters              | UNDEF                 | List of dictionaries that describe the cluster. |
| data_center_name      | UNDEF (Required)      | Name of the data center.                 |
| compatibility_version | UNDEF (Required)      | Compatibility version of data center.    |

The items in `clusters` list can contain the following parameters:

| Name                              | Default value       | Description                             |
|-----------------------------------|---------------------|-----------------------------------------|
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

More information about the parameters can be found in the [Ansible documentation](http://docs.ansible.com/ansible/ovirt_cluster_module.html).

Possible `profile` options are `development` and `production`, their default values are described below:

`Development`:

| Parameter        | Value         |
|------------------|---------------|
| ballooning       | true          |
| ksm              | true          |
| host_reason      | false         |
| vm_reason        | false         |
| memory_policy    | server        |
| migration_policy | post_copy     |

`Production`:

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

Example Playbook
----------------

```yaml
- name: oVirt clusters
  hosts: localhost
  connection: local
  gather_facts: false

  vars:
   data_center_name: mydatacenter
   compatibility_version: 4.4

   clusters:
     - name: production
       cpu_type: Intel Conroe Family
       profile: production
       mac_pool: production_mac_pools

  roles:
    - ovirt.ovirt.infra.roles.clusters
```
