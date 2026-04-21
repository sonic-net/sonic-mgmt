<a id="readme-top"></a>

# iSCSI Host-Attached Volume Migration

## Table of Contents
- [Objective](#objective)
- [Prerequisites](#prerequisites)
- [Tasks Performed](#tasks-performed)
- [Playbooks Overview](#playbooks-overview)
- [Variables](#variables)

## Objective
Migrate volumes from one Flashsystem to another Flashsystem in application-transparent manner, with target host as iSCSI.


## Prerequisites
- IBM Storage Virtualize ansible collection plugins must be installed.

## Tasks Performed
- Migrate a volume from a source IBM FlashSystem cluster to a destination FlashSystem cluster.
- Support both Fibre Channel (FC) or iSCSI host-mapped volumes on the source cluster.
- Map the migrated volume to an iSCSI host on the destination cluster.


## Playbooks Overview
### 1. initiate_migration_for_given_volume.yml:
   - This playbook initiates the migration.
   - Most importantly, it also starts data copy from source cluster to destination cluster.

### 2. create_iscsi_host_map_vol_switch.yml:
   - Execute this playbook only once the relationship created by above playbook is in `consistent_syncronized` state.
   - Create an iSCSI host on flashsystem from iqn defined in variable application_host_iqn from `vol_migration_vars.txt` file.
   - Configuring ip on each node for iSCSI host connectivity.
   - Establish iSCSI session from host to flashsystem nodes.
   - Maps the volume to the Host and starts scsi rescan on the host.
   - Switch replication direction of a migration relationship once host is mapped.
   - Again rescan the volume on the host to get the updated path details.
   - Deletes the original source volume and relationship.
   - Final rescan to confirm only paths from the destination cluster are active.

> [!IMPORTANT]
> Do **not** execute `create_iscsi_host_map_vol_switch.yml` until the volume relationship is in the **consistent_synchronized** state.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Variables
### These variables should be defined in your vol_migration_vars.txt file,


| Variable                         | Description                                                                                 |
|----------------------------------|---------------------------------------------------------------------------------------------|
| `src_cluster_name`              | Name of the source cluster.                                |
| `src_cluster_ip`                | IP address of the source cluster.                                                |
| `src_cluster_username`          | Username for the source cluster.                                               |
| `src_cluster_password`          | Password for the source cluster.                                                       |
| `dest_cluster_name`             | Name of the destination cluster.                          |
| `dest_cluster_ip`               | IP address of the destination cluster.                                           |
| `dest_cluster_username`         | Username for the destination cluster.                                          |
| `dest_cluster_password`         | Password for the destination cluster.                                                  |
| `dest_cluster_pool_name`        | Name of the pool where the destination volume will be created.          |
| `application_host_ip`           | IP address of the application host.              |
| `application_host_username`     | Username for accessing the application host.                                            |
| `application_host_iqn`          | iSCSI Qualified Name (IQN) of the application host (used to identify the iSCSI initiator).  |
| `application_iscsi_ip[x].node_name`     | Name of the FlashSystem node on which IP will be configured.                      |
| `application_iscsi_ip[x].portset`       | Portset to be used for iSCSI configuration on the node.                            |
| `application_iscsi_ip[x].ip_address`    | IP address to configure on the node for iSCSI connectivity.                        |
| `application_iscsi_ip[x].subnet_prefix` | Subnet prefix (e.g., 24 for `255.255.255.0`) for the iSCSI IP.                     |
| `application_iscsi_ip[x].gateway`       | Gateway IP address for the iSCSI network.                                           |
| `application_iscsi_ip[x].port`          | Port number (e.g., `6`) on the node to assign the IP to.                            |
| `src_vol_name`                 | Name of the volume on the source cluster to be migrated.                                           |
| `dest_vol_name`                | Name of the volume to be created on the destination cluster.                          |
| `host_name`                    | Hostname used for creating the host object on the destination cluster. |
| `rel_name`                     | Name of the relationship to be created between source and destination clusters.             |



## Authors:
- Ajinkya Nanavati (ananava1@in.ibm.com)
- Mohit Chitlange (mochitla@in.ibm.com)
- Devendra Mahajan (demahaj1@in.ibm.com)

<p align="right">(<a href="#readme-top">back to top</a>)</p>
