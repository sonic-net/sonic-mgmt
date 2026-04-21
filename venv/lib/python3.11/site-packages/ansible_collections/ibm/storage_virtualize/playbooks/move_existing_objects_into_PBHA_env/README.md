<a id="readme-top"></a>

# Move Existing Objects into Policy-Based High Availability (PBHA)

## Table of Contents
- [Objective](#objective)
- [Prerequisites](#prerequisites)
- [Tasks Performed](#tasks-performed)
- [Playbooks Overview](#playbooks-overview)
- [Variables](#variables)

## Objective
  Move **existing single-cluster objects** into **Policy-Based High Availability (PBHA)** environment.

## Prerequisites
  - IBM Storage Virtualize ansible collection plugins must be installed.
  - Pool on secondary cluster must have enough space for data that is in source volumegroup(s) on primary cluster. Here, source volumegroup(s) points to volumegroup(s) that are being added into partition for high-availability.
  - Volumes must be added to volumegroup before running the playbooks.

## Tasks Performed
  - Setup mTLS
  - Setup FC partnership between 2 clusters
  - Create a draft partition
  - Add a new or existing volumegroup in draft partition
  - Add a new or existing host in a draft partition
  - Publish draft partition
  - Create a replication policy between IO-groups of 2 clusters
  - Assign replication policy to partition

## Playbooks Overview
There are total 4 files used for moving existing objects in PBHA, and decommission_partition.yml is for decommissioning the partition.
### 1. main.yml:
  - This is the main file to be executed using: `ansible-playbook main.yml`
  - It leverages `create_mTLS.yml` and `replication_setup.yml` for completing its initial setup tasks. 
  - After that, it continues to move objects into a new partition, finally establishing high-availability between primary and secondary clusters.

### 2. create_mTLS.yml:
  - This playbook sets up Mutual Transport Layer Security (mTLS) which includes generating and exporting certificate and creating truststore on both clusters.

### 3. replication_setup.yml:
  - This file links pools of both the sites and creates an HA replication policy.

### 4. decommission_partition.yml:
  - This file should be run when user wants to decommission partition. It does following:
    - Make partition non-HA (if it is in HA relationship) by removing HA replication policy
    - Remove all volumegroups from partition
    - Delete partition
    - Delete volumegroup(s) while keeping volumes, if keep_volumegroups == false

  >[!NOTE]
  > When last task (i.e. assigning HA replication policy to partition) is completed, objects are replicated to secondary cluster's pool and data copy starts immediately from primary cluster to secondary. Time taken by data-synchronization is dependent on amount of data. After sync is complete, 'lspartition' output shows ha_status=established and link_status=synchronized.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Variables
### These variables should be defined in your inventory.ini file,
| Parameter              | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| `clusters`             | A list containing primary cluster (from where user wants to replicate data) details as well as secondary cluster (where volumes will be replicated to) details. It is required if user wants to setup HA partitions between 2 clusters.       |
| `cluster_ip`           | Cluster's IP address.                                                       |
| `cluster_name`         | Cluster's name.                                                             |
| `cluster_username`     | Cluster's user login name.                                                  |
| `cluster_password`     | Cluster's user password.                                                    |
| `pool_name`            | Storage pool name to be used for linking.                                  |
| `truststore_name`      | Truststore name.                                                            |
| `io_grp`               | ID or name of the IO-Group used to create HA replication policy.            |
| `host_name`            | FC (Fibre-channel) host to map all volumes of the volume group.             |
| `fcwwpn`               | List of FC WWPNs to be added to FC host.                                    |
| `ha_policy_name`       | HA replication policy name.                                                 |
| `partition_name`       | Storage partition name.                                                     |
| `volume_group_name`    | Volume group name.                                                          |
| `log_path`             | Log path of playbook. Default file is `ansiblePB.debug`.                    |
| `ams_cluster_name`     | Active management site's cluster name.                                     |
| `ams_cluster_ip`       | Active management site's cluster IP.                                       |
| `ams_cluster_username` | Active management site's cluster username.                                 |
| `ams_cluster_password` | Active management site's cluster password.                                 |
| `keep_volumegroups`    | Boolean (`true`/`false`) to retain volume groups.                           |

## Authors
Sumit Kumar Gupta (sumit.gupta16@ibm.com)

<p align="right">(<a href="#readme-top">back to top</a>)</p>
