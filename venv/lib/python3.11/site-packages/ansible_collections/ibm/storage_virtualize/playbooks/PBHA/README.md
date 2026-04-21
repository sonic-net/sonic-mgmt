<a id="readme-top"></a>

# Playbook to Set Up Policy-Based High Availability (PBHA)

## Table of Contents
- [Objective](#objective)
- [Prerequisites](#prerequisites)
- [Tasks Performed](#tasks-performed)
- [Playbooks Overview](#playbooks-overview)
- [Variables](#variables)

## Objective
  - Set up **Policy Based High Availability (PBHA) Replication**.

## Prerequisites
  - IBM Storage Virtualize ansible collection plugins must be installed.
  - FC partnership must be present between the clusters.
  - Truststores with certificates of partnered system must be present on both clusters.
  - Policy-based Replication must be enabled for the partnership. It can be done by running the below command on **both clusters**:
    ```bash
    chpartnership -pbrinuse yes <partnership_name>
    ```

## Tasks Performed
This playbook automates the setup and configure PBHA Replication between source cluster to destination cluster. It performs the following tasks,
  - Creates Data Reduction Pool, links them, and creates provisionining policy. 
  - Create multiple volumes with specified prefix, along with volume group, and maps them to the specified host.

## Playbooks Overview
### 1. main.yml:
  - This is the main file to be executed using:
     ```ansible-playbook main.yml```
  - It leverages other files for PBHA configuration. It executes playbook like `create_mdiskgrp_provisioningpolicy.yml` and later on, this playbook creates partition, volume group and associated volumes with volume_prefix name specified in inventory file `inventory.ini`. 
  - It also maps all the volumes to specified host.

### 2. create_mdiskgrp_provisioning_policy.yml:
  - This playbook checks the drive status and drive count. Based on this drive info, it creates standard or data reduction pool with specified level. 
  - It links pools of both the sites, and creates provisioning policy.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Variables
### These variables should be defined in your inventory.ini file,

| Parameter                    | Description                                                                                                                     |
|-----------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| `users_data`                | Details of primary (source) and secondary (target) clusters for replication.                  |
| `host_name`                 | FC host name to which all volumes should be mapped after creation.                                                          |
| `fcwwpn`                    | List of Fibre Channel (FC) WWPNs to be added to the FC host.                                                                     |
| `pool_name`                 | Name of the storage pool to be created.                                                                                         |
| `provisioning_policy_name` | Name of the provisioning policy to be created and added to the storage pool.                                                     |
| `mdisk_name`                | Name of the array to be created and added to the storage pool.                                                                   |
| `level`                     | RAID level for the array being created. [Refer to RAID level combinations](https://www.ibm.com/docs/en/flashsystem-5x00/8.7.x?topic=commands-mkdistributedarray). |
| `drivecount`                | Number of drives to be used in the array.                                                                                        |
| `ha_policy_name`            | Name of the High Availability (HA) replication policy to be created.                                                             |
| `partition_name`           | Name of the storage partition to be created.                                                                                      |
| `volume_size`                    | Size of each volume to be created.                                        |
| `volume_prefix`                    | Prefix for naming volumes (e.g., `vol_` results in `vol_1`, `vol_2`, etc.).                                        |
| `volume_group_name`                    | Name of the volume group under which all created volumes will be grouped.                                        |
| `number_of_volumes`        | Number of volumes to be created.                                                                                                  |
| `log_path`                  | Path where playbook logs will be stored. Defaults to `/tmp/ansiblePB.debug` if not specified.                                    |



## Authors
- Lavanya C R (lavanya.c.r1@ibm.com)
- Sandip Rajbanshi (sandip.rajbanshi@ibm.com)

<p align="right">(<a href="#readme-top">back to top</a>)</p>
