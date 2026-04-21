<a id="readme-top"></a>

# Playbook to Setup Policy-Based Replication (PBR)

## Table of Contents
- [Objective](#objective)
- [Prerequisites](#prerequisites)
- [Tasks Performed](#tasks-performed)
- [Playbooks Overview](#playbooks-overview)
- [Variables](#variables)

## Objective
  - Set up mTLS and configure Policy Based Replication between 2 Flashsystems.

## Prerequisites
  - IBM Storage Virtualize ansible collection plugins must be installed.
  - FC or IP partnership must be present between the clusters.
  - Host must be present on primary cluster.

## Tasks Performed
- These playbooks set up mTLS and configure Policy Based Replication between a primary cluster and the secondary cluster.
- These playbook is designed to set up mTLS on both the site and configure Policy Based Replication between source cluster to destination cluster. This is designed in a way that it creates Data Reduction Pool, links them, creates provision policy and replication policy. 
- These playbooks also creates multiple Volumes with specified prefix along with volume group and maps all of them to the specified host.

## Playbooks Overview
### 1. main.yml:
  - This is the main file to be executed using: `ansible-playbook main.yml`
  - It leverages other files for PBR configuration. It executes `create_mTLS.yml` and `drp_pool_setup.yml` and then creates volume group and associated volumes with volume_prefix name, specified in `pbr_inventory.ini`. It also maps all the volumes to specified host.
  - Any additional volumes that need to be added to volumegroup, and/or need to be mapped to existing host object (but were not part of volumegroup at the time of execution of the playbook), can be added to inventory file. They'll be added to volumegroup and mapped to host in subsequent execution of the playbook.

###  2. create_mTLS.yml:
  - This playbook sets Mutual Transport Layer Security (mTLS) which includes generating and exporting certificate and creating truststore on both clusters.

###  3. drp_pool_setup.yml:
  - This playbook checks the drive status and drive count. Based on this drive info, it creates mdiskgrp, and data reduction pool with specified level. It links pools of both the sites. Then, it creates provisioning policy and replication policy. Already exiting mdiskgrps (pools) can also be used, only mention name of desired pool in `pbr_inventory.ini`.
  - If user wants to decide drives to be used in pool before running the playbook, he can create a pool and add drives to it (example below):
    - Create a pool:
      ```sh
      mkmdiskgrp -unit mb -datareduction yes -easytier auto -encrypt no -ext 1024 -gui -guiid 0 -name mdg0-warning 80%
      ```
    - Assign first 2 disks  (via drivecount parameter) to pool:
      ```sh
      svctask mkdistributedarray -level raid1 -driveclass 0 -drivecount 2 mdg0 (used drive 0 and drive 1) 
      ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Variables
### These variables should be defined in your pbr_inventory.ini file,

| Parameter                    | Description                                                                                                                     |
|-----------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| `clusters_data`                | Contains primary cluster details (source of replication) and secondary cluster details (target for volume replication).         |
| `host_name`                 | Host name to which all volumes should be mapped after creation. Assumes the host already exists on the primary cluster.         |
| `volume_size`                    | Size of each volume to be created.                                        |
| `volume_prefix`                    | Prefix for naming volumes (e.g., `vol_` results in `vol_1`, `vol_2`, etc.).                                        |
| `volume_group_name`                    | Name of the volume group under which all created volumes will be grouped.                                        |
| `number_of_volumes`        | Number of volumes to be created between clusters.                                                                                |
| `log_path`                  | Specifies the log path for the playbook. Defaults to `/tmp/ansiblePB.debug` if not provided.                                    |



## Authors
- Akshada Thorat  (akshada.thorat@ibm.com)
- Sandip Rajbanshi (sandip.rajbanshi@ibm.com)
- Lavanya C R (lavanya.c.r1@ibm.com)

<p align="right">(<a href="#readme-top">back to top</a>)</p>
