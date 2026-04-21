<a id="readme-top"></a>

# Playbook to Set Up and configure PBRHA (3-site)

This suite of playbooks helps user to configure disaster recovery site, for an existing High Availability(PBHA) setup.

## Table of Contents
- [Objective](#objective)
- [Prerequisites](#prerequisites)
- [Tasks Performed](#tasks-performed)
- [Playbooks Overview](#playbooks-overview)
- [Variables](#variables)

## Objective
  - Set up and configure PBRHA (3-site).

## Prerequisites
  - IBM Storage Virtualize ansible collection plugins must be installed.
  - From here on, refer to highly-available site 1 as HA1, highly-available site 2 as HA2, and the disaster recovery
    site as DR1.
  - Partition-based High-availability (PBHA) must be configured between HA1 and HA2 sites. Please refer to `PBHA/`
    and `move_existing_objects_into_PBHA_env/` directories in `playbooks/` folder to configure PBHA for new and existing
    objects respectively.
  - Disaster recovery (DR) site must be in partnership with both HA1 and HA2 sites.
  - DR site must have a pool for replication.

## Tasks Performed
  - Set replication pool link uid on DR site.
  - Create Storage Partition at DR site. `(Note: Existing partition can also be specified in inventory.ini)`
  - Configure DR link to HA1's Storage Partition.
  - Create async-dr replication policy in HA1 stoarge.
  - Assign DR replication-policy to existing volumegroups.

## Playbooks Overview
### 1. main.yml:
  - It will configure PBRHA 3-site over existing PBHA.
  - This is the main file to be executed using: `ansible-playbook main.yml`

### 2. remove_dr_link.yml:
  - It will remove async-dr replication policy from volumgroup, removes the DR system from PBRHA setup, and it will remove partition used for DR-link.

>[!NOTE]
> There are 2 relevant playbook directories as below in `playbooks/` section of this collection:
> - `PBHA/`: For configuring new PBHA setup
> - `move_existing_objects_into_PBHA_env/`: For configuring PBHA for existing volumegroups

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Variables
### These variables should be defined in your inventory.ini file,

| Parameter                    | Description                                                                                                                     |
|-----------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| `clusters`                  | A list containing AMS system from PBHA configuration and DR site.                                                              |
| `clusters[x].name`           | Cluster's name.                                                                                                                 |
| `clusters[x].clustername`    | Cluster's IP address.                                                                                                           |
| `clusters[x].username`       | Cluster's user login name.                                                                                                      |
| `clusters[x].password`       | Cluster's user password.                                                                                                        |
| `clusters[x].pool_name`      | Storage pool name to be used for linking.                                                                                      |
| `clusters[x].partition_name` | Name of the storage partition used in PBRHA.                                                                                   |
| `ha_policy_name`            | Name of the High Availability (HA) Replication policy.                                                                          |
| `dr_policy_name`            | Name of the Disaster Recovery (DR) Replication policy.                                                                          |
| `volume_group_name`         | List of volume groups.                                                                                                          |
| `log_path`                  | Log path of the playbook. Defaults to `/tmp/ansiblePBRHA.log` if not specified.                                                 |

## Authors
Sandip Gulab Rajbanshi (sandip.rajbanshi@ibm.com)

<p align="right">(<a href="#readme-top">back to top</a>)</p>
