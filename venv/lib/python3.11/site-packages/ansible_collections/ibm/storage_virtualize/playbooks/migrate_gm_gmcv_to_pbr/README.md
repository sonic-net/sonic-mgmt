<a id="readme-top"></a>

# Automated Migration of Global Mirror & GMCV (Global Mirror with Change Volumes) Relationships & Consistency Groups to PBR (Policy-based Replication)

This document runs through the Ansible playbooks required for the migration of Global Mirror and GMCV (Global Mirror with change volumes) relationships and consistency groups to PBR (Policy-based Replication).

## Table of Contents
- [Objective](#objective)
- [Prerequisites](#prerequisites)
- [Overview](#overview)
- [Playbooks](#playbooks)
- [Variables](#variables)

## Objective
Migrate Global Mirror & GMCV (Global Mirror with Change Volumes) relationships and consistency groups to PBR (Policy-based Replication) while maintaining a consistent secondary copy.

## Prerequisites
- IBM Storage Virtualize Ansible Collection v2.5.0 or later must be installed.
- Both systems should support PBR. Supported builds are - 8.6.0.x or 8.7.0.x.
- Both systems must have working GM/GMCV relationships and/or consistency groups (implying working partnerships).
- Global Mirror relationships/consistency groups must be in `Consistent Synchronized` state while GMCV relationships/consistency groups must be in `Consistent Copying` state, if the state is `Inconsistent Copying` or `Inconsistent Stopped`, the playbook will try to bring these relationships/consistency groups into the required states, but may fail to do so if the state does not change in a pre-defined time interval.
- The migration process for GMCV (Global Mirror with Change Volumes) converts the relationships/consistency groups into Global Mirror first, hence the link between the systems should be able to support Global Mirror, particularly the bandwidth requirements.
- Pools given as input (which are to be linked), should have enough space to contain every volume which is to be migrated.

## Overview
The suite of playbooks to migrate GM/GMCV to PBR performs following steps:
- Setup PBR on the partnership
- Link the specified pools
- Create a replication policy
- Convert GMCV relationships/consistency groups to Global Mirror if not already Global Mirror (deleting the change volumes)
- Create a volumegroup with replication policy
- Add master volume to the volume group
- Optional: Cleanup Global Mirror/GMCV remnants

> Migration of consistency groups will lead to creation of a single volume group, while migration of independent relationships (prefix-selected too) will create a new volume group for each relationship.

## Playbooks
Migrating Global Mirror, GMCV to PBR currently has 6 executable playbooks - 
- migrate_independent_relationships/main.yaml - For migrating a list of independent relationships.
- migrate_independent_relationships/cleanup.yaml - For delayed cleanup of a list of independent relationships which have been already migrated.
- migrate_prefix_relationships/main.yaml - For migrating a set of independent relationships with a common prefix.
- migrate_prefix_relationships/cleanup.yaml - For delayed cleanup of a set of independent relationships which have been already migrated with a common prefix.
- migrate_consistency_groups/main.yaml - For migrating a list of consistency groups.
- migrate_consistency_groups/cleanup.yaml - For delayed cleanup of a list of consistency groups which have been already migrated.
>[!NOTE]
> Only the .yaml files which do not begin with an underscore are meant to be executed as Ansible Playbooks.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

These playbooks can be found in the repository as - 
```
ibm.storage_virtualize    
│
└─playbooks
  │
  └─migrate_gm_gmcv_to_pbr
    │
    └─migrate_consistency_groups
    │ └─main.yaml
    │ └─cleanup.yaml
    │ └─inventory.yaml
    │ └─...
    │
    └─migrate_independent_relationships
    │ └─main.yaml
    │ └─cleanup.yaml
    │ └─inventory.yaml
    │ └─...
    │
    └─migrate_prefix_relationships
    │ └─main.yaml
    │ └─cleanup.yaml
    │ └─inventory.yaml
    │ └─...
    │
    └─README.md
...
```
>[!NOTE]
> For delayed cleanup, a file named `inventory_cleanup_[ir/prefix/cg]_master_system_name_aux_system_name.ini` will be created which will contain the necessary information to clean up the GM/GMCV setup. Due to security concerns, security credentials will not be added to this file. Thus, before running the cleanup playbook, these credentials should be added to the file, and the name of the inventory file should be added to the vars_files section of the cleanup playbook.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Variables

### Common Variables

| Variable                | Required     | Default | Notes                                                                                 |
|-------------------------|--------------|---------|---------------------------------------------------------------------------------------|
|master_clustername       |yes           |X        |Clustername of the master system                                                       |
|master_username          |yes           |X        |Username for the master system                                                         |
|master_password          |yes           |X        |Password for the master system                                                         |
|master_pool_name         |yes           |X        |Name of the pool to be linked on the master system                                     |
|aux_clustername          |yes           |X        |Clustername of the auxiliary system                                                    |
|aux_username             |yes           |X        |Username for the auxiliary system                                                      |
|aux_password             |yes           |X        |Password of the auxiliary system                                                       |
|aux_pool_name            |yes           |X        |Name of the pool to be linked on the auxiliary system                                  |
|truststore_name          |yes           |X        |Name of the truststore to be created                                                   |
|replication_policy_name  |yes           |X        |Name of the replication policy to be created                                           |
|rpo_alert                |yes           |X        |Recovery Point Objective for replication policy                                        |
|volume_group_name_prefix |yes           |X        |Prefix for the volume group to be created, the name of the GMCV relationship/consistency groups is appended to this prefix for each migration|
|location_1_iogrp_id      |no            |0        |ID of the IO Group on location 1 for replication policy                                |
|location_2_iogrp_id      |no            |0        |ID of the IO Group on location 2 for replication policy                                |
|use_existing_certificate |no            |true     |Whether the system should use the existing certificate for truststores                 |
|remove_aux_volumes       |no            |false    |Whether to delete GMCV/GM relationships/consistency groups and auxiliary volumes       |
|log_path                 |no            |./gm_gmcv_pbr_migration.log    |Where should logs of the migration process be placed             |

>[!CAUTION]
> The remove_aux_volumes variable, when set to true, will delete all specified GMCV relationships, consistency groups and their auxiliary volumes as well once PBR is fully setup. If set to false, all the information necessary to clean up the Global Mirror/GMCV remnants later will be stored in an inventory_cleanup_<ir/prefix/cg>\_master_system_name_aux_system_name.ini file, and can be cleaned up later using the cleanup_gm_gmcv_<ir/prefix/cg>_pbr_migration.yaml.yaml playbook.

>[!CAUTION]
> The use_existing_certificate variable, when set to false, will create a new self-signed system certificate and discard the old certificate of the system, which can lead to issues with Truststores and PBR setups created before the creation of the new certificate.

### Variables for independent relationship migration

| Variable               | Required     | Default | Notes                                                                                                                    |
|------------------------|--------------|---------|--------------------------------------------------------------------------------------------------------------------------|
|relationships_to_migrate|yes           |X        |List of names of GMCV relationships to migrate                                                                            |


### Variables for prefix-selected relationship migration

| Variable      | Required | Default | Notes                                                                                                                    |
|---------------|----------|---------|--------------------------------------------------------------------------------------------------------------------------|
|rel_name_prefix|yes       |X        |Prefix of names of GMCV relationships to migrate                                                                          |

### Variables for consistency group migration

| Variable                    | Required     | Default | Notes                                   |
|-----------------------------|--------------|---------|-----------------------------------------|
|consistency_groups_to_migrate|yes           |X        |Name of GMCV consistency group to migrate|

## Authors
- Sumit Kumar Gupta (SUMIT.GUPTA16@ibm.com)
- Prathamesh Deshpande (prathamesh.deshpande@ibm.com)

<p align="right">(<a href="#readme-top">back to top</a>)</p>
