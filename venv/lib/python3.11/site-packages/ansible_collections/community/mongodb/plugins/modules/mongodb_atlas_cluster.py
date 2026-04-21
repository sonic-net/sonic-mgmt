#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 T-Systems MMS
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
---
module: mongodb_atlas_cluster
short_description: Manage database clusters in Atlas
description:
  - The clusters module provides access to your cluster configurations.
  - The module lets you create, edit and delete clusters.
  - L(API Documentation,https://docs.atlas.mongodb.com/reference/api/clusters/)
author: "Martin Schurz (@schurzi)"
extends_documentation_fragment: community.mongodb.atlas_options
options:
  name:
    description:
      - Name of the cluster as it appears in Atlas. Once the cluster is created, its name cannot be changed.
    type: str
    required: True
  mongo_db_major_version:
    description:
      - Version of the cluster to deploy.
      - Atlas always deploys the cluster with the latest stable release of the specified version.
      - You can upgrade to a newer version of MongoDB when you modify a cluster.
    choices: [ "4.2", "4.4", "5.0", "6.0", "7.0" ]
    type: str
    aliases: [ "mongoDBMajorVersion" ]
  cluster_type:
    description:
      - Type of the cluster that you want to create.
    choices: [ "REPLICASET", "SHARDED" ]
    default: "REPLICASET"
    type: str
    aliases: [ "clusterType" ]
  replication_factor:
    description:
      - Number of replica set members. Each member keeps a copy of your databases, providing high availability and data redundancy.
    choices: [ 3, 5, 7 ]
    default: 3
    type: int
    aliases: [ "replicationFactor" ]
  auto_scaling:
    description:
      - Configure your cluster to automatically scale its storage and cluster tier.
    suboptions:
      disk_gb_enabled:
        type: bool
        description:
          - Specifies whether disk auto-scaling is enabled. The default is true.
        aliases: [ "diskGBEnabled" ]
    required: False
    type: dict
    aliases: [ "autoScaling" ]
  provider_settings:
    description:
      - Configuration for the provisioned servers on which MongoDB runs.
      - The available options are specific to the cloud service provider.
    suboptions:
      provider_name:
        required: True
        type: str
        description:
          - Cloud service provider on which the servers are provisioned.
        aliases: [ "providerName" ]
      region_name:
        required: True
        type: str
        description:
          - Physical location of your MongoDB cluster.
        aliases: [ "regionName" ]
      instance_size_name:
        required: True
        type: str
        description:
          - Atlas provides different cluster tiers, each with a default storage capacity and RAM size.
          - The cluster you select is used for all the data-bearing servers in your cluster tier.
        aliases: [ "instanceSizeName" ]
    required: True
    type: dict
    aliases: [ "providerSettings" ]
  disk_size_gb:
    description:
      - Capacity, in gigabytes, of the host's root volume. Increase this number to add capacity,
        up to a maximum possible value of 4096 (i.e., 4 TB). This value must be a positive integer.
    type: int
    aliases: [ "diskSizeGB" ]
  provider_backup_enabled:
    description:
      - Flag that indicates if the cluster uses Cloud Backups for backups.
    type: bool
    aliases: [ "providerBackupEnabled" ]
  pit_enabled:
    description:
      - Flag that indicates the cluster uses continuous cloud backups.
    type: bool
    aliases: [ "pitEnabled" ]
'''

EXAMPLES = '''
    - name: test cluster
      community.mongodb.mongodb_atlas_cluster:
        api_username: "API_user"
        api_password: "API_passwort_or_token"
        group_id: "GROUP_ID"
        name: "testcluster"
        mongo_db_major_version: "4.0"
        cluster_type: "REPLICASET"
        provider_settings:
          provider_name: "GCP"
          region_name: "EUROPE_WEST_3"
          instance_size_name: "M10"
...
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.mongodb.plugins.module_utils.mongodb_atlas import (
    AtlasAPIObject,
)


# ===========================================
# Module execution.
#
def main():
    # add our own arguments
    argument_spec = dict(
        state=dict(default="present", choices=["absent", "present"]),
        api_username=dict(required=True, aliases=['apiUsername']),
        api_password=dict(required=True, no_log=True, aliases=['apiPassword']),
        group_id=dict(required=True, aliases=['groupId']),
        name=dict(required=True),
        mongo_db_major_version=dict(
            choices=["4.2", "4.4", "5.0", "6.0", "7.0"],
            aliases=["mongoDBMajorVersion"]
        ),
        cluster_type=dict(
            default="REPLICASET", choices=["REPLICASET", "SHARDED"],
            aliases=["clusterType"]
        ),
        replication_factor=dict(default=3, type="int", choices=[3, 5, 7], aliases=["replicationFactor"]),
        auto_scaling=dict(
            type="dict",
            options=dict(
                disk_gb_enabled=dict(type="bool", aliases=["diskGBEnabled"]),
            ),
            aliases=["autoScaling"]
        ),
        provider_settings=dict(
            type="dict",
            required=True,
            options=dict(
                provider_name=dict(required=True, aliases=["providerName"]),
                region_name=dict(required=True, aliases=["regionName"]),
                instance_size_name=dict(required=True, aliases=["instanceSizeName"]),
            ),
            aliases=["providerSettings"]
        ),
        disk_size_gb=dict(type="int", aliases=["diskSizeGB"]),
        provider_backup_enabled=dict(type="bool", aliases=["providerBackupEnabled"]),
        pit_enabled=dict(type="bool", aliases=["pitEnabled"]),
    )

    # Define the main module
    module = AnsibleModule(
        argument_spec=argument_spec, supports_check_mode=True
    )

    data = {
        "name": module.params["name"],
        "clusterType": module.params["cluster_type"],
        "replicationFactor": module.params["replication_factor"],
        "providerSettings": {
            "providerName": module.params["provider_settings"]["provider_name"],
            "regionName": module.params["provider_settings"]["region_name"],
            "instanceSizeName": module.params["provider_settings"]["instance_size_name"],
        }
    }

    # handle optional options
    optional_vars = {
        "mongo_db_major_version": "mongoDBMajorVersion",
        "auto_scaling": "autoScaling",
        "disk_size_gb": "diskSizeGB",
        "provider_backup_enabled": "providerBackupEnabled",
        "pit_enabled": "pitEnabled",
    }

    for key in optional_vars:
        if module.params[key] is not None:
            if key == "auto_scaling":
                data.update({optional_vars[key]: {"diskGBEnabled": module.params[key]["disk_gb_enabled"]}})
            else:
                data.update({optional_vars[key]: module.params[key]})

    try:
        atlas = AtlasAPIObject(
            module=module,
            path="/clusters",
            object_name="name",
            group_id=module.params["group_id"],
            data=data,
        )
    except Exception as e:
        module.fail_json(
            msg="unable to connect to Atlas API. Exception message: %s" % e
        )

    changed, diff = atlas.update(module.params["state"])
    module.exit_json(
        changed=changed,
        data=atlas.data,
        diff=diff,
    )


# import module snippets
if __name__ == "__main__":
    main()
