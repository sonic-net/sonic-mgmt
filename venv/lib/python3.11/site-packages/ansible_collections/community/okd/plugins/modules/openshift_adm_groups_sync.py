#!/usr/bin/python

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

# STARTREMOVE (downstream)
DOCUMENTATION = r"""

module: openshift_adm_groups_sync

short_description: Sync OpenShift Groups with records from an external provider.

version_added: "2.1.0"

author:
  - Aubin Bikouo (@abikouo)

description:
  - In order to sync/prune OpenShift Group records with those from an external provider, determine which Groups you wish to sync
    and where their records live.
  - Analogous to `oc adm prune groups` and `oc adm group sync`.
  - LDAP sync configuration file syntax can be found here
    U(https://docs.openshift.com/container-platform/4.9/authentication/ldap-syncing.html).
  - The bindPassword attribute of the LDAP sync configuration is expected to be a string,
    please use ansible-vault encryption to secure this information.

extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options

options:
  state:
    description:
    - Determines if the group should be sync when set to C(present) or pruned when set to C(absent).
    type: str
    default: present
    choices: [ absent, present ]
  type:
    description:
    - which groups allow and deny list entries refer to.
    type: str
    default: ldap
    choices: [ ldap, openshift ]
  sync_config:
    description:
    - Provide a valid YAML definition of an LDAP sync configuration.
    type: dict
    aliases:
    - config
    - src
    required: True
  deny_groups:
    description:
    - Denied groups, could be openshift group name or LDAP group dn value.
    - When parameter C(type) is set to I(ldap) this should contains only LDAP group definition
      like I(cn=developers,ou=groups,ou=rfc2307,dc=ansible,dc=redhat).
    - The elements specified in this list will override the ones specified in C(allow_groups).
    type: list
    elements: str
    default: []
  allow_groups:
    description:
    - Allowed groups, could be openshift group name or LDAP group dn value.
    - When parameter C(type) is set to I(ldap) this should contains only LDAP group definition
      like I(cn=developers,ou=groups,ou=rfc2307,dc=ansible,dc=redhat).
    type: list
    elements: str
    default: []

requirements:
  - python >= 3.6
  - kubernetes >= 12.0.0
  - python-ldap
"""

EXAMPLES = r"""
# Prune all orphaned groups
- name: Prune all orphan groups
  openshift_adm_groups_sync:
    state: absent
    src: "{{ lookup('file', '/path/to/ldap-sync-config.yaml') | from_yaml }}"

# Prune all orphaned groups from a list of specific groups specified in allow_groups
- name: Prune all orphan groups from a list of specific groups specified in allow_groups
  openshift_adm_groups_sync:
    state: absent
    src: "{{ lookup('file', '/path/to/ldap-sync-config.yaml') | from_yaml }}"
    allow_groups:
      - cn=developers,ou=groups,ou=rfc2307,dc=ansible,dc=redhat
      - cn=developers,ou=groups,ou=rfc2307,dc=ansible,dc=redhat

# Sync all groups from an LDAP server
- name: Sync all groups from an LDAP server
  openshift_adm_groups_sync:
    src:
      kind: LDAPSyncConfig
      apiVersion: v1
      url: ldap://localhost:1390
      insecure: true
      bindDN: cn=admin,dc=example,dc=org
      bindPassword: adminpassword
      rfc2307:
        groupsQuery:
          baseDN: "cn=admins,ou=groups,dc=example,dc=org"
          scope: sub
          derefAliases: never
          filter: (objectClass=*)
          pageSize: 0
        groupUIDAttribute: dn
        groupNameAttributes: [cn]
        groupMembershipAttributes: [member]
        usersQuery:
          baseDN: "ou=users,dc=example,dc=org"
          scope: sub
          derefAliases: never
          pageSize: 0
        userUIDAttribute: dn
        userNameAttributes: [mail]
        tolerateMemberNotFoundErrors: true
        tolerateMemberOutOfScopeErrors: true

# Sync all groups except the ones from the deny_groups  from an LDAP server
- name: Sync all groups from an LDAP server using deny_groups
  openshift_adm_groups_sync:
    src: "{{ lookup('file', '/path/to/ldap-sync-config.yaml') | from_yaml }}"
    deny_groups:
      - cn=developers,ou=groups,ou=rfc2307,dc=ansible,dc=redhat
      - cn=developers,ou=groups,ou=rfc2307,dc=ansible,dc=redhat

# Sync all OpenShift Groups that have been synced previously with an LDAP server
- name: Sync all OpenShift Groups that have been synced previously with an LDAP server
  openshift_adm_groups_sync:
    src: "{{ lookup('file', '/path/to/ldap-sync-config.yaml') | from_yaml }}"
    type: openshift
"""


RETURN = r"""
builds:
  description:
  - The groups that were created, updated or deleted
  returned: success
  type: list
  elements: dict
  sample: [
    {
      "apiVersion": "user.openshift.io/v1",
      "kind": "Group",
      "metadata": {
        "annotations": {
          "openshift.io/ldap.sync-time": "2021-12-17T12:20:28.125282",
          "openshift.io/ldap.uid": "cn=developers,ou=groups,ou=rfc2307,dc=ansible,dc=redhat",
          "openshift.io/ldap.url": "localhost:1390"
        },
        "creationTimestamp": "2021-12-17T11:09:49Z",
        "labels": {
          "openshift.io/ldap.host": "localhost"
        },
        "managedFields": [{
          "apiVersion": "user.openshift.io/v1",
          "fieldsType": "FieldsV1",
          "fieldsV1": {
            "f:metadata": {
              "f:annotations": {
                ".": {},
                "f:openshift.io/ldap.sync-time": {},
                "f:openshift.io/ldap.uid": {},
                "f:openshift.io/ldap.url": {}
              },
              "f:labels": {
                ".": {},
                "f:openshift.io/ldap.host": {}
              }
            },
            "f:users": {}
          },
          "manager": "OpenAPI-Generator",
          "operation": "Update",
          "time": "2021-12-17T11:09:49Z"
        }],
        "name": "developers",
        "resourceVersion": "2014696",
        "uid": "8dc211cb-1544-41e1-96b1-efffeed2d7d7"
      },
      "users": ["jordanbulls@ansible.org"]
    }
  ]
"""
# ENDREMOVE (downstream)

import copy

from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
    AUTH_ARG_SPEC,
)


def argument_spec():
    args = copy.deepcopy(AUTH_ARG_SPEC)
    args.update(
        dict(
            state=dict(type="str", choices=["absent", "present"], default="present"),
            type=dict(type="str", choices=["ldap", "openshift"], default="ldap"),
            sync_config=dict(type="dict", aliases=["config", "src"], required=True),
            deny_groups=dict(type="list", elements="str", default=[]),
            allow_groups=dict(type="list", elements="str", default=[]),
        )
    )
    return args


def main():
    from ansible_collections.community.okd.plugins.module_utils.openshift_groups import (
        OpenshiftGroupsSync,
    )

    module = OpenshiftGroupsSync(
        argument_spec=argument_spec(), supports_check_mode=True
    )
    module.run_module()


if __name__ == "__main__":
    main()
