#!/usr/bin/env python

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type


from datetime import datetime

from ansible.module_utils.parsing.convert_bool import boolean
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import missing_required_lib

from ansible_collections.community.okd.plugins.module_utils.openshift_ldap import (
    validate_ldap_sync_config,
    ldap_split_host_port,
    OpenshiftLDAPRFC2307,
    OpenshiftLDAPActiveDirectory,
    OpenshiftLDAPAugmentedActiveDirectory,
)

try:
    import ldap

    HAS_PYTHON_LDAP = True
    PYTHON_LDAP_ERROR = None
except ImportError as e:
    HAS_PYTHON_LDAP = False
    PYTHON_LDAP_ERROR = e

from ansible_collections.community.okd.plugins.module_utils.openshift_common import (
    AnsibleOpenshiftModule,
)

try:
    from kubernetes.dynamic.exceptions import DynamicApiError
except ImportError as e:
    pass


LDAP_OPENSHIFT_HOST_LABEL = "openshift.io/ldap.host"
LDAP_OPENSHIFT_URL_ANNOTATION = "openshift.io/ldap.url"
LDAP_OPENSHIFT_UID_ANNOTATION = "openshift.io/ldap.uid"
LDAP_OPENSHIFT_SYNCTIME_ANNOTATION = "openshift.io/ldap.sync-time"


def connect_to_ldap(
    module, server_uri, bind_dn=None, bind_pw=None, insecure=True, ca_file=None
):
    if insecure:
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    elif ca_file:
        ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, ca_file)
    try:
        connection = ldap.initialize(server_uri)
        connection.set_option(ldap.OPT_REFERRALS, 0)

        connection.simple_bind_s(bind_dn, bind_pw)
        return connection
    except ldap.LDAPError as e:
        module.fail_json(
            msg="Cannot bind to the LDAP server '{0}' due to: {1}".format(server_uri, e)
        )


def validate_group_annotation(definition, host_ip):
    name = definition["metadata"]["name"]
    # Validate LDAP URL Annotation
    annotate_url = (
        definition["metadata"].get("annotations", {}).get(LDAP_OPENSHIFT_URL_ANNOTATION)
    )
    if host_ip:
        if not annotate_url:
            return "group '{0}' marked as having been synced did not have an '{1}' annotation".format(
                name, LDAP_OPENSHIFT_URL_ANNOTATION
            )
        elif annotate_url != host_ip:
            return "group '{0}' was not synchronized from: '{1}'".format(name, host_ip)
    # Validate LDAP UID Annotation
    annotate_uid = definition["metadata"]["annotations"].get(
        LDAP_OPENSHIFT_UID_ANNOTATION
    )
    if not annotate_uid:
        return "group '{0}' marked as having been synced did not have an '{1}' annotation".format(
            name, LDAP_OPENSHIFT_UID_ANNOTATION
        )
    return None


class OpenshiftLDAPGroups(object):
    kind = "Group"
    version = "user.openshift.io/v1"

    def __init__(self, module):
        self.module = module
        self.cache = {}
        self.__group_api = None

    @property
    def k8s_group_api(self):
        if not self.__group_api:
            params = dict(kind=self.kind, api_version=self.version, fail=True)
            self.__group_api = self.module.find_resource(**params)
        return self.__group_api

    def get_group_info(self, return_list=False, **kwargs):
        params = dict(
            kind=self.kind,
            api_version=self.version,
        )
        params.update(kwargs)
        result = self.module.kubernetes_facts(**params)
        if len(result["resources"]) == 0:
            return None
        if len(result["resources"]) == 1 and not return_list:
            return result["resources"][0]
        else:
            return result["resources"]

    def list_groups(self):
        allow_groups = self.module.params.get("allow_groups")
        deny_groups = self.module.params.get("deny_groups")
        name_mapping = self.module.config.get("groupUIDNameMapping")

        if name_mapping and (allow_groups or deny_groups):

            def _map_group_names(groups):
                return [name_mapping.get(value, value) for value in groups]

            allow_groups = _map_group_names(allow_groups)
            deny_groups = _map_group_names(deny_groups)

        host = self.module.host
        netlocation = self.module.netlocation
        groups = []
        if allow_groups:
            missing = []
            for grp in allow_groups:
                if grp in deny_groups:
                    continue
                resource = self.get_group_info(name=grp)
                if not resource:
                    missing.append(grp)
                    continue
                groups.append(resource)

            if missing:
                self.module.fail_json(
                    msg="The following groups were not found: %s" % "".join(missing)
                )
        else:
            label_selector = "%s=%s" % (LDAP_OPENSHIFT_HOST_LABEL, host)
            resources = self.get_group_info(
                label_selectors=[label_selector], return_list=True
            )
            if not resources:
                return (
                    None,
                    "Unable to find Group matching label selector '%s'"
                    % label_selector,
                )
            groups = resources
            if deny_groups:
                groups = [
                    item
                    for item in groups
                    if item["metadata"]["name"] not in deny_groups
                ]

        uids = []
        for grp in groups:
            err = validate_group_annotation(grp, netlocation)
            if err and allow_groups:
                # We raise an error for group part of the allow_group not matching LDAP sync criteria
                return None, err
            group_uid = grp["metadata"]["annotations"].get(
                LDAP_OPENSHIFT_UID_ANNOTATION
            )
            self.cache[group_uid] = grp
            uids.append(group_uid)
        return uids, None

    def get_group_name_for_uid(self, group_uid):
        if group_uid not in self.cache:
            return None, "No mapping found for Group uid: %s" % group_uid
        return self.cache[group_uid]["metadata"]["name"], None

    def make_openshift_group(self, group_uid, group_name, usernames):
        group = self.get_group_info(name=group_name)
        if not group:
            group = {
                "apiVersion": "user.openshift.io/v1",
                "kind": "Group",
                "metadata": {
                    "name": group_name,
                    "labels": {LDAP_OPENSHIFT_HOST_LABEL: self.module.host},
                    "annotations": {
                        LDAP_OPENSHIFT_URL_ANNOTATION: self.module.netlocation,
                        LDAP_OPENSHIFT_UID_ANNOTATION: group_uid,
                    },
                },
            }

        # Make sure we aren't taking over an OpenShift group that is already related to a different LDAP group
        ldaphost_label = (
            group["metadata"].get("labels", {}).get(LDAP_OPENSHIFT_HOST_LABEL)
        )
        if not ldaphost_label or ldaphost_label != self.module.host:
            return (
                None,
                "Group %s: %s label did not match sync host: wanted %s, got %s"
                % (
                    group_name,
                    LDAP_OPENSHIFT_HOST_LABEL,
                    self.module.host,
                    ldaphost_label,
                ),
            )

        ldapurl_annotation = (
            group["metadata"].get("annotations", {}).get(LDAP_OPENSHIFT_URL_ANNOTATION)
        )
        if not ldapurl_annotation or ldapurl_annotation != self.module.netlocation:
            return (
                None,
                "Group %s: %s annotation did not match sync host: wanted %s, got %s"
                % (
                    group_name,
                    LDAP_OPENSHIFT_URL_ANNOTATION,
                    self.module.netlocation,
                    ldapurl_annotation,
                ),
            )

        ldapuid_annotation = (
            group["metadata"].get("annotations", {}).get(LDAP_OPENSHIFT_UID_ANNOTATION)
        )
        if not ldapuid_annotation or ldapuid_annotation != group_uid:
            return (
                None,
                "Group %s: %s annotation did not match LDAP UID: wanted %s, got %s"
                % (
                    group_name,
                    LDAP_OPENSHIFT_UID_ANNOTATION,
                    group_uid,
                    ldapuid_annotation,
                ),
            )

        # Overwrite Group Users data
        group["users"] = usernames
        group["metadata"]["annotations"][
            LDAP_OPENSHIFT_SYNCTIME_ANNOTATION
        ] = datetime.now().isoformat()
        return group, None

    def create_openshift_groups(self, groups: list):
        diffs = []
        results = []
        changed = False
        for definition in groups:
            name = definition["metadata"]["name"]
            existing = self.get_group_info(name=name)
            if not self.module.check_mode:
                method = "patch" if existing else "create"
                try:
                    if existing:
                        definition = self.k8s_group_api.patch(definition).to_dict()
                    else:
                        definition = self.k8s_group_api.create(definition).to_dict()
                except DynamicApiError as exc:
                    self.module.fail_json(
                        msg="Failed to %s Group '%s' due to: %s"
                        % (method, name, exc.body)
                    )
                except Exception as exc:
                    self.module.fail_json(
                        msg="Failed to %s Group '%s' due to: %s"
                        % (method, name, to_native(exc))
                    )
            equals = False
            if existing:
                equals, diff = self.module.diff_objects(existing, definition)
                diffs.append(diff)
            changed = changed or not equals
            results.append(definition)
        return results, diffs, changed

    def delete_openshift_group(self, name: str):
        result = dict(kind=self.kind, apiVersion=self.version, metadata=dict(name=name))
        if not self.module.check_mode:
            try:
                result = self.k8s_group_api.delete(name=name).to_dict()
            except DynamicApiError as exc:
                self.module.fail_json(
                    msg="Failed to delete Group '{0}' due to: {1}".format(
                        name, exc.body
                    )
                )
            except Exception as exc:
                self.module.fail_json(
                    msg="Failed to delete Group '{0}' due to: {1}".format(
                        name, to_native(exc)
                    )
                )
        return result


class OpenshiftGroupsSync(AnsibleOpenshiftModule):
    def __init__(self, **kwargs):
        super(OpenshiftGroupsSync, self).__init__(**kwargs)
        self.__k8s_group_api = None
        self.__ldap_connection = None
        self.host = None
        self.port = None
        self.netlocation = None
        self.scheme = None
        self.config = self.params.get("sync_config")

        if not HAS_PYTHON_LDAP:
            self.fail_json(
                msg=missing_required_lib("python-ldap"),
                error=to_native(PYTHON_LDAP_ERROR),
            )

    @property
    def k8s_group_api(self):
        if not self.__k8s_group_api:
            params = dict(kind="Group", api_version="user.openshift.io/v1", fail=True)
            self.__k8s_group_api = self.find_resource(**params)
        return self.__k8s_group_api

    @property
    def hostIP(self):
        return self.netlocation

    @property
    def connection(self):
        if not self.__ldap_connection:
            # Create connection object
            params = dict(
                module=self,
                server_uri=self.config.get("url"),
                bind_dn=self.config.get("bindDN"),
                bind_pw=self.config.get("bindPassword"),
                insecure=boolean(self.config.get("insecure")),
                ca_file=self.config.get("ca"),
            )
            self.__ldap_connection = connect_to_ldap(**params)
        return self.__ldap_connection

    def close_connection(self):
        if self.__ldap_connection:
            self.__ldap_connection.unbind_s()
        self.__ldap_connection = None

    def exit_json(self, **kwargs):
        self.close_connection()
        self.module.exit_json(**kwargs)

    def fail_json(self, **kwargs):
        self.close_connection()
        self.module.fail_json(**kwargs)

    def get_syncer(self):
        syncer = None
        if "rfc2307" in self.config:
            syncer = OpenshiftLDAPRFC2307(self.config, self.connection)
        elif "activeDirectory" in self.config:
            syncer = OpenshiftLDAPActiveDirectory(self.config, self.connection)
        elif "augmentedActiveDirectory" in self.config:
            syncer = OpenshiftLDAPAugmentedActiveDirectory(self.config, self.connection)
        else:
            msg = "No schema-specific config was found, should be one of 'rfc2307', 'activeDirectory', 'augmentedActiveDirectory'"
            self.fail_json(msg=msg)
        return syncer

    def synchronize(self):
        sync_group_type = self.module.params.get("type")

        groups_uids = []
        ldap_openshift_group = OpenshiftLDAPGroups(module=self)

        # Get Synchronize object
        syncer = self.get_syncer()

        # Determine what to sync : list groups
        if sync_group_type == "openshift":
            groups_uids, err = ldap_openshift_group.list_groups()
            if err:
                self.fail_json(msg="Failed to list openshift groups", errors=err)
        else:
            # List LDAP Group to synchronize
            groups_uids = self.params.get("allow_groups")
            if not groups_uids:
                groups_uids, err = syncer.list_groups()
                if err:
                    self.module.fail_json(msg=err)
            deny_groups = self.params.get("deny_groups")
            if deny_groups:
                groups_uids = [uid for uid in groups_uids if uid not in deny_groups]

        openshift_groups = []
        for uid in groups_uids:
            # Get membership data
            member_entries, err = syncer.extract_members(uid)
            if err:
                self.fail_json(msg=err)

            # Determine usernames for members entries
            usernames = []
            for entry in member_entries:
                name, err = syncer.get_username_for_entry(entry)
                if err:
                    self.exit_json(
                        msg="Unable to determine username for entry %s: %s"
                        % (entry, err)
                    )
                if isinstance(name, list):
                    usernames.extend(name)
                else:
                    usernames.append(name)
            # Get group name
            if sync_group_type == "openshift":
                group_name, err = ldap_openshift_group.get_group_name_for_uid(uid)
            else:
                group_name, err = syncer.get_group_name_for_uid(uid)
            if err:
                self.exit_json(msg=err)

            # Make Openshift group
            group, err = ldap_openshift_group.make_openshift_group(
                uid, group_name, usernames
            )
            if err:
                self.fail_json(msg=err)
            openshift_groups.append(group)

        # Create Openshift Groups
        results, diffs, changed = ldap_openshift_group.create_openshift_groups(
            openshift_groups
        )
        self.module.exit_json(changed=True, groups=results)

    def prune(self):
        ldap_openshift_group = OpenshiftLDAPGroups(module=self)
        groups_uids, err = ldap_openshift_group.list_groups()
        if err:
            self.fail_json(msg="Failed to list openshift groups", errors=err)

        # Get Synchronize object
        syncer = self.get_syncer()

        changed = False
        groups = []
        for uid in groups_uids:
            # Check if LDAP group exist
            exists, err = syncer.is_ldapgroup_exists(uid)
            if err:
                msg = "Error determining LDAP group existence for group %s: %s" % (
                    uid,
                    err,
                )
                self.module.fail_json(msg=msg)

            if exists:
                continue

            # if the LDAP entry that was previously used to create the group doesn't exist, prune it
            group_name, err = ldap_openshift_group.get_group_name_for_uid(uid)
            if err:
                self.module.fail_json(msg=err)

            # Delete Group
            result = ldap_openshift_group.delete_openshift_group(group_name)
            groups.append(result)
            changed = True

        self.exit_json(changed=changed, groups=groups)

    def execute_module(self):
        # validate LDAP sync configuration
        error = validate_ldap_sync_config(self.config)
        if error:
            self.fail_json(msg="Invalid LDAP Sync config: %s" % error)

        # Split host/port
        if self.config.get("url"):
            result, error = ldap_split_host_port(self.config.get("url"))
            if error:
                self.fail_json(
                    msg="Failed to parse url='{0}': {1}".format(
                        self.config.get("url"), error
                    )
                )
            self.netlocation, self.host, self.port = (
                result["netlocation"],
                result["host"],
                result["port"],
            )
            self.scheme = result["scheme"]

        if self.params.get("state") == "present":
            self.synchronize()
        else:
            self.prune()
