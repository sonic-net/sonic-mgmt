#!/usr/bin/env python

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type


import os
import copy

from ansible.module_utils.parsing.convert_bool import boolean
from ansible.module_utils.six import iteritems

try:
    import ldap
except ImportError as e:
    pass


LDAP_SEARCH_OUT_OF_SCOPE_ERROR = "trying to search by DN for an entry that exists outside of the tree specified with the BaseDN for search"


def validate_ldap_sync_config(config):
    # Validate url
    url = config.get("url")
    if not url:
        return "url should be non empty attribute."

    # Make sure bindDN and bindPassword are both set, or both unset
    bind_dn = config.get("bindDN", "")
    bind_password = config.get("bindPassword", "")
    if (len(bind_dn) == 0) != (len(bind_password) == 0):
        return "bindDN and bindPassword must both be specified, or both be empty."

    insecure = boolean(config.get("insecure"))
    ca_file = config.get("ca")
    if insecure:
        if url.startswith("ldaps://"):
            return "Cannot use ldaps scheme with insecure=true."
        if ca_file:
            return "Cannot specify a ca with insecure=true."
    elif ca_file and not os.path.isfile(ca_file):
        return "could not read ca file: {0}.".format(ca_file)

    nameMapping = config.get("groupUIDNameMapping", {})
    for k, v in iteritems(nameMapping):
        if len(k) == 0 or len(v) == 0:
            return "groupUIDNameMapping has empty key or value"

    schemas = []
    schema_list = ("rfc2307", "activeDirectory", "augmentedActiveDirectory")
    for schema in schema_list:
        if schema in config:
            schemas.append(schema)

    if len(schemas) == 0:
        return (
            "No schema-specific config was provided, should be one of %s"
            % ", ".join(schema_list)
        )
    if len(schemas) > 1:
        return "Exactly one schema-specific config is required; found (%d) %s" % (
            len(schemas),
            ",".join(schemas),
        )

    if schemas[0] == "rfc2307":
        return validate_RFC2307(config.get("rfc2307"))
    elif schemas[0] == "activeDirectory":
        return validate_ActiveDirectory(config.get("activeDirectory"))
    elif schemas[0] == "augmentedActiveDirectory":
        return validate_AugmentedActiveDirectory(config.get("augmentedActiveDirectory"))


def validate_ldap_query(qry, isDNOnly=False):
    # validate query scope
    scope = qry.get("scope")
    if scope and scope not in ("", "sub", "one", "base"):
        return "invalid scope %s" % scope

    # validate deref aliases
    derefAlias = qry.get("derefAliases")
    if derefAlias and derefAlias not in ("never", "search", "base", "always"):
        return "not a valid LDAP alias dereferncing behavior: %s", derefAlias

    # validate timeout
    timeout = qry.get("timeout")
    if timeout and float(timeout) < 0:
        return "timeout must be equal to or greater than zero"

    # Validate DN only
    qry_filter = qry.get("filter", "")
    if isDNOnly:
        if len(qry_filter) > 0:
            return 'cannot specify a filter when using "dn" as the UID attribute'
    else:
        # validate filter
        if len(qry_filter) == 0 or qry_filter[0] != "(":
            return "filter does not start with an '('"
    return None


def validate_RFC2307(config):
    qry = config.get("groupsQuery")
    if not qry or not isinstance(qry, dict):
        return "RFC2307: groupsQuery requires a dictionary"
    error = validate_ldap_query(qry)
    if not error:
        return error
    for field in (
        "groupUIDAttribute",
        "groupNameAttributes",
        "groupMembershipAttributes",
        "userUIDAttribute",
        "userNameAttributes",
    ):
        value = config.get(field)
        if not value:
            return "RFC2307: {0} is required.".format(field)

    users_qry = config.get("usersQuery")
    if not users_qry or not isinstance(users_qry, dict):
        return "RFC2307: usersQuery requires a dictionary"

    isUserDNOnly = config.get("userUIDAttribute").strip() == "dn"
    return validate_ldap_query(users_qry, isDNOnly=isUserDNOnly)


def validate_ActiveDirectory(config, label="ActiveDirectory"):
    users_qry = config.get("usersQuery")
    if not users_qry or not isinstance(users_qry, dict):
        return "{0}: usersQuery requires as dictionnary".format(label)
    error = validate_ldap_query(users_qry)
    if not error:
        return error

    for field in ("userNameAttributes", "groupMembershipAttributes"):
        value = config.get(field)
        if not value:
            return "{0}: {1} is required.".format(field, label)

    return None


def validate_AugmentedActiveDirectory(config):
    error = validate_ActiveDirectory(config, label="AugmentedActiveDirectory")
    if not error:
        return error
    for field in ("groupUIDAttribute", "groupNameAttributes"):
        value = config.get(field)
        if not value:
            return "AugmentedActiveDirectory: {0} is required".format(field)
    groups_qry = config.get("groupsQuery")
    if not groups_qry or not isinstance(groups_qry, dict):
        return "AugmentedActiveDirectory: groupsQuery requires as dictionnary."

    isGroupDNOnly = config.get("groupUIDAttribute").strip() == "dn"
    return validate_ldap_query(groups_qry, isDNOnly=isGroupDNOnly)


def determine_ldap_scope(scope):
    if scope in ("", "sub"):
        return ldap.SCOPE_SUBTREE
    elif scope == "base":
        return ldap.SCOPE_BASE
    elif scope == "one":
        return ldap.SCOPE_ONELEVEL
    return None


def determine_deref_aliases(derefAlias):
    mapping = {
        "never": ldap.DEREF_NEVER,
        "search": ldap.DEREF_SEARCHING,
        "base": ldap.DEREF_FINDING,
        "always": ldap.DEREF_ALWAYS,
    }
    result = None
    if derefAlias in mapping:
        result = mapping.get(derefAlias)
    return result


def openshift_ldap_build_base_query(config):
    qry = {}
    if config.get("baseDN"):
        qry["base"] = config.get("baseDN")

    scope = determine_ldap_scope(config.get("scope"))
    if scope:
        qry["scope"] = scope

    pageSize = config.get("pageSize")
    if pageSize and int(pageSize) > 0:
        qry["sizelimit"] = int(pageSize)

    timeout = config.get("timeout")
    if timeout and int(timeout) > 0:
        qry["timeout"] = int(timeout)

    filter = config.get("filter")
    if filter:
        qry["filterstr"] = filter

    derefAlias = determine_deref_aliases(config.get("derefAliases"))
    if derefAlias:
        qry["derefAlias"] = derefAlias
    return qry


def openshift_ldap_get_attribute_for_entry(entry, attribute):
    attributes = [attribute]
    if isinstance(attribute, list):
        attributes = attribute
    for k in attributes:
        if k.lower() == "dn":
            return entry[0]
        v = entry[1].get(k, None)
        if v:
            if isinstance(v, list):
                result = []
                for x in v:
                    if hasattr(x, "decode"):
                        result.append(x.decode("utf-8"))
                    else:
                        result.append(x)
                return result
            else:
                return v.decode("utf-8") if hasattr(v, "decode") else v
    return ""


def ldap_split_host_port(hostport):
    """
    ldap_split_host_port splits a network address of the form "host:port",
    "host%zone:port", "[host]:port" or "[host%zone]:port" into host or
    host%zone and port.
    """
    result = dict(scheme=None, netlocation=None, host=None, port=None)
    if not hostport:
        return result, None

    # Extract Scheme
    netlocation = hostport
    scheme_l = "://"
    if "://" in hostport:
        idx = hostport.find(scheme_l)
        result["scheme"] = hostport[:idx]
        netlocation = hostport[idx + len(scheme_l):]  # fmt: skip
    result["netlocation"] = netlocation

    if netlocation[-1] == "]":
        # ipv6 literal (with no port)
        result["host"] = netlocation

    v = netlocation.rsplit(":", 1)
    if len(v) != 1:
        try:
            result["port"] = int(v[1])
        except ValueError:
            return None, "Invalid value specified for port: %s" % v[1]
    result["host"] = v[0]
    return result, None


def openshift_ldap_query_for_entries(connection, qry, unique_entry=True):
    # set deref alias (TODO: need to set a default value to reset for each transaction)
    derefAlias = qry.pop("derefAlias", None)
    if derefAlias:
        ldap.set_option(ldap.OPT_DEREF, derefAlias)
    try:
        result = connection.search_ext_s(**qry)
        if not result or len(result) == 0:
            return None, "Entry not found for base='{0}' and filter='{1}'".format(
                qry["base"], qry["filterstr"]
            )
        if len(result) > 1 and unique_entry:
            if qry.get("scope") == ldap.SCOPE_BASE:
                return None, "multiple entries found matching dn={0}: {1}".format(
                    qry["base"], result
                )
            else:
                return None, "multiple entries found matching filter {0}: {1}".format(
                    qry["filterstr"], result
                )
        return result, None
    except ldap.NO_SUCH_OBJECT:
        return (
            None,
            "search for entry with base dn='{0}' refers to a non-existent entry".format(
                qry["base"]
            ),
        )


def openshift_equal_dn_objects(dn_obj, other_dn_obj):
    if len(dn_obj) != len(other_dn_obj):
        return False

    for k, v in enumerate(dn_obj):
        if len(v) != len(other_dn_obj[k]):
            return False
        for j, item in enumerate(v):
            if not (item == other_dn_obj[k][j]):
                return False
    return True


def openshift_equal_dn(dn, other):
    dn_obj = ldap.dn.str2dn(dn)
    other_dn_obj = ldap.dn.str2dn(other)

    return openshift_equal_dn_objects(dn_obj, other_dn_obj)


def openshift_ancestorof_dn(dn, other):
    dn_obj = ldap.dn.str2dn(dn)
    other_dn_obj = ldap.dn.str2dn(other)

    if len(dn_obj) >= len(other_dn_obj):
        return False
    # Take the last attribute from the other DN to compare against
    return openshift_equal_dn_objects(
        dn_obj, other_dn_obj[len(other_dn_obj) - len(dn_obj):]  # fmt: skip
    )


class OpenshiftLDAPQueryOnAttribute(object):
    def __init__(self, qry, attribute):
        # qry retrieves entries from an LDAP server
        self.qry = copy.deepcopy(qry)
        # query_attributes is the attribute for a specific filter that, when conjoined with the common filter,
        # retrieves the specific LDAP entry from the LDAP server. (e.g. "cn", when formatted with "aGroupName"
        # and conjoined with "objectClass=groupOfNames", becomes (&(objectClass=groupOfNames)(cn=aGroupName))")
        self.query_attribute = attribute

    @staticmethod
    def escape_filter(buffer):
        """
        escapes from the provided LDAP filter string the special
        characters in the set '(', ')', '*', \\ and those out of the range 0 < c < 0x80, as defined in RFC4515.
        """
        output = []
        hex_string = "0123456789abcdef"
        for c in buffer:
            if ord(c) > 0x7F or c in ("(", ")", "\\", "*") or c == 0:
                first = ord(c) >> 4
                second = ord(c) & 0xF
                output += ["\\", hex_string[first], hex_string[second]]
            else:
                output.append(c)
        return "".join(output)

    def build_request(self, ldapuid, attributes):
        params = copy.deepcopy(self.qry)
        if self.query_attribute.lower() == "dn":
            if ldapuid:
                if not openshift_equal_dn(
                    ldapuid, params["base"]
                ) and not openshift_ancestorof_dn(params["base"], ldapuid):
                    return None, LDAP_SEARCH_OUT_OF_SCOPE_ERROR
                params["base"] = ldapuid
            params["scope"] = ldap.SCOPE_BASE
            # filter that returns all values
            params["filterstr"] = "(objectClass=*)"
            params["attrlist"] = attributes
        else:
            # Builds the query containing a filter that conjoins the common filter given
            # in the configuration with the specific attribute filter for which the attribute value is given
            specificFilter = "%s=%s" % (
                self.escape_filter(self.query_attribute),
                self.escape_filter(ldapuid),
            )
            qry_filter = params.get("filterstr", None)
            if qry_filter:
                params["filterstr"] = "(&%s(%s))" % (qry_filter, specificFilter)
            params["attrlist"] = attributes
        return params, None

    def ldap_search(self, connection, ldapuid, required_attributes, unique_entry=True):
        query, error = self.build_request(ldapuid, required_attributes)
        if error:
            return None, error
        # set deref alias (TODO: need to set a default value to reset for each transaction)
        derefAlias = query.pop("derefAlias", None)
        if derefAlias:
            ldap.set_option(ldap.OPT_DEREF, derefAlias)

        try:
            result = connection.search_ext_s(**query)
            if not result or len(result) == 0:
                return None, "Entry not found for base='{0}' and filter='{1}'".format(
                    query["base"], query["filterstr"]
                )
            if unique_entry:
                if len(result) > 1:
                    return (
                        None,
                        "Multiple Entries found matching search criteria: %s (%s)"
                        % (query, result),
                    )
                result = result[0]
            return result, None
        except ldap.NO_SUCH_OBJECT:
            return None, "Entry not found for base='{0}' and filter='{1}'".format(
                query["base"], query["filterstr"]
            )
        except Exception as err:
            return None, "Request %s failed due to: %s" % (query, err)


class OpenshiftLDAPQuery(object):
    def __init__(self, qry):
        # Query retrieves entries from an LDAP server
        self.qry = qry

    def build_request(self, attributes):
        params = copy.deepcopy(self.qry)
        params["attrlist"] = attributes
        return params

    def ldap_search(self, connection, required_attributes):
        query = self.build_request(required_attributes)
        # set deref alias (TODO: need to set a default value to reset for each transaction)
        derefAlias = query.pop("derefAlias", None)
        if derefAlias:
            ldap.set_option(ldap.OPT_DEREF, derefAlias)

        try:
            result = connection.search_ext_s(**query)
            if not result or len(result) == 0:
                return None, "Entry not found for base='{0}' and filter='{1}'".format(
                    query["base"], query["filterstr"]
                )
            return result, None
        except ldap.NO_SUCH_OBJECT:
            return (
                None,
                "search for entry with base dn='{0}' refers to a non-existent entry".format(
                    query["base"]
                ),
            )


class OpenshiftLDAPInterface(object):
    def __init__(
        self,
        connection,
        groupQuery,
        groupNameAttributes,
        groupMembershipAttributes,
        userQuery,
        userNameAttributes,
        config,
    ):
        self.connection = connection
        self.groupQuery = copy.deepcopy(groupQuery)
        self.groupNameAttributes = groupNameAttributes
        self.groupMembershipAttributes = groupMembershipAttributes
        self.userQuery = copy.deepcopy(userQuery)
        self.userNameAttributes = userNameAttributes
        self.config = config

        self.tolerate_not_found = boolean(
            config.get("tolerateMemberNotFoundErrors", False)
        )
        self.tolerate_out_of_scope = boolean(
            config.get("tolerateMemberOutOfScopeErrors", False)
        )

        self.required_group_attributes = [self.groupQuery.query_attribute]
        for x in self.groupNameAttributes + self.groupMembershipAttributes:
            if x not in self.required_group_attributes:
                self.required_group_attributes.append(x)

        self.required_user_attributes = [self.userQuery.query_attribute]
        for x in self.userNameAttributes:
            if x not in self.required_user_attributes:
                self.required_user_attributes.append(x)

        self.cached_groups = {}
        self.cached_users = {}

    def get_group_entry(self, uid):
        """
        get_group_entry returns an LDAP group entry for the given group UID by searching the internal cache
        of the LDAPInterface first, then sending an LDAP query if the cache did not contain the entry.
        """
        if uid in self.cached_groups:
            return self.cached_groups.get(uid), None

        group, err = self.groupQuery.ldap_search(
            self.connection, uid, self.required_group_attributes
        )
        if err:
            return None, err
        self.cached_groups[uid] = group
        return group, None

    def get_user_entry(self, uid):
        """
        get_user_entry returns an LDAP group entry for the given user UID by searching the internal cache
        of the LDAPInterface first, then sending an LDAP query if the cache did not contain the entry.
        """
        if uid in self.cached_users:
            return self.cached_users.get(uid), None

        entry, err = self.userQuery.ldap_search(
            self.connection, uid, self.required_user_attributes
        )
        if err:
            return None, err
        self.cached_users[uid] = entry
        return entry, None

    def exists(self, ldapuid):
        group, error = self.get_group_entry(ldapuid)
        return bool(group), error

    def list_groups(self):
        group_qry = copy.deepcopy(self.groupQuery.qry)
        group_qry["attrlist"] = self.required_group_attributes

        groups, err = openshift_ldap_query_for_entries(
            connection=self.connection, qry=group_qry, unique_entry=False
        )
        if err:
            return None, err

        group_uids = []
        for entry in groups:
            uid = openshift_ldap_get_attribute_for_entry(
                entry, self.groupQuery.query_attribute
            )
            if not uid:
                return None, "Unable to find LDAP group uid for entry %s" % entry
            self.cached_groups[uid] = entry
            group_uids.append(uid)
        return group_uids, None

    def extract_members(self, uid):
        """
        returns the LDAP member entries for a group specified with a ldapGroupUID
        """
        # Get group entry from LDAP
        group, err = self.get_group_entry(uid)
        if err:
            return None, err

        # Extract member UIDs from group entry
        member_uids = []
        for attribute in self.groupMembershipAttributes:
            member_uids += openshift_ldap_get_attribute_for_entry(group, attribute)

        members = []
        for user_uid in member_uids:
            entry, err = self.get_user_entry(user_uid)
            if err:
                if self.tolerate_not_found and err.startswith("Entry not found"):
                    continue
                elif err == LDAP_SEARCH_OUT_OF_SCOPE_ERROR:
                    continue
                return None, err
            members.append(entry)

        return members, None


class OpenshiftLDAPRFC2307(object):
    def __init__(self, config, ldap_connection):
        self.config = config
        self.ldap_interface = self.create_ldap_interface(ldap_connection)

    def create_ldap_interface(self, connection):
        segment = self.config.get("rfc2307")
        groups_base_qry = openshift_ldap_build_base_query(segment["groupsQuery"])
        users_base_qry = openshift_ldap_build_base_query(segment["usersQuery"])

        groups_query = OpenshiftLDAPQueryOnAttribute(
            groups_base_qry, segment["groupUIDAttribute"]
        )
        users_query = OpenshiftLDAPQueryOnAttribute(
            users_base_qry, segment["userUIDAttribute"]
        )

        params = dict(
            connection=connection,
            groupQuery=groups_query,
            groupNameAttributes=segment["groupNameAttributes"],
            groupMembershipAttributes=segment["groupMembershipAttributes"],
            userQuery=users_query,
            userNameAttributes=segment["userNameAttributes"],
            config=segment,
        )
        return OpenshiftLDAPInterface(**params)

    def get_username_for_entry(self, entry):
        username = openshift_ldap_get_attribute_for_entry(
            entry, self.ldap_interface.userNameAttributes
        )
        if not username:
            return (
                None,
                "The user entry (%s) does not map to a OpenShift User name with the given mapping"
                % entry,
            )
        return username, None

    def get_group_name_for_uid(self, uid):
        # Get name from User defined mapping
        groupuid_name_mapping = self.config.get("groupUIDNameMapping")
        if groupuid_name_mapping and uid in groupuid_name_mapping:
            return groupuid_name_mapping.get(uid), None
        elif self.ldap_interface.groupNameAttributes:
            group, err = self.ldap_interface.get_group_entry(uid)
            if err:
                return None, err
            group_name = openshift_ldap_get_attribute_for_entry(
                group, self.ldap_interface.groupNameAttributes
            )
            if not group_name:
                error = (
                    "The group entry (%s) does not map to an OpenShift Group name with the given name attribute (%s)"
                    % (group, self.ldap_interface.groupNameAttributes)
                )
                return None, error
            if isinstance(group_name, list):
                group_name = group_name[0]
            return group_name, None
        else:
            return None, "No OpenShift Group name defined for LDAP group UID: %s" % uid

    def is_ldapgroup_exists(self, uid):
        group, err = self.ldap_interface.get_group_entry(uid)
        if err:
            if (
                err == LDAP_SEARCH_OUT_OF_SCOPE_ERROR
                or err.startswith("Entry not found")
                or "non-existent entry" in err
            ):
                return False, None
            return False, err
        if group:
            return True, None
        return False, None

    def list_groups(self):
        return self.ldap_interface.list_groups()

    def extract_members(self, uid):
        return self.ldap_interface.extract_members(uid)


class OpenshiftLDAP_ADInterface(object):
    def __init__(self, connection, user_query, group_member_attr, user_name_attr):
        self.connection = connection
        self.userQuery = user_query
        self.groupMembershipAttributes = group_member_attr
        self.userNameAttributes = user_name_attr

        self.required_user_attributes = self.userNameAttributes or []
        for attr in self.groupMembershipAttributes:
            if attr not in self.required_user_attributes:
                self.required_user_attributes.append(attr)

        self.cache = {}
        self.cache_populated = False

    def is_entry_present(self, cache_item, entry):
        for item in cache_item:
            if item[0] == entry[0]:
                return True
        return False

    def populate_cache(self):
        if not self.cache_populated:
            self.cache_populated = True
            entries, err = self.userQuery.ldap_search(
                self.connection, self.required_user_attributes
            )
            if err:
                return err

            for entry in entries:
                for group_attr in self.groupMembershipAttributes:
                    uids = openshift_ldap_get_attribute_for_entry(entry, group_attr)
                    if not isinstance(uids, list):
                        uids = [uids]
                    for uid in uids:
                        if uid not in self.cache:
                            self.cache[uid] = []
                        if not self.is_entry_present(self.cache[uid], entry):
                            self.cache[uid].append(entry)
        return None

    def list_groups(self):
        err = self.populate_cache()
        if err:
            return None, err
        result = []
        if self.cache:
            result = self.cache.keys()
        return result, None

    def extract_members(self, uid):
        # ExtractMembers returns the LDAP member entries for a group specified with a ldapGroupUID
        # if we already have it cached, return the cached value
        if uid in self.cache:
            return self.cache[uid], None

        # This happens in cases where we did not list out every group.
        # In that case, we're going to be asked about specific groups.
        users_in_group = []
        for attr in self.groupMembershipAttributes:
            query_on_attribute = OpenshiftLDAPQueryOnAttribute(self.userQuery.qry, attr)
            entries, error = query_on_attribute.ldap_search(
                self.connection, uid, self.required_user_attributes, unique_entry=False
            )
            if error and "not found" not in error:
                return None, error
            if not entries:
                continue

            for entry in entries:
                if not self.is_entry_present(users_in_group, entry):
                    users_in_group.append(entry)

        self.cache[uid] = users_in_group
        return users_in_group, None


class OpenshiftLDAPActiveDirectory(object):
    def __init__(self, config, ldap_connection):
        self.config = config
        self.ldap_interface = self.create_ldap_interface(ldap_connection)

    def create_ldap_interface(self, connection):
        segment = self.config.get("activeDirectory")
        base_query = openshift_ldap_build_base_query(segment["usersQuery"])
        user_query = OpenshiftLDAPQuery(base_query)

        return OpenshiftLDAP_ADInterface(
            connection=connection,
            user_query=user_query,
            group_member_attr=segment["groupMembershipAttributes"],
            user_name_attr=segment["userNameAttributes"],
        )

    def get_username_for_entry(self, entry):
        username = openshift_ldap_get_attribute_for_entry(
            entry, self.ldap_interface.userNameAttributes
        )
        if not username:
            return (
                None,
                "The user entry (%s) does not map to a OpenShift User name with the given mapping"
                % entry,
            )
        return username, None

    def get_group_name_for_uid(self, uid):
        return uid, None

    def is_ldapgroup_exists(self, uid):
        members, error = self.extract_members(uid)
        if error:
            return False, error
        exists = members and len(members) > 0
        return exists, None

    def list_groups(self):
        return self.ldap_interface.list_groups()

    def extract_members(self, uid):
        return self.ldap_interface.extract_members(uid)


class OpenshiftLDAP_AugmentedADInterface(OpenshiftLDAP_ADInterface):
    def __init__(
        self,
        connection,
        user_query,
        group_member_attr,
        user_name_attr,
        group_qry,
        group_name_attr,
    ):
        super(OpenshiftLDAP_AugmentedADInterface, self).__init__(
            connection, user_query, group_member_attr, user_name_attr
        )
        self.groupQuery = copy.deepcopy(group_qry)
        self.groupNameAttributes = group_name_attr

        self.required_group_attributes = [self.groupQuery.query_attribute]
        for x in self.groupNameAttributes:
            if x not in self.required_group_attributes:
                self.required_group_attributes.append(x)

        self.cached_groups = {}

    def get_group_entry(self, uid):
        """
        get_group_entry returns an LDAP group entry for the given group UID by searching the internal cache
        of the LDAPInterface first, then sending an LDAP query if the cache did not contain the entry.
        """
        if uid in self.cached_groups:
            return self.cached_groups.get(uid), None

        group, err = self.groupQuery.ldap_search(
            self.connection, uid, self.required_group_attributes
        )
        if err:
            return None, err
        self.cached_groups[uid] = group
        return group, None

    def exists(self, ldapuid):
        # Get group members
        members, error = self.extract_members(ldapuid)
        if error:
            return False, error
        group_exists = bool(members)

        # Check group Existence
        entry, error = self.get_group_entry(ldapuid)
        if error:
            if "not found" in error:
                return False, None
            else:
                return False, error
        else:
            return group_exists and bool(entry), None


class OpenshiftLDAPAugmentedActiveDirectory(OpenshiftLDAPRFC2307):
    def __init__(self, config, ldap_connection):
        self.config = config
        self.ldap_interface = self.create_ldap_interface(ldap_connection)

    def create_ldap_interface(self, connection):
        segment = self.config.get("augmentedActiveDirectory")
        user_base_query = openshift_ldap_build_base_query(segment["usersQuery"])
        groups_base_qry = openshift_ldap_build_base_query(segment["groupsQuery"])

        user_query = OpenshiftLDAPQuery(user_base_query)
        groups_query = OpenshiftLDAPQueryOnAttribute(
            groups_base_qry, segment["groupUIDAttribute"]
        )

        return OpenshiftLDAP_AugmentedADInterface(
            connection=connection,
            user_query=user_query,
            group_member_attr=segment["groupMembershipAttributes"],
            user_name_attr=segment["userNameAttributes"],
            group_qry=groups_query,
            group_name_attr=segment["groupNameAttributes"],
        )

    def is_ldapgroup_exists(self, uid):
        return self.ldap_interface.exists(uid)
