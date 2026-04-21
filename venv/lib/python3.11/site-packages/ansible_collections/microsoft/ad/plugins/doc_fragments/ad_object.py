# -*- coding: utf-8 -*-

# Copyright (c) 2023 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


class ModuleDocFragment:

    # Common options for ansible_collections.microsoft.ad.plugins.module_utils._ADObject
    DOCUMENTATION = r"""
requirements:
- C(ActiveDirectory) PowerShell module
options:
  attributes:
    description:
    - The attributes to either add, remove, or set on the AD object.
    - The value of each attribute option should be a dictionary where the key
      is the LDAP attribute, e.g. C(firstName), C(comment) and the value is the
      value, or list of values, to set for that attribute.
    - The attribute value(s) can either be the raw string, integer, or bool
      value to add, remove, or set on the attribute in question.
    - The value can also be a dictionary with the I(type) key set to C(bytes),
      C(date_time), C(security_descriptor), or C(raw) and the value for this
      entry under the I(value) key.
    - The C(bytes) type has a value that is a base64 encoded string of the raw
      bytes to set.
    - The C(date_time) type has a value that is the ISO 8601 DateTime string of
      the DateTime to set. The DateTime will be set as the Microsoft FILETIME
      integer value which is the number of 100 nanoseconds since 1601-01-01 in
      UTC.
    - The C(security_descriptor) type has a value that is the Security
      Descriptor SDDL string used for the C(nTSecurityDescriptor) attribute.
    - The C(raw) type is the int, string, or boolean value to set.
    - String attribute values are compared using a case sensitive match on the
      AD object being managed.
    - See R(LDAP attributes help,ansible_collections.microsoft.ad.docsite.guide_attributes)
      for more information.
    default: {}
    type: dict
    suboptions:
      add:
        description:
        - A dictionary of all the attributes and their value(s) to add to the
          AD object being managed if they are not already present.
        - This is used for attributes that can contain multiple values, if the
          attribute only allows a single value, use I(set) instead.
        default: {}
        type: dict
      remove:
        description:
        - A dictionary of all the attributes and their value(s) to remove from
          the AD object being managed if they are present.
        - This is used for attributes that can contain multiple values, if the
          attribute only allows a single value, use I(set) instead.
        default: {}
        type: dict
      set:
        description:
        - A dictionary of all attributes and their value(s) to set on the AD
          object being managed.
        - This will replace any existing values if they do not match the ones
          being requested.
        - The order of attribute values are not checked only, only that the
          values requested are the only values on the object attribute.
        - Set this to null or an empty list to clear any values for the
          attribute.
        default: {}
        type: dict
  description:
    description:
    - The description of the AD object to set.
    - This is the value set on the C(description) LDAP attribute.
    type: str
  display_name:
    description:
    - The display name of the AD object to set.
    - This is the value of the C(displayName) LDAP attribute.
    type: str
  domain_credentials:
    description:
    - Specifies the credentials that should be used when using the server
      specified by I(name).
    - To specify credentials for the default domain server, use an entry
      without the I(name) key or use the I(domain_username) and
      I(domain_password) option.
    - This can be set under the R(play's module defaults,module_defaults_groups)
      under the C(group/microsoft.ad.domain) group.
    - See R(AD authentication in modules,ansible_collections.microsoft.ad.docsite.guide_ad_module_authentication)
      for more information.
    default: []
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The name of the server these credentials are for.
        - This value should correspond to the value used in other options that
          specify a custom server to use, for example an option that references
          an AD identity located on a different AD server.
        - This key can be omitted in one entry to specify the default
          credentials to use when a server is not specified instead of using
          I(domain_username) and I(domain_password).
        type: str
      username:
        description:
        - The username to use when connecting to the server specified by
          I(name).
        type: str
        required: true
      password:
        description:
        - The password to use when connecting to the server specified by
          I(name).
        type: str
        required: true
  domain_password:
    description:
    - The password for I(domain_username).
    - The I(domain_credentials) sub entry without a I(name) key can also be
      used to specify the credentials for the default domain authentication.
    - This can be set under the R(play's module defaults,module_defaults_groups)
      under the C(group/microsoft.ad.domain) group.
    type: str
  domain_server:
    description:
    - Specified the Active Directory Domain Services instance to connect to.
    - Can be in the form of an FQDN or NetBIOS name.
    - If not specified then the value is based on the default domain of the computer running PowerShell.
    - Custom credentials can be specified under a I(domain_credentials) entry
      without a I(name) key or through I(domain_username) and
      I(domain_password).
    - This can be set under the R(play's module defaults,module_defaults_groups)
      under the C(group/microsoft.ad.domain) group.
    type: str
  domain_username:
    description:
    - The username to use when interacting with AD.
    - If this is not set then the user that is used for authentication will be the connection user.
    - Ansible will be unable to use the connection user unless auth is Kerberos with credential delegation or CredSSP,
      or become is used on the task.
    - The I(domain_credentials) sub entry without a I(name) key can also be
      used to specify the credentials for the default domain authentication.
    - This can be set under the R(play's module defaults,module_defaults_groups)
      under the C(group/microsoft.ad.domain) group.
    type: str
  identity:
    description:
    - The identity of the AD object used to find the AD object to manage.
    - This must be specified if; I(name) is not set, when trying to rename the
      object with a new I(name), or when trying to move the object into a
      different I(path).
    - The identity can be in the form of a GUID representing the C(objectGUID)
      value, the C(userPrincipalName), C(sAMAccountName), C(objectSid), or
      C(distinguishedName).
    - If omitted, the AD object to manage is selected by the
      C(distinguishedName) using the format C(CN={{ name }},{{ path }}). If
      I(path) is not defined, the C(defaultNamingContext) is used instead.
    - When using the M(microsoft.ad.computer) module, the identity will
      automatically append C($) to the end of the C(sAMAccountName) if the
      provided value did not result in a match and did not already have a C($)
      at the end.
    type: str
  name:
    description:
    - The C(name) of the AD object to manage, this is not the C(sAMAccountName)
      of the object but the LDAP C(cn) or C(name) entry of the object in the
      path specified. Use I(identity) to select an object to manage by its
      C(sAMAccountName).
    - If I(identity) is specified, and the name of the object found by that
      identity does not match this value, the object will be renamed.
    - This must be specified if I(identity) is not set.
    type: str
  path:
    description:
    - The path of the OU or the container where the new object should exist in.
    - If creating a new object, the new object will be created at the path
      specified. If no path is specified then the C(defaultNamingContext) of
      the domain will be used as the path for most object types.
    - If managing an existing object found by I(identity), the path of the
      found object will be moved to the one specified by this option. If no
      path is specified, the object will not be moved.
    - The modules M(microsoft.ad.computer), M(microsoft.ad.user), and
      M(microsoft.ad.group) have their own default path that is
      configured on the Active Directory domain controller.
    - This can be set to the literal value C(microsoft.ad.default_path) which
      will equal the default value used when creating a new object.
    type: str
  protect_from_deletion:
    description:
    - Marks the object as protected from accidental deletion.
    - This applies a deny access right from deleting the object normally and
      the protection needs to be removed before the object can be deleted
      through the GUI or any other tool outside Ansible.
    - Using I(state=absent) will still delete the AD object even if it is
      marked as protected from deletion.
    type: bool
  state:
    description:
    - Set to C(present) to ensure the AD object exists.
    - Set to C(absent) to remove the AD object if it exists.
    - The option I(name) must be set when I(state=present).
    - Using C(absent) will recursively remove the AD object and any child
      objects if it's a container. It will also remove the AD object even if
      the object is marked as protected from accidental deletion.
    choices:
    - absent
    - present
    default: present
    type: str
notes:
- Some LDAP attributes can have only a single value set while others can have
  multiple. Some attributes are also read only and cannot be changed. It is
  recommended to look at the schema metadata for an attribute where
  C(System-Only) are read only values and C(Is-Single-Value) are attributes
  with only 1 value.
- Attempting to set multiple values to a C(Is-Single-Value) attribute results
  in undefined behaviour.
- If running on a server that is not a Domain Controller, credential
  delegation through CredSSP or Kerberos with delegation must be used or the
  I(domain_username), I(domain_password) must be set.
"""
