# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
name: ldap
author: Jordan Borean (@jborean93)
short_description: Inventory plugin for Active Directory
version_added: 1.1.0
description:
- Inventory plugin for Active Directory or other LDAP sources.
- Uses a YAML configuration file that ends with C(microsoft.ad.ldap.{yml|yaml}).
- Each host that is added will set the C(inventory_hostname) to the C(name) of
  the LDAP computer object and C(ansible_host) to the value of the
  C(dNSHostName) LDAP attribute if set. If the C(dNSHostName) attribute is not
  set on the computer object then C(ansible_host) is not set. See
  R(LDAP inventory hostname,ansible_collections.microsoft.ad.docsite.guide_ldap_inventory.inventory_hostname)
  for more information on how these values are set and how to adjust them.
- The host fact C(microsoft_ad_distinguished_name) will also be set to the
  distinguished name of the host that was used to derive the host entry.
- Any other fact that is needed, needs to be defined in the I(attributes)
  option.
options:
  attributes:
    description:
    - The LDAP attributes to retrieve.
    - The keys specified are the LDAP attributes requested and the values for
      each attribute is a dictionary that reflects what host var to set it to
      and how.
    - Each key of the inner dictionary value is the host variable name to set
      and the value is the template to use to derive the value. If no value is
      explicitly set then it will use the coerced value as returned from the
      LDAP attribute.
    - Attributes that are denoted as single value in the LDAP schema are
      returned as that single value, multi valued attributes are returned as a
      list of values.
    - See R(LDAP inventory attributes,ansible_collections.microsoft.ad.docsite.guide_ldap_inventory.attributes)
      for more information.
    default: {}
    type: dict
  filter:
    description:
    - The LDAP filter string used to query the computer objects.
    - By default, this will be combined with the filter
      "(objectCategory=computer)". Use I(filter_without_computer) to override
      this behavior and have I(filter) be the only filter used.
    type: str
  filter_without_computer:
    description:
    - Will not combine the I(filter) value with the default filter
      "(objectCategory=computer)".
    - In most cases this should be C(false) but can be set to C(true) to have
      the I(filter) value specified be the only filter used.
    type: bool
    default: false
    version_added: '1.3.0'
  search_base:
    description:
    - The LDAP search base to find the computer objects in.
    - Defaults to the C(defaultNamingContext) of the Active Directory server
      if not specified.
    - If searching a larger Active Directory database, it is recommended to
      narrow the search base to speed up the queries.
    type: str
  search_scope:
    description:
    - The scope of the LDAP search to perform.
    - C(base) will search only the current path or object specified by
      I(search_base). This is typically not useful for inventory plugins.
    - C(one_level) will search only the immediate child objects in
      I(search_base).
    - C(subtree) will search the immediate child objects and any nested
      objects in I(search_base).
    choices:
    - base
    - one_level
    - subtree
    default: subtree
    type: str
notes:
- See R(LDAP inventory,ansible_collections.microsoft.ad.docsite.guide_ldap_inventory)
  for more details on how to use this inventory plugin.
- See R(LAPS,ansible_collections.microsoft.ad.docsite.guide_ldap_inventory.laps)
  for more details on how this plugin can retrieve the LAPS password
  information.
- This plugin is a tech preview and the module options are subject to change
  based on feedback received.
- Unless specified otherwise in the option description, the value specified in
  the config file is used as is. Only the LDAP connection options allow using
  a Jinja2 template.
extends_documentation_fragment:
- constructed
- microsoft.ad.ldap_connection
"""

EXAMPLES = r"""
# Set in the file ending with microsoft.ad.ldap.yml or microsoft.ad.ldap.yaml
plugin: microsoft.ad.ldap


####################################################################
#                        Connection Options                        #
#                                                                  #
# These options control how the plugin connects to the LDAP server #
####################################################################

# Connects to ldap://dc01.domain.com:389
server: dc01.domain.com
port: 389

# Connects to ldaps://dc01.domain.com:636
server: dc01.domain.com
tls_mode: ldaps

# Connects to the global catalog
# ldap://dc01.domain.com:3268
server: dc01.domain.com
port: 3268

# Provides explicit user, will use the current Kerberos ticket if no credential
# is provided.
username: domain-user@DOMAIN.COM
password: Password123!

# Only allow Kerberos authentication.
auth_protocol: kerberos

# Verify LDAPS CA chain with custom CA chain.
tls_mode: ldaps
ca_cert: /home/user/certs/ldap.pem

# The username and password can be retrieved using a template with a lookup.
# Other connection options can also be set this way, the option description
# tells you whether it can be set to a template.
username: '{{ lookup("ansible.builtin.env", "LDAP_USERNAME") }}'
password: '{{ lookup("ansible.builtin.env", "LDAP_PASSWORD") }}'


##############################################
#               Search Options               #
#                                            #
# These options control the searching rules  #
##############################################

# Search for computer accounts in the Workshop OU.
search_base: OU=Workshop A,DC=domain,DC=com

# Filter the computer accounts returned for only ones with the dNSDomainName
# attribute set.
filter: (dNSDomainName=*)

# Filter computer accounts returned for ones starting with PROD and with the
# LAPS password set.
filter: (&(sAMAccountName=PROD*)(ms-Mcs-AdmPwd=*))

# See documentation for more details
attributes:
  sAMAccountName:
    sam_account_name:
  objectSid:
    computer_sid:
  pwdLastSet:
    password_last_set: this | microsoft.ad.as_datetime
  comment:
    host_comment
  memberOf:
    # Gets the value (1) of the first RDN (0) of each memberOf instance (this).
    # For example 'CN=Domain Admins,CN=Users,DC=domain,DC=test'
    # will be returned as just 'Domain Admins'
    computer_membership: this | microsoft.ad.parse_dn | map(attribute="0.1")
  location:


############################################################################
#                             LAPS Integration                             #
#                                                                          #
# Examples on how to use the new Windows LAPS values as connection options #
############################################################################

attributes:
  # msLAPS-Password is used if no encryption has been configured.
  # Currently an encrypted LAPS password is not supported.
  msLAPS-Password:
    ansible_user: (this | from_json).n
    ansible_password: (this | from_json).p

  # msLAPS-EncryptedPassword is used if encryption has been configured.
  # If the Python dpapi-ng library is installed the `this`` value will
  # contain the entry `value` which is the decrypted value. The ``info``
  # entry will contain the reason why the value could not be decrypted.
  msLAPS-EncryptedPassword:
    ansible_user: (this.value | from_json).n
    ansible_password: (this.value | from_json).p

  # ms-Mcs-AdmPwd is used for Legacy LAPS and stores just the password.
  # The username needs to be hardcoded as a string value for this template.
  ms-Mcs-AdmPwd:
    ansible_user: '"Administrator"'
    ansible_password: this


#####################################################################
#                        Constructed Options                        #
#                                                                   #
# These options control the constructed values like vars and groups #
#####################################################################

# Build composed host variables. Requires attributes to be set in the
# attributes option to be referenced here.
compose:
  host_var: computer_sid

# Conditionals that adds found hosts to the groups specified.
groups:
  # Adds all hosts to the windows group
  windows: true

  # Uses the memberOf fact documented above to place the host in the production
  # group if it's a member of that group
  production: '"Production Group" in computer_membership'

# Adds the host to a group site_{{ location }} with the default group of
# site_unknown if the location isn't defined
keyed_groups:
  - key: location | default(omit)
    prefix: site
    default_value: unknown
"""

import base64
import typing as t

from ansible.errors import AnsibleError
from ansible.inventory.data import InventoryData
from ansible.module_utils.basic import missing_required_lib
from ansible.parsing.dataloader import DataLoader
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable
from ansible.utils.unsafe_proxy import wrap_var

USE_DATA_TAGGING = False
try:
    from ansible.template import trust_as_template

    USE_DATA_TAGGING = True
except ImportError:
    pass


try:
    import sansldap

    from ..plugin_utils._ldap import create_ldap_connection
    from ..plugin_utils._ldap.schema import LDAPSchema
    from ..plugin_utils._ldap.laps import LAPSDecryptor

    HAS_LDAP = True
    LDAP_IMP_ERR = None
except Exception as e:
    HAS_LDAP = False
    LDAP_IMP_ERR = e


class InventoryModule(BaseInventoryPlugin, Constructable):
    NAME = "microsoft.ad.ldap"

    def verify_file(self, path: str) -> bool:
        if super().verify_file(path):
            return path.endswith(("microsoft.ad.ldap.yml", "microsoft.ad.ldap.yaml"))

        return False

    def parse(
        self,
        inventory: InventoryData,
        loader: DataLoader,
        path: str,
        cache: bool,
    ) -> None:
        super().parse(inventory, loader, path, cache)
        self.set_options()
        self._read_config_data(path)

        if not HAS_LDAP:
            msg = missing_required_lib(
                "sansldap and pyspnego",
                url="https://pypi.org/project/sansldap/ and https://pypi.org/project/pyspnego/",
                reason="for ldap lookups",
            )
            raise AnsibleError(f"{msg}: {LDAP_IMP_ERR}") from LDAP_IMP_ERR

        compose = self.get_option("compose")
        groups = self.get_option("groups")
        keyed_groups = self.get_option("keyed_groups")
        ldap_filter = self.get_option("filter")
        ldap_filter_without_computer = self.get_option("filter_without_computer")
        search_base = self.get_option("search_base")
        search_scope = self.get_option("search_scope")
        strict = self.get_option("strict")

        ldap_search_scope = {
            "base": sansldap.SearchScope.BASE,
            "one_level": sansldap.SearchScope.ONE_LEVEL,
            "subtree": sansldap.SearchScope.SUBTREE,
        }[search_scope]

        computer_filter = sansldap.FilterEquality("objectCategory", b"computer")
        final_filter: sansldap.LDAPFilter
        if ldap_filter:
            ldap_filter_obj = sansldap.LDAPFilter.from_string(ldap_filter)

            if ldap_filter_without_computer:
                final_filter = ldap_filter_obj
            else:
                final_filter = sansldap.FilterAnd(
                    filters=[computer_filter, ldap_filter_obj]
                )
        else:
            final_filter = computer_filter

        custom_attributes = self._get_custom_attributes()
        attributes = {"name", "dnshostname"}.union(
            [a.lower() for a in custom_attributes.keys()]
        )

        # If inventory_hostname was defined in compose, set it in the custom
        # attributes so we can set the hostname before processing the rest of
        # compose entries.
        inventory_hostname = compose.pop("inventory_hostname", None)
        if inventory_hostname:
            custom_attributes["inventory_hostname"] = {
                "inventory_hostname": inventory_hostname
            }
        connection_options = self.get_options()

        # These options are in ../doc_fragments/ldap_connection.py
        template_fields = {
            "auth_protocol",
            "ca_cert",
            "cert_validation",
            "certificate",
            "certificate_key",
            "certificate_password",
            "connection_timeout",
            "encrypt",
            "password",
            "port",
            "server",
            "tls_mode",
            "username",
        }
        templated_option_kwargs = {}
        if not USE_DATA_TAGGING:
            templated_option_kwargs['disable_lookups'] = False

        for option_name, option_value in connection_options.items():
            if option_name in template_fields and self.templar.is_template(
                option_value
            ):
                self.display.vvv(f"Templating option {option_name}")
                connection_options[option_name] = self.templar.template(
                    variable=option_value,
                    **templated_option_kwargs,
                )

        laps_decryptor = LAPSDecryptor(**connection_options)
        with create_ldap_connection(**connection_options) as client:
            schema = LDAPSchema.load_schema(client)

            for dn, info in client.search(
                filter=final_filter,
                attributes=list(attributes),
                search_base=search_base,
                search_scope=ldap_search_scope,
            ).items():
                insensitive_info = {k.lower(): v for k, v in info.items()}

                host_name = insensitive_info["name"][0].decode("utf-8")
                host_vars: t.Dict[str, t.Any] = {
                    "microsoft_ad_distinguished_name": dn,
                }

                dns_host_name = insensitive_info.get("dnshostname", None)
                if dns_host_name:
                    host_vars["ansible_host"] = dns_host_name[0].decode("utf-8")

                for name, var_info in custom_attributes.items():
                    raw_values = insensitive_info.get(name.lower(), [])
                    values = schema.cast_object(name, raw_values)

                    host_vars["raw"] = wrap_var(
                        [base64.b64encode(r).decode() for r in raw_values]
                    )

                    if name.lower() == "mslaps-encryptedpassword" and raw_values:
                        host_vars["this"] = wrap_var(laps_decryptor.decrypt(raw_values[0]))
                    else:
                        host_vars["this"] = wrap_var(values)

                    for n, v in var_info.items():
                        if USE_DATA_TAGGING:
                            v = trust_as_template(v)

                        try:
                            composite = self._compose(v, host_vars)
                        except Exception as e:
                            if strict:
                                raise AnsibleError(
                                    f"Could not set {n} for host {host_name}: {e}"
                                ) from e
                            continue

                        host_vars[n] = composite

                    host_vars.pop("raw")
                    host_vars.pop("this")

                actual_host_name = host_vars.get("inventory_hostname", host_name)
                inventory.add_host(actual_host_name)
                for n, v in host_vars.items():
                    if n == "inventory_hostname":
                        continue
                    inventory.set_variable(actual_host_name, n, v)

                self._set_composite_vars(
                    compose, host_vars, actual_host_name, strict=strict
                )
                self._add_host_to_composed_groups(
                    groups, host_vars, actual_host_name, strict=strict
                )
                self._add_host_to_keyed_groups(
                    keyed_groups, host_vars, actual_host_name, strict=strict
                )

    def _get_custom_attributes(self) -> t.Dict[str, t.Dict[str, str]]:
        custom_attributes = self.get_option("attributes")

        processed_attributes: t.Dict[str, t.Dict[str, str]] = {}
        for name, info in custom_attributes.items():
            if not info:
                info = {name.replace("-", "_"): "this"}
            elif isinstance(info, str):
                info = {name.replace("-", "_"): info}
            elif not isinstance(info, dict):
                raise AnsibleError(
                    f"Attribute {name} value was {type(info).__name__} but was expecting a dictionary"
                )

            for var_name in list(info.keys()):
                var_template = info[var_name]
                if not var_template:
                    info[var_name] = "this"

                elif not isinstance(var_template, str):
                    raise AnsibleError(
                        f"Attribute {name}.{var_name} template value was {type(var_template).__name__} but was expecting a string"
                    )

            processed_attributes[name] = info

        return processed_attributes
