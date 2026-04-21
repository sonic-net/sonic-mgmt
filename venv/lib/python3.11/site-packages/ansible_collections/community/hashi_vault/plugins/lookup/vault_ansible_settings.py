# (c) 2022, Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
name: vault_ansible_settings
version_added: 2.5.0
author:
  - Brian Scholer (@briantist)
short_description: Returns plugin settings (options)
description:
  - Returns a dictionary of options and their values for a given plugin.
  - This is most useful for using plugin settings in modules and C(module_defaults),
    especially when common settings are set in C(ansible.cfg), in Ansible vars, or via environment variables on the controller.
  - Options can be filtered by name, and can include or exclude defaults, unset options, and private options.
seealso:
  - ref: Module defaults <module_defaults>
    description: Using the C(module_defaults) keyword.
notes:
  - This collection supports some "low precedence" environment variables that get loaded after all other sources, such as C(VAULT_ADDR).
  - These environment variables B(are not supported) with this plugin.
  - If you wish to use them, use the R(ansible.builtin.env lookup,ansible_collections.ansible.builtin.env_lookup) to
    load them directly when calling a module or setting C(module_defaults).
  - Similarly, any options that rely on additional processing to fill in their values will not have that done.
  - For example, tokens will not be loaded from the token sink file, auth methods will not have their C(validate) methods called.
  - See the examples for workarounds, but consider using Ansible-specific ways of setting these values instead.
options:
  _terms:
    description:
      - The names of the options to load.
      - Supports C(fnmatch) L(style wildcards,https://docs.python.org/3/library/fnmatch.html).
      - Prepend any name or pattern with C(!) to invert the match.
    type: list
    elements: str
    required: false
    default: ['*']
  plugin:
    description:
      - The name of the plugin whose options will be returned.
      - Only lookups are supported.
      - Short names (without a dot C(.)) will be fully qualified with C(community.hashi_vault).
    type: str
    default: community.hashi_vault.vault_login
  include_private:
    description: Include options that begin with underscore C(_).
    type: bool
    default: false
  include_none:
    description: Include options whose value is C(None) (this usually means they are unset).
    type: bool
    default: false
  include_default:
    description: Include options whose value comes from a default.
    type: bool
    default: false
'''

EXAMPLES = r'''
### In these examples, we assume an ansible.cfg like this:
# [hashi_vault_collection]
# url = https://config-based-vault.example.com
# retries = 5
### end ansible.cfg

### We assume some environment variables set as well
# ANSIBLE_HASHI_VAULT_URL: https://env-based-vault.example.com
# ANSIBLE_HASHI_VAULT_TOKEN: s.123456789
### end environment variables

# playbook - ansible-core 2.12 and higher
## set defaults for the collection group
- hosts: all
  vars:
    ansible_hashi_vault_auth_method: token
  module_defaults:
    group/community.hashi_vault.vault: "{{ lookup('community.hashi_vault.vault_ansible_settings') }}"
  tasks:
    - name: Get a secret from the remote host with settings from the controller
      community.hashi_vault.vault_kv2_get:
        path: app/some/secret
######

# playbook - ansible any version
## set defaults for a specific module
- hosts: all
  vars:
    ansible_hashi_vault_auth_method: token
  module_defaults:
    community.hashi_vault.vault_kv2_get: "{{ lookup('community.hashi_vault.vault_ansible_settings') }}"
  tasks:
    - name: Get a secret from the remote host with settings from the controller
      community.hashi_vault.vault_kv2_get:
        path: app/some/secret
######

# playbook - ansible any version
## set defaults for several modules
## do not use controller's auth
- hosts: all
  vars:
    ansible_hashi_vault_auth_method: aws_iam
    settings: "{{ lookup('community.hashi_vault.vault_ansible_settings', '*', '!*token*') }}"
  module_defaults:
    community.hashi_vault.vault_kv2_get: '{{ settings }}'
    community.hashi_vault.vault_kv1_get: '{{ settings }}'
  tasks:
    - name: Get a secret from the remote host with some settings from the controller, auth from remote
      community.hashi_vault.vault_kv2_get:
        path: app/some/secret

    - name: Same with kv1
      community.hashi_vault.vault_kv1_get:
        path: app/some/secret
######

# playbook - ansible any version
## set defaults for several modules
## do not use controller's auth
## override returned settings
- hosts: all
  vars:
    ansible_hashi_vault_auth_method: userpass
    plugin_settings: "{{ lookup('community.hashi_vault.vault_ansible_settings', '*', '!*token*') }}"
    overrides:
      auth_method: aws_iam
      retries: '{{ (plugin_settings.retries | int) + 2 }}'
    settings: >-
      {{
        plugin_settings
        | combine(overrides)
      }}
  module_defaults:
    community.hashi_vault.vault_kv2_get: '{{ settings }}'
    community.hashi_vault.vault_kv1_get: '{{ settings }}'
  tasks:
    - name: Get a secret from the remote host with some settings from the controller, auth from remote
      community.hashi_vault.vault_kv2_get:
        path: app/some/secret

    - name: Same with kv1
      community.hashi_vault.vault_kv1_get:
        path: app/some/secret
######

# using a block is similar
- name: Settings
  vars:
    ansible_hashi_vault_auth_method: aws_iam
    settings: "{{ lookup('community.hashi_vault.vault_ansible_settings', '*', '!*token*') }}"
  module_defaults:
    community.hashi_vault.vault_kv2_get: '{{ settings }}'
    community.hashi_vault.vault_kv1_get: '{{ settings }}'
  block:
    - name: Get a secret from the remote host with some settings from the controller, auth from remote
      community.hashi_vault.vault_kv2_get:
        path: app/some/secret

    - name: Same with kv1
      community.hashi_vault.vault_kv1_get:
        path: app/some/secret
#####

# use settings from a different plugin
## when you need settings that are not in the default plugin (vault_login)
- name: Settings
  vars:
    ansible_hashi_vault_engine_mount_point: dept-secrets
    settings: "{{ lookup('community.hashi_vault.vault_ansible_settings', plugin='community.hashi_vault.vault_kv2_get') }}"
  module_defaults:
    community.hashi_vault.vault_kv2_get: '{{ settings }}'
  block:
    - name: Get a secret from the remote host with some settings from the controller, auth from remote
      community.hashi_vault.vault_kv2_get:
        path: app/some/secret
#####

# use settings from a different plugin (on an indivdual call)
## short names assume community.hashi_vault
- name: Settings
  vars:
    ansible_hashi_vault_engine_mount_point: dept-secrets
    settings: "{{ lookup('community.hashi_vault.vault_ansible_settings') }}"
  module_defaults:
    community.hashi_vault.vault_kv2_get: '{{ settings }}'
  block:
    - name: Get a secret from the remote host with some settings from the controller, auth from remote
      community.hashi_vault.vault_kv2_get:
        engine_mount_point: "{{ lookup('community.hashi_vault.vault_ansible_settings', plugin='vault_kv2_get') }}"
        path: app/some/secret
#####

# normally, options with default values are not returned, but can be
- name: Settings
  vars:
    settings: "{{ lookup('community.hashi_vault.vault_ansible_settings') }}"
  module_defaults:
    # we usually want to use the remote host's IAM auth
    community.hashi_vault.vault_kv2_get: >-
      {{
        settings
        | combine({'auth_method': aws_iam})
      }}
  block:
    - name: Use the plugin auth method instead, even if it is the default method
      community.hashi_vault.vault_kv2_get:
        auth_method: "{{ lookup('community.hashi_vault.vault_ansible_settings', 'auth_method', include_default=True) }}"
        path: app/some/secret
#####

# normally, options with None/null values are not returned,
# nor are private options (names begin with underscore _),
# but they can be returned too if desired
- name: Show all plugin settings
  ansible.builtin.debug:
    msg: "{{ lookup('community.hashi_vault.vault_ansible_settings', include_none=True, include_private=True, include_default=True) }}"
#####

# dealing with low-precedence env vars and token sink loading
## here, VAULT_ADDR is usually used with plugins, but that will not work with vault_ansible_settings.
## additionally, the CLI `vault login` is used before running Ansible, so the token sink is usually used, which also will not work.
- hosts: all
  vars:
    plugin_settings: "{{ lookup('community.hashi_vault.vault_ansible_settings', 'url', 'token*', include_default=True) }}"
    overrides:
      url: "{{ plugin_settings.url | default(lookup('ansible.builtin.env', 'VAULT_ADDR')) }}"
      token: >-
        {{
          plugin_settings.token
          | default(
            lookup(
              'ansible.builtin.file',
              (
                plugin_settings.token_path | default(lookup('ansible.builtin.env', 'HOME')),
                plugin_settings.token_file
              ) | path_join
            )
          )
        }}
      auth_method: token
    settings: >-
      {{
        plugin_settings
        | combine(overrides)
      }}
  module_defaults:
    community.hashi_vault.vault_kv2_get: "{{ lookup('community.hashi_vault.vault_ansible_settings') }}"
  tasks:
    - name: Get a secret from the remote host with settings from the controller
      community.hashi_vault.vault_kv2_get:
        path: app/some/secret
#####
'''

RETURN = r'''
_raw:
  description:
    - A dictionary of the options and their values.
    - Only a single dictionary will be returned, even with multiple terms.
  type: dict
  sample:
    retries: 5
    timeout: 20
    token: s.jRHAoqElnJDx6J5ExYelCDYR
    url: https://vault.example.com
'''

from fnmatch import fnmatchcase

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible import constants as C
from ansible.plugins.loader import lookup_loader
from ansible.utils.display import Display


display = Display()


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        self.set_options(direct=kwargs, var_options=variables)

        include_private = self.get_option('include_private')
        include_none = self.get_option('include_none')
        include_default = self.get_option('include_default')

        plugin = self.get_option('plugin')
        if '.' not in plugin:
            plugin = 'community.hashi_vault.' + plugin

        if not terms:
            terms = ['*']

        opts = {}

        try:
            # ansible-core 2.10 or later
            p = lookup_loader.find_plugin_with_context(plugin)
            loadname = p.plugin_resolved_name
            resolved = p.resolved
        except AttributeError:
            # ansible 2.9
            p = lookup_loader.find_plugin_with_name(plugin)
            loadname = p[0]
            resolved = loadname is not None

        if not resolved:
            raise AnsibleError("'%s' plugin not found." % plugin)

        # Loading ensures that the options are initialized in ConfigManager
        lookup_loader.get(plugin, class_only=True)

        pluginget = C.config.get_configuration_definitions('lookup', loadname)

        for option in pluginget.keys():
            if not include_private and option.startswith('_'):
                continue

            keep = False
            for pattern in terms:
                if pattern.startswith('!'):
                    if keep and fnmatchcase(option, pattern[1:]):
                        keep = False
                else:
                    keep = keep or fnmatchcase(option, pattern)

            if not keep:
                continue

            value, origin = C.config.get_config_value_and_origin(option, None, 'lookup', loadname, None, variables=variables)
            if (include_none or value is not None) and (include_default or origin != 'default'):
                opts[option] = value

        return [opts]
