#!/usr/bin/python
#
# Copyright 2025 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: docker_context_info

short_description: Retrieve information on Docker contexts for the current user

version_added: 4.4.0

description:
  - Return information on Docker contexts.
  - This includes some generic information, as well as a RV(contexts[].config) dictionary that can be used for module defaults for all community.docker modules
    that use the C(community.docker.docker) module defaults group.
extends_documentation_fragment:
  - community.docker.attributes
  - community.docker.attributes.info_module
  - community.docker.attributes.idempotent_not_modify_state

options:
  only_current:
    description:
      - If set to V(true), RV(contexts) will just contain the current context and none else.
      - If set to V(false) (default), RV(contexts) will list all contexts, unless O(name) is specified.
      - Mutually exclusive to O(name).
    type: bool
    default: false
  name:
    description:
      - A specific Docker CLI context to query.
      - The module will fail if this context does not exist. If you simply want to query whether a context exists,
        do not specify this parameter and use Jinja2 to search the resulting list for a context of the given name instead.
      - Mutually exclusive with O(only_current).
    type: str
  cli_context:
    description:
      - Override for the default context's name.
      - This is preferably used for context selection when O(only_current=true),
        and it is used to compute the return values RV(contexts[].current) and RV(current_context_name).
    type: str

author:
  - "Felix Fontein (@felixfontein)"
"""

EXAMPLES = r"""
---
- name: Get infos on contexts
  community.docker.docker_context_info:
  register: result

- name: Show all contexts
  ansible.builtin.debug:
    msg: "{{ result.contexts }}"

- name: Get current context
  community.docker.docker_context_info:
    only_current: true
  register: docker_current_context

- name: Run community.docker modules with current context
  module_defaults:
    group/community.docker.docker: "{{ docker_current_context.contexts[0].config }}"
  block:
    - name: Task using the current context
      community.docker.docker_container:
        image: ubuntu:latest
        name: ubuntu
        state: started
"""

RETURN = r"""
contexts:
  description:
    - A list of all contexts (O(only_current=false), O(name) not specified),
      only the current context (O(only_current=true)),
      or the requested context (O(name) specified).
  type: list
  elements: dict
  returned: success
  contains:
    current:
      description:
        - Whether this context is the current one.
      type: bool
      returned: success
      sample: true
    name:
      description:
        - The context's name.
      type: bool
      returned: success
      sample: default
    description:
      description:
        - The context's description, if available.
      type: bool
      returned: success
      sample: My context
    meta_path:
      description:
        - The path to the context's meta directory.
        - Not present for RV(contexts[].name=default).
      type: str
      returned: success
      sample: /home/felix/.docker/contexts/meta/0123456789abcdef01234567890abcdef0123456789abcdef0123456789abcde
    tls_path:
      description:
        - The path to the context's TLS config directory.
        - Not present for RV(contexts[].name=default).
      type: str
      returned: success
      sample: /home/user/.docker/contexts/tls/0123456789abcdef01234567890abcdef0123456789abcdef0123456789abcde/
    config:
      description:
        - In case the context is for Docker, contains option values to configure the community.docker modules to use this context.
        - Note that the exact values returned here and their values might change over time if incompatibilities to existing modules are found.
          The goal is that this configuration works fine with all modules in this collection, but we do not have the capabilities to
          test all possible configuration options at the moment.
      type: dict
      returned: success
      sample: {}
      contains:
        docker_host:
          description:
            - The Docker daemon to connect to.
          type: str
          returned: success and context is for Docker
          sample: unix:///var/run/docker.sock
        tls:
          description:
            - Whether the Docker context should use an unvalidated TLS connection.
          type: bool
          returned: success and context is for Docker
          sample: false
        ca_path:
          description:
            - The CA certificate used to validate the Docker daemon's certificate.
          type: bool
          returned: success, context is for Docker, TLS config is present, and CA cert is present
          sample: /path/to/ca-cert.pem
        client_cert:
          description:
            - The client certificate to authenticate with to the Docker daemon.
          type: bool
          returned: success, context is for Docker, TLS config is present, and client cert info is present
          sample: /path/to/client-cert.pem
        client_key:
          description:
            - The client certificate's key to authenticate with to the Docker daemon.
          type: bool
          returned: success, context is for Docker, TLS config is present, and client cert info is present
          sample: /path/to/client-key.pem
        validate_certs:
          description:
            - Whether the Docker context should use a validated TLS connection.
          type: bool
          returned: success, context is for Docker, and TLS config is present
          sample: true

current_context_name:
  description:
    - The name of the current Docker context.
  type: str
  returned: success
  sample: default
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native, to_text
from ansible_collections.community.docker.plugins.module_utils._six import string_types

from ansible_collections.community.docker.plugins.module_utils._api.context.api import (
    ContextAPI,
)
from ansible_collections.community.docker.plugins.module_utils._api.context.config import (
    get_current_context_name_with_source,
)
from ansible_collections.community.docker.plugins.module_utils._api.context.context import (
    IN_MEMORY,
)
from ansible_collections.community.docker.plugins.module_utils._api.errors import (
    ContextException,
    DockerException,
)


def tls_context_to_json(context):
    if context is None:
        return None
    return {
        'client_cert': context.cert[0] if context.cert else None,
        'client_key': context.cert[1] if context.cert else None,
        'ca_cert': context.ca_cert,
        'verify': context.verify,
        # 'ssl_version': context.ssl_version,  -- this isn't used anymore
    }


def to_bool(value):
    return True if value else False


def context_to_json(context, current):
    module_config = {}
    if 'docker' in context.endpoints:
        endpoint = context.endpoints['docker']
        if isinstance(endpoint.get('Host'), string_types):
            host_str = to_text(endpoint['Host'])

            # Adjust protocol name so that it works with the Docker CLI tool as well
            proto = None
            idx = host_str.find('://')
            if idx >= 0:
                proto = host_str[:idx]
                host_str = host_str[idx + 3:]
            if proto in ('http', 'https'):
                proto = 'tcp'
            if proto == 'http+unix':
                proto = 'unix'
            if proto:
                host_str = "{0}://{1}".format(proto, host_str)

            # Create config for the modules
            module_config['docker_host'] = host_str
            if context.tls_cfg.get('docker'):
                tls_cfg = context.tls_cfg['docker']
                if tls_cfg.ca_cert:
                    module_config['ca_path'] = tls_cfg.ca_cert
                if tls_cfg.cert:
                    module_config['client_cert'] = tls_cfg.cert[0]
                    module_config['client_key'] = tls_cfg.cert[1]
                module_config['validate_certs'] = tls_cfg.verify
                module_config['tls'] = True
            else:
                module_config['tls'] = to_bool(endpoint.get('SkipTLSVerify'))
    return {
        'current': current,
        'name': context.name,
        'description': context.description,
        'meta_path': None if context.meta_path is IN_MEMORY else context.meta_path,
        'tls_path': None if context.tls_path is IN_MEMORY else context.tls_path,
        'config': module_config,
    }


def main():
    argument_spec = dict(
        only_current=dict(type='bool', default=False),
        name=dict(type='str'),
        cli_context=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("only_current", "name"),
        ],
    )

    try:
        if module.params['cli_context']:
            current_context_name, current_context_source = module.params['cli_context'], "cli_context module option"
        else:
            current_context_name, current_context_source = get_current_context_name_with_source()
        if module.params['name']:
            contexts = [ContextAPI.get_context(module.params['name'])]
            if not contexts[0]:
                module.fail_json(msg="There is no context of name {name!r}".format(name=module.params['name']))
        elif module.params['only_current']:
            contexts = [ContextAPI.get_context(current_context_name)]
            if not contexts[0]:
                module.fail_json(
                    msg="There is no context of name {name!r}, which is configured as the default context ({source})".format(
                        name=current_context_name,
                        source=current_context_source,
                    ),
                )
        else:
            contexts = ContextAPI.contexts()

        json_contexts = sorted([
            context_to_json(context, context.name == current_context_name)
            for context in contexts
        ], key=lambda entry: entry['name'])

        module.exit_json(
            changed=False,
            contexts=json_contexts,
            current_context_name=current_context_name,
        )
    except ContextException as e:
        module.fail_json(msg='Error when handling Docker contexts: {0}'.format(to_native(e)), exception=traceback.format_exc())
    except DockerException as e:
        module.fail_json(msg='An unexpected Docker error occurred: {0}'.format(to_native(e)), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
