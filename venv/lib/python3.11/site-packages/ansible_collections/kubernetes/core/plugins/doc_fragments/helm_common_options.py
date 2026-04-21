# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Ansible Project
# Copyright: (c) 2020, Red Hat Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Options for common Helm modules

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    DOCUMENTATION = r"""
options:
  binary_path:
    description:
      - The path of a helm binary to use.
    required: false
    type: path
  context:
    description:
      - Helm option to specify which kubeconfig context to use.
      - If the value is not specified in the task, the value of environment variable C(K8S_AUTH_CONTEXT) will be used instead.
    type: str
    aliases: [ kube_context ]
  kubeconfig:
    description:
      - Helm option to specify kubeconfig path to use.
      - If the value is not specified in the task, the value of environment variable C(K8S_AUTH_KUBECONFIG) will be used instead.
      - The configuration can be provided as dictionary. Added in version 2.4.0.
    type: raw
    aliases: [ kubeconfig_path ]
  host:
    description:
    - Provide a URL for accessing the API. Can also be specified via C(K8S_AUTH_HOST) environment variable.
    type: str
    version_added: 1.2.0
  api_key:
    description:
    - Token used to authenticate with the API. Can also be specified via C(K8S_AUTH_API_KEY) environment variable.
    type: str
    version_added: 1.2.0
  validate_certs:
    description:
    - Whether or not to verify the API server's SSL certificates. Can also be specified via C(K8S_AUTH_VERIFY_SSL)
      environment variable.
    type: bool
    aliases: [ verify_ssl ]
    default: True
    version_added: 1.2.0
  ca_cert:
    description:
    - Path to a CA certificate used to authenticate with the API. The full certificate chain must be provided to
      avoid certificate validation errors. Can also be specified via C(K8S_AUTH_SSL_CA_CERT) environment variable.
    type: path
    aliases: [ ssl_ca_cert ]
    version_added: 1.2.0
"""
