# -*- coding: utf-8 -*-
# Copyright 2024 Red Hat, Inc.
# Based on the kubernetes.core.k8s_auth_options doc fragment
# Apache License 2.0 (see LICENSE or http://www.apache.org/licenses/LICENSE-2.0)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    DOCUMENTATION = """
options:
  host:
    description:
    - Provide a URL for accessing the API.
    - Can also be specified via E(K8S_AUTH_HOST) environment variable.
    type: str
  api_key:
    description:
    - Token used to authenticate with the API.
    - Can also be specified via E(K8S_AUTH_API_KEY) environment variable.
    type: str
  kubeconfig:
    description:
    - Path to an existing Kubernetes config file. If not provided, and no other connection
      options are provided, the Kubernetes client will attempt to load the default
      configuration file from I(~/.kube/config).
    - Can also be specified via E(K8S_AUTH_KUBECONFIG) environment variable.
    - Multiple Kubernetes config file can be provided using separator C(;) for Windows platform or C(:) for others platforms.
    - The kubernetes configuration can be provided as dictionary. This feature requires a python kubernetes client version >= 17.17.0.
    type: raw
  context:
    description:
    - The name of a context found in the config file.
    - Can also be specified via E(K8S_AUTH_CONTEXT) environment variable.
    type: str
  username:
    description:
    - Provide a username for authenticating with the API.
    - Can also be specified via E(K8S_AUTH_USERNAME) environment variable.
    type: str
  password:
    description:
    - Provide a password for authenticating with the API.
    - Can also be specified via E(K8S_AUTH_PASSWORD) environment variable.
    - Please read the description of the O(username) option for a discussion of when this option is applicable.
    type: str
  client_cert:
    description:
    - Path to a certificate used to authenticate with the API.
    - Can also be specified via E(K8S_AUTH_CERT_FILE) environment variable.
    type: path
    aliases: [ cert_file ]
  client_key:
    description:
    - Path to a key file used to authenticate with the API.
    - Can also be specified via E(K8S_AUTH_KEY_FILE) environment variable.
    type: path
    aliases: [ key_file ]
  ca_cert:
    description:
    - Path to a CA certificate used to authenticate with the API. The full certificate chain must be provided to
      avoid certificate validation errors.
    - Can also be specified via E(K8S_AUTH_SSL_CA_CERT) environment variable.
    type: path
    aliases: [ ssl_ca_cert ]
  validate_certs:
    description:
    - Whether or not to verify the API server's SSL certificates.
    - Can also be specified via E(K8S_AUTH_VERIFY_SSL) environment variable.
    type: bool
    aliases: [ verify_ssl ]
  proxy:
    description:
    - The URL of an HTTP proxy to use for the connection.
    - Can also be specified via E(K8S_AUTH_PROXY) environment variable.
    - Please note that this module does not pick up typical proxy settings from the environment (e.g. E(HTTP_PROXY)).
    type: str
  no_proxy:
    description:
    - The comma separated list of hosts/domains/IP/CIDR that shouldn't go through proxy.
    - Can also be specified via E(K8S_AUTH_NO_PROXY) environment variable.
    - Please note that this module does not pick up typical proxy settings from the environment (e.g. E(NO_PROXY)).
    - This feature requires C(kubernetes>=19.15.0). When kubernetes library is less than 19.15.0, it fails even no_proxy set in correct.
    - Example value is C(localhost,.local,.example.com,127.0.0.1,127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16).
    type: str
  proxy_headers:
    description:
    - The Header used for the HTTP proxy.
    - Documentation can be found here U(https://urllib3.readthedocs.io/en/latest/reference/urllib3.util.html?highlight=proxy_headers#urllib3.util.make_headers).
    type: dict
    suboptions:
      proxy_basic_auth:
        description:
        - Colon-separated username:password for proxy basic authentication header.
        - Can also be specified via E(K8S_AUTH_PROXY_HEADERS_PROXY_BASIC_AUTH) environment variable.
        type: str
      basic_auth:
        description:
        - Colon-separated username:password for basic authentication header.
        - Can also be specified via E(K8S_AUTH_PROXY_HEADERS_BASIC_AUTH) environment variable.
        type: str
      user_agent:
        description:
        - String representing the user-agent you want, such as foo/1.0.
        - Can also be specified via E(K8S_AUTH_PROXY_HEADERS_USER_AGENT) environment variable.
        type: str
  persist_config:
    description:
    - Whether or not to save the kube config refresh tokens.
    - Can also be specified via E(K8S_AUTH_PERSIST_CONFIG) environment variable.
    - When the k8s context is using a user credentials with refresh tokens (like oidc or gke/gcloud auth),
      the token is refreshed by the k8s python client library but not saved by default. So the old refresh token can
      expire and the next auth might fail. Setting this flag to true will tell the k8s python client to save the
      new refresh token to the kube config file.
    - Disabled by default.
    type: bool
  impersonate_user:
    description:
    - Username to impersonate for the operation.
    - Can also be specified via E(K8S_AUTH_IMPERSONATE_USER) environment variable.
    type: str
  impersonate_groups:
    description:
    - Group(s) to impersonate for the operation.
    - Can also be specified via E(K8S_AUTH_IMPERSONATE_GROUPS) environment variable, e.g. C(Group1,Group2).
    type: list
    elements: str
notes:
  - "To avoid SSL certificate validation errors when O(validate_certs=yes), the full
    certificate chain for the API server must be provided via O(ca_cert) or in the
    O(kubeconfig) file."
"""
