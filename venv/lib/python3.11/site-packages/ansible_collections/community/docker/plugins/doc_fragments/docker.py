# -*- coding: utf-8 -*-

# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    # Docker doc fragment
    DOCUMENTATION = r"""
options:
  docker_host:
    description:
      - The URL or Unix socket path used to connect to the Docker API. To connect to a remote host, provide the TCP connection
        string. For example, V(tcp://192.0.2.23:2376). If TLS is used to encrypt the connection, the module will automatically
        replace C(tcp) in the connection URL with C(https).
      - If the value is not specified in the task, the value of environment variable E(DOCKER_HOST) will be used instead.
        If the environment variable is not set, the default value will be used.
    type: str
    default: unix:///var/run/docker.sock
    aliases:
      - docker_url
  tls_hostname:
    description:
      - When verifying the authenticity of the Docker Host server, provide the expected name of the server.
      - If the value is not specified in the task, the value of environment variable E(DOCKER_TLS_HOSTNAME) will be used instead.
        If the environment variable is not set, the default value will be used.
      - Note that this option had a default value V(localhost) in older versions. It was removed in community.docker 3.0.0.
      - B(Note:) this option is no longer supported for Docker SDK for Python 7.0.0+. Specifying it with Docker SDK for Python
        7.0.0 or newer will lead to an error.
    type: str
  api_version:
    description:
      - The version of the Docker API running on the Docker Host.
      - Defaults to the latest version of the API supported by Docker SDK for Python and the docker daemon.
      - If the value is not specified in the task, the value of environment variable E(DOCKER_API_VERSION) will be used instead.
        If the environment variable is not set, the default value will be used.
    type: str
    default: auto
    aliases:
      - docker_api_version
  timeout:
    description:
      - The maximum amount of time in seconds to wait on a response from the API.
      - If the value is not specified in the task, the value of environment variable E(DOCKER_TIMEOUT) will be used instead.
        If the environment variable is not set, the default value will be used.
    type: int
    default: 60
  ca_path:
    description:
      - Use a CA certificate when performing server verification by providing the path to a CA certificate file.
      - If the value is not specified in the task and the environment variable E(DOCKER_CERT_PATH) is set, the file C(ca.pem)
        from the directory specified in the environment variable E(DOCKER_CERT_PATH) will be used.
      - This option was called O(ca_cert) and got renamed to O(ca_path) in community.docker 3.6.0. The old name has been added
        as an alias and can still be used.
    type: path
    aliases:
      - ca_cert
      - tls_ca_cert
      - cacert_path
  client_cert:
    description:
      - Path to the client's TLS certificate file.
      - If the value is not specified in the task and the environment variable E(DOCKER_CERT_PATH) is set, the file C(cert.pem)
        from the directory specified in the environment variable E(DOCKER_CERT_PATH) will be used.
    type: path
    aliases:
      - tls_client_cert
      - cert_path
  client_key:
    description:
      - Path to the client's TLS key file.
      - If the value is not specified in the task and the environment variable E(DOCKER_CERT_PATH) is set, the file C(key.pem)
        from the directory specified in the environment variable E(DOCKER_CERT_PATH) will be used.
    type: path
    aliases:
      - tls_client_key
      - key_path
  tls:
    description:
      - Secure the connection to the API by using TLS without verifying the authenticity of the Docker host server. Note that
        if O(validate_certs) is set to V(true) as well, it will take precedence.
      - If the value is not specified in the task, the value of environment variable E(DOCKER_TLS) will be used instead. If
        the environment variable is not set, the default value will be used.
    type: bool
    default: false
  use_ssh_client:
    description:
      - For SSH transports, use the C(ssh) CLI tool instead of paramiko.
      - Requires Docker SDK for Python 4.4.0 or newer.
    type: bool
    default: false
    version_added: 1.5.0
  validate_certs:
    description:
      - Secure the connection to the API by using TLS and verifying the authenticity of the Docker host server.
      - If the value is not specified in the task, the value of environment variable E(DOCKER_TLS_VERIFY) will be used instead.
        If the environment variable is not set, the default value will be used.
    type: bool
    default: false
    aliases:
      - tls_verify
  debug:
    description:
      - Debug mode.
    type: bool
    default: false

notes:
  - Connect to the Docker daemon by providing parameters with each task or by defining environment variables. You can define
    E(DOCKER_HOST), E(DOCKER_TLS_HOSTNAME), E(DOCKER_API_VERSION), E(DOCKER_CERT_PATH), E(DOCKER_TLS), E(DOCKER_TLS_VERIFY)
    and E(DOCKER_TIMEOUT). If you are using docker machine, run the script shipped with the product that sets up the environment.
    It will set these variables for you. See U(https://docs.docker.com/machine/reference/env/) for more details.
  - When connecting to Docker daemon with TLS, you might need to install additional Python packages. For the Docker SDK for
    Python, version 2.4 or newer, this can be done by installing C(docker[tls]) with M(ansible.builtin.pip).
  - Note that the Docker SDK for Python only allows to specify the path to the Docker configuration for very few functions.
    In general, it will use C($HOME/.docker/config.json) if the E(DOCKER_CONFIG) environment variable is not specified, and
    use C($DOCKER_CONFIG/config.json) otherwise.
"""

    # For plugins: allow to define common options with Ansible variables

    VAR_NAMES = r'''
options:
  docker_host:
    vars:
      - name: ansible_docker_docker_host
  tls_hostname:
    vars:
      - name: ansible_docker_tls_hostname
  api_version:
    vars:
      - name: ansible_docker_api_version
  timeout:
    vars:
      - name: ansible_docker_timeout
  ca_path:
    vars:
      - name: ansible_docker_ca_cert
      - name: ansible_docker_ca_path
        version_added: 3.6.0
  client_cert:
    vars:
      - name: ansible_docker_client_cert
  client_key:
    vars:
      - name: ansible_docker_client_key
  tls:
    vars:
      - name: ansible_docker_tls
  validate_certs:
    vars:
      - name: ansible_docker_validate_certs
'''

    # Additional, more specific stuff for minimal Docker SDK for Python version < 2.0

    DOCKER_PY_1_DOCUMENTATION = r'''
options: {}
notes:
  - This module uses the L(Docker SDK for Python,https://docker-py.readthedocs.io/en/stable/) to
    communicate with the Docker daemon.
requirements:
  - "Docker SDK for Python: Please note that the L(docker-py,https://pypi.org/project/docker-py/)
     Python module has been superseded by L(docker,https://pypi.org/project/docker/)
     (see L(here,https://github.com/docker/docker-py/issues/1310) for details). Note that both
     modules should *not* be installed at the same time. Also note that when both modules are
     installed and one of them is uninstalled, the other might no longer function and a reinstall
     of it is required."
'''

    # Additional, more specific stuff for minimal Docker SDK for Python version >= 2.0.
    # Note that Docker SDK for Python >= 2.0 requires Python 2.7 or newer.

    DOCKER_PY_2_DOCUMENTATION = r'''
options: {}
notes:
  - This module uses the L(Docker SDK for Python,https://docker-py.readthedocs.io/en/stable/) to
    communicate with the Docker daemon.
requirements:
  - "Python >= 2.7"
  - "Docker SDK for Python: Please note that the L(docker-py,https://pypi.org/project/docker-py/)
     Python module has been superseded by L(docker,https://pypi.org/project/docker/)
     (see L(here,https://github.com/docker/docker-py/issues/1310) for details).
     This module does *not* work with docker-py."
'''

    # Docker doc fragment when using the vendored API access code
    API_DOCUMENTATION = r'''
options:
  docker_host:
    description:
      - The URL or Unix socket path used to connect to the Docker API. To connect to a remote host, provide the
        TCP connection string. For example, V(tcp://192.0.2.23:2376). If TLS is used to encrypt the connection,
        the module will automatically replace C(tcp) in the connection URL with C(https).
      - If the value is not specified in the task, the value of environment variable E(DOCKER_HOST) will be used
        instead. If the environment variable is not set, the default value will be used.
    type: str
    default: unix:///var/run/docker.sock
    aliases:
      - docker_url
  tls_hostname:
    description:
      - When verifying the authenticity of the Docker Host server, provide the expected name of the server.
      - If the value is not specified in the task, the value of environment variable E(DOCKER_TLS_HOSTNAME) will
        be used instead. If the environment variable is not set, the default value will be used.
      - Note that this option had a default value V(localhost) in older versions. It was removed in community.docker 3.0.0.
    type: str
  api_version:
    description:
      - The version of the Docker API running on the Docker Host.
      - Defaults to the latest version of the API supported by this collection and the docker daemon.
      - If the value is not specified in the task, the value of environment variable E(DOCKER_API_VERSION) will be
        used instead. If the environment variable is not set, the default value will be used.
    type: str
    default: auto
    aliases:
      - docker_api_version
  timeout:
    description:
      - The maximum amount of time in seconds to wait on a response from the API.
      - If the value is not specified in the task, the value of environment variable E(DOCKER_TIMEOUT) will be used
        instead. If the environment variable is not set, the default value will be used.
    type: int
    default: 60
  ca_path:
    description:
      - Use a CA certificate when performing server verification by providing the path to a CA certificate file.
      - If the value is not specified in the task and the environment variable E(DOCKER_CERT_PATH) is set,
        the file C(ca.pem) from the directory specified in the environment variable E(DOCKER_CERT_PATH) will be used.
      - This option was called O(ca_cert) and got renamed to O(ca_path) in community.docker 3.6.0. The old name has
        been added as an alias and can still be used.
    type: path
    aliases:
      - ca_cert
      - tls_ca_cert
      - cacert_path
  client_cert:
    description:
      - Path to the client's TLS certificate file.
      - If the value is not specified in the task and the environment variable E(DOCKER_CERT_PATH) is set,
        the file C(cert.pem) from the directory specified in the environment variable E(DOCKER_CERT_PATH) will be used.
    type: path
    aliases:
      - tls_client_cert
      - cert_path
  client_key:
    description:
      - Path to the client's TLS key file.
      - If the value is not specified in the task and the environment variable E(DOCKER_CERT_PATH) is set,
        the file C(key.pem) from the directory specified in the environment variable E(DOCKER_CERT_PATH) will be used.
    type: path
    aliases:
      - tls_client_key
      - key_path
  tls:
    description:
      - Secure the connection to the API by using TLS without verifying the authenticity of the Docker host
        server. Note that if O(validate_certs) is set to V(true) as well, it will take precedence.
      - If the value is not specified in the task, the value of environment variable E(DOCKER_TLS) will be used
        instead. If the environment variable is not set, the default value will be used.
    type: bool
    default: false
  use_ssh_client:
    description:
      - For SSH transports, use the C(ssh) CLI tool instead of paramiko.
    type: bool
    default: false
    version_added: 1.5.0
  validate_certs:
    description:
      - Secure the connection to the API by using TLS and verifying the authenticity of the Docker host server.
      - If the value is not specified in the task, the value of environment variable E(DOCKER_TLS_VERIFY) will be
        used instead. If the environment variable is not set, the default value will be used.
    type: bool
    default: false
    aliases:
      - tls_verify
  debug:
    description:
      - Debug mode
    type: bool
    default: false

notes:
  - Connect to the Docker daemon by providing parameters with each task or by defining environment variables.
    You can define E(DOCKER_HOST), E(DOCKER_TLS_HOSTNAME), E(DOCKER_API_VERSION), E(DOCKER_CERT_PATH),
    E(DOCKER_TLS), E(DOCKER_TLS_VERIFY) and E(DOCKER_TIMEOUT). If you are using docker machine, run the script shipped
    with the product that sets up the environment. It will set these variables for you. See
    U(https://docs.docker.com/machine/reference/env/) for more details.
#  - Note that the Docker SDK for Python only allows to specify the path to the Docker configuration for very few functions.
#    In general, it will use C($HOME/.docker/config.json) if the E(DOCKER_CONFIG) environment variable is not specified,
#    and use C($DOCKER_CONFIG/config.json) otherwise.
  - This module does B(not) use the L(Docker SDK for Python,https://docker-py.readthedocs.io/en/stable/) to
    communicate with the Docker daemon. It uses code derived from the Docker SDK or Python that is included in this
    collection.
requirements:
  - requests
  - pywin32 (when using named pipes on Windows 32)
  - paramiko (when using SSH with O(use_ssh_client=false))
  - pyOpenSSL (when using TLS)
  - backports.ssl_match_hostname (when using TLS on Python 2)
'''

    # Docker doc fragment when using the Docker CLI
    CLI_DOCUMENTATION = r'''
options:
  docker_cli:
    description:
      - Path to the Docker CLI. If not provided, will search for Docker CLI on the E(PATH).
    type: path
  docker_host:
    description:
      - The URL or Unix socket path used to connect to the Docker API. To connect to a remote host, provide the
        TCP connection string. For example, V(tcp://192.0.2.23:2376). If TLS is used to encrypt the connection,
        the module will automatically replace C(tcp) in the connection URL with C(https).
      - If the value is not specified in the task, the value of environment variable E(DOCKER_HOST) will be used
        instead. If the environment variable is not set, the default value will be used.
      - Mutually exclusive with O(cli_context). If neither O(docker_host) nor O(cli_context) are provided, the
        value V(unix:///var/run/docker.sock) is used.
    type: str
    aliases:
      - docker_url
  tls_hostname:
    description:
      - When verifying the authenticity of the Docker Host server, provide the expected name of the server.
      - If the value is not specified in the task, the value of environment variable E(DOCKER_TLS_HOSTNAME) will
        be used instead. If the environment variable is not set, the default value will be used.
    type: str
  api_version:
    description:
      - The version of the Docker API running on the Docker Host.
      - Defaults to the latest version of the API supported by this collection and the docker daemon.
      - If the value is not specified in the task, the value of environment variable E(DOCKER_API_VERSION) will be
        used instead. If the environment variable is not set, the default value will be used.
    type: str
    default: auto
    aliases:
      - docker_api_version
  ca_path:
    description:
      - Use a CA certificate when performing server verification by providing the path to a CA certificate file.
      - If the value is not specified in the task and the environment variable E(DOCKER_CERT_PATH) is set,
        the file C(ca.pem) from the directory specified in the environment variable E(DOCKER_CERT_PATH) will be used.
    type: path
    aliases:
      - ca_cert
      - tls_ca_cert
      - cacert_path
  client_cert:
    description:
      - Path to the client's TLS certificate file.
      - If the value is not specified in the task and the environment variable E(DOCKER_CERT_PATH) is set,
        the file C(cert.pem) from the directory specified in the environment variable E(DOCKER_CERT_PATH) will be used.
    type: path
    aliases:
      - tls_client_cert
      - cert_path
  client_key:
    description:
      - Path to the client's TLS key file.
      - If the value is not specified in the task and the environment variable E(DOCKER_CERT_PATH) is set,
        the file C(key.pem) from the directory specified in the environment variable E(DOCKER_CERT_PATH) will be used.
    type: path
    aliases:
      - tls_client_key
      - key_path
  tls:
    description:
      - Secure the connection to the API by using TLS without verifying the authenticity of the Docker host
        server. Note that if O(validate_certs) is set to V(true) as well, it will take precedence.
      - If the value is not specified in the task, the value of environment variable E(DOCKER_TLS) will be used
        instead. If the environment variable is not set, the default value will be used.
    type: bool
    default: false
  validate_certs:
    description:
      - Secure the connection to the API by using TLS and verifying the authenticity of the Docker host server.
      - If the value is not specified in the task, the value of environment variable E(DOCKER_TLS_VERIFY) will be
        used instead. If the environment variable is not set, the default value will be used.
    type: bool
    default: false
    aliases:
      - tls_verify
  # debug:
  #   description:
  #     - Debug mode
  #   type: bool
  #   default: false
  cli_context:
    description:
      - The Docker CLI context to use.
      - Mutually exclusive with O(docker_host).
    type: str

notes:
  - Connect to the Docker daemon by providing parameters with each task or by defining environment variables.
    You can define E(DOCKER_HOST), E(DOCKER_TLS_HOSTNAME), E(DOCKER_API_VERSION), E(DOCKER_CERT_PATH),
    E(DOCKER_TLS), E(DOCKER_TLS_VERIFY) and E(DOCKER_TIMEOUT). If you are using docker machine, run the script shipped
    with the product that sets up the environment. It will set these variables for you. See
    U(https://docs.docker.com/machine/reference/env/) for more details.
  - This module does B(not) use the L(Docker SDK for Python,https://docker-py.readthedocs.io/en/stable/) to
    communicate with the Docker daemon. It directly calls the Docker CLI program.
'''
