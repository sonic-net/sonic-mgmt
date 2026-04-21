# (c) 2022 Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
author:
  - Ansible Networking Team (@ansible-network)
name: grpc
short_description: Provides a persistent connection using the gRPC protocol
description:
  - This connection plugin provides a connection to remote devices over gRPC and
    is typically used with devices for sending and receiving RPC calls
    over gRPC framework.
  - Note this connection plugin requires the grpcio python library to be installed on the
    local Ansible controller.
version_added: "3.1.0"
requirements:
  - grpcio
  - protobuf
extends_documentation_fragment:
  - ansible.netcommon.connection_persistent
options:
  host:
    description:
      - Specifies the remote device FQDN or IP address to establish the gRPC
        connection to.
    default: inventory_hostname
    type: string
    vars:
      - name: ansible_host
  port:
    type: int
    description:
      - Specifies the port on the remote device that listens for connections
        when establishing the gRPC connection. If None only the C(host) part will
        be used.
    ini:
      - section: defaults
        key: remote_port
    env:
      - name: ANSIBLE_REMOTE_PORT
    vars:
      - name: ansible_port
  network_os:
    description:
      - Configures the device platform network operating system. This value is
        used to load a device specific grpc plugin to communicate with the remote
        device.
    type: string
    vars:
      - name: ansible_network_os
  remote_user:
    description:
      - The username used to authenticate to the remote device when the gRPC
        connection is first established.  If the remote_user is not specified,
        the connection will use the username of the logged in user.
      - Can be configured from the CLI via the C(--user) or C(-u) options.
    type: string
    ini:
      - section: defaults
        key: remote_user
    env:
      - name: ANSIBLE_REMOTE_USER
    vars:
      - name: ansible_user
  password:
    description:
      - Configures the user password used to authenticate to the remote device
        when first establishing the gRPC connection.
    type: string
    vars:
      - name: ansible_password
      - name: ansible_ssh_pass
  private_key_file:
    description:
      - The PEM encoded private key file used to authenticate to the
        remote device when first establishing the grpc connection.
    type: string
    ini:
      - section: grpc_connection
        key: private_key_file
    env:
      - name: ANSIBLE_PRIVATE_KEY_FILE
    vars:
      - name: ansible_private_key_file
  root_certificates_file:
    description:
      - The PEM encoded root certificate file used to create a SSL-enabled
        channel, if the value is None it reads the root certificates from
        a default location chosen by gRPC at runtime.
    type: string
    ini:
      - section: grpc_connection
        key: root_certificates_file
    env:
      - name: ANSIBLE_ROOT_CERTIFICATES_FILE
    vars:
      - name: ansible_root_certificates_file
  certificate_chain_file:
    description:
      - The PEM encoded certificate chain file used to create a SSL-enabled
        channel. If the value is None, no certificate chain is used.
    type: string
    ini:
      - section: grpc_connection
        key: certificate_chain_file
    env:
      - name: ANSIBLE_CERTIFICATE_CHAIN_FILE
    vars:
      - name: ansible_certificate_chain_file
  ssl_target_name_override:
    description:
      - The option overrides SSL target name used for SSL host name checking.
        The name used for SSL host name checking will be the target parameter
        (assuming that the secure channel is an SSL channel). If this parameter is
        specified and the underlying is not an SSL channel, it will just be ignored.
    type: string
    ini:
      - section: grpc_connection
        key: ssl_target_name_override
    env:
      - name: ANSIBLE_GPRC_SSL_TARGET_NAME_OVERRIDE
    vars:
      - name: ansible_grpc_ssl_target_name_override
  grpc_type:
    description:
        - This option indicates the grpc type and it can be used
          in place of network_os. (example cisco.iosxr.iosxr)
    default: False
    ini:
      - section: grpc_connection
        key: type
    env:
      - name: ANSIBLE_GRPC_CONNECTION_TYPE
    vars:
      - name: ansible_grpc_connection_type
"""

from importlib import import_module

from ansible.errors import AnsibleConnectionFailure, AnsibleError
from ansible.plugins.connection import NetworkConnectionBase


try:
    from grpc import insecure_channel, secure_channel, ssl_channel_credentials
    from grpc.beta import implementations

    HAS_GRPC = True
except ImportError:
    HAS_GRPC = False

try:
    from google import protobuf  # noqa: F401  # pylint: disable=unused-import

    HAS_PROTOBUF = True
except ImportError:
    HAS_PROTOBUF = False


class Connection(NetworkConnectionBase):
    """GRPC connections"""

    transport = "ansible.netcommon.grpc"
    has_pipelining = False

    def __init__(self, play_context, new_stdin, *args, **kwargs):
        super(Connection, self).__init__(play_context, new_stdin, *args, **kwargs)

        grpc_type = self._network_os or self.get_option("grpc_type")
        if grpc_type:
            if not HAS_PROTOBUF:
                raise AnsibleError(
                    "protobuf is required to use the grpc connection type. Please run 'pip install protobuf'"
                )
            if not self._network_os:
                self._network_os = grpc_type
            cref = dict(zip(["corg", "cname", "plugin"], grpc_type.split(".")))
            grpclib = "ansible_collections.{corg}.{cname}.plugins.sub_plugins.grpc.{plugin}".format(
                **cref
            )
            grpccls = getattr(import_module(grpclib), "Grpc")
            grpc_obj = grpccls(self)

            if grpc_obj:
                self._sub_plugin = {
                    "type": "grpc",
                    "name": grpc_type,
                    "obj": grpc_obj,
                }
                self.queue_message("log", "loaded gRPC plugin for type %s" % grpc_type)
                self.queue_message("log", "grpc type is set to %s" % grpc_type)
            else:
                raise AnsibleConnectionFailure(
                    "unable to load API plugin for network_os %s" % grpc_type
                )
        else:
            raise AnsibleConnectionFailure(
                "Unable to automatically determine gRPC implementation type."
                " Please manually configure ansible_network_os value or grpc_type configuration for this host",
            )

    def _connect(self):
        """
        Create GRPC connection to target host
        :return: None
        """
        if not HAS_GRPC:
            raise AnsibleError(
                "grpcio is required to use the gRPC connection type. Please run 'pip install grpcio'"
            )
        host = self.get_option("host")
        host = self._play_context.remote_addr
        if self.connected:
            self.queue_message("log", "gRPC connection to host %s already exist" % host)
            return

        port = self.get_option("port")
        self._target = host if port is None else "%s:%d" % (host, port)
        self._timeout = self.get_option("persistent_command_timeout")
        self._login_credentials = [
            ("username", self.get_option("remote_user")),
            ("password", self.get_option("password")),
        ]
        ssl_target_name_override = self.get_option("ssl_target_name_override")
        if ssl_target_name_override:
            self._channel_options = [
                ("grpc.ssl_target_name_override", ssl_target_name_override),
            ]
        else:
            self._channel_options = None

        certs = {}
        private_key_file = self.get_option("private_key_file")
        root_certificates_file = self.get_option("root_certificates_file")
        certificate_chain_file = self.get_option("certificate_chain_file")

        try:
            if root_certificates_file:
                with open(root_certificates_file, "rb") as f:
                    certs["root_certificates"] = f.read()
            if private_key_file:
                with open(private_key_file, "rb") as f:
                    certs["private_key"] = f.read()
            if certificate_chain_file:
                with open(certificate_chain_file, "rb") as f:
                    certs["certificate_chain"] = f.read()
        except Exception as e:
            raise AnsibleConnectionFailure("Failed to read certificate keys: %s" % e)
        if certs:
            creds = ssl_channel_credentials(**certs)
            channel = secure_channel(self._target, creds, options=self._channel_options)
        else:
            channel = insecure_channel(self._target, options=self._channel_options)

        self.queue_message(
            "vvv",
            "ESTABLISH GRPC CONNECTION FOR USER: %s on PORT %s TO %s"
            % (self.get_option("remote_user"), port, host),
        )
        self._channel = implementations.Channel(channel)
        self.queue_message("vvvv", "grpc connection has completed successfully")
        self._connected = True

    def close(self):
        """
        Close the active session to the device
        :return: None
        """
        if self._connected:
            self.queue_message("vvvv", "closing gRPC connection to target host")
            self._channel.close()
        super(Connection, self).close()
