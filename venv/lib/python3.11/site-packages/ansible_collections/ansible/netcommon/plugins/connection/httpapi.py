# (c) 2018 Red Hat Inc.
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
author:
 - Ansible Networking Team (@ansible-network)
name: httpapi
short_description: Use httpapi to run command on network appliances
description:
- This connection plugin provides a connection to remote devices over a HTTP(S)-based
  api.
version_added: 1.0.0
extends_documentation_fragment:
- ansible.netcommon.connection_persistent
options:
  host:
    description:
    - Specifies the remote device FQDN or IP address to establish the HTTP(S) connection
      to.
    default: inventory_hostname
    type: string
    vars:
    - name: inventory_hostname
    - name: ansible_host
  port:
    type: int
    description:
    - Specifies the port on the remote device that listens for connections when establishing
      the HTTP(S) connection.
    - When unspecified, will pick 80 or 443 based on the value of use_ssl.
    ini:
    - section: defaults
      key: remote_port
    env:
    - name: ANSIBLE_REMOTE_PORT
    vars:
    - name: ansible_httpapi_port
  network_os:
    description:
    - Configures the device platform network operating system.  This value is used
      to load the correct httpapi plugin to communicate with the remote device
    type: string
    vars:
    - name: ansible_network_os
  remote_user:
    description:
    - The username used to authenticate to the remote device when the API connection
      is first established.  If the remote_user is not specified, the connection will
      use the username of the logged in user.
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
    - Configures the user password used to authenticate to the remote device when
      needed for the device API.
    type: string
    vars:
    - name: ansible_password
    - name: ansible_httpapi_pass
    - name: ansible_httpapi_password
  session_key:
    type: dict
    description:
    - Configures the session key to be used to authenticate to the remote device when
      needed for the device API.
    - This should contain a dictionary representing the key name and value for the
      token.
    - When specified, I(password) is ignored.
    vars:
    - name: ansible_httpapi_session_key
  ca_path:
    description:
      - Path to CA cert bundle to use.
    type: path
    version_added: 5.2.0
    vars:
      - name: ansible_httpapi_ca_path
  client_cert:
    description:
      - PEM formatted certificate chain file to be used for SSL client
        authentication. This file can also include the key as well, and if the key
        is included, I(client_key) is not required
    version_added: 5.2.0
    vars:
      - name: ansible_httpapi_client_cert
  client_key:
    description:
      - PEM formatted file that contains the private key to be used for SSL client
        authentication. If I(client_cert) contains both the certificate and key,
        this option is not required.
    version_added: 5.2.0
    vars:
      - name: ansible_httpapi_client_key
  http_agent:
    description: User-Agent to use in the request.
    version_added: 5.2.0
    vars:
      - name: ansible_httpapi_http_agent
  use_ssl:
    type: boolean
    description:
    - Whether to connect using SSL (HTTPS) or not (HTTP).
    default: false
    vars:
    - name: ansible_httpapi_use_ssl
  validate_certs:
    type: boolean
    description:
    - Whether to validate SSL certificates
    default: true
    vars:
    - name: ansible_httpapi_validate_certs
  use_proxy:
    type: boolean
    description:
    - Whether to use https_proxy for requests.
    default: true
    vars:
    - name: ansible_httpapi_use_proxy
  ciphers:
    description:
      - SSL/TLS Ciphers to use for requests
      - 'When a list is provided, all ciphers are joined in order with C(:)'
      - See the L(OpenSSL Cipher List Format,https://www.openssl.org/docs/manmaster/man1/openssl-ciphers.html#CIPHER-LIST-FORMAT)
        for more details.
      - The available ciphers is dependent on the Python and OpenSSL/LibreSSL versions.
      - This option will have no effect on ansible-core<2.14 but a warning will be emitted.
    version_added: 5.0.0
    type: list
    elements: string
    vars:
    - name: ansible_httpapi_ciphers
  become:
    type: boolean
    description:
    - The become option will instruct the CLI session to attempt privilege escalation
      on platforms that support it.  Normally this means transitioning from user mode
      to C(enable) mode in the CLI session. If become is set to True and the remote
      device does not support privilege escalation or the privilege has already been
      elevated, then this option is silently ignored.
    - Can be configured from the CLI via the C(--become) or C(-b) options.
    default: false
    ini:
    - section: privilege_escalation
      key: become
    env:
    - name: ANSIBLE_BECOME
    vars:
    - name: ansible_become
  become_method:
    description:
    - This option allows the become method to be specified in for handling privilege
      escalation.  Typically the become_method value is set to C(enable) but could
      be defined as other values.
    default: sudo
    type: string
    ini:
    - section: privilege_escalation
      key: become_method
    env:
    - name: ANSIBLE_BECOME_METHOD
    vars:
    - name: ansible_become_method
  platform_type:
    description:
    - Set type of platform.
    type: string
    env:
    - name: ANSIBLE_PLATFORM_TYPE
    vars:
    - name: ansible_platform_type
"""

from io import BytesIO

from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils.common.text.converters import to_bytes
from ansible.module_utils.six.moves import cPickle
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from ansible.module_utils.urls import open_url
from ansible.playbook.play_context import PlayContext
from ansible.plugins.connection import ensure_connect
from ansible.plugins.loader import httpapi_loader
from ansible.release import __version__ as ANSIBLE_CORE_VERSION

from ansible_collections.ansible.netcommon.plugins.plugin_utils.connection_base import (
    NetworkConnectionBase,
)
from ansible_collections.ansible.netcommon.plugins.plugin_utils.version import Version


class Connection(NetworkConnectionBase):
    """Network API connection"""

    transport = "ansible.netcommon.httpapi"
    has_pipelining = True

    def __init__(self, play_context, new_stdin, *args, **kwargs):
        super(Connection, self).__init__(play_context, new_stdin, *args, **kwargs)

        self._auth = None
        if self._network_os:
            self.load_platform_plugins(self._network_os)

    def load_platform_plugins(self, platform_type=None):
        platform_type = platform_type or self.get_option("platform_type")

        if platform_type:
            self.httpapi = httpapi_loader.get(platform_type, self)
            if self.httpapi:
                self._sub_plugin = {
                    "type": "httpapi",
                    "name": self.httpapi._load_name,
                    "obj": self.httpapi,
                }
                self.queue_message(
                    "vvvv",
                    "loaded API plugin %s from path %s for platform type %s"
                    % (
                        self.httpapi._load_name,
                        self.httpapi._original_path,
                        platform_type,
                    ),
                )
            else:
                raise AnsibleConnectionFailure(
                    "unable to load API plugin for platform type %s" % platform_type
                )

        else:
            raise AnsibleConnectionFailure(
                "Unable to automatically determine host platform type. Please "
                "manually configure platform_type value for this host"
            )
        self.queue_message("log", "platform_type is set to %s" % platform_type)

    @property
    def _url(self):
        protocol = "https" if self.get_option("use_ssl") else "http"
        host = self.get_option("host")
        port = self.get_option("port") or (443 if protocol == "https" else 80)
        return "%s://%s:%s" % (protocol, host, port)

    def update_play_context(self, pc_data):
        """Updates the play context information for the connection"""
        pc_data = to_bytes(pc_data)
        pc_data = cPickle.loads(pc_data, encoding="bytes")

        play_context = PlayContext()
        play_context.deserialize(pc_data)

        self.queue_message("vvvv", "updating play_context for connection")
        if self._play_context.become ^ play_context.become:
            self.set_become(play_context)
            if play_context.become is True:
                self.queue_message("vvvv", "authorizing connection")
            else:
                self.queue_message("vvvv", "deauthorizing connection")

        self._play_context = play_context

    def _connect(self):
        if not self.connected:
            self.queue_message(
                "vvv",
                "ESTABLISH HTTP(S) CONNECTFOR USER: %s TO %s"
                % (self._play_context.remote_user, self._url),
            )
            self.httpapi.set_become(self._play_context)
            self._connected = True

            if self.get_option("session_key"):
                self._auth = self.get_option("session_key")
            else:
                self.httpapi.login(self.get_option("remote_user"), self.get_option("password"))

    def close(self):
        """
        Close the active session to the device
        """
        # only close the connection if its connected.
        if self._connected:
            self.queue_message("vvvv", "closing http(s) connection to device")
            self.logout()

        super(Connection, self).close()

    @ensure_connect
    def send(self, path, data, retries=None, **kwargs):
        """
        Sends the command to the device over api
        """
        url_kwargs = dict(
            headers={},
            use_proxy=self.get_option("use_proxy"),
            timeout=self.get_option("persistent_command_timeout"),
            validate_certs=self.get_option("validate_certs"),
            http_agent=self.get_option("http_agent"),
            client_cert=self.get_option("client_cert"),
            client_key=self.get_option("client_key"),
            ca_path=self.get_option("ca_path"),
        )
        url_kwargs.update(kwargs)

        ciphers = self.get_option("ciphers")
        if ciphers:
            if Version(ANSIBLE_CORE_VERSION) >= Version("2.14.0"):
                # Only insert "ciphers" kwarg for ansible-core versions >= 2.14.0.
                url_kwargs["ciphers"] = ciphers
            else:
                # Emit warning when "ansible_httpapi_ciphers" is set but not supported
                self.queue_message(
                    "warning",
                    "'ansible_httpapi_ciphers' option is unavailable on ansible-core<2.14",
                )

        if self._auth:
            # Avoid modifying passed-in headers
            headers = dict(kwargs.get("headers", {}))
            headers.update(self._auth)
            url_kwargs["headers"] = headers
        else:
            url_kwargs["force_basic_auth"] = True
            url_kwargs["url_username"] = self.get_option("remote_user")
            url_kwargs["url_password"] = self.get_option("password")

        try:
            url = self._url + path
            self._log_messages(
                "send url '%s' with data '%s' and kwargs '%s'" % (url, data, url_kwargs)
            )
            response = open_url(url, data=data, **url_kwargs)
        except HTTPError as exc:
            is_handled = self.handle_httperror(exc)
            if is_handled is True:
                if retries is None:
                    # The default behavior, retry indefinitely until timeout.
                    return self.send(path, data, **kwargs)
                if retries:
                    return self.send(path, data, retries=retries - 1, **kwargs)
                raise
            if is_handled is False:
                raise
            response = is_handled
        except URLError as exc:
            raise AnsibleConnectionFailure(
                "Could not connect to {0}: {1}".format(self._url + path, exc.reason)
            )

        response_buffer = BytesIO()
        resp_data = response.read()
        self._log_messages("received response: '%s'" % resp_data)
        response_buffer.write(resp_data)

        # Try to assign a new auth token if one is given
        self._auth = self.update_auth(response, response_buffer) or self._auth

        response_buffer.seek(0)

        return response, response_buffer

    def transport_test(self, connect_timeout):
        """This method enables wait_for_connection to work.

        The sole purpose of this method is to raise an exception if the API's URL
        cannot be reached. As such, it does not do anything except attempt to
        request the root URL with no error handling.
        """

        open_url(self._url, timeout=connect_timeout)
