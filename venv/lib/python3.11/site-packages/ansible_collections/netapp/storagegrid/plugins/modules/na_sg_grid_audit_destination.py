#!/usr/bin/python

# (c) 2025, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage audit log destinations"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_grid_audit_destination
short_description: Configure audit log destinations on StorageGRID.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.15.0'
author: NetApp Ansible Team (@vinaykus) <ng-ansibleteam@netapp.com>
description:
  - Configure audit log destinations on NetApp StorageGRID.
options:
  state:
    description:
    - The audit destination should be present.
    choices: ['present']
    default: 'present'
    type: str
  defaults:
    description:
    - The defaults will be used to configure audit destinations on all nodes which are not in the nodes array.
    type: dict
    suboptions:
      admin_nodes:
        description:
        - Configuration for traditional audit log export to admin nodes.
        type: dict
        suboptions:
          enabled:
            description:
            - If true, traditional audit log export to admin nodes is enabled.
            type: bool
            default: True
      remote_syslog_server:
        description:
        - Configuration for sending audit logs to an external syslog server.
        type: dict
        suboptions:
          enabled:
            description:
            - If true, the external syslog server destination is enabled.
            type: bool
            default: False
          protocol:
            description:
            - The IP protocol to use for sending to the external syslog server.
            choices: ['udp', 'tcp', 'tls', 'relp+tcp', 'relp+tls']
            default: 'udp'
            type: str
          server_ca_cert:
            description:
            - One or more trusted CA certificates for verifying the external syslog server (in PEM encoding).
            - If omitted, the operating system CA certificates will be used.
            type: str
          insecure_TLS:
            description:
            - Flag to permit insecure Transport Layer Security (TLS) for external syslog server connections.
            type: bool
            default: False
          client_cert:
            description:
            - Client certificate for authentication to external syslog server (in PEM encoding).
            type: str
          client_key:
            description:
            - Private key for the client certificate (in PEM encoding).
            - If encrypted, must use traditional format (cannot use PKCS #8 format).
            type: str
          client_key_passphrase:
            description:
            - Passphrase for decrypting the client private key; omit the passphrase if the private key is not encrypted.
            type: str
          tls_configuration_parameters:
            description:
            - OpenSSL configuration commands, only used when C(protocol) is tls.
            type: str
          hostname:
            description:
            - The IP or DNS hostname to send syslog messages to.
            type: str
            required: True
          port:
            description:
            - The port number to send syslog messages to.
            type: int
            default: 514
          auth_events_send:
            description:
            - If true, send security events to the external syslog server.
            type: bool
            default: True
          auth_events_facility:
            description:
            - Syslog facility to use for security events sent to external syslog server, or -1 to preserve the local facility.
            type: int
            default: -1
          auth_events_severity:
            description:
            - Syslog severity to use for security events sent to external syslog server, or -1 to preserve the local severity.
            type: int
            default: -1
          audit_logs_send:
            description:
            - If true, send audit logs to the external syslog server.
            type: bool
            default: True
          audit_logs_facility:
            description:
            - Syslog facility to use for audit logs sent to external syslog server, or -1 to preserve the local facility.
            type: int
            default: 23
          audit_logs_severity:
            description:
            - Syslog severity to use for audit logs sent to external syslog server, or -1 to preserve the local severity.
            type: int
            default: 6
          application_logs_send:
            description:
            - If true, send application logs to the external syslog server.
            type: bool
            default: True
          application_logs_facility:
            description:
            - Syslog facility to use for application logs sent to external syslog server, or -1 to preserve the local facility.
            type: int
            default: -1
          application_logs_severity:
            description:
            - Syslog severity to use for application logs sent to external syslog server, or -1 to preserve the local severity.
            type: int
            default: -1
      remote_syslog_server_test:
        description:
        - Configuration for sending audit test messages to an external syslog server.
        type: dict
        suboptions:
          enabled:
            description:
            - If true, the external syslog server destination is enabled.
            type: bool
            default: False
          protocol:
            description:
            - The IP protocol to use for sending to the external syslog server.
            choices: ['udp', 'tcp', 'tls', 'relp+tcp', 'relp+tls']
            default: 'udp'
            type: str
          server_ca_cert:
            description:
            - One or more trusted CA certificates for verifying the external syslog server (in PEM encoding).
            - If omitted, the operating system CA certificates will be used.
            type: str
          insecure_TLS:
            description:
            - Flag to permit insecure Transport Layer Security (TLS) for external syslog server connections.
            type: bool
            default: False
          client_cert:
            description:
            - Client certificate for authentication to external syslog server (in PEM encoding).
            type: str
          client_key:
            description:
            - Private key for the client certificate (in PEM encoding).
            - If encrypted, must use traditional format (cannot use PKCS #8 format).
            type: str
          client_key_passphrase:
            description:
            - Passphrase for decrypting the client private key; omit the passphrase if the private key is not encrypted.
            type: str
          tls_configuration_parameters:
            description:
            - OpenSSL configuration commands, only used when C(protocol) is tls.
            type: str
          hostname:
            description:
            - The IP or DNS hostname to send syslog messages to.
            type: str
            required: True
          port:
            description:
            - The port number to send syslog messages to.
            type: int
            default: 514
          auth_events_send:
            description:
            - If true, send security events to the external syslog server.
            type: bool
            default: True
          auth_events_facility:
            description:
            - Syslog facility to use for security events sent to external syslog server, or -1 to preserve the local facility.
            type: int
            default: -1
          auth_events_severity:
            description:
            - Syslog severity to use for security events sent to external syslog server, or -1 to preserve the local severity.
            type: int
            default: -1
          audit_logs_send:
            description:
            - If true, send audit logs to the external syslog server.
            type: bool
            default: True
          audit_logs_facility:
            description:
            - Syslog facility to use for audit logs sent to external syslog server, or -1 to preserve the local facility.
            type: int
            default: 23
          audit_logs_severity:
            description:
            - Syslog severity to use for audit logs sent to external syslog server, or -1 to preserve the local severity.
            type: int
            default: 6
          application_logs_send:
            description:
            - If true, send application logs to the external syslog server.
            type: bool
            default: True
          application_logs_facility:
            description:
            - Syslog facility to use for application logs sent to external syslog server, or -1 to preserve the local facility.
            type: int
            default: -1
          application_logs_severity:
            description:
            - Syslog severity to use for application logs sent to external syslog server, or -1 to preserve the local severity.
            type: int
            default: -1
  nodes:
    description:
    - Optional per-node configuration stanzas in the nodes array override the default configuration.
    type: list
    elements: dict
    suboptions:
      node_id:
        description:
        - An optional map of node UUIDs to their audit log destination configurations.
        type: str
      admin_nodes:
        description:
        - Configuration for traditional audit log export to admin nodes.
        type: dict
        suboptions:
          enabled:
            description:
            - If true, traditional audit log export to admin nodes is enabled.
            type: bool
            default: True
      remote_syslog_server:
        description:
        - Configuration for sending audit logs to an external syslog server.
        type: dict
        suboptions:
          enabled:
            description:
            - If true, the external syslog server destination is enabled.
            type: bool
            default: False
          protocol:
            description:
            - The IP protocol to use for sending to the external syslog server.
            choices: ['udp', 'tcp', 'tls', 'relp+tcp', 'relp+tls']
            default: 'udp'
            type: str
          server_ca_cert:
            description:
            - One or more trusted CA certificates for verifying the external syslog server (in PEM encoding).
            - If omitted, the operating system CA certificates will be used.
            type: str
          insecure_TLS:
            description:
            - Flag to permit insecure Transport Layer Security (TLS) for external syslog server connections.
            type: bool
            default: False
          client_cert:
            description:
            - Client certificate for authentication to external syslog server (in PEM encoding).
            type: str
          client_key:
            description:
            - Private key for the client certificate (in PEM encoding).
            - If encrypted, must use traditional format (cannot use PKCS #8 format).
            type: str
          client_key_passphrase:
            description:
            - Passphrase for decrypting the client private key; omit the passphrase if the private key is not encrypted.
            type: str
          tls_configuration_parameters:
            description:
            - OpenSSL configuration commands, only used when C(protocol) is tls.
            type: str
          hostname:
            description:
            - The IP or DNS hostname to send syslog messages to.
            type: str
            required: True
          port:
            description:
            - The port number to send syslog messages to.
            type: int
            default: 514
          auth_events_send:
            description:
            - If true, send security events to the external syslog server.
            type: bool
            default: True
          auth_events_facility:
            description:
            - Syslog facility to use for security events sent to external syslog server, or -1 to preserve the local facility.
            type: int
            default: -1
          auth_events_severity:
            description:
            - Syslog severity to use for security events sent to external syslog server, or -1 to preserve the local severity.
            type: int
            default: -1
          audit_logs_send:
            description:
            - If true, send audit logs to the external syslog server.
            type: bool
            default: True
          audit_logs_facility:
            description:
            - Syslog facility to use for audit logs sent to external syslog server, or -1 to preserve the local facility.
            type: int
            default: 23
          audit_logs_severity:
            description:
            - Syslog severity to use for audit logs sent to external syslog server, or -1 to preserve the local severity.
            type: int
            default: 6
          application_logs_send:
            description:
            - If true, send application logs to the external syslog server.
            type: bool
            default: True
          application_logs_facility:
            description:
            - Syslog facility to use for application logs sent to external syslog server, or -1 to preserve the local facility.
            type: int
            default: -1
          application_logs_severity:
            description:
            - Syslog severity to use for application logs sent to external syslog server, or -1 to preserve the local severity.
            type: int
            default: -1
      remote_syslog_server_test:
        description:
        - Configuration for sending audit test messages to an external syslog server.
        type: dict
        suboptions:
          enabled:
            description:
            - If true, the external syslog server destination is enabled.
            type: bool
            default: False
          protocol:
            description:
            - The IP protocol to use for sending to the external syslog server.
            choices: ['udp', 'tcp', 'tls', 'relp+tcp', 'relp+tls']
            default: 'udp'
            type: str
          server_ca_cert:
            description:
            - One or more trusted CA certificates for verifying the external syslog server (in PEM encoding).
            - If omitted, the operating system CA certificates will be used.
            type: str
          insecure_TLS:
            description:
            - Flag to permit insecure Transport Layer Security (TLS) for external syslog server connections.
            type: bool
            default: False
          client_cert:
            description:
            - Client certificate for authentication to external syslog server (in PEM encoding).
            type: str
          client_key:
            description:
            - Private key for the client certificate (in PEM encoding).
            - If encrypted, must use traditional format (cannot use PKCS #8 format).
            type: str
          client_key_passphrase:
            description:
            - Passphrase for decrypting the client private key; omit the passphrase if the private key is not encrypted.
            type: str
          tls_configuration_parameters:
            description:
            - OpenSSL configuration commands, only used when C(protocol) is tls.
            type: str
          hostname:
            description:
            - The IP or DNS hostname to send syslog messages to.
            type: str
            required: True
          port:
            description:
            - The port number to send syslog messages to.
            type: int
            default: 514
          auth_events_send:
            description:
            - If true, send security events to the external syslog server.
            type: bool
            default: True
          auth_events_facility:
            description:
            - Syslog facility to use for security events sent to external syslog server, or -1 to preserve the local facility.
            type: int
            default: -1
          auth_events_severity:
            description:
            - Syslog severity to use for security events sent to external syslog server, or -1 to preserve the local severity.
            type: int
            default: -1
          audit_logs_send:
            description:
            - If true, send audit logs to the external syslog server.
            type: bool
            default: True
          audit_logs_facility:
            description:
            - Syslog facility to use for audit logs sent to external syslog server, or -1 to preserve the local facility.
            type: int
            default: 23
          audit_logs_severity:
            description:
            - Syslog severity to use for audit logs sent to external syslog server, or -1 to preserve the local severity.
            type: int
            default: 6
          application_logs_send:
            description:
            - If true, send application logs to the external syslog server.
            type: bool
            default: True
          application_logs_facility:
            description:
            - Syslog facility to use for application logs sent to external syslog server, or -1 to preserve the local facility.
            type: int
            default: -1
          application_logs_severity:
            description:
            - Syslog severity to use for application logs sent to external syslog server, or -1 to preserve the local severity.
            type: int
            default: -1
"""

EXAMPLES = """
- name: Configure audit destination defaults
  na_sg_grid_audit_destination:
    state: present
    api_url: "https://gmi.example.com"
    auth_token: "01234567-5678-9abc-78de-9fgabc123def"
    validate_certs: false
    defaults:
      admin_nodes:
        enabled: true
      remote_syslog_server:
        enabled: true
        protocol: udp
        hostname: "syslog.example.com"
        port: 514
        auth_events_send: true
        auth_events_facility: -1
        auth_events_severity: -1
        audit_logs_send: true
        audit_logs_facility: 23
        audit_logs_severity: 6
        application_logs_send: true
        application_logs_facility: -1
        application_logs_severity: -1

- name: Configure audit destination for specific nodes
  na_sg_grid_audit_destination:
    state: present
    api_url: "https://gmi.example.com"
    auth_token: "01234567-5678-9abc-78de-9fgabc123def"
    validate_certs: false
    nodes:
      - node_id: "6562d5d8-f218-45ff-a466-5bb39e729288"
        admin_nodes:
          enabled: true
        remote_syslog_server:
          enabled: true
          protocol: udp
          hostname: "syslog.example.com"
          port: 514
          auth_events_send: true
          auth_events_facility: -1
          auth_events_severity: -1
          audit_logs_send: true
          audit_logs_facility: 23
          audit_logs_severity: 6
          application_logs_send: true
          application_logs_facility: -1
          application_logs_severity: -1
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID Audit destination.
    returned: If state is 'present'.
    type: dict
    sample: {
        "defaults": {
            "adminNodes": {
                "enabled": true
            },
            "remoteSyslogServerA": {
                "enabled": true,
                "protocol": "tls",
                "serverCaCert": "<CA bundle in PEM-encoding>",
                "insecureTLS": false,
                "clientCert": "<Client certificate in PEM-encoding>",
                "clientKey": "<Client private key in PEM-encoding>",
                "clientKeyPassphrase": "<Client private key passphrase>",
                "tlsConfigurationParameters": "<OpenSSL configuration commands>",
                "hostname": "syslog.example.com",
                "port": 514,
                "authEventsSend": true,
                "authEventsFacility": -1,
                "authEventsSeverity": -1,
                "auditLogsSend": true,
                "auditLogsFacility": 23,
                "auditLogsSeverity": 6,
                "applicationLogsSend": true,
                "applicationLogsFacility": -1,
                "applicationLogsSeverity": -1
            },
            "remoteSyslogServerATest": {
                "enabled": true,
                "protocol": "tls",
                "serverCaCert": "<CA bundle in PEM-encoding>",
                "insecureTLS": false,
                "clientCert": "<Client certificate in PEM-encoding>",
                "clientKey": "<Client private key in PEM-encoding>",
                "clientKeyPassphrase": "<Client private key passphrase>",
                "tlsConfigurationParameters": "<OpenSSL configuration commands>",
                "hostname": "syslog.example.com",
                "port": 514,
                "authEventsSend": true,
                "authEventsFacility": -1,
                "authEventsSeverity": -1,
                "auditLogsSend": true,
                "auditLogsFacility": 23,
                "auditLogsSeverity": 6,
                "applicationLogsSend": true,
                "applicationLogsFacility": -1,
                "applicationLogsSeverity": -1
            }
        },
        "nodes": {
            "6562d5d8-f218-45ff-a466-5bb39e729288": {
                "adminNodes": {
                    "enabled": true
                },
                "remoteSyslogServerA": {
                    "enabled": true,
                    "protocol": "tls",
                    "serverCaCert": "<CA bundle in PEM-encoding>",
                    "insecureTLS": false,
                    "clientCert": "<Client certificate in PEM-encoding>",
                    "clientKey": "<Client private key in PEM-encoding>",
                    "clientKeyPassphrase": "<Client private key passphrase>",
                    "tlsConfigurationParameters": "<OpenSSL configuration commands>",
                    "hostname": "syslog.example.com",
                    "port": 514,
                    "authEventsSend": true,
                    "authEventsFacility": -1,
                    "authEventsSeverity": -1,
                    "auditLogsSend": true,
                    "auditLogsFacility": 23,
                    "auditLogsSeverity": 6,
                    "applicationLogsSend": true,
                    "applicationLogsFacility": -1,
                    "applicationLogsSeverity": -1
                },
                "remoteSyslogServerATest": {
                    "enabled": true,
                    "protocol": "tls",
                    "serverCaCert": "<CA bundle in PEM-encoding>",
                    "insecureTLS": false,
                    "clientCert": "<Client certificate in PEM-encoding>",
                    "clientKey": "<Client private key in PEM-encoding>",
                    "clientKeyPassphrase": "<Client private key passphrase>",
                    "tlsConfigurationParameters": "<OpenSSL configuration commands>",
                    "hostname": "syslog.example.com",
                    "port": 514,
                    "authEventsSend": true,
                    "authEventsFacility": -1,
                    "authEventsSeverity": -1,
                    "auditLogsSend": true,
                    "auditLogsFacility": 23,
                    "auditLogsSeverity": 6,
                    "applicationLogsSend": true,
                    "applicationLogsFacility": -1,
                    "applicationLogsSeverity": -1
                }
            }
        }
    }
"""

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI
from ansible_collections.netapp.storagegrid.plugins.module_utils.tools import first_inside_second_dict_or_list


class SgAuditDestination:
    """
    Configure audit destination on NetApp StorageGRID
    """

    def __init__(self):
        """
        Parse arguments, setup state variables,
        check parameters and ensure request module is installed
        """
        self.argument_spec = netapp_utils.na_storagegrid_host_argument_spec()
        self.argument_spec.update(
            dict(
                state=dict(type="str", choices=["present"], default="present"),
                defaults=dict(
                    required=False,
                    type="dict",
                    options=dict(
                        admin_nodes=dict(
                            required=False,
                            type="dict",
                            options=dict(
                                enabled=dict(type="bool", default=True),
                            )
                        ),
                        remote_syslog_server=dict(
                            required=False,
                            type="dict",
                            options=dict(
                                enabled=dict(type="bool", default=False),
                                protocol=dict(type="str", choices=["udp", "tcp", "tls", "relp+tcp", "relp+tls"], default="udp"),
                                server_ca_cert=dict(type="str"),
                                insecure_TLS=dict(type="bool", default=False),
                                client_cert=dict(type="str"),
                                client_key=dict(type="str", no_log=True),
                                client_key_passphrase=dict(type="str", no_log=True),
                                tls_configuration_parameters=dict(type="str"),
                                hostname=dict(type="str", required=True),
                                port=dict(type="int", default=514),
                                auth_events_send=dict(type="bool", default=True),
                                auth_events_facility=dict(type="int", default=-1),
                                auth_events_severity=dict(type="int", default=-1),
                                audit_logs_send=dict(type="bool", default=True),
                                audit_logs_facility=dict(type="int", default=23),
                                audit_logs_severity=dict(type="int", default=6),
                                application_logs_send=dict(type="bool", default=True),
                                application_logs_facility=dict(type="int", default=-1),
                                application_logs_severity=dict(type="int", default=-1),
                            ),
                        ),
                        remote_syslog_server_test=dict(
                            required=False,
                            type="dict",
                            options=dict(
                                enabled=dict(type="bool", default=False),
                                protocol=dict(type="str", choices=["udp", "tcp", "tls", "relp+tcp", "relp+tls"], default="udp"),
                                server_ca_cert=dict(type="str"),
                                insecure_TLS=dict(type="bool", default=False),
                                client_cert=dict(type="str"),
                                client_key=dict(type="str", no_log=True),
                                client_key_passphrase=dict(type="str", no_log=True),
                                tls_configuration_parameters=dict(type="str"),
                                hostname=dict(type="str", required=True),
                                port=dict(type="int", default=514),
                                auth_events_send=dict(type="bool", default=True),
                                auth_events_facility=dict(type="int", default=-1),
                                auth_events_severity=dict(type="int", default=-1),
                                audit_logs_send=dict(type="bool", default=True),
                                audit_logs_facility=dict(type="int", default=23),
                                audit_logs_severity=dict(type="int", default=6),
                                application_logs_send=dict(type="bool", default=True),
                                application_logs_facility=dict(type="int", default=-1),
                                application_logs_severity=dict(type="int", default=-1),
                            ),
                        ),
                    ),
                ),
                nodes=dict(
                    required=False,
                    type="list",
                    elements="dict",
                    options=dict(
                        node_id=dict(type="str", required=False),
                        admin_nodes=dict(
                            required=False,
                            type="dict",
                            options=dict(
                                enabled=dict(type="bool", default=True),
                            )
                        ),
                        remote_syslog_server=dict(
                            required=False,
                            type="dict",
                            options=dict(
                                enabled=dict(type="bool", default=False),
                                protocol=dict(type="str", choices=["udp", "tcp", "tls", "relp+tcp", "relp+tls"], default="udp"),
                                server_ca_cert=dict(type="str"),
                                insecure_TLS=dict(type="bool", default=False),
                                client_cert=dict(type="str"),
                                client_key=dict(type="str", no_log=True),
                                client_key_passphrase=dict(type="str", no_log=True),
                                tls_configuration_parameters=dict(type="str"),
                                hostname=dict(type="str", required=True),
                                port=dict(type="int", default=514),
                                auth_events_send=dict(type="bool", default=True),
                                auth_events_facility=dict(type="int", default=-1),
                                auth_events_severity=dict(type="int", default=-1),
                                audit_logs_send=dict(type="bool", default=True),
                                audit_logs_facility=dict(type="int", default=23),
                                audit_logs_severity=dict(type="int", default=6),
                                application_logs_send=dict(type="bool", default=True),
                                application_logs_facility=dict(type="int", default=-1),
                                application_logs_severity=dict(type="int", default=-1),
                            ),
                        ),
                        remote_syslog_server_test=dict(
                            required=False,
                            type="dict",
                            options=dict(
                                enabled=dict(type="bool", default=False),
                                protocol=dict(type="str", choices=["udp", "tcp", "tls", "relp+tcp", "relp+tls"], default="udp"),
                                server_ca_cert=dict(type="str"),
                                insecure_TLS=dict(type="bool", default=False),
                                client_cert=dict(type="str"),
                                client_key=dict(type="str", no_log=True),
                                client_key_passphrase=dict(type="str", no_log=True),
                                tls_configuration_parameters=dict(type="str"),
                                hostname=dict(type="str", required=True),
                                port=dict(type="int", default=514),
                                auth_events_send=dict(type="bool", default=True),
                                auth_events_facility=dict(type="int", default=-1),
                                auth_events_severity=dict(type="int", default=-1),
                                audit_logs_send=dict(type="bool", default=True),
                                audit_logs_facility=dict(type="int", default=23),
                                audit_logs_severity=dict(type="int", default=6),
                                application_logs_send=dict(type="bool", default=True),
                                application_logs_facility=dict(type="int", default=-1),
                                application_logs_severity=dict(type="int", default=-1),
                            ),
                        ),
                    ),
                ),
            ),
        )

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_one_of=[["defaults", "nodes"]],
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)
        # Get API version
        self.rest_api.get_sg_product_version(api_root="grid")

        # Checking for the parameters passed and create new parameters list
        self.data = {}

        if self.parameters.get("defaults"):
            self.data["defaults"] = {}
            if self.parameters["defaults"].get("admin_nodes"):
                self.data["defaults"]["adminNodes"] = {
                    "enabled": self.parameters["defaults"]["admin_nodes"].get("enabled")
                }
            if self.parameters["defaults"].get("remote_syslog_server"):
                self.data["defaults"]["remoteSyslogServerA"] = self.external_syslog_server_params(self.parameters["defaults"]["remote_syslog_server"])
            if self.parameters["defaults"].get("remote_syslog_server_test"):
                self.data["defaults"]["remoteSyslogServerATest"] = self.external_syslog_server_params(self.parameters["defaults"]["remote_syslog_server_test"])

        if self.parameters.get("nodes"):
            self.data["nodes"] = {}
            for node in self.parameters["nodes"]:
                node_id = node.get("node_id")
                if node_id:
                    self.data["nodes"][node_id] = {}
                    if node.get("admin_nodes"):
                        self.data["nodes"][node_id]["adminNodes"] = {
                            "enabled": node["admin_nodes"].get("enabled")
                        }
                    if node.get("remote_syslog_server"):
                        self.data["nodes"][node_id]["remoteSyslogServerA"] = self.external_syslog_server_params(node["remote_syslog_server"])
                    if node.get("remote_syslog_server_test"):
                        self.data["nodes"][node_id]["remoteSyslogServerATest"] = self.external_syslog_server_params(node["remote_syslog_server_test"])

    def external_syslog_server_params(self, params):
        """ Get external syslog server parameters """
        return {
            "enabled": params.get("enabled", False),
            "protocol": params.get("protocol", "udp"),
            "serverCaCert": params.get("server_ca_cert"),
            "insecureTLS": params.get("insecure_TLS", False),
            "clientCert": params.get("client_cert"),
            "clientKey": params.get("client_key"),
            "clientKeyPassphrase": params.get("client_key_passphrase"),
            "tlsConfigurationParameters": params.get("tls_configuration_parameters"),
            "hostname": params.get("hostname"),
            "port": params.get("port", 514),
            "authEventsSend": params.get("auth_events_send", True),
            "authEventsFacility": params.get("auth_events_facility", -1),
            "authEventsSeverity": params.get("auth_events_severity", -1),
            "auditLogsSend": params.get("audit_logs_send", True),
            "auditLogsFacility": params.get("audit_logs_facility", 23),
            "auditLogsSeverity": params.get("audit_logs_severity", 6),
            "applicationLogsSend": params.get("application_logs_send", True),
            "applicationLogsFacility": params.get("application_logs_facility", -1),
            "applicationLogsSeverity": params.get("application_logs_severity", -1),
        }

    def get_audit_log_destination_config(self):
        """ Get current audit log destination configuration """
        api = "api/v4/private/audit-destinations"
        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)
        else:
            return response["data"]

    def update_audit_log_destination_config(self):
        """ Update audit log destination configuration """
        api = "api/v4/private/audit-destinations"
        response, error = self.rest_api.put(api, self.data)

        if error:
            self.module.fail_json(msg=error)
        else:
            return response["data"]

    def apply(self):
        ''' Apply audit destination configuration '''

        current_audit_destination = self.get_audit_log_destination_config()

        if self.parameters["state"] == "present":
            # let's see if we need to update parameters
            if self.data.get("defaults") and not first_inside_second_dict_or_list(self.data.get("defaults"), current_audit_destination.get("defaults")):
                self.na_helper.changed = True
            if self.data.get("nodes") and not first_inside_second_dict_or_list(self.data.get("nodes"), current_audit_destination.get("nodes")):
                self.na_helper.changed = True

        result_message = ""
        resp_data = current_audit_destination
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                resp_data = self.update_audit_log_destination_config()
                result_message = "Audit destination configuration updated successfully."

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_audit_destination = SgAuditDestination()
    na_sg_grid_audit_destination.apply()


if __name__ == "__main__":
    main()
