#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_fabric_management_access
short_description: Manage Fabric Management Access (comm:Pol)
description:
- Manage Fabric Management Access on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the Fabric Management Access policy.
    type: str
    aliases: [ fabric_management_access_policy_name ]
  description:
    description:
    - The description of the Fabric Management Access policy.
    type: str
    aliases: [ descr ]
  name_alias:
    description:
    - The name alias of the Fabric Management Access policy.
    - This relates to the nameAlias property in ACI.
    type: str
  http:
    description:
    - Parameters for HTTP configuration (comm:Http).
    type: dict
    suboptions:
      admin_state:
        description:
        - The admin state of the HTTP connection.
        - The APIC defaults to C(disabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      port:
        description:
        - The port for the HTTP connection.
        - The APIC defaults to C(80) when unset during creation.
        type: int
      redirect:
        description:
        - The state of the HTTP to HTTPS redirect service.
        - The APIC defaults to C(disabled) when unset during creation.
        type: str
        choices: [ enabled, disabled, tested ]
      allow_origins:
        description:
        - The allowed origins for the HTTP connection.
        - 'Example format: http://127.0.0.1:8000'
        type: str
      allow_credentials:
        description:
        - The state of the allow credential for the HTTP connection.
        - The APIC defaults to C(disabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      throttle:
        description:
        - The state of the request throttle for the HTTP connection.
        - The APIC defaults to C(disabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      throttle_rate:
        description:
        - The rate of the request throttle.
        - The APIC defaults to C(10000) when unset during creation.
        type: int
      throttle_unit:
        description:
        - The unit of the request throttle rate.
        - The APIC defaults to C(requests_per_second) when unset during creation.
        type: str
        choices: [ requests_per_second, requests_per_minute ]
  https:
    description:
    - Parameters for HTTPS configuration (comm:Https).
    type: dict
    suboptions:
      admin_state:
        description:
        - The admin state of the HTTPS connection.
        - The APIC defaults to C(enabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      port:
        description:
        - The port for the HTTPS connection.
        - The APIC defaults to C(443) when unset during creation.
        type: int
      allow_origins:
        description:
        - The allowed origins for the HTTPS connection.
        - 'Example format: http://127.0.0.1:8000'
        type: str
      allow_credentials:
        description:
        - The state of the allow credential for the HTTPS connection.
        - The APIC defaults to C(disabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      ssl:
        description:
        - The SSL protocol(s) for the HTTPS connection.
        - The APIC defaults to C(tls_v1.1) and C(tls_v1.2) set when unset during creation.
        type: list
        elements: str
        choices: [ tls_v1.0, tls_v1.1, tls_v1.2, tls_v1.3 ]
        aliases: [ ssl_protocols ]
      dh_param:
        description:
        - The Diffie-Hellman parameter for the HTTPS connection.
        - The APIC defaults to C(none) when unset during creation.
        type: str
        choices: [ '1024', '2048', '4096', none ]
      throttle:
        description:
        - The state of the request throttle for the HTTPS connection.
        - The APIC defaults to C(disabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      throttle_rate:
        description:
        - The rate of the request throttle.
        - The APIC defaults to C(10000) when unset during creation.
        type: int
      throttle_unit:
        description:
        - The unit of the request throttle rate.
        - The APIC defaults to C(requests_per_second) when unset during creation.
        type: str
        choices: [ requests_per_second, requests_per_minute ]
      admin_key_ring:
        description:
        - The admin key ring for the HTTPS connection.
        - The APIC defaults to C(default) when unset during creation.
        type: str
      client_certificate_trustpoint:
        description:
        - The client certificate trustpoint for the HTTPS connection.
        type: str
        aliases: [ trustpoint ]
      client_certificate_authentication_state:
        description:
        - The client certificate authentication state for the HTTPS connection.
        - The APIC defaults to C(disabled) when unset during creation.
        - The C(enabled) state requires a C(client_certificate_trustpoint) to be set.
        type: str
        choices: [ enabled, disabled ]
        aliases: [ client_certificate_auth_state, auth_state, authentication_state ]
  telnet:
    description:
    - Parameters for telnet configuration (comm:Telnet).
    type: dict
    suboptions:
      admin_state:
        description:
        - The admin state of the telnet connection.
        - The APIC defaults to C(disabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      port:
        description:
        - The port for the telnet connection.
        - The APIC defaults to C(23) when unset during creation.
        type: int
  ssh:
    description:
    - Parameters for SSH configuration (comm:Ssh).
    type: dict
    suboptions:
      admin_state:
        description:
        - The admin state of the SSH connection.
        - The APIC defaults to C(enabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      password_auth_state:
        description:
        - The password authentication state of the SSH connection.
        - The APIC defaults to C(enabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
      port:
        description:
        - The port for the SSH connection.
        - The APIC defaults to C(22) when unset during creation.
        type: int
      ciphers:
        description:
        - The ciphers of the SSH connection.
        - The APIC defaults to all options set when unset during creation.
        type: list
        elements: str
        choices: [ aes128_ctr, aes192_ctr, aes256_ctr, aes128_gcm, aes256_gcm, chacha20 ]
      kex:
        description:
        - The KEX algorithms of the SSH connection.
        - The APIC defaults to all options set when unset during creation.
        type: list
        elements: str
        choices: [ dh_sha1, dh_sha256, dh_sha512, curve_sha256, curve_sha256_libssh, ecdh_256, ecdh_384, ecdh_521 ]
      macs:
        description:
        - The MACs of the SSH connection.
        - The APIC defaults to all options set  when unset during creation.
        type: list
        elements: str
        choices: [ sha1, sha2_256, sha2_512, sha2_256_etm, sha2_512_etm ]
  ssh_web:
    description:
    - Parameters for SSH access via WEB configuration (comm:Shellinabox).
    type: dict
    suboptions:
      admin_state:
        description:
        - The admin state of the SSH access via WEB connection.
        - The APIC defaults to C(disabled) when unset during creation.
        type: str
        choices: [ enabled, disabled ]
  state:
    description:
    - Use C(present) for updating configuration.
    - Use C(query) for showing current configuration.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci
- cisco.aci.annotation
- cisco.aci.owner

seealso:
- name: APIC Management Information Model reference
  description: More information about the internal APIC class B(comm:Pol).
  link: https://developer.cisco.com/docs/apic-mim-ref/
author:
- Akini Ross (@akinross)
"""

EXAMPLES = r"""
- name: Create a Fabric Management Access policy
  cisco.aci.aci_fabric_management_access:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: fabric_management_access_policy_1
    description: "This is a example Fabric Management Access policy."
    state: present
  delegate_to: localhost

- name: Create a Fabric Management Access policy with telnet enabled
  cisco.aci.aci_fabric_management_access:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: fabric_management_access_policy_1
    description: "This is a example Fabric Management Access policy."
    telnet:
      admin_state: enabled
    state: present
  delegate_to: localhost

- name: Create a Fabric Management Access policy with SSH access via WEB enabled
  cisco.aci.aci_fabric_management_access:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: fabric_management_access_policy_1
    description: "This is a example Fabric Management Access policy."
    ssh_web:
      admin_state: enabled
    state: present
  delegate_to: localhost

- name: Create a Fabric Management Access policy with SSH enabled and ciphers set
  cisco.aci.aci_fabric_management_access:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: fabric_management_access_policy_1
    description: "This is a example Fabric Management Access policy."
    ssh:
      admin_state: enabled
      ciphers:
        - aes128_ctr
        - aes192_ctr
        - aes256_ctr
    state: present
  delegate_to: localhost

- name: Create a Fabric Management Access policy with HTTP enabled
  cisco.aci.aci_fabric_management_access:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: fabric_management_access_policy_1
    description: "This is a example Fabric Management Access policy."
    http:
      admin_state: enabled
      allow_origins: http://127.0.0.1:8000
      throttle: enabled
      throttle_rate: 7500
      throttle_unit: requests_per_minute
    state: present
  delegate_to: localhost

- name: Create a Fabric Management Access policy with HTTPS enabled
  cisco.aci.aci_fabric_management_access:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: fabric_management_access_policy_1
    description: "This is a example Fabric Management Access policy."
    https:
      admin_state: enabled
      port: 445
      allow_origins: http://127.0.0.1:8000
      allow_credentials: enabled
      ssl:
        - tls_v1.2
      dh_param: 4096
      throttle: enabled
      throttle_rate: 7500
      throttle_unit: requests_per_minute
      admin_key_ring: default
      client_certificate_trustpoint: ansible_trustpoint
      client_certificate_authentication_state: enabled
    state: present
  delegate_to: localhost

- name: Query a Fabric Management Access policy
  cisco.aci.aci_fabric_management_access:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: fabric_management_access_policy_1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all Fabric Management Access policies
  cisco.aci.aci_fabric_management_access:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Delete a Fabric Management Access policy
  cisco.aci.aci_fabric_management_access:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: fabric_management_access_policy_1
    state: absent
  delegate_to: localhost
"""

RETURN = r"""
current:
  description: The existing configuration from the APIC after the module has finished
  returned: success
  type: list
  sample:
    [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production environment",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
error:
  description: The error information as returned from the APIC
  returned: failure
  type: dict
  sample:
    {
        "code": "122",
        "text": "unknown managed object class foo"
    }
raw:
  description: The raw output returned by the APIC REST API (xml or json)
  returned: parse error
  type: str
  sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class foo"/></imdata>'
sent:
  description: The actual/minimal configuration pushed to the APIC
  returned: info
  type: list
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment"
            }
        }
    }
previous:
  description: The original configuration from the APIC before the module has started
  returned: info
  type: list
  sample:
    [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
proposed:
  description: The assembled configuration from the user-provided parameters
  returned: info
  type: dict
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment",
                "name": "production"
            }
        }
    }
filter_string:
  description: The filter string used for the request
  returned: failure or debug
  type: str
  sample: ?rsp-prop-include=config-only
method:
  description: The HTTP method used for the request to the APIC
  returned: failure or debug
  type: str
  sample: POST
response:
  description: The HTTP response from the APIC
  returned: failure or debug
  type: str
  sample: OK (30 bytes)
status:
  description: The HTTP status from the APIC
  returned: failure or debug
  type: int
  sample: 200
url:
  description: The HTTP url used for the request to the APIC
  returned: failure or debug
  type: str
  sample: https://10.11.12.13/api/mo/uni/tn-production.json
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec, aci_annotation_spec, aci_owner_spec
from ansible_collections.cisco.aci.plugins.module_utils.constants import THROTTLE_UNIT, SSH_CIPHERS, KEX_ALGORITHMS, SSH_MACS, HTTP_TLS_MAPPING


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(aci_annotation_spec())
    argument_spec.update(aci_owner_spec())
    argument_spec.update(
        name=dict(type="str", aliases=["fabric_management_access_policy_name"]),  # Not required for querying all objects
        description=dict(type="str", aliases=["descr"]),
        name_alias=dict(type="str"),
        http=dict(
            type="dict",
            options=dict(
                admin_state=dict(type="str", choices=["enabled", "disabled"]),
                port=dict(type="int"),
                redirect=dict(type="str", choices=["enabled", "disabled", "tested"]),
                allow_origins=dict(type="str"),
                allow_credentials=dict(type="str", choices=["enabled", "disabled"]),
                throttle=dict(type="str", choices=["enabled", "disabled"]),
                throttle_rate=dict(type="int"),
                throttle_unit=dict(type="str", choices=["requests_per_second", "requests_per_minute"]),
            ),
        ),
        https=dict(
            type="dict",
            options=dict(
                admin_state=dict(type="str", choices=["enabled", "disabled"]),
                port=dict(type="int"),
                allow_origins=dict(type="str"),
                allow_credentials=dict(type="str", choices=["enabled", "disabled"]),
                ssl=dict(
                    type="list",
                    elements="str",
                    choices=list(HTTP_TLS_MAPPING.keys()),
                    aliases=["ssl_protocols"],
                ),
                dh_param=dict(type="str", choices=["1024", "2048", "4096", "none"]),
                throttle=dict(type="str", choices=["enabled", "disabled"]),
                throttle_rate=dict(type="int"),
                throttle_unit=dict(type="str", choices=["requests_per_second", "requests_per_minute"]),
                admin_key_ring=dict(type="str", no_log=False),
                client_certificate_trustpoint=dict(type="str", aliases=["trustpoint"]),
                client_certificate_authentication_state=dict(
                    type="str",
                    choices=["enabled", "disabled"],
                    aliases=["client_certificate_auth_state", "auth_state", "authentication_state"],
                ),
            ),
        ),
        telnet=dict(
            type="dict",
            options=dict(
                admin_state=dict(type="str", choices=["enabled", "disabled"]),
                port=dict(type="int"),
            ),
        ),
        ssh=dict(
            type="dict",
            options=dict(
                admin_state=dict(type="str", choices=["enabled", "disabled"]),
                password_auth_state=dict(type="str", choices=["enabled", "disabled"]),
                port=dict(type="int"),
                ciphers=dict(type="list", elements="str", choices=list(SSH_CIPHERS.keys())),
                kex=dict(type="list", elements="str", choices=list(KEX_ALGORITHMS.keys())),
                macs=dict(type="list", elements="str", choices=list(SSH_MACS.keys())),
            ),
        ),
        ssh_web=dict(
            type="dict",
            options=dict(
                admin_state=dict(type="str", choices=["enabled", "disabled"]),
            ),
        ),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["name"]],
            ["state", "absent", ["name"]],
        ],
    )

    aci = ACIModule(module)
    aci_class = "commPol"
    aci_child_classes = ["commSsh", "commHttp", "commHttps", "commTelnet", "commShellinabox"]

    name = module.params.get("name")
    description = module.params.get("description")
    name_alias = module.params.get("name_alias")
    http = module.params.get("http")
    https = module.params.get("https")
    telnet = module.params.get("telnet")
    ssh = module.params.get("ssh")
    ssh_web = module.params.get("ssh_web")
    state = module.params.get("state")

    aci.construct_url(
        root_class=dict(
            aci_class=aci_class,
            aci_rn="fabric/comm-{0}".format(name),
            module_object=name,
            target_filter={"name": name},
        ),
        child_classes=aci_child_classes,
    )

    aci.get_existing()

    if state == "present":
        child_configs = []

        if ssh:
            child_configs.append(
                dict(
                    commSsh=dict(
                        attributes=dict(
                            adminSt=ssh.get("admin_state"),
                            passwordAuth=ssh.get("password_auth_state"),
                            port=ssh.get("port"),
                            sshCiphers=",".join(sorted(SSH_CIPHERS.get(v) for v in set(ssh.get("ciphers")))) if ssh.get("ciphers") else None,
                            kexAlgos=",".join(sorted(KEX_ALGORITHMS.get(v) for v in set(ssh.get("kex")))) if ssh.get("kex") else None,
                            sshMacs=",".join(sorted(SSH_MACS.get(v) for v in set(ssh.get("macs")))) if ssh.get("macs") else None,
                        )
                    )
                )
            )

        if http:
            child_configs.append(
                dict(
                    commHttp=dict(
                        attributes=dict(
                            adminSt=http.get("admin_state"),
                            port=http.get("port"),
                            redirectSt=http.get("redirect"),
                            accessControlAllowOrigins=http.get("allow_origins"),
                            accessControlAllowCredential=http.get("allow_credentials"),
                            globalThrottleSt=http.get("throttle"),
                            globalThrottleRate=http.get("throttle_rate"),
                            globalThrottleUnit=THROTTLE_UNIT.get(http.get("throttle_unit")),
                        )
                    )
                )
            )

        if https:
            https_config = dict(
                commHttps=dict(
                    attributes=dict(
                        adminSt=https.get("admin_state"),
                        port=https.get("port"),
                        accessControlAllowOrigins=https.get("allow_origins"),
                        accessControlAllowCredential=https.get("allow_credentials"),
                        sslProtocols=",".join(sorted(HTTP_TLS_MAPPING.get(v) for v in set(https.get("ssl")))) if https.get("ssl") else None,
                        dhParam=https.get("dh_param"),
                        globalThrottleSt=https.get("throttle"),
                        globalThrottleRate=https.get("throttle_rate"),
                        globalThrottleUnit=THROTTLE_UNIT.get(https.get("throttle_unit")),
                        clientCertAuthState=https.get("client_certificate_authentication_state"),
                    ),
                    children=[],
                )
            )

            if https.get("admin_key_ring"):
                https_config["commHttps"]["children"].append(dict(commRsKeyRing=dict(attributes=dict(tnPkiKeyRingName=https.get("admin_key_ring")))))

            if https.get("client_certificate_trustpoint"):
                https_config["commHttps"]["children"].append(
                    dict(commRsClientCertCA=dict(attributes=dict(tDn="uni/userext/pkiext/tp-{0}".format(https.get("client_certificate_trustpoint")))))
                )

            child_configs.append(https_config)

        if telnet:
            child_configs.append(
                dict(
                    commTelnet=dict(
                        attributes=dict(
                            adminSt=telnet.get("admin_state"),
                            port=telnet.get("port"),
                        )
                    )
                )
            )

        if ssh_web:
            child_configs.append(
                dict(
                    commShellinabox=dict(
                        attributes=dict(
                            adminSt=ssh_web.get("admin_state"),
                        )
                    )
                )
            )

        aci.payload(
            aci_class=aci_class,
            class_config=dict(
                name=name,
                descr=description,
                nameAlias=name_alias,
            ),
            child_configs=child_configs,
        )

        aci.get_diff(aci_class=aci_class)

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
