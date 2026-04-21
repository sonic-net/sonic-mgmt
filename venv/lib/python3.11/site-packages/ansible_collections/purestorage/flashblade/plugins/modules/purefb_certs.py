#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2024, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefb_certs
version_added: '1.4.0'
short_description: Manage FlashBlade SSL Certificates
description:
- Create, delete, import and export FlashBlade SSL Certificates
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the SSL Certificate
    type: str
    default: management
  state:
    description:
    - Action for the module to perform
    - I(present) will create or re-create an SSL certificate
    - I(absent) will delete an existing SSL certificate
    - I(sign) will construct a Certificate Signing request (CSR)
    - I(export) will export the exisitng SSL certificate
    - I(import) will import a CA provided certificate.
    default: present
    choices: [ absent, present, import, export, sign ]
    type: str
  country:
    type: str
    description:
    - The two-letter ISO code for the country where your organization is located
  province:
    type: str
    description:
    - The full name of the state or province where your organization is located
  locality:
    type: str
    description:
    - The full name of the city where your organization is located
  organization:
    type: str
    description:
    - The full and exact legal name of your organization.
    - The organization name should not be abbreviated and should
      include suffixes such as Inc, Corp, or LLC.
  org_unit:
    type: str
    description:
    - The department within your organization that is managing the certificate
  common_name:
    type: str
    description:
    - The fully qualified domain name (FQDN) of the current system
    - For example, the common name for https://pureblade.example.com is
      pureblade.example.com, or *.example.com for a wildcard certificate
    - This can also be the management IP address of the system or the
      shortname of the current system.
    - Maximum of 64 characters
    - If not provided this will default to the shortname of the system
  email:
    type: str
    description:
    - The email address used to contact your organization
  key_size:
    type: int
    description:
    - The key size in bits if you generate a new private key
    default: 2048
    choices: [ 1024, 2048, 4096 ]
  days:
    default: 3650
    type: int
    description:
    - The number of valid days for the self-signed certificate being generated
    - If not specified, the self-signed certificate expires after 3650 days.
  generate:
    default: false
    type: bool
    description:
    - Generate a new private key.
    - If not selected, the certificate will use the existing key
  certificate:
    aliases: [ contents ]
    type: str
    description:
    - Required for I(import)
    - A valid signed certicate in PEM format (Base64 encoded)
    - Includes the "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----" lines
    - Does not exceed 3000 characters in length
  intermediate_cert:
    aliases: [ intermeadiate_cert ]
    type: str
    description:
    - Intermeadiate certificate provided by the CA
  key:
    aliases: [ private_key ]
    type: str
    description:
    - If the Certificate Signed Request (CSR) was not constructed on the system
      or the private key has changed since construction the CSR, provide
      a new private key here
  passphrase:
    type: str
    description:
    - Passphrase if the private key is encrypted
  export_file:
    type: str
    description:
    - Name of file to contain Certificate Signing Request when `status sign`
    - Name of file to export the current SSL Certificate when `status export`
    - File will be overwritten if it already exists
  key_algorithm:
    type: str
    description:
    - The key algorithm used to generate the certificate.
    - This field can only be specified when creating a new self-signed certificate
    choices: [ rsa, ec, ed448, ed25519 ]
    version_added: "1.22.0"
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create SSL certifcate foo
  purestorage.flashblade.purefb_certs:
    name: foo
    key_size: 4096
    country: US
    province: FL
    locality: Miami
    organization: "Acme Inc"
    org_unit: "DevOps"
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete SSL certificate foo
  purestorage.flashblade.purefb_certs:
    name: foo
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Request CSR
  purestorage.flashblade.purefb_certs:
    state: sign
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Request CSR with updated fields
  purestorage.flashblade.purefb_certs:
    state: sign
    org_unit: Development
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Regenerate key for SSL foo
  purestorage.flashblade.purefb_certs:
    generate: true
    name: foo
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Import SSL Cert foo and Private Key
  purestorage.flashblade.purefb_certs:
    state: import
    name: foo
    certificate: "{{lookup('file', 'example.crt') }}"
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flashblade import (
        CertificatePost,
        CertificateSigningRequestPost,
        Reference,
        Certificate,
        CertificatePatch,
    )
except ImportError:
    HAS_PURESTORAGE = False

HAS_PYCOUNTRY = True
try:
    import pycountry
except ImportError:
    HAS_PYCOUNTRY = False

import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


CERT_TYPE_VERSION = "2.15"
CSR_API_VERSION = "2.20"


def update_cert(module, blade):
    """Update existing SSL Certificate"""
    api_versions = list(blade.get_versions().items)
    changed = False
    if CSR_API_VERSION in api_versions:
        current_cert = list(
            blade.get_certificates(names=[module.params["name"]]).items
        )[0]
        new_cert = current_cert
        if module.params["certificate"] and module.params["certificate"] != getattr(
            current_cert, "certificate", None
        ):
            new_cert.certificate = module.params["certificate"]
        else:
            new_cert.certificate = getattr(current_cert, "certificate", None)
        if module.params["common_name"] and module.params["common_name"] != getattr(
            current_cert, "common_name", None
        ):
            new_cert.common_name = module.params["common_name"]
        else:
            new_cert.common_name = getattr(current_cert, "common_name", None)
        if module.params["country"] and module.params["country"] != getattr(
            current_cert, "country", None
        ):
            new_cert.country = module.params["country"]
        else:
            new_cert.country = getattr(current_cert, "country")
        if module.params["email"] and module.params["email"] != getattr(
            current_cert, "email", None
        ):
            new_cert.email = module.params["email"]
        else:
            new_cert.email = getattr(current_cert, "email", None)
        if module.params["key_size"] and module.params["key_size"] != getattr(
            current_cert, "key_size", None
        ):
            new_cert.key_size = module.params["key_size"]
        else:
            new_cert.key_size = getattr(current_cert, "key_size", None)
        if module.params["locality"] and module.params["locality"] != getattr(
            current_cert, "locality", None
        ):
            new_cert.locality = module.params["locality"]
        else:
            new_cert.locality = getattr(current_cert, "locality", None)
        if module.params["province"] and module.params["province"] != getattr(
            current_cert, "state", None
        ):
            new_cert.state = module.params["province"]
        else:
            new_cert.state = getattr(current_cert, "state", None)
        if module.params["organization"] and module.params["organization"] != getattr(
            current_cert, "organization", None
        ):
            new_cert.organization = module.params["organization"]
        else:
            new_cert.organization = getattr(current_cert, "organization", None)
        if module.params["org_unit"] and module.params["org_unit"] != getattr(
            current_cert, "organizational_unit", None
        ):
            new_cert.organizational_unit = module.params["org_unit"]
        else:
            new_cert.organizational_unit = getattr(
                current_cert, "organizational_unit", None
            )
        if module.params["key_algorithm"] and module.params["key_algorithm"] != getattr(
            current_cert, "key_algorithm", None
        ):
            new_cert.key_algorithm = module.params["key_algorithm"]
        else:
            new_cert.key_algorithm = getattr(current_cert, "key_algorithm", None)
        if new_cert != current_cert:
            changed = True
            certificate = CertificatePost(
                certificate=new_cert.certificate,
                certificate_type="array",
                common_name=new_cert.common_name,
                country=getattr(new_cert, "country", None),
                email=getattr(new_cert, "email", None),
                key_size=getattr(new_cert, "key_size", None),
                locality=getattr(new_cert, "locality", None),
                organization=getattr(new_cert, "organization", None),
                organizational_unit=getattr(new_cert, "organizational_unit", None),
                key_algorithm=getattr(new_cert, "key_algorithm", None),
                state=getattr(new_cert, "state", None),
                days=module.params["days"],
            )
            if not module.check_mode:
                res = blade.patch_certificates(
                    names=[module.params["name"]],
                    certificate=certificate,
                    generate_new_key=module.params["generate"],
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Updating existing SSL certificate {0} failed. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
    else:
        changed = True
        certificate = CertificatePatch(
            certificate=module.params["certificate"],
            intermeadiate_certificate=module.params["intermeadiate_cert"],
            private_key=module.params["key"],
            passphrase=module.params["passphrase"],
        )
        res = blade.patch_certificates(
            names=[module.params["name"]], certificate=certificate
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Updating existing SSL certificate {0} failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def create_cert(module, blade):
    changed = True
    api_versions = list(blade.get_versions().items)
    if CERT_TYPE_VERSION in api_versions:
        certificate = CertificatePost(
            certificate=module.params["certificate"],
            certificate_type="array",
            common_name=module.params["common_name"],
            country=module.params["country"],
            email=module.params["email"],
            key_size=module.params["key_size"],
            locality=module.params["locality"],
            organization=module.params["organization"],
            organizational_unit=module.params["org_unit"],
            state=module.params["province"],
            status="self-signed",
            days=module.params["days"],
        )
    else:
        certificate = CertificatePost(
            certificate=module.params["certificate"],
            certificate_type="array",
            common_name=module.params["common_name"],
            country=module.params["country"],
            email=module.params["email"],
            key_size=module.params["key_size"],
            locality=module.params["locality"],
            organization=module.params["organization"],
            organizational_unit=module.params["org_unit"],
            state=module.params["province"],
            status="self-signed",
            days=module.params["days"],
        )
    if not module.check_mode:
        res = blade.post_certificates(
            names=[module.params["name"]], certificate=certificate
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Creating SSL certificate {0} failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )

    module.exit_json(changed=changed)


def delete_cert(module, blade):
    changed = True
    if module.params["name"] == "management":
        module.fail_json(msg="management SSL cannot be deleted")
    if not module.check_mode:
        res = blade.delete_certificates(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete {0} SSL certifcate. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def import_cert(module, blade):
    """Import a CA provided SSL certificate"""
    changed = True
    if not module.check_mode:
        if CERT_TYPE_VERSION in list(blade.get_versions().items):
            certificate = CertificatePost(
                certificate_type="external",
                certificate=module.params["certificate"],
                status="imported",
            )
        else:
            certificate = CertificatePost(
                certificate=module.params["certificate"],
                intermediate_certificate=module.params["intermediate_cert"],
                key_size=module.params["key_size"],
                passphrase=module.params["passphrase"],
                status="imported",
            )
        res = blade.post_certificates(
            names=[module.params["name"]], certificate=certificate
        )
    if res.status_code != 200:
        module.fail_json(
            msg="Importing Certificate failed. Error: {0}".format(res.errors[0].message)
        )
    module.exit_json(changed=changed)


def export_cert(module, blade):
    """Export current SSL certificate"""
    changed = True
    if not module.check_mode:
        ssl = blade.get_certificates(names=[module.params["name"]])
        if ssl.status_code != 200:
            module.fail_json(
                msg="Exporting Certificate failed. Error: {0}".format(
                    ssl.errors[0].message
                )
            )
        with open(module.params["export_file"], "w", encoding="utf-8") as ssl_file:
            ssl_file.write(list(ssl.items)[0].certificate)
    module.exit_json(changed=changed)


def create_csr(module, blade):
    """Construct a Certificate Signing Request

    Output the result to a specified file
    """
    changed = True
    current_attr = Certificate()
    res = blade.get_certificates(names=[module.params["name"]])
    if res.status_code == 200:
        current_attr = list(res.items)[0]
    if module.params["common_name"] and module.params["common_name"] != getattr(
        current_attr, "common_name", None
    ):
        current_attr.common_name = module.params["common_name"]
    if module.params["country"] and module.params["country"] != getattr(
        current_attr, "country", None
    ):
        current_attr.country = module.params["country"]
    if module.params["email"] and module.params["email"] != getattr(
        current_attr, "email", None
    ):
        current_attr.email = module.params["email"]
    if module.params["locality"] and module.params["locality"] != getattr(
        current_attr, "locality", None
    ):
        current_attr.locality = module.params["locality"]
    if module.params["province"] and module.params["province"] != getattr(
        current_attr, "state", None
    ):
        current_attr.state = module.params["province"]
    if module.params["organization"] and module.params["organization"] != getattr(
        current_attr, "organization", None
    ):
        current_attr.organization = module.params["organization"]
    if module.params["org_unit"] and module.params["org_unit"] != getattr(
        current_attr, "organizational_unit", None
    ):
        current_attr.organizational_unit = module.params["org_unit"]
    if not module.check_mode:
        certificate = CertificateSigningRequestPost(
            certificate=Reference(name=module.params["name"]),
            common_name=getattr(current_attr, "common_name", None),
            country=getattr(current_attr, "country", None),
            email=getattr(current_attr, "email", None),
            locality=getattr(current_attr, "locality", None),
            state=getattr(current_attr, "state", None),
            organization=getattr(current_attr, "organization", None),
            organizational_unit=getattr(current_attr, "organizational_unit", None),
        )
        csr = list(
            blade.post_certificates_certificate_signing_requests(
                certificate=certificate
            ).items
        )[0].certificate_signing_request
        with open(module.params["export_file"], "w", encoding="utf-8") as csr_file:
            csr_file.write(list(csr))
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(
                type="str",
                default="present",
                choices=["absent", "present", "import", "export", "sign"],
            ),
            generate=dict(type="bool", default=False),
            name=dict(type="str", default="management"),
            country=dict(type="str"),
            province=dict(type="str"),
            locality=dict(type="str"),
            organization=dict(type="str"),
            org_unit=dict(type="str"),
            common_name=dict(type="str"),
            email=dict(type="str"),
            key_size=dict(type="int", default=2048, choices=[1024, 2048, 4096]),
            certificate=dict(type="str", no_log=True, aliases=["contents"]),
            intermediate_cert=dict(
                type="str", no_log=True, aliases=["intermeadiate_cert"]
            ),
            key=dict(type="str", no_log=True, aliases=["private_key"]),
            export_file=dict(type="str"),
            passphrase=dict(type="str", no_log=True),
            days=dict(type="int", default=3650),
            key_algorithm=dict(type="str", choices=["rsa", "ec", "ed448", "ed25519"]),
        )
    )

    mutually_exclusive = [["certificate", "key_size"]]
    required_if = [
        ["state", "import", ["certificate"]],
        ["state", "export", ["export_file"]],
        ["state", "sign", ["export_file"]],
    ]

    module = AnsibleModule(
        argument_spec,
        mutually_exclusive=mutually_exclusive,
        required_if=required_if,
        supports_check_mode=True,
    )

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    if not HAS_PYCOUNTRY:
        module.fail_json(msg="pycountry sdk is required for this module")

    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    blade = get_system(module)
    api_versions = list(blade.get_versions().items)

    if module.params["email"]:
        if not re.search(email_pattern, module.params["email"]):
            module.fail_json(
                msg="Email {0} is not valid".format(module.params["email"])
            )
    if module.params["country"]:
        if len(module.params["country"]) != 2:
            module.fail_json(msg="Country must be a two-letter country (ISO) code")
        if not pycountry.countries.get(alpha_2=module.params["country"].upper()):
            module.fail_json(
                msg="Country code {0} is not an assigned ISO 3166-1 code".format(
                    module.params["country"].upper()
                )
            )
    state = module.params["state"]
    if state in ["present"]:
        if not module.params["common_name"]:
            module.params["common_name"] = list(blade.get_arrays().items)[0].name
        module.params["common_name"] = module.params["common_name"][:64]

    exists = bool(
        blade.get_certificates(names=[module.params["name"]]).status_code == 200
    )

    if not exists and state == "present":
        create_cert(module, blade)
    elif exists and state == "present":
        update_cert(module, blade)
    elif state == "sign":
        if CSR_API_VERSION not in api_versions:
            module.fail_json(msg="Purity//FB 4.6.3+ is required for CSRs")
        create_csr(module, blade)
    elif not exists and state == "import":
        import_cert(module, blade)
    elif exists and state == "import":
        module.fail_json(msg="External Certificates cannot be reimported")
    elif state == "export":
        export_cert(module, blade)
    elif exists and state == "absent":
        delete_cert(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
