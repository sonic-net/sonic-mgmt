#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2021, Simon Dodsley (simon@purestorage.com)
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
module: purefa_certs
version_added: '1.8.0'
short_description: Manage FlashArray SSL Certificates
description:
- Create, delete, import and export FlashArray SSL Certificates
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
    - The fully qualified domain name (FQDN) of the current array
    - For example, the common name for https://purearray.example.com is
      purearray.example.com, or *.example.com for a wildcard certificate
    - This can also be the management IP address of the array or the
      shortname of the current array.
    - Maximum of 64 characters
    - If not provided this will default to the shortname of the array
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
    type: str
    description:
    - Required for I(import)
    - A valid signed certicate in PEM format (Base64 encoded)
    - Includes the "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----" lines
  intermeadiate_cert:
    type: str
    description:
    - Intermeadiate certificate provided by the CA
  key:
    type: str
    description:
    - If the Certificate Signed Request (CSR) was not constructed on the array
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
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create SSL certifcate foo
  purestorage.flasharray.purefa_certs:
    name: foo
    key_size: 4096
    country: US
    province: FL
    locality: Miami
    organization: "Acme Inc"
    org_unit: "DevOps"
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete SSL certificate foo
  purestorage.flasharray.purefa_certs:
    name: foo
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Request CSR
  purestorage.flasharray.purefa_certs:
    state: sign
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Request CSR with updated fields
  purestorage.flasharray.purefa_certs:
    state: sign
    org_unit: Development
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Regenerate key for SSL foo
  purestorage.flasharray.purefa_certs:
    generate: true
    name: foo
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Import SSL Cert foo and Private Key
  purestorage.flasharray.purefa_certs:
    state: import
    name: foo
    certificate: "{{lookup('file', 'example.crt') }}"
    key: "{{lookup('file', 'example.key') }}"
    passphrase: password
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient import flasharray
except ImportError:
    HAS_PURESTORAGE = False

HAS_PYCOUNTRY = True
try:
    import pycountry
except ImportError:
    HAS_PYCOUNTRY = False

import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)

MIN_REQUIRED_API_VERSION = "2.4"


def update_cert(module, array):
    """Update existing SSL Certificate"""
    changed = False
    current_cert = list(array.get_certificates(names=[module.params["name"]]).items)[0]
    new_cert = current_cert
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
    if new_cert != current_cert:
        changed = True
        certificate = flasharray.CertificatePost(
            common_name=new_cert.common_name,
            country=getattr(new_cert, "country", None),
            email=getattr(new_cert, "email", None),
            key_size=getattr(new_cert, "key_size", None),
            locality=getattr(new_cert, "locality", None),
            organization=getattr(new_cert, "organization", None),
            organizational_unit=getattr(new_cert, "organizational_unit", None),
            state=getattr(new_cert, "state", None),
        )
        if not module.check_mode:
            res = array.patch_certificates(
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

    module.exit_json(changed=changed)


def create_cert(module, array):
    changed = True
    certificate = flasharray.CertificatePost(
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
        res = array.post_certificates(
            names=[module.params["name"]], certificate=certificate
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Creating SSL certificate {0} failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )

    module.exit_json(changed=changed)


def delete_cert(module, array):
    changed = True
    if module.params["name"] == "management":
        module.fail_json(msg="management SSL cannot be deleted")
    if not module.check_mode:
        res = array.delete_certificates(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete {0} SSL certifcate. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def import_cert(module, array, reimport=False):
    """Import a CA provided SSL certificate"""
    changed = True
    certificate = flasharray.CertificatePost(
        certificate=module.params["certificate"],
        intermediate_certificate=module.params["intermeadiate_cert"],
        key=module.params["key"],
        passphrase=module.params["passphrase"],
        status="imported",
    )
    if not module.check_mode:
        if reimport:
            res = array.patch_certificates(
                names=[module.params["name"]], certificate=certificate
            )
        else:
            res = array.post_certificates(
                names=[module.params["name"]], certificate=certificate
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Importing Certificate failed. Error: {0}".format(
                    res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def export_cert(module, array):
    """Export current SSL certificate"""
    changed = True
    if not module.check_mode:
        ssl = array.get_certificates(names=[module.params["name"]])
        if ssl.status_code != 200:
            module.fail_json(
                msg="Exporting Certificate failed. Error: {0}".format(
                    ssl.errors[0].message
                )
            )
        with open(module.params["export_file"], "w", encoding="utf-8") as ssl_file:
            ssl_file.write(list(ssl.items)[0].certificate)
    module.exit_json(changed=changed)


def create_csr(module, array):
    """Construct a Certificate Signing Request

    Output the result to a specified file
    """
    changed = True
    current_attr = list(array.get_certificates(names=[module.params["name"]]).items)[0]
    try:
        if module.params["common_name"] and module.params["common_name"] != getattr(
            current_attr, "common_name", None
        ):
            current_attr.common_name = module.params["common_name"]
    except AttributeError:
        pass
    try:
        if module.params["country"] and module.params["country"] != getattr(
            current_attr, "country", None
        ):
            current_attr.country = module.params["country"]
    except AttributeError:
        pass
    try:
        if module.params["email"] and module.params["email"] != getattr(
            current_attr, "email", None
        ):
            current_attr.email = module.params["email"]
    except AttributeError:
        pass
    try:
        if module.params["locality"] and module.params["locality"] != getattr(
            current_attr, "locality", None
        ):
            current_attr.locality = module.params["locality"]
    except AttributeError:
        pass
    try:
        if module.params["province"] and module.params["province"] != getattr(
            current_attr, "state", None
        ):
            current_attr.state = module.params["province"]
    except AttributeError:
        pass
    try:
        if module.params["organization"] and module.params["organization"] != getattr(
            current_attr, "organization", None
        ):
            current_attr.organization = module.params["organization"]
    except AttributeError:
        pass
    try:
        if module.params["org_unit"] and module.params["org_unit"] != getattr(
            current_attr, "organizational_unit", None
        ):
            current_attr.organizational_unit = module.params["org_unit"]
    except AttributeError:
        pass
    if not module.check_mode:
        certificate = flasharray.CertificateSigningRequestPost(
            certificate={"name": module.params["name"]},
            common_name=getattr(current_attr, "common_name", None),
            country=getattr(current_attr, "country", None),
            email=getattr(current_attr, "email", None),
            locality=getattr(current_attr, "locality", None),
            state=getattr(current_attr, "state", None),
            organization=getattr(current_attr, "organization", None),
            organizational_unit=getattr(current_attr, "organizational_unit", None),
        )
        csr = list(
            array.post_certificates_certificate_signing_requests(
                certificate=certificate
            ).items
        )[0].certificate_signing_request
        with open(module.params["export_file"], "w", encoding="utf-8") as csr_file:
            csr_file.write(list(csr))
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
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
            certificate=dict(type="str", no_log=True),
            intermeadiate_cert=dict(type="str", no_log=True),
            key=dict(type="str", no_log=True),
            export_file=dict(type="str"),
            passphrase=dict(type="str", no_log=True),
            days=dict(type="int", default=3650),
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
    array = get_array(module)
    api_version = array.get_rest_version()

    if LooseVersion(MIN_REQUIRED_API_VERSION) > LooseVersion(api_version):
        module.fail_json(
            msg="FlashArray REST version not supported. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )

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
            module.params["common_name"] = list(array.get_arrays().items)[0].name
        module.params["common_name"] = module.params["common_name"][:64]

    exists = bool(
        array.get_certificates(names=[module.params["name"]]).status_code == 200
    )

    if not exists and state == "present":
        create_cert(module, array)
    elif exists and state == "present":
        update_cert(module, array)
    elif state == "sign":
        create_csr(module, array)
    elif not exists and state == "import":
        import_cert(module, array)
    elif exists and state == "import":
        import_cert(module, array, reimport=True)
    elif state == "export":
        export_cert(module, array)
    elif exists and state == "absent":
        delete_cert(module, array)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
