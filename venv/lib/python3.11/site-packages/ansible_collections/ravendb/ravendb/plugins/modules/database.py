# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: database
short_description: Manage RavenDB databases
description:
  - Create or delete a RavenDB database, and optionally apply per-database settings.
  - Supports secured connections using client certificates and optional CA verification.
  - Check mode is supported to simulate creation, deletion, or settings changes without applying them.
  - Supports creating encrypted databases by assigning a secret key (generated or user-provided) and distributing it to all cluster nodes.
  - Supports fixed placement by specifying exact cluster node tags to host the database (topology members).
  - Supports applying per-database settings (C(database_settings)) and triggering a safe database reload so changes take effect.
version_added: "1.0.0"
author: "Omer Ratsaby <omer.ratsaby@ravendb.net> (@thegoldenplatypus)"

extends_documentation_fragment:
  - ravendb.ravendb.ravendb

options:
  replication_factor:
    description:
      - Number of server nodes to replicate the database to.
      - Must be a positive integer.
      - Only used when creating a database.
      - Required on creation; ignored for existing databases.
    required: false
    default: null
    type: int
  topology_members:
    description:
      - Optional list of cluster node tags to host this database (fixed placement).
      - When provided, its length must equal C(replication_factor).
      - Honored only on creation. If the database already exists, providing C(topology_members) will fail.
    required: false
    type: list
    elements: str
    default: []
  state:
    description:
      - Desired state of the database.
      - If C(present), the database will be created if it does not exist, and settings will be reconciled.
      - If C(absent), the database will be deleted if it exists.
      - If omitted (C(null)), the module reconciles settings on an existing database but will not create or delete it.
      - If the database does not exist and C(state) is omitted, the task fails with guidance to use C(state=present).
    required: false
    type: str
    choices: [present, absent]
    default: null
  encrypted:
    description:
      - Create the database as encrypted.
      - When C(true), the module ensures a secret key is assigned (generated or read from file) and distributed to all cluster nodes before creation.
      - Requires C(certificate_path) to access admin endpoints.
    required: false
    default: false
    type: bool
  encryption_key:
    description:
      - Path to a file that contains the raw encryption key (plain text).
      - Mutually exclusive with C(generate_encryption_key).
      - Used only when C(encrypted=true).
    required: false
    type: str
  generate_encryption_key:
    description:
      - If C(true), asks the server to generate a new encryption key via the admin API.
      - Mutually exclusive with C(encryption_key).
      - Used only when C(encrypted=true).
    required: false
    default: false
    type: bool
  encryption_key_output_path:
    description:
      - When C(generate_encryption_key=true), write the generated key to this local file with safe permissions.
      - Ignored if C(generate_encryption_key=false).
    required: false
    type: str
  database_settings:
    description:
      - Dictionary of database-level settings to apply.
      - Keys and values are normalized to strings and compared against current customized settings.
      - When differences exist, the module updates settings and toggles the database state to reload them safely.
    required: false
    type: dict
    default: {}

seealso:
  - name: RavenDB documentation
    description: Official RavenDB documentation
    link: https://ravendb.net/docs

'''

EXAMPLES = '''
- name: Create a RavenDB database
  ravendb.ravendb.database:
    url: "http://{{ ansible_host }}:8080"
    database_name: "my_database"
    replication_factor: 3
    state: present

- name: Create RF=2 database on specific nodes A and C (fixed placement)
  ravendb.ravendb.database:
    url: "http://{{ ansible_host }}:8080"
    database_name: "placed_db"
    replication_factor: 2
    topology_members: ["A", "C"]
    state: present

- name: Create an encrypted database with a generated key and save it locally (requires client cert)
  become: true
  ravendb.ravendb.database:
    url: "https://{{ ansible_host }}:443"
    database_name: "secure_db"
    replication_factor: 1
    certificate_path: "admin.client.combined.pem"
    ca_cert_path: "ca_certificate.pem"
    encrypted: true
    generate_encryption_key: true
    encryption_key_output_path: "/home/$USER/secure_db.key"
    state: present

- name: Create an encrypted database using a pre-provisioned key file
  ravendb.ravendb.database:
    url: "https://{{ ansible_host }}:443"
    database_name: "secure_db2"
    replication_factor: 1
    certificate_path: "admin.client.combined.pem"
    ca_cert_path: "ca_certificate.pem"
    encrypted: true
    encryption_key: "/home/$USER/secure_db2.key"
    state: present

- name: Update database settings (idempotent) – will not create database if absent (state omitted)
  ravendb.ravendb.database:
    url: "http://{{ ansible_host }}:8080"
    database_name: "my_database"
    database_settings:
      Indexing.MapBatchSize: "64"

- name: Apply settings in check mode (no changes will be made)
  ravendb.ravendb.database:
    url: "http://{{ ansible_host }}:8080"
    database_name: "my_database"
    database_settings:
      Indexing.MapBatchSize: "64"
  check_mode: yes

- name: Delete a RavenDB database
  ravendb.ravendb.database:
    url: "http://{{ ansible_host }}:8080"
    database_name: "my_database"
    state: absent
'''

RETURN = '''
changed:
  description: Indicates if any change was made (or would have been made in check mode).
  type: bool
  returned: always
  sample: true

msg:
  description: Human-readable message describing the result or error.
  type: str
  returned: always
  sample: Database 'my_database' created successfully.
  version_added: "1.0.0"
'''

import traceback
from ansible.module_utils.basic import AnsibleModule, missing_required_lib

LIB_ERR = None
try:
    from ansible_collections.ravendb.ravendb.plugins.module_utils.common_args import ravendb_common_argument_spec
    from ansible_collections.ravendb.ravendb.plugins.module_utils.core.validation import (
        validate_url, validate_database_name, validate_replication_factor_optional, validate_paths_exist,
        validate_state_optional, validate_topology_members, collect_errors
    )
    from ansible_collections.ravendb.ravendb.plugins.module_utils.core.configuration import validate_kv
    from ansible_collections.ravendb.ravendb.plugins.module_utils.core.client import DocumentStoreFactory
    from ansible_collections.ravendb.ravendb.plugins.module_utils.core.tls import TLSConfig
    from ansible_collections.ravendb.ravendb.plugins.module_utils.reconcilers.database_reconciler import DatabaseReconciler
    from ansible_collections.ravendb.ravendb.plugins.module_utils.dto.database import DatabaseSpec, EncryptionSpec
    from ansible_collections.ravendb.ravendb.plugins.module_utils.services.encryption_service import validate_encryption_params
    from ansible_collections.ravendb.ravendb.plugins.module_utils.services import database_service as dbs
    HAS_LIB = True
except ImportError:
    HAS_LIB = False
    LIB_ERR = traceback.format_exc()


def main():
    module_args = ravendb_common_argument_spec()
    module_args.update(
        replication_factor=dict(type='int', default=None),
        state=dict(type='str', choices=['present', 'absent'], default=None),
        encrypted=dict(type='bool', default=False),
        encryption_key=dict(type='str', required=False, no_log=True),
        generate_encryption_key=dict(type='bool', default=False),
        encryption_key_output_path=dict(type='str', required=False, no_log=True),
        database_settings=dict(type='dict', default={}),
        topology_members=dict(type='list', elements='str', required=False, default=[]),
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    if not HAS_LIB:
        module.fail_json(msg=missing_required_lib("ravendb"), exception=LIB_ERR)

    url = module.params['url']
    name = module.params['database_name']
    repl = module.params['replication_factor']
    cert_path = module.params.get('certificate_path')
    ca_path = module.params.get('ca_cert_path')
    state = module.params['state']
    encrypted = module.params['encrypted']
    key_path = module.params.get('encryption_key')
    gen_key = module.params.get('generate_encryption_key')
    ekey_out_path = module.params.get('encryption_key_output_path')
    db_settings = module.params.get('database_settings') or {}
    topology_members = module.params.get('topology_members') or []

    ok, err = collect_errors(
        validate_url(url),
        validate_database_name(name),
        validate_replication_factor_optional(repl),
        validate_paths_exist(cert_path, ca_path),
        validate_state_optional(state),
        validate_topology_members(topology_members, repl)
    )
    if not ok:
        module.fail_json(msg=err)

    tls = TLSConfig(certificate_path=cert_path, ca_cert_path=ca_path)
    ok, err = validate_encryption_params(state, tls, encrypted, gen_key, key_path, ekey_out_path)
    if not ok:
        module.fail_json(msg=err)

    ok, normalized_settings, err = validate_kv(db_settings, "database_settings", allow_none=True)
    if not ok:
        module.fail_json(msg=err)

    ctx = None
    db_name = name if state == "present" else None

    try:
        ctx = DocumentStoreFactory.create(url, db_name, cert_path, ca_path)
        reconciler = DatabaseReconciler(ctx)

        spec = DatabaseSpec(
            url=url,
            name=name,
            replication_factor=repl,
            members=topology_members,
            settings=normalized_settings or {},
            encryption=EncryptionSpec(
                enabled=encrypted,
                certificate_path=cert_path,
                ca_cert_path=ca_path,
                generate_key=gen_key,
                key_path=key_path,
                output_path=ekey_out_path,
            ),
        )

        if state == "present":
            res = reconciler.ensure_present(spec, tls, module.check_mode)
        elif state == "absent":
            res = reconciler.ensure_absent(name, module.check_mode)
        else:
            existing = set(dbs.list_databases(ctx))
            if name not in existing:
                module.fail_json(msg="Database '{}' does not exist. Provide state=present to create it.".format(name))

            res = reconciler.ensure_present(spec, tls, module.check_mode)

        if res.failed:
            module.fail_json(**res.to_ansible())
        else:
            module.exit_json(**res.to_ansible())

    except Exception as e:
        module.fail_json(msg="Unexpected error: {}".format(str(e)))
    finally:
        if ctx:
            ctx.close()


if __name__ == '__main__':
    main()
