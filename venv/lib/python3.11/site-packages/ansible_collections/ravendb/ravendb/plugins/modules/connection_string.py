# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: connection_string
short_description: Manage RavenDB connection strings
description:
  - Create or delete RavenDB connection strings for supported providers.
  - Supported types - C(RAVEN), C(SQL), C(OLAP), C(ELASTIC_SEARCH), C(QUEUE), C(SNOWFLAKE), C(AI).
  - Supports secured connections using client certificates and optional CA verification.
  - Check mode is supported to simulate creation/deletion without applying changes.
  - Validates server support and enforces minimum server versions where required.
version_added: "1.1.0"
author: "Omer Ratsaby <omer.ratsaby@ravendb.net> (@thegoldenplatypus)"

extends_documentation_fragment:
  - ravendb.ravendb.ravendb

options:
  name:
    description:
      - Connection string name.
    required: true
    type: str
  cs_type:
    description:
      - Connection string type.
    required: false
    type: str
    choices: [RAVEN, SQL, OLAP, ELASTIC_SEARCH, QUEUE, SNOWFLAKE, AI]
    default: RAVEN
  properties:
    description:
      - Type-specific properties dictionary (see examples).
      - Secrets may be inline or loaded from using Ansible lookups.
    required: false
    type: dict
    default: null
  state:
    description:
      - Desired state of the connection string.
      - If C(present), the item is created when absent (no in-place updates; existing items are left unchanged).
      - If C(absent), the item is removed when present.
    required: false
    type: str
    choices: [present, absent]
    default: present

seealso:
  - name: RavenDB documentation
    description: Official RavenDB documentation
    link: https://ravendb.net/docs
'''

EXAMPLES = '''
- name: Create Raven connection string
  ravendb.ravendb.connection_string:
    url: "http://{{ ansible_host }}:8080"
    database_name: "MyDB"
    name: "raven-out"
    cs_type: RAVEN
    properties:
      database: "OtherDB"
      urls:
        - "http://node-a:8080"
        - "http://node-b:8080"
    state: present

- name: Create SQL connection string
  ravendb.ravendb.connection_string:
    url: "https://{{ ansible_host }}:443"
    database_name: "etl_db"
    certificate_path: "admin.client.combined.pem"
    ca_cert_path: "ca_certificate.pem"
    name: "sql-target"
    cs_type: SQL
    properties:
      connection_string: "{{ lookup('ansible.builtin.file', '/etc/ansible/secrets/sql_dsn.txt') | trim }}"
      factory_name: "Npgsql.NpgsqlFactory"
    state: present

- name: Create OLAP (GCS) connection string
  ravendb.ravendb.connection_string:
    url: "https://{{ ansible_host }}:443"
    database_name: "analytics"
    certificate_path: "admin.client.combined.pem"
    ca_cert_path: "ca_certificate.pem"
    name: "olap-gcs"
    cs_type: OLAP
    properties:
      google_cloud_settings:
        disabled: false
        bucket_name: "my-olap-bucket"
        remote_folder_name: "exports"
        google_credentials_json: "{{ lookup('ansible.builtin.file', '/etc/ansible/secrets//gcs.json') | trim }}"
        overriding_external_script:
          exec: "/usr/local/bin/olap.sh"
          arguments: ["--fast"]
          timeout_in_ms: 60000
    state: present

- name: Create ElasticSearch connection string
  ravendb.ravendb.connection_string:
    url: "http://{{ ansible_host }}:8080"
    database_name: "searchdb"
    name: "es-out"
    cs_type: ELASTIC_SEARCH
    properties:
      nodes: ["https://es1:9200","https://es2:9200"]
      authentication:
        basic:
          username: "elastic"
          password: "{{ lookup('ansible.builtin.file', '/etc/ansible/secrets/es_password.txt') | trim }}"
    state: present

# Queue (Azure Queue Storage) - requires RavenDB >= 6.2
- name: Create Queue (Azure Queue Storage) connection string
  ravendb.ravendb.connection_string:
    url: "http://{{ ansible_host }}:8080"
    database_name: "queue_db"
    name: "az-queue"
    cs_type: QUEUE
    properties:
      broker_type: "AZUREQUEUESTORAGE"
      azure_queue_storage_settings:
        connection_string: "{{ lookup('ansible.builtin.file', '/etc/ansible/secrets/az_queue_conn.txt') | trim }}"
    state: present

# Queue (Amazon SQS) - requires RavenDB >= 7.1
- name: Create Queue (Amazon SQS) connection string
  ravendb.ravendb.connection_string:
    url: "http://{{ ansible_host }}:8080"
    database_name: "queue_db"
    name: "sqs-out"
    cs_type: QUEUE
    properties:
      broker_type: "AMAZONSQS"
      amazon_sqs_settings:
        basic:
          access_key: "{{ lookup('ansible.builtin.file', '/etc/ansible/secrets/aws_access_key.txt') | trim }}"
          secret_key: "{{ lookup('ansible.builtin.file', '/etc/ansible/secrets/aws_secret_key.txt') | trim }}"
          region_name: "eu-central-1"
    state: present

# Snowflake - requires RavenDB >= 7.1
- name: Create Snowflake connection string
  ravendb.ravendb.connection_string:
    url: "http://{{ ansible_host }}:8080"
    database_name: "dw"
    name: "snowflake-dwh"
    cs_type: SNOWFLAKE
    properties:
      connection_string: "{{ lookup('ansible.builtin.file', '/etc/ansible/secrets/snowflake_dsn.txt') | trim }}"
    state: present

# AI (OpenAI) - requires RavenDB >= 7.1
- name: Create AI connection string (OpenAI)
  ravendb.ravendb.connection_string:
    url: "http://{{ ansible_host }}:8080"
    database_name: "ai_db"
    name: "openai-default"
    cs_type: AI
    properties:
      identifier: "default"
      model_type: "CHAT"
      openai_settings:
        api_key: "{{ lookup('ansible.builtin.file', '/etc/ansible/secrets/openai.key') | trim }}"
        base_url: "https://api.openai.com/v1"
    state: present

- name: Delete connection string
  ravendb.ravendb.connection_string:
    url: "http://{{ ansible_host }}:8080"
    database_name: "MyDB"
    name: "raven-out"
    cs_type: RAVEN
    state: absent

# Check mode (no changes)
- name: Would create Raven connection string (check mode)
  ravendb.ravendb.connection_string:
    url: "http://{{ ansible_host }}:8080"
    database_name: "MyDB"
    name: "raven-out"
    cs_type: RAVEN
    properties:
      database: "OtherDB"
      urls: ["http://node-a:8080"]
    state: present
  check_mode: yes
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
  sample: "Created connection string 'openai-default' (type AI)."
  version_added: "1.1.0"
'''

import traceback
from ansible.module_utils.basic import AnsibleModule, missing_required_lib

LIB_ERR = None
try:
    from ansible_collections.ravendb.ravendb.plugins.module_utils.common_args import ravendb_common_argument_spec

    from ansible_collections.ravendb.ravendb.plugins.module_utils.core.validation import (
        validate_url,
        validate_database_name,
        validate_paths_exist,
        validate_dict,
        collect_errors,
    )
    from ansible_collections.ravendb.ravendb.plugins.module_utils.core.tls import TLSConfig
    from ansible_collections.ravendb.ravendb.plugins.module_utils.core.client import DocumentStoreFactory

    from ansible_collections.ravendb.ravendb.plugins.module_utils.dto.connection_string import (
        ConnectionStringSpec as CSSpec,
    )
    from ansible_collections.ravendb.ravendb.plugins.module_utils.reconcilers.connection_string_reconciler import (
        ConnectionStringReconciler as CSReconciler,
    )
    HAS_LIB = True
except ImportError:
    HAS_LIB = False
    LIB_ERR = traceback.format_exc()


def main():
    module_args = ravendb_common_argument_spec()
    module_args.update(
        name=dict(type='str', required=True),
        cs_type=dict(type='str', required=False, default="RAVEN",
                     choices=['RAVEN', 'SQL', 'OLAP', 'ELASTIC_SEARCH', 'QUEUE', 'SNOWFLAKE', 'AI']),
        properties=dict(type='dict', required=False, default=None),
        state=dict(type='str', choices=['present', 'absent'], default='present'),
    )
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    if not HAS_LIB:
        module.fail_json(msg=missing_required_lib("ravendb"), exception=LIB_ERR)

    url = module.params['url']
    db = module.params['database_name']
    cert_path = module.params.get('certificate_path')
    ca_path = module.params.get('ca_cert_path')
    state = module.params['state']
    name = module.params['name'].strip()
    cs_type = module.params['cs_type']
    props = module.params['properties']

    checks = [
        validate_url(url),
        validate_database_name(db),
        validate_paths_exist(cert_path, ca_path),
    ]

    if state == "present":
        checks.append(validate_dict("properties", props))

    ok, err = collect_errors(*checks)
    if not ok:
        module.fail_json(msg=err)

    tls = TLSConfig(certificate_path=cert_path, ca_cert_path=ca_path)
    ctx = None
    try:
        ctx = DocumentStoreFactory.create(url, db, cert_path, ca_path)
        reconciler = CSReconciler(ctx)

        if state == "present":
            spec = CSSpec(cs_type=cs_type, name=name, properties=props or {})
            res = reconciler.ensure_present(spec, tls, module.check_mode)
        elif state == "absent":
            res = reconciler.ensure_absent(cs_type, name, tls, module.check_mode)

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
