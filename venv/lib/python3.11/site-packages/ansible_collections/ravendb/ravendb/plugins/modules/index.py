# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: index
short_description: Manage RavenDB indexes
description:
  - Create, delete, update, or apply operational modes to RavenDB indexes.
  - Supports both single-map and multi-map index definitions (with optional reduce).
  - Supports check mode to simulate changes without applying them.
  - Can reconcile per-index configuration via C(index_configuration).
version_added: "1.0.0"
author: "Omer Ratsaby <omer.ratsaby@ravendb.net> (@thegoldenplatypus)"

extends_documentation_fragment:
  - ravendb.ravendb.ravendb

options:
  index_name:
    description:
      - Name of the index to create, delete, or modify.
      - Must consist only of letters, numbers, dashes, and underscores.
    required: true
    type: str
  index_definition:
    description:
      - Dictionary defining the index (C(map) list and optional C(reduce) string).
      - Required when creating a new index.
      - When present for an existing index, differences are applied idempotently.
    required: false
    type: dict
  state:
    description:
      - Desired state of the index.
      - If C(present), the index will be created if it does not exist, and the definition/configuration will be reconciled.
      - If C(absent), the index will be deleted if it exists.
      - If omitted (C(null)), the module operates in "reconcile" mode on existing indexes only (definition, configuration, and/or C(mode)).
      - If the index does not exist and only C(mode) is provided, the task fails with guidance to use C(state=present).
    required: false
    type: str
    choices: [present, absent]
    default: null  # CHANGED: explicitly document None-default reconcile behavior
  mode:
    description:
      - Operational mode to apply to an existing index (one of enable/disable/pause/resume/reset).
      - If the index does not exist and only C(mode) is provided, the task fails with guidance to create it first.
    required: false
    type: str
    choices: [resumed, paused, enabled, disabled, reset]
  cluster_wide:
    description:
      - Whether to apply enable/disable operations cluster-wide.
    required: false
    type: bool
    default: false
  index_configuration:
    description:
      - Per-index configuration key/value pairs to reconcile.
      - Keys and values are normalized to strings and compared against the current index definition's configuration.
      - If differences exist, the module updates the definition with the merged configuration.
    required: false
    type: dict
    default: {}  # ADDED
seealso:
  - name: RavenDB documentation
    description: Official RavenDB documentation
    link: https://ravendb.net/docs

'''

EXAMPLES = '''
- name: Create a RavenDB index with map and reduce
  ravendb.ravendb.index:
    url: "http://{{ ansible_host }}:8080"
    database_name: "my_database"
    index_name: "UsersByName"
    index_definition:
      map:
        - "from c in docs.Users select new { c.name, count = 5 }"
      reduce: >
        from result in results
        group result by result.name
        into g
        select new
        {
          name = g.Key,
          count = g.Sum(x => x.count)
        }
    state: present

- name: Create a RavenDB multi-map index
  ravendb.ravendb.index:
    url: "http://{{ ansible_host }}:8080"
    database_name: "my_database"
    index_name: "UsersAndOrdersByName"
    index_definition:
      map:
        - "from c in docs.Users select new { Name = c.name, UserCount = 1, OrderCount = 0, TotalCount = 1 }"
        - "from o in docs.Orders select new { Name = o.customer, UserCount = 0, OrderCount = 1, TotalCount = 1 }"
      reduce: >
        from result in results
        group result by result.Name
        into g
        select new
        {
          Name = g.Key,
          UserCount = g.Sum(x => x.UserCount),
          OrderCount = g.Sum(x => x.OrderCount),
          TotalCount = g.Sum(x => x.TotalCount)
        }
    state: present

- name: Reconcile per-index configuration (idempotent)
  ravendb.ravendb.index:
    url: "http://{{ ansible_host }}:8080"
    database_name: "my_database"
    index_name: "UsersByName"
    index_configuration:
      Indexing.MapBatchSize: "128"

- name: Disable a RavenDB index (cluster-wide)
  ravendb.ravendb.index:
    url: "http://{{ ansible_host }}:8080"
    database_name: "my_database"
    index_name: "Orders/ByCompany"
    mode: disabled
    cluster_wide: true

- name: Pause a RavenDB index (check mode)
  ravendb.ravendb.index:
    url: "http://{{ ansible_host }}:8080"
    database_name: "my_database"
    index_name: "Orders/ByCompany"
    mode: paused
  check_mode: yes

- name: Update an existing RavenDB index definition (idempotent update)
  ravendb.ravendb.index:
    url: "http://{{ ansible_host }}:8080"
    database_name: "my_database"
    index_name: "UsersByName"
    index_definition:
      map:
        - "from c in docs.Users select new { c.name, count = 13 }"
      reduce: >
        from result in results
        group result by result.name
        into g
        select new
        {
          name = g.Key,
          count = g.Sum(x => x.count)
        }
    state: present

- name: Delete a RavenDB index
  ravendb.ravendb.index:
    url: "http://{{ ansible_host }}:8080"
    database_name: "my_database"
    index_name: "UsersByName"
    state: absent

- name: Create index with rolling deployment
  ravendb.ravendb.index:
    url: "http://{{ ansible_host }}:8080"
    database_name: "my_database"
    index_name: "Orders/ByCompany"
    state: present
    index_definition:
      map:
        - "from o in docs.Orders select new { o.Company }"
      deployment_mode: rolling

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
  sample: Index 'Products_ByName' created successfully.
  version_added: "1.0.0"
'''

import traceback
from ansible.module_utils.basic import AnsibleModule, missing_required_lib

LIB_ERR = None
try:
    from ansible_collections.ravendb.ravendb.plugins.module_utils.common_args import ravendb_common_argument_spec
    from ansible_collections.ravendb.ravendb.plugins.module_utils.core.client import DocumentStoreFactory
    from ansible_collections.ravendb.ravendb.plugins.module_utils.core.validation import (
        validate_url, validate_database_name, validate_index_name, validate_dict,
        validate_paths_exist, validate_state_optional, validate_mode, validate_bool, collect_errors
    )
    from ansible_collections.ravendb.ravendb.plugins.module_utils.services import index_service as idxsvc
    from ansible_collections.ravendb.ravendb.plugins.module_utils.services.index_config_service import validate_index_configuration
    from ansible_collections.ravendb.ravendb.plugins.module_utils.reconcilers.index_reconciler import IndexReconciler
    from ansible_collections.ravendb.ravendb.plugins.module_utils.dto.index import IndexSpec, IndexDefinitionSpec
    HAS_LIB = True
except ImportError:
    HAS_LIB = False
    LIB_ERR = traceback.format_exc()


def main():
    module_args = ravendb_common_argument_spec()
    module_args.update(
        index_name=dict(type='str', required=True),
        index_definition=dict(type='dict', required=False),
        state=dict(type='str', choices=['present', 'absent'], required=False, default=None),
        mode=dict(type='str', choices=['resumed', 'paused', 'enabled', 'disabled', 'reset'], required=False),
        cluster_wide=dict(type='bool', default=False),
        index_configuration=dict(type='dict', required=False, default={})
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    if not HAS_LIB:
        module.fail_json(msg=missing_required_lib("ravendb"), exception=LIB_ERR)

    url = module.params['url']
    db_name = module.params['database_name']
    idx_name = module.params['index_name']
    raw_def = module.params.get('index_definition')
    cert_path = module.params.get('certificate_path')
    ca_path = module.params.get('ca_cert_path')
    state = module.params.get('state')
    mode = module.params.get('mode')
    cluster_wide = module.params['cluster_wide']
    idx_cfg = module.params.get('index_configuration') or {}

    ok, err = collect_errors(
        validate_url(url),
        validate_database_name(db_name),
        validate_index_name(idx_name),
        validate_dict("index definition", raw_def),
        validate_paths_exist(cert_path, ca_path),
        validate_state_optional(state),
        validate_mode(mode),
        validate_bool("cluster_wide", cluster_wide),
    )
    if not ok:
        module.fail_json(msg=err)

    ok, normalized_cfg, err = validate_index_configuration(idx_cfg)
    if not ok:
        module.fail_json(msg=err)

    def_spec = IndexDefinitionSpec.from_dict(raw_def) if raw_def else None
    spec = IndexSpec(
        db_name=db_name,
        name=idx_name,
        definition=def_spec,
        mode=mode,
        cluster_wide=cluster_wide,
        configuration=normalized_cfg or {}
    )

    ctx = None
    try:
        ctx = DocumentStoreFactory.create(url, db_name, cert_path, ca_path)
        reconciler = IndexReconciler(ctx, db_name)

        exists = idxsvc.get_definition(ctx, db_name, idx_name) is not None

        if state == "absent":
            res = reconciler.ensure_absent(idx_name, module.check_mode)
        elif state == "present":
            res = reconciler.ensure_present(spec, module.check_mode)
        else:
            if not exists:
                if mode:
                    module.fail_json(msg="Index '{}' does not exist. Provide state=present to create it before applying mode.".format(idx_name))
                module.fail_json(msg="Index '{}' does not exist. Provide state=present and index_definition to create it.".format(idx_name))

            res = reconciler.ensure_present(spec, module.check_mode)

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
