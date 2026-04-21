# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: healthcheck
short_description: Perform RavenDB node and cluster health checks
description:
  - Runs one or more health checks against a RavenDB node.
  - C(node_alive) verifies C(/setup/alive) returns success.
  - C(cluster_connectivity) verifies the node can ping cluster peers.
  - C(db_groups_available) verifies each database group has at least one usable member in the cluster (no exclusion).
  - C(db_groups_available_excluding_target) verifies each database group has at least one usable member while excluding the node identified by C(url).
  - Supports secured connections using client certificates and optional CA verification.
version_added: "1.0.0"
author: "Omer Ratsaby <omer.ratsaby@ravendb.net> (@thegoldenplatypus)"

options:
  url:
    description:
      - Base URL of the RavenDB node to check, e.g. C(http://node-a:8080) or C(https://node-a:443).
    required: true
    type: str
  validate_certificate:
    description:
      - Verify the server TLS certificate when using HTTPS.
      - Automatically disabled for IP hosts when running C(node_alive) or C(cluster_connectivity).
    required: false
    type: bool
    default: true
  certificate_path:
    description:
      - Path to a client certificate for secured clusters.
    required: false
    type: str
  ca_cert_path:
    description:
      - Path to a CA bundle used to validate the server certificate.
    required: false
    type: str
  checks:
    description:
      - List of health checks to run.
    required: false
    type: list
    elements: str
    choices: [node_alive, cluster_connectivity, db_groups_available, db_groups_available_excluding_target]
    default:
      - node_alive
      - cluster_connectivity
  max_time_to_wait:
    description:
      - Max time window in seconds for each selected check before timing out.
    required: false
    type: int
    default: 1200
  retry_interval_seconds:
    description:
      - Interval in seconds between attempts for C(node_alive) and C(cluster_connectivity).
    required: false
    type: int
    default: 5
  db_retry_interval_seconds:
    description:
      - Interval in seconds between attempts for C(db_groups_available) and C(db_groups_available_excluding_target).
    required: false
    type: int
    default: 10
  on_db_timeout:
    description:
      - Behavior when C(db_groups_available) times out.
      - C(fail) fails the task; C(continue) returns success with timeout noted in results.
    required: false
    type: str
    choices: [fail, continue]
    default: fail

seealso:
  - name: RavenDB documentation
    description: Official RavenDB documentation
    link: https://ravendb.net/docs

'''

EXAMPLES = '''
- name: Default checks (node_alive + cluster_connectivity)
  ravendb.ravendb.healthcheck:
    url: "http://{{ inventory_hostname }}:8080"

- name: HTTPS with client cert + CA bundle
  ravendb.ravendb.healthcheck:
    url: "https://node-a.example.com:443"
    certificate_path: "/etc/ravendb/admin.client.pem"
    ca_cert_path: "/etc/ssl/private/ca.pem"
    validate_certificate: true
    checks: ["node_alive", "cluster_connectivity"]

- name: Add database-group availability (exclude current), continue on timeout
  ravendb.ravendb.healthcheck:
    url: "https://node-b.example.com:443"
    certificate_path: "/etc/ravendb/admin.client.pem"
    ca_cert_path: "/etc/ssl/private/ca.pem"
    checks: ["node_alive", "cluster_connectivity", "db_groups_available_excluding_target"]
    max_time_to_wait: 900
    db_retry_interval_seconds: 15
    on_db_timeout: continue

- name: Cluster-wide database-group availability (no exclusion)
  ravendb.ravendb.healthcheck:
    url: "https://node-c.example.com:443"
    certificate_path: "/etc/ravendb/admin.client.pem"
    ca_cert_path: "/etc/ssl/private/ca.pem"
    checks: ["db_groups_available"]
    max_time_to_wait: 1200
    db_retry_interval_seconds: 10
    on_db_timeout: fail
'''

RETURN = '''
changed:
  description: Always false; health checks are read-only.
  type: bool
  returned: always
  sample: false

msg:
  description: Summary string of executed checks and outcomes.
  type: str
  returned: always
  sample: "node_alive OK (attempts:1); cluster_connectivity OK (attempts:1)"

results:
  description:
    - Per-check structured results including attempts, error (if any), and detail.
  type: dict
  returned: success
  sample:
    node_alive:
      ok: true
      attempts: 1
      error: null
      detail:
        status: 200
    cluster_connectivity:
      ok: true
      attempts: 1
      error: null
      detail:
        peers: 3
    db_groups_available_excluding_target:
      ok: false
      attempts: 60
      error: timeout
      detail:
        failing:
          db1: "no usable member with LastStatus==Ok (or only excluded tag)"
warnings:
  description: Optional warnings (e.g., cert validation auto-disabled for IP hosts).
  type: list
  elements: str
  returned: sometimes
  sample:
    - "validate_certificate automatically disabled for IP host (NodeAlive/ClusterConnectivity)."
'''

import traceback
from ansible.module_utils.basic import AnsibleModule, missing_required_lib

LIB_ERR = None
try:
    from ansible_collections.ravendb.ravendb.plugins.module_utils.core.validation import (
        validate_url, validate_paths_exist, collect_errors, ip_host_warning
    )
    from ansible_collections.ravendb.ravendb.plugins.module_utils.dto.healthcheck import HealthcheckSpec
    from ansible_collections.ravendb.ravendb.plugins.module_utils.reconcilers.healthcheck_reconciler import HealthcheckReconciler
    HAS_LIB = True
except ImportError:
    HAS_LIB = False
    LIB_ERR = traceback.format_exc()


CHECK_CHOICES = ('node_alive', 'cluster_connectivity', 'db_groups_available', 'db_groups_available_excluding_target')


def main():
    argument_spec = dict(
        url=dict(type='str', required=True),
        validate_certificate=dict(type='bool', default=True),
        certificate_path=dict(type='str', required=False, default=None),
        ca_cert_path=dict(type='str', required=False, default=None),
        checks=dict(type='list', elements='str', choices=list(CHECK_CHOICES), default=['node_alive', 'cluster_connectivity']),
        max_time_to_wait=dict(type='int', default=1200),
        retry_interval_seconds=dict(type='int', default=5),
        db_retry_interval_seconds=dict(type='int', default=10),
        on_db_timeout=dict(type='str', choices=['fail', 'continue'], default='fail'),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=False)

    if not HAS_LIB:
        module.fail_json(msg=missing_required_lib("ravendb"), exception=LIB_ERR)

    url = module.params['url']
    validate_cert = bool(module.params['validate_certificate'])
    cert_path = module.params.get('certificate_path')
    ca_path = module.params.get('ca_cert_path')
    checks = module.params['checks'] or []
    max_time_to_wait = int(module.params['max_time_to_wait'])
    retry_interval_seconds = int(module.params['retry_interval_seconds'])
    db_retry_interval_seconds = int(module.params['db_retry_interval_seconds'])
    on_db_timeout = module.params['on_db_timeout']

    ok, err = collect_errors(
        validate_url(url),
        validate_paths_exist(cert_path, ca_path),
    )
    if not ok:
        module.fail_json(msg=err)

    warnings = []
    warning = ip_host_warning(url, validate_cert)
    if warning:
        warnings.append(warning)

    try:
        spec = HealthcheckSpec(
            url=url,
            validate_certificate=validate_cert,
            certificate_path=cert_path,
            ca_cert_path=ca_path,
            checks=checks,
            max_time_to_wait=max_time_to_wait,
            retry_interval_seconds=retry_interval_seconds,
            db_retry_interval_seconds=db_retry_interval_seconds,
            on_db_timeout=on_db_timeout,
        )

        reconciler = HealthcheckReconciler()
        res = reconciler.run(spec)

        out = res.to_ansible()
        if warnings:
            out["warnings"] = warnings

        if res.failed:
            module.fail_json(**out)
        else:
            module.exit_json(**out)

    except Exception as e:
        module.fail_json(msg="Unexpected error: {}".format(str(e)))


if __name__ == '__main__':
    main()
