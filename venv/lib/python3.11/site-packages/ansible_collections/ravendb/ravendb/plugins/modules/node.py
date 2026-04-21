# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: node
short_description: Add a RavenDB node to an existing cluster
description:
  - Adds a RavenDB node to a cluster, either as a member or a watcher.
  - Performs a topology check first and becomes a no-op if the node is already present (by tag or URL).
  - Supports secured clusters with HTTPS, client certificates (PEM format), and optional CA bundle for verification.
  - Check mode is supported to simulate the addition without applying changes.
version_added: "1.0.0"
author: "Omer Ratsaby <omer.ratsaby@ravendb.net> (@thegoldenplatypus)"

attributes:
  check_mode:
    support: full
    description: Can run in check_mode and return changed status prediction without modifying target. If not supported, the action will be skipped.

options:
  tag:
    description:
      - The unique tag for the node (uppercase alphanumeric, 1–4 chars).
    required: true
    type: str
  type:
    description:
      - Node type. Use C(Watcher) to add the node as a watcher instead of a full member.
    required: false
    type: str
    default: Member
    choices: [Member, Watcher]
  url:
    description:
      - The HTTP/HTTPS URL of the node being added.
    required: true
    type: str
  leader_url:
    description:
      - The HTTP/HTTPS URL of the cluster leader the module will contact to add the node.
    required: true
    type: str
  certificate_path:
    description:
      - Path to a client certificate in PEM format (combined certificate and key).
      - Required for secured clusters (HTTPS with client authentication).
    required: false
    type: str
  ca_cert_path:
    description:
      - Path to a CA certificate bundle to verify the server certificate.
    required: false
    type: str

seealso:
  - name: RavenDB documentation
    description: Official RavenDB documentation
    link: https://ravendb.net/docs

'''

EXAMPLES = '''
- name: Join Node B as a Watcher (HTTP, no cert)
  ravendb.ravendb.node:
    tag: B
    type: "Watcher"
    url: "http://192.168.118.120:8080"
    leader_url: "http://192.168.117.90:8080"

- name: Join Node B as Watcher (HTTPS)
  ravendb.ravendb.node:
    tag: B
    type: "Watcher"
    url: "https://b.ravendbansible.development.run"
    leader_url: "https://a.ravendbansible.development.run"
    certificate_path: admin.client.combined.pem
    ca_cert_path: ca_certificate.pem

- name: Simulate adding Node D (check mode)
  ravendb.ravendb.node:
    tag: D
    url: "http://192.168.118.200:8080"
    leader_url: "http://192.168.117.90:8080"
  check_mode: yes
'''

RETURN = '''
changed:
  description: Indicates if the cluster topology was changed or would have changed (check mode).
  type: bool
  returned: always
  sample: true

msg:
  description: Human-readable message describing the result or error.
  type: str
  returned: always
  sample: Node 'B' added as Member.
  version_added: "1.0.0"
'''

import traceback
from ansible.module_utils.basic import AnsibleModule, missing_required_lib

LIB_ERR = None
try:
    from ansible_collections.ravendb.ravendb.plugins.module_utils.core.client import DocumentStoreFactory
    from ansible_collections.ravendb.ravendb.plugins.module_utils.core.validation import (
        validate_url, validate_tag, validate_paths_exist, collect_errors
    )
    from ansible_collections.ravendb.ravendb.plugins.module_utils.core.tls import TLSConfig
    from ansible_collections.ravendb.ravendb.plugins.module_utils.dto.node import NodeSpec
    from ansible_collections.ravendb.ravendb.plugins.module_utils.reconcilers.node_reconciler import NodeReconciler
    HAS_LIB = True
except ImportError:
    HAS_LIB = False
    LIB_ERR = traceback.format_exc()


def main():
    module_args = dict(
        tag=dict(type='str', required=True),
        type=dict(type='str', required=False, default='Member', choices=['Member', 'Watcher']),
        url=dict(type='str', required=True),
        leader_url=dict(type='str', required=True),
        certificate_path=dict(type='str', required=False, default=None),
        ca_cert_path=dict(type='str', required=False, default=None),
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    if not HAS_LIB:
        module.fail_json(msg=missing_required_lib("ravendb"), exception=LIB_ERR)

    tag = module.params['tag']
    node_type = module.params['type']
    node_url = module.params['url']
    leader_url = module.params['leader_url']
    cert_path = module.params.get('certificate_path')
    ca_path = module.params.get('ca_cert_path')

    ok, err = collect_errors(
        validate_tag(tag),
        validate_url(node_url),
        validate_url(leader_url),
        validate_paths_exist(cert_path, ca_path),
    )
    if not ok:
        module.fail_json(msg=err)

    tls = TLSConfig(certificate_path=cert_path, ca_cert_path=ca_path)
    ctx = None
    try:
        ctx = DocumentStoreFactory.create(leader_url, None, cert_path, ca_path)

        spec = NodeSpec(
            tag=tag,
            url=node_url,
            leader_url=leader_url,
            node_type=node_type,
        )

        reconciler = NodeReconciler(ctx)
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
