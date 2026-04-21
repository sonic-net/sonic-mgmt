# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.ravendb.ravendb.plugins.module_utils.services.cluster_service import fetch_topology, collect_tags


def _requests():
    try:
        import requests
        return requests
    except ImportError:
        raise RuntimeError("Python 'requests' is required for encryption operations. Install 'requests'.")


def fetch_generated_key(ctx, tls):
    """
    Ask the server to generate an encryption key.
    """
    base = ctx.store.urls[0].rstrip("/")
    url = "{}/admin/secrets/generate".format(base)
    cert, verify = tls.to_requests_tuple()

    response = _requests().get(url, cert=cert, verify=verify)
    response.raise_for_status()
    return response.text.strip()


def distribute_key(ctx, db_name, key, tls, only_tags=None):
    """
    Distribute the encryption key to ALL nodes in the cluster.
    If only_tags is None/empty, distribute to all nodes in the cluster.
    """
    if only_tags:
        tags = list(only_tags)
    else:
        topology = fetch_topology(ctx)
        tags = collect_tags(topology)
    if not tags:
        raise RuntimeError("No nodes found in cluster topology.")

    params = [("name", db_name)]
    for t in tags:
        params.append(("node", t))

    base = ctx.store.urls[0].rstrip("/")
    url = "{}/admin/secrets/distribute".format(base)
    cert, verify = tls.to_requests_tuple()

    response = _requests().post(url, params=params, data=key, headers={"Content-Type": "text/plain"}, cert=cert, verify=verify)
    if response.status_code not in (200, 201, 204):
        raise RuntimeError("Assigning encryption key failed: HTTP {} - {}".format(response.status_code, response.text))

    return tags


def validate_encryption_params(desired_state, tls, encrypted,
                               generate_key, key_path=None, output_path=None):
    """
    Validate parameters when creating an encrypted database.
    """
    if desired_state == "present" and encrypted:
        if not tls.certificate_path:
            return False, "encrypted=true requires certificate_path for admin endpoints."

        if not (generate_key or key_path):
            return False, "encrypted=true requires either generate_encryption_key=true or key_path=<path>."

        if generate_key and key_path:
            return False, "generate_encryption_key and key_path are mutually exclusive."

        if output_path and not generate_key:
            return False, "encryption_key_output_path can only be used when generate_encryption_key=true."

    return True, None
