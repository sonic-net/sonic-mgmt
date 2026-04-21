# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


def _requests():
    try:
        import requests
        return requests
    except ImportError:
        raise RuntimeError("Python 'requests' is required for node operations. Install 'requests'.")


def node_in_topology(topology, search_tag, search_url):
    """
    Return tuple (present: bool, role: str|None, existing_tag: str|None, existing_url: str|None)
    by scanning members/watchers/promotables.
    """
    roles = [
        ("members", "Member"),
        ("watchers", "Watcher"),
        ("promotables", "Promotable"),
    ]
    for attr, role_name in roles:
        group = getattr(topology, attr, None) or {}
        for tag, url in group.items():
            if tag == search_tag or url == search_url:
                return True, role_name, tag, url
    return False, None, None, None


def add_node(ctx, tag, url, is_watcher, tls):
    """
    PUT /admin/cluster/node on the leader the ctx is connected to.
    Raises RuntimeError on HTTP error.
    """
    base = ctx.store.urls[0].rstrip("/")
    endpoint = "{}/admin/cluster/node".format(base)

    params = {"url": url, "tag": tag}
    if is_watcher:
        params["watcher"] = "true"

    cert, verify = tls.to_requests_tuple()
    r = _requests().put(endpoint, params=params, headers={"Content-Type": "application/json"}, cert=cert, verify=verify)
    if r.status_code not in (200, 201, 204):
        try:
            detail = r.json().get("Message", r.text)
        except Exception:
            detail = r.text
        raise RuntimeError(detail)
