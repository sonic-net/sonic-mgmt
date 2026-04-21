# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
import time
from ansible_collections.ravendb.ravendb.plugins.module_utils.services.retry_service import retry_until
from ansible_collections.ravendb.ravendb.plugins.module_utils.core.tls import TLSConfig
from ansible_collections.ravendb.ravendb.plugins.module_utils.services.retry_service import BreakRetry
try:
    from urllib.parse import urlparse
except Exception:
    from urlparse import urlparse

try:
    from ipaddress import ip_address as _ip_address
except Exception:
    _ip_address = None


_IGNORE_SUBSTRINGS = [
    "(status: loading)",
    "not responding",
    "connection refused",
    "serviceunavailable",
    "node in rehabilitation",
]


def _requests():
    try:
        import requests
        return requests
    except ImportError:
        raise RuntimeError("Python 'requests' is required for node operations. Install 'requests'.")


def _base(url):
    return (url or "").rstrip("/")


def pluck_tags(group):
    if not group:
        return []

    if isinstance(group, dict):
        return [str(k).strip() for k in group.keys()]

    if isinstance(group, str):
        return [group.strip()]
    try:
        items = list(group)
    except TypeError:
        return []

    out = []
    for item in items:
        if isinstance(item, str):
            out.append(item.strip())
            continue
        if isinstance(item, dict):
            t = item.get("NodeTag")
        else:
            t = getattr(item, "NodeTag", None)
        if t:
            out.append(str(t).strip())

    return list(dict.fromkeys(out))


def build_session(tls, validate_certificate=None):
    s = _requests().Session()
    tls = tls or TLSConfig()
    cert, verify = tls.to_requests_tuple()
    if cert:
        s.cert = cert
    s.verify = False if validate_certificate is False else verify
    return s


def get_setup_alive(session, base_url, timeout=20):
    endpoint = _base(base_url) + "/setup/alive"
    try:
        r = session.get(endpoint, timeout=timeout)

        if 200 <= r.status_code < 300:
            return True, {"status": r.status_code}

        return False, "HTTP {}{}".format(
            r.status_code,
            " ({})".format(r.text.strip()[:200]) if r.text else ""
        )

    except _requests().RequestException as e:
        return False, str(e)


def get_node_ping(session, base_url, timeout=30, peer_url=None, node_tag=None):
    endpoint = _base(base_url) + "/admin/debug/node/ping"
    params = {}
    if peer_url:
        params["url"] = peer_url
    if node_tag:
        params["node"] = node_tag

    try:
        r = session.get(endpoint, params=params, timeout=timeout)
        if not (200 <= r.status_code < 300):
            return False, "HTTP {}{}".format(r.status_code, " ({})".format(r.text.strip()[:200]) if r.text else "")
        try:
            data = r.json()
        except ValueError:
            return False, "invalid JSON response {}".format(r.text.strip()[:200])

        result = data.get("Result")
        if not result or not isinstance(result, list):
            return False, "missing/empty 'Result'"

        for item in result:
            url_i = item.get("Url") or "unknown"
            sa = (item.get("SetupAlive") or {}) or {}
            ti = (item.get("TcpInfo") or {}) or {}
            sa_err = sa.get("Error") if isinstance(sa, dict) else None
            ti_err = ti.get("Error") if isinstance(ti, dict) else None
            if sa_err or ti_err:
                return False, {
                    "peer": url_i,
                    "setup_alive_error": sa_err,
                    "tcp_info_error": ti_err
                }

        return True, {"peers": len(result)}
    except _requests().RequestException as e:
        return False, str(e)


def wait_for_node_alive(session, base_url, max_time_to_wait, retry_interval_seconds):
    return retry_until(
        get_setup_alive,
        max_time_to_wait,
        retry_interval_seconds,
        session,
        base_url,
        20
    )


def wait_for_cluster_connectivity(session, base_url, max_time_to_wait, retry_interval_seconds, peer_url=None, node_tag=None):
    return retry_until(
        get_node_ping,
        max_time_to_wait,
        retry_interval_seconds,
        session,
        base_url,
        30,
        peer_url,
        node_tag
    )


def wait_for_node_databases_online(ctx, max_time_to_wait, interval_seconds, excluded_tag):
    return retry_until(
        _check_all_databases_online,
        max_time_to_wait,
        interval_seconds,
        ctx,
        excluded_tag,
    )


def _list_db_names_via_http(ctx, timeout=30):
    base = _base(ctx.store.urls[0])
    session = build_session(TLSConfig())
    try:
        r = session.get(base + "/databases", timeout=timeout)
        r.raise_for_status()
        data = r.json() or {}
        dbs = data.get("Databases") or []
        return [d.get("Name") for d in dbs if d.get("Name")]
    finally:
        try:
            session.close()
        except Exception:
            pass


def _check_all_databases_online(ctx, excluded_tag):
    try:
        names = _list_db_names_via_http(ctx)
    except Exception as e:
        return False, "failed to list databases: {}".format(e)

    failing = {}
    for name in names:
        try:
            ok, detail = _db_has_usable_member(ctx, name, excluded_tag)
        except BreakRetry:
            raise

        except Exception as e:
            failing[name] = "failed to evaluate database: {}".format(e)
            continue

        if not ok and not (isinstance(detail, dict) and detail.get("skipped") == "rf=1"):
            failing[name] = detail

    if failing:
        return False, {"failing": failing}
    return True, {"checked": len(names)}


def _db_has_usable_member(ctx, db_name, excluded_tag):
    def _eval_once():
        base = _base(ctx.store.urls[0])
        session = build_session(TLSConfig())
        try:
            r = session.get(base + "/databases", timeout=30)
            r.raise_for_status()
            data = r.json()
        finally:
            try:
                session.close()
            except Exception:
                pass

        dbs = data.get("Databases") or []
        info = next((it for it in dbs if (it.get("Name") or "") == db_name), None)
        if not info:
            return ("notfound", None, None, None, None, None)

        if info.get("Disabled") is True:
            return ("disabled", None, None, None, None, None)

        rf = info.get("ReplicationFactor")
        try:
            rf = int(rf) if rf is not None else None
        except Exception:
            rf = None
        if rf == 1:
            return ("rf1", None, None, None, None, None)

        topo = info.get("NodesTopology") or {}
        members = topo.get("Members") or []
        promotables = topo.get("Promotables") or []
        rehabs = topo.get("Rehabs") or []
        status = topo.get("Status") or {}

        tags = sorted(set(pluck_tags(members) + pluck_tags(promotables) + pluck_tags(rehabs)))
        ok_tags, hard_errors, non_ignored_errors = _scan_status(status, tags, excluded_tag)
        rehab_tags = set(pluck_tags(rehabs))
        return ("ok", tags, ok_tags, (hard_errors, non_ignored_errors), rehab_tags, status)

    try:
        state, tags, ok_tags, errs, rehabs, status = _eval_once()
    except Exception as e:
        return False, "failed to read /databases: {}".format(e)

    if state == "notfound":
        return False, "database_not_found_in_/databases"
    if state == "disabled":
        return True, {"skipped": "disabled"}
    if state == "rf1":
        return True, {"skipped": "rf=1"}

    fail_fast = excluded_tag is not None
    hard_errors, non_ignored_errors = errs

    if hard_errors:
        time.sleep(2)
        state2, tags2, ok_tags2, errs2, rehabs2, status2 = _eval_once()
        if state2 == "notfound":
            return False, "database_not_found_in_/databases"
        if state2 == "disabled":
            return True, {"skipped": "disabled"}
        if state2 == "rf1":
            return True, {"skipped": "rf=1"}

        hard_errors2, non_ignored_errors2 = errs2
        ok_tags, tags = ok_tags2, tags2

        if hard_errors2:
            n = hard_errors2[0]
            if fail_fast:
                raise BreakRetry("database_load_error", {"db": db_name, "node": n["tag"], "error": n["error"]})
            return False, {"db": db_name, "node": n["tag"], "error": n["error"], "reason": "load_error"}

        persistent_rehab = [
            t for t in (rehabs2 or [])
            if t != excluded_tag and "node in rehabilitation"
            in str((status2 or {}).get(t, {}).get("LastError") or "").lower()
        ]
        if persistent_rehab:
            node = sorted(persistent_rehab)[0]
            if fail_fast:
                raise BreakRetry("database_load_error", {"db": db_name, "node": node, "error": "Node in rehabilitation"})
            return False, {"db": db_name, "node": node, "error": "Node in rehabilitation", "reason": "rehab_persist"}

    if ok_tags:
        return True, {"members": tags or [], "excluded": excluded_tag, "ok_on": ok_tags}

    if non_ignored_errors:
        n = non_ignored_errors[0]
        if fail_fast:
            raise BreakRetry("database_load_error", {"db": db_name, "node": n["tag"], "error": n["error"]})
        return False, {"db": db_name, "node": n["tag"], "error": n["error"], "reason": "load_error"}

    return False, {
        "members": (tags or []),
        "excluded": excluded_tag,
        "reason": "no usable member with LastStatus==Ok (or only excluded tag)",
    }


def _is_hard_load_error(err):
    if not err:
        return False
    e = err.lower()
    return "endofstreamexception" in e


def _is_ignored_transient(err):
    if not err:
        return False
    e = err.lower()
    return any(s in e for s in _IGNORE_SUBSTRINGS)


def _scan_status(status, tags, excluded_tag):
    ok_tags = []
    hard_errors = []
    non_ignored_errors = []
    if not isinstance(status, dict):
        return ok_tags, hard_errors, non_ignored_errors

    for t in tags:
        if t == excluded_tag:
            continue
        st = (status.get(t) or {})
        last_status = str(st.get("LastStatus") or "").strip().lower()
        last_err = st.get("LastError") or ""

        if last_status == "ok":
            ok_tags.append(t)
            continue

        if _is_hard_load_error(last_err):
            hard_errors.append({"tag": t, "error": last_err})
            continue

        if last_err and not _is_ignored_transient(last_err):
            non_ignored_errors.append({"tag": t, "error": last_err})

    return ok_tags, hard_errors, non_ignored_errors


def hostname_is_ip(url):
    try:
        host = urlparse(url).hostname or ""
        _ip_address.ip_address(host)
        return True
    except Exception:
        return False
