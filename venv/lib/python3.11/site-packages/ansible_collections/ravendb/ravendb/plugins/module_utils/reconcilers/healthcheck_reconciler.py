# -*- coding: utf-8 -*-
#
# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.ravendb.ravendb.plugins.module_utils.core.result import ModuleResult
from ansible_collections.ravendb.ravendb.plugins.module_utils.services import healthcheck_service as hcsvc
from ansible_collections.ravendb.ravendb.plugins.module_utils.core.tls import TLSConfig
from ansible_collections.ravendb.ravendb.plugins.module_utils.core.client import DocumentStoreFactory
from ansible_collections.ravendb.ravendb.plugins.module_utils.services.cluster_service import fetch_topology_http
from ansible_collections.ravendb.ravendb.plugins.module_utils.services.healthcheck_service import hostname_is_ip


CHECK_NODE_ALIVE = 'node_alive'
CHECK_CLUSTER_CONN = 'cluster_connectivity'
CHECK_DB_GROUPS_AVAILABLE = 'db_groups_available'
CHECK_DB_GROUPS_AVAILABLE_EXCL = 'db_groups_available_excluding_target'


class HealthcheckReconciler(object):
    def run(self, spec):
        results = {}
        summary_bits = []
        tls = TLSConfig(spec.certificate_path, spec.ca_cert_path)
        effective_validate = spec.validate_certificate
        warnings = []

        if (CHECK_NODE_ALIVE in spec.checks or CHECK_CLUSTER_CONN in spec.checks) and hostname_is_ip(spec.url):
            if effective_validate:
                effective_validate = False
                warnings.append("validate_certificate automatically disabled for IP host (NodeAlive/ClusterConnectivity).")

        session = hcsvc.build_session(tls, validate_certificate=effective_validate)

        try:
            if CHECK_NODE_ALIVE in spec.checks:
                result = hcsvc.wait_for_node_alive(
                    session,
                    spec.url,
                    spec.max_time_to_wait,
                    spec.retry_interval_seconds,
                )
                results[CHECK_NODE_ALIVE] = result
                if not result.get('ok'):
                    return ModuleResult.error(
                        "node_alive failed: {}".format(result.get('error', 'unknown error')),
                        diagnostics=results
                    )

                summary_bits.append("node_alive OK (attempts:{})".format(result.get('attempts', 0)))

            if CHECK_CLUSTER_CONN in spec.checks:
                result = hcsvc.wait_for_cluster_connectivity(
                    session,
                    spec.url,
                    spec.max_time_to_wait,
                    spec.retry_interval_seconds,
                )
                results[CHECK_CLUSTER_CONN] = result
                if not result.get('ok'):
                    return ModuleResult.error(
                        "cluster_connectivity failed: {}".format(result.get('error', 'unknown error')),
                        diagnostics=results
                    )

                summary_bits.append("cluster_connectivity OK (attempts:{})".format(result.get('attempts', 0)))

            if (CHECK_DB_GROUPS_AVAILABLE in spec.checks) or (CHECK_DB_GROUPS_AVAILABLE_EXCL in spec.checks):
                if hostname_is_ip(spec.url):
                    return ModuleResult.error("database group availability checks require a hostname URL (not an IP).")

                excluded = None
                try:
                    if CHECK_DB_GROUPS_AVAILABLE_EXCL in spec.checks:
                        topo = fetch_topology_http(spec.url, tls)
                        target = spec.url.rstrip("/")
                        for group in (
                            getattr(topo, "members", {}) or {},
                            getattr(topo, "watchers", {}) or {},
                            getattr(topo, "promotables", {}) or {},
                        ):
                            for tag, u in group.items():
                                if (u or "").rstrip("/") == target:
                                    excluded = tag
                                    break
                            if excluded:
                                break
                    else:
                        excluded = None
                except Exception:
                    excluded = None

                ctx = DocumentStoreFactory.create(spec.url, None, spec.certificate_path, spec.ca_cert_path)
                try:
                    result = hcsvc.wait_for_node_databases_online(
                        ctx,
                        spec.max_time_to_wait,
                        spec.db_retry_interval_seconds,
                        excluded,
                    )

                    if isinstance(result, dict):
                        result["excluded_tag"] = excluded
                    key = CHECK_DB_GROUPS_AVAILABLE_EXCL if CHECK_DB_GROUPS_AVAILABLE_EXCL in spec.checks else CHECK_DB_GROUPS_AVAILABLE
                    results[key] = result

                    if not result.get("ok"):
                        err = result.get("error") or "unknown error"

                        if err == "timeout":
                            if spec.on_db_timeout == "fail":
                                return ModuleResult.error(
                                    "{} failed: timeout".format(key),
                                    diagnostics=results,
                                )
                            summary_bits.append(
                                "{} TIMEOUT (excluded:{} attempts:{})".format(
                                    key, excluded or "?", result.get("attempts", 0)
                                )
                            )
                        else:
                            return ModuleResult.error(
                                "{} failed: {}".format(key, err),
                                diagnostics=results,
                            )
                    else:
                        summary_bits.append(
                            "{} OK (excluded:{} attempts:{})".format(
                                key, excluded or "?", result.get("attempts", 0)
                            )
                        )
                finally:
                    ctx.close()
        finally:
            try:
                session.close()
            except Exception:
                pass

        msg = "; ".join(summary_bits) if summary_bits else "No checks selected."
        out = ModuleResult.ok(msg=msg, changed=False, results=results)
        if warnings:
            out.extras.setdefault("warnings", []).extend(warnings)
        return out
