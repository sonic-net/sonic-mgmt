"""OTG tests: ports from conn graph; network/proxy setup for lab API access."""

import os

import pytest

from tests.common.snappi_tests.otg_throughput_helpers import (
    build_snappi_ports_from_conn_graph,
    configure_otg_client_environment,
)


def _is_otg_tb(tbinfo):
    return "OTG" in (tbinfo.get("ptf_image_name") or "").upper()


@pytest.fixture(scope="session", autouse=True)
def otg_client_environment(tbinfo):
    """
    Corporate HTTP proxies break requests to the lab tgen IP. Bridge-network
    sonic-mgmt containers often cannot reach the host-only bind 100.117.x:8443;
    set TGEN_API=http://172.17.0.1:8443 when dpdk-tgen listens on 0.0.0.0.
    """
    if not _is_otg_tb(tbinfo):
        yield
        return
    saved = configure_otg_client_environment(tbinfo)
    yield
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


@pytest.fixture(scope="module")
def otg_snappi_ports(conn_graph_facts, duthost, tbinfo):
    return build_snappi_ports_from_conn_graph(
        conn_graph_facts,
        duthost.hostname,
        tbinfo["ptf_ip"],
    )
