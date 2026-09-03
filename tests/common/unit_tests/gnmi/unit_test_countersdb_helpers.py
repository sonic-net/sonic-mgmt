from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.gnmi import test_gnmi_countersdb
from tests.gnmi import test_gnmi_countersdb_config_reload
from tests.gnmi.countersdb_helpers import countersdb_config_path, countersdb_prefix, response_has_update


def test_response_has_update_checks_structured_path_and_value():
    response = {
        "notification": [{
            "update": [{
                "path": "COUNTERS/oid:0x1",
                "val": {"SAI_PORT_STAT_IF_IN_ERRORS": "0"},
            }],
        }],
    }

    assert response_has_update(response, "oid:0x1")
    assert response_has_update(response, "SAI_PORT_STAT_IF_IN_ERRORS")
    assert not response_has_update(response, "SAI_PORT_STAT_IF_OUT_ERRORS")


def test_response_has_update_ignores_empty_updates():
    response = {"update": [{"path": "COUNTERS/oid:0x1", "val": {}}]}

    assert not response_has_update(response, "oid:0x1")


def test_response_has_update_handles_subscription_envelope_and_scalar_value():
    response = {
        "update": {
            "update": [{
                "path": "COUNTERS/oid:0x1/SAI_PORT_STAT_IF_IN_ERRORS",
                "val": "0",
            }],
        },
    }

    assert response_has_update(response, "SAI_PORT_STAT_IF_IN_ERRORS")


def test_countersdb_prefix_preserves_namespace():
    single_asic = SimpleNamespace(is_multi_asic=False)
    multi_asic = SimpleNamespace(
        is_multi_asic=True,
        get_port_asic_instance=lambda iface: SimpleNamespace(namespace="asic2", asic_index=2),
    )

    assert countersdb_prefix(single_asic) == "sonic-db:COUNTERS_DB/localhost"
    assert countersdb_prefix(multi_asic) == "sonic-db:COUNTERS_DB/asic2"
    assert countersdb_config_path(single_asic) == "/etc/sonic/config_db.json"
    assert countersdb_config_path(multi_asic) == "/etc/sonic/config_db2.json"


def test_module_fixture_reuses_lifecycle_for_selected_dut(monkeypatch):
    marker = getattr(test_gnmi_countersdb.gnmi_tls, "_fixture_function_marker", None)
    marker = marker or test_gnmi_countersdb.gnmi_tls._pytestfixturefunction
    selected = object()
    ptfhost = object()
    calls = []

    def lifecycle(duthost, ptf):
        calls.append((duthost, ptf))
        yield "fixture"

    monkeypatch.setattr(test_gnmi_countersdb, "_gnmi_tls_lifecycle", lifecycle)

    assert marker.scope == "module"
    assert list(test_gnmi_countersdb.gnmi_tls.__wrapped__(
        {"selected": selected}, "selected", ptfhost, None, None
    )) == ["fixture"]
    assert calls == [(selected, ptfhost)]


def test_queue_count_retry_suppresses_rpc_error_but_final_read_does_not():
    duthost = SimpleNamespace(is_multi_asic=False)
    client = Mock()
    client.get.side_effect = test_gnmi_countersdb_config_reload.PygnmiClientError("unavailable")

    assert not test_gnmi_countersdb_config_reload._check_buffer_queues_cnt(
        duthost, client, "Ethernet0"
    )
    with pytest.raises(test_gnmi_countersdb_config_reload.PygnmiClientError):
        test_gnmi_countersdb_config_reload._get_buffer_queues_cnt(
            duthost, client, "Ethernet0"
        )
