import logging
import re
from contextlib import closing

import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.pygnmi_client import Encoding, SubscribeMode
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
]


def _srv6_namespace(duthost):
    return "asic0" if duthost.is_multi_asic else None


def _sonic_db_cli(duthost):
    return "sonic-db-cli" + (" -n asic0" if duthost.is_multi_asic else "")


def _check_srv6_stats(duthost):
    return len(duthost.shell("show srv6 stats")["stdout_lines"]) > 2


@pytest.fixture()
def setup_my_sid(gnmi_tls):  # noqa: F811
    # Take the TLS checkpoint before adding temporary SID configuration.
    duthost = gnmi_tls.duthost
    cli = _sonic_db_cli(duthost)
    duthost.command(cli + " CONFIG_DB HSET SRV6_MY_LOCATORS\\|loc1 prefix fcbb:bbbb:1:: func_len 0")
    duthost.command(cli + " CONFIG_DB HSET SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48 action uN decap_dscp_mode pipe")
    yield
    duthost.command(cli + " CONFIG_DB DEL SRV6_MY_LOCATORS\\|loc1")
    duthost.command(cli + " CONFIG_DB DEL SRV6_MY_SIDS\\|loc1\\|fcbb:bbbb:1::/48")


def test_poll_mode_srv6_sid_counters(gnmi_tls, rand_one_dut_hostname, setup_my_sid):  # noqa: F811
    """
    POLL COUNTERS_DB for SRv6 MY_SID counters: query before data exists (no error),
    then enable counter polling and confirm counter data arrives.
    """
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    ns = _srv6_namespace(duthost)
    target = "COUNTERS_DB/{}".format(ns) if ns else "COUNTERS_DB"
    # PR28374: the empty first query completes on sync, not data updates.
    result = list(
        client.subscribe(
            ["COUNTERS/SID:*"],
            target=target,
            mode=SubscribeMode.POLL,
            encoding=Encoding.JSON,
            poll_interval=2,
            poll_count=5,
        )
    )
    assert any(response.get("sync_response") is True for response in result), "Incorrect sync responses"

    duthost.shell("counterpoll srv6 enable")
    wait_until(30, 1, 5, _check_srv6_stats, duthost)

    try:
        result = []
        update_count = 0
        with closing(
            client.subscribe(
                ["COUNTERS/SID:*"],
                target=target,
                mode=SubscribeMode.POLL,
                encoding=Encoding.JSON,
                poll_interval=10,
                poll_count=10,
            )
        ) as responses:
            for response in responses:
                result.append(response)
                update_count += len(response.get("update", {}).get("update", []))
                if update_count >= 10:
                    break
        out = str(result)
        assert re.findall("SAI_COUNTER_STAT_PACKETS", out), "Missing update responses: {}".format(out)
    finally:
        duthost.shell("counterpoll srv6 disable")


def test_poll_mode_srv6_sid_counters_with_mock_data(gnmi_tls, rand_one_dut_hostname):  # noqa: F811
    """
    POLL COUNTERS_DB for SRv6 MY_SID counters using injected mock COUNTERS data.
    """
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    ns = _srv6_namespace(duthost)
    target = "COUNTERS_DB/{}".format(ns) if ns else "COUNTERS_DB"
    # PR28374: the empty first query completes on sync, not data updates.
    result = list(
        client.subscribe(
            ["COUNTERS/SID:*"],
            target=target,
            mode=SubscribeMode.POLL,
            encoding=Encoding.JSON,
            poll_interval=2,
            poll_count=5,
        )
    )
    assert any(response.get("sync_response") is True for response in result), "Incorrect sync responses"

    cli = _sonic_db_cli(duthost)
    duthost.shell(
        cli + ' COUNTERS_DB HSET "COUNTERS:oid:0x11110000001eb3" '
        "SAI_COUNTER_STAT_PACKETS 10 SAI_COUNTER_STAT_BYTES 40960"
    )
    duthost.shell(cli + ' COUNTERS_DB HSET "COUNTERS_SRV6_NAME_MAP" ' '"fcbb:bbbb:1::/48" "oid:0x11110000001eb3"')

    try:
        result = []
        update_count = 0
        with closing(
            client.subscribe(
                ["COUNTERS/SID:*"],
                target=target,
                mode=SubscribeMode.POLL,
                encoding=Encoding.JSON,
                poll_interval=10,
                poll_count=10,
            )
        ) as responses:
            for response in responses:
                result.append(response)
                update_count += len(response.get("update", {}).get("update", []))
                if update_count >= 10:
                    break
        out = str(result)
        assert re.findall("SAI_COUNTER_STAT_PACKETS", out), "Missing update responses: {}".format(out)
    finally:
        duthost.shell(cli + ' COUNTERS_DB DEL "COUNTERS:oid:0x11110000001eb3"')
        duthost.shell(cli + ' COUNTERS_DB HDEL "COUNTERS_SRV6_NAME_MAP" "fcbb:bbbb:1::/48"')
