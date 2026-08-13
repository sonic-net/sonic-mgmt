import logging
import time
from datetime import datetime

import pytest

from tests.common.fixtures.conn_graph_facts import enum_fanout_graph_facts  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.pfc_storm import PFCStorm
from tests.common.helpers.pfcwd_helper import start_wd_on_ports
from tests.common.helpers.sonic_db import CONFIG_DB, redis_hget
from tests.common.utilities import wait_until
from tests.common import config_reload


pytestmark = [
    pytest.mark.topology("any"),
]

logger = logging.getLogger(__name__)

# constants based on existing PFCWD storm tests
PFC_QUEUE = 4
HISTORY_UPDATE_TIMEOUT = 30
HISTORY_UPDATE_INTERVAL = 2
PFC_FRAMES_COUNT = 1000000
T2_PFC_SEND_PERIOD = 60

ACCURACY_SAMPLE_SECONDS = 5
CUMULATIVE_STORM_COUNT = 3
# recent rx pause timestamp has resolution of 1 second, so we need to wait > 1 second
TIMESTAMP_SETTLE_SECONDS = 1.1
UNPAUSED_POLL_COUNT = 2


def _history_config_is(duthost, port, expected):
    """verify CONFIG_DB contains the expected history setting"""
    asic = duthost.get_port_asic_instance(port)
    return redis_hget(
        asic, CONFIG_DB, "PFC_WD|{}".format(port), "pfc_stat_history"
    ) == expected


def _to_int(value):
    try:
        return int(value.replace(",", ""))
    except (AttributeError, ValueError):
        return 0


def _parse_history_timestamp(value):
    if value in ("", "N/A"):
        return None
    return datetime.strptime(value, "%m/%d/%Y, %H:%M:%S")


def _get_history(duthost, port, queue):
    """get history for one port/priority row from ``show pfc counters --history``"""
    priority = "PFC{}".format(queue)
    asic = duthost.get_port_asic_instance(port)
    rows = asic.show_and_parse(
        "show pfc counters --history | awk 'NF'"
    )

    for row in rows:
        if row["port"] == port and row["priority"] == priority:
            return {
                "transitions": _to_int(row["rx pause transitions"]),
                "total_pause_time_us": _to_int(row["total rx pause time us"]),
                "recent_pause_time_us": _to_int(row["recent rx pause time us"]),
                "recent_pause_timestamp": row["recent rx pause timestamp"],
            }
    return None


def _history_was_recorded(duthost, port, queue, before):
    """return whether a new pause period is visible in the CLI"""
    current = _get_history(duthost, port, queue)
    if current is None:
        return False

    # History must have updated with an increase in recent pause time or transitions
    timestamp = current["recent_pause_timestamp"]
    has_recent_pause = (
        timestamp not in ("", "N/A")
        and timestamp != before["recent_pause_timestamp"]
        and current["recent_pause_time_us"] > 0
    )
    total_advanced = (
        current["transitions"] > before["transitions"]
        or current["total_pause_time_us"] > before["total_pause_time_us"]
    )
    return has_recent_pause and total_advanced


def _enable_history(duthost, port):
    duthost.command("config pfcwd pfc_stat_history enable {}".format(port))
    pytest_assert(
        wait_until(10, 1, 0, _history_config_is, duthost, port, "enable"),
        "PFC statistics history was not enabled on {}".format(port),
    )


def _sample_history(duthost, port, queue):
    """get history and the midpoint of the CLI execution time"""
    before = time.monotonic()
    history = _get_history(duthost, port, queue)
    after = time.monotonic()
    return history, (before + after) / 2


@pytest.fixture(scope="module")
def ip_version():
    # these tests are not dependent on the IP version, choose one arbitrarily
    return "IPv4"


@pytest.fixture(scope="module")
def stat_history_setup(
    setup_pfc_test,
    enum_fanout_graph_facts,  # noqa: F811
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    fanouthosts,
):
    """prepare one Broadcom port and its fanout to generate PFC pause frames"""
    # currently only pfc_detect_broadcom.lua supports history
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # setup similar to pfcwd timer accuracy test
    setup_info = setup_pfc_test
    port = next(iter(setup_info["selected_test_ports"]))
    neighbor = setup_info["neighbors"].get(port)
    if not neighbor:
        pytest.skip("The selected test port has no fanout neighbor")

    peer_device = neighbor["peerdevice"]
    peer_info = {
        "peerdevice": peer_device,
        "hwsku": enum_fanout_graph_facts[peer_device]["device_info"]["HwSku"],
        "pfc_fanout_interface": neighbor["peerport"],
    }

    # use the specific pfc gen file for t2 fanouts
    pfc_gen_file = "pfc_gen.py"
    pfc_send_period = None
    if duthost.topo_type == "t2" and fanouthosts[peer_device].os == "sonic":
        pfc_gen_file = "pfc_gen_t2.py"
        pfc_send_period = T2_PFC_SEND_PERIOD

    storm = PFCStorm(
        duthost,
        enum_fanout_graph_facts,
        fanouthosts,
        pfc_queue_index=PFC_QUEUE,
        pfc_frames_number=PFC_FRAMES_COUNT,
        pfc_gen_file=pfc_gen_file,
        pfc_send_period=pfc_send_period,
        peer_info=peer_info,
    )
    storm.deploy_pfc_gen()

    # Start PFCWD in alert mode so detection records history without mitigating traffic.
    timers = setup_info["pfc_timers"]
    start_wd_on_ports(
        duthost,
        port,
        timers["pfc_wd_restore_time"],
        timers["pfc_wd_detect_time"],
        action="alert",
    )

    yield duthost, port, storm, timers["pfc_wd_poll_time"]

    # Stop storm and restore the per-port history configuration
    storm.stop_storm()
    config_reload(
        duthost,
        safe_reload=True,
        check_intf_up_ports=True,
        wait_for_bgp=True,
    )


@pytest.fixture
def stat_history_test_setup(stat_history_setup):
    """ensure there is no storm before each test and enable history"""
    duthost, port, storm, poll_interval_ms = stat_history_setup

    # Force XON and wait for two at least PFCWD polls before taking a new test baseline.
    storm.stop_storm()
    time.sleep(
        max(
            TIMESTAMP_SETTLE_SECONDS,
            UNPAUSED_POLL_COUNT * poll_interval_ms / 1000.0,
        )
    )
    # Enable collection once the queue unpaused
    _enable_history(duthost, port)

    yield stat_history_setup
    storm.stop_storm()


def test_pfcwd_stat_history(stat_history_test_setup):
    """
    verify that enabling history records a real PFC pause in the history CLI
    note that time is measured in microseconds (us)
    """
    duthost, port, storm, _ = stat_history_test_setup

    # Snapshot of current history before pause
    before = _get_history(duthost, port, PFC_QUEUE)
    pytest_assert(
        before is not None,
        "No history row was shown for {} PFC{}".format(port, PFC_QUEUE),
    )

    # start the storm and wait to see history update
    try:
        storm.start_storm()
        pytest_assert(
            wait_until(
                HISTORY_UPDATE_TIMEOUT,
                HISTORY_UPDATE_INTERVAL,
                0,  # The storm is already running, so begin polling immediately.
                _history_was_recorded,
                duthost,
                port,
                PFC_QUEUE,
                before,
            ),
            "PFC pause history did not update for {} PFC{}".format(port, PFC_QUEUE),
        )
    finally:
        storm.stop_storm()

    # Read the new history to verify it incremented from the snapshot
    history = _get_history(duthost, port, PFC_QUEUE)
    logger.info("Recorded PFC history for %s PFC%s: %s", port, PFC_QUEUE, history)
    pytest_assert(
        history is not None,
        "No history row was shown after the PFC storm",
    )
    pytest_assert(
        history["recent_pause_timestamp"] != before["recent_pause_timestamp"],
        "Recent pause timestamp did not change after the PFC storm",
    )
    pytest_assert(
        history["transitions"] > before["transitions"]
        or history["total_pause_time_us"] > before["total_pause_time_us"],
        "PFC history counters did not increase after the PFC storm",
    )


def test_pfcwd_stat_history_accuracy(stat_history_test_setup):
    """verify that estimated pause time tracks elapsed pause time"""
    duthost, port, storm, poll_interval_ms = stat_history_test_setup

    # save snapshot of history before storm
    before = _get_history(duthost, port, PFC_QUEUE)
    pytest_assert(
        before is not None,
        "No history row was shown for {} PFC{}".format(port, PFC_QUEUE),
    )

    # start the storm and wait to see history begin updating
    try:
        storm.start_storm()
        pytest_assert(
            wait_until(
                HISTORY_UPDATE_TIMEOUT,
                HISTORY_UPDATE_INTERVAL,
                0,
                _history_was_recorded,
                duthost,
                port,
                PFC_QUEUE,
                before,
            ),
            "PFC pause history did not start for {} PFC{}".format(
                port, PFC_QUEUE
            ),
        )

        # sample history before and after the wait period
        history_start, sample_start = _sample_history(
            duthost, port, PFC_QUEUE
        )
        pytest_assert(history_start is not None, "Failed to read initial history")
        time.sleep(ACCURACY_SAMPLE_SECONDS)

        # Take the ending counter sample while the queue is still paused.
        history_end, sample_end = _sample_history(duthost, port, PFC_QUEUE)
        pytest_assert(history_end is not None, "Failed to read final history")
    finally:
        storm.stop_storm()

    # time delta between reported recent pause time
    estimated_elapsed_us = (
        history_end["recent_pause_time_us"]
        - history_start["recent_pause_time_us"]
    )
    # time delta between cli calls
    actual_elapsed_us = int(
        (sample_end - sample_start) * 1000000
    )

    # allow one PFCWD polling interval of tolerance
    tolerance_us = poll_interval_ms * 1000
    error_us = abs(estimated_elapsed_us - actual_elapsed_us)

    logger.info(
        "PFC history accuracy on %s PFC%s: estimated=%sus actual=%sus "
        "error=%sus tolerance=%sus",
        port,
        PFC_QUEUE,
        estimated_elapsed_us,
        actual_elapsed_us,
        error_us,
        tolerance_us,
    )
    # the estimated pause time should be within the tolerance
    pytest_assert(
        error_us <= tolerance_us,
        "Estimated pause time differs from elapsed time by {}us; "
        "allowed tolerance is {}us".format(error_us, tolerance_us),
    )


def test_pfcwd_stat_history_is_cumulative(stat_history_test_setup):
    """verify that three separate storms accumulate three history periods"""
    duthost, port, storm, poll_interval_ms = stat_history_test_setup

    # get snapshot of history before storms
    previous = _get_history(duthost, port, PFC_QUEUE)
    pytest_assert(
        previous is not None,
        "No history row was shown for {} PFC{}".format(port, PFC_QUEUE),
    )

    # subsequent storms should increase history counters cumulatively
    for cycle in range(0, CUMULATIVE_STORM_COUNT):
        try:
            storm.start_storm()
            pytest_assert(
                wait_until(
                    HISTORY_UPDATE_TIMEOUT,
                    HISTORY_UPDATE_INTERVAL,
                    0,
                    _history_was_recorded,
                    duthost,
                    port,
                    PFC_QUEUE,
                    previous,
                ),
                "PFC history did not record storm {} on {} PFC{}".format(
                    cycle, port, PFC_QUEUE
                ),
            )
        finally:
            storm.stop_storm()

        time.sleep(
            max(
                TIMESTAMP_SETTLE_SECONDS,
                UNPAUSED_POLL_COUNT * poll_interval_ms / 1000.0,
            )
        )
        current = _get_history(duthost, port, PFC_QUEUE)
        pytest_assert(current is not None, "Failed to read history after storm")

        # Every period must increase both cumulative duration and transition count
        pytest_assert(
            current["total_pause_time_us"] > previous["total_pause_time_us"],
            "Total pause time did not accumulate after storm {}".format(cycle),
        )
        pytest_assert(
            current["transitions"] > previous["transitions"],
            "Pause transition count did not accumulate after storm {}".format(
                cycle
            ),
        )

        # the recent period should be more recent than the previous recent pause
        current_timestamp = _parse_history_timestamp(
            current["recent_pause_timestamp"]
        )
        previous_timestamp = _parse_history_timestamp(
            previous["recent_pause_timestamp"]
        )
        pytest_assert(
            current_timestamp is not None,
            "Storm {} did not record a valid pause timestamp".format(cycle),
        )
        if previous_timestamp is not None:
            pytest_assert(
                current_timestamp > previous_timestamp,
                "Storm {} did not create a more recent pause period".format(cycle),
            )

        logger.info(
            "PFC history after storm %s on %s PFC%s: %s",
            cycle,
            port,
            PFC_QUEUE,
            current,
        )
        previous = current
