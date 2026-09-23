"""System / Link Behavior - port shutdown/startup link toggle validation.

Implements the port shutdown, port startup, and Pre-FEC BER peer-side-flap
tests from ``docs/testplan/transceiver/system_test_plan.md`` (Link Behavior
Test Cases, TC 1-3).

Execution order::

  session start
    `- check_links_up()                       <- session-scoped via
                                                 ``links_verified`` in
                                                 tests/transceiver/conftest.py
                                                 (failure skips every
                                                 System test)
    `- test_system_port_shutdown
         |- <body>: bulk shutdown all ports -> verify each reaches oper-down
    `- test_system_port_startup
         |- <body>: bulk startup all ports -> Standard Port Recovery and
                    Verification for all ports
    `- test_system_prefec_ber_peer_side_flap
         |- <body>: skip unless a prefec_ber_check_supported port has a
                    peer DUT resolvable in the connection graph
         `-         flap the peer end -> Standard Port Recovery and
                    Verification -> Pre-FEC BER Guard
  session end
    `- _system_post_session_checks (system/conftest.py)
         |- post_state_restoration()
         |- STATE_DB consistency check
         `- final link + LLDP check

Failure handling: failures are accumulated per port and reported in a
single pytest.fail at the end, so a single run surfaces all issues across
all ports.
"""
import logging

import pytest

from tests.transceiver.attribute_parser.attribute_keys import (
    SYSTEM_ATTRIBUTES_KEY
)
from tests.transceiver.common import scenario_ops
from tests.transceiver.common.health_checks import capture_baseline
from tests.transceiver.common.peer_resolution import resolve_peer_duthost_port
from tests.transceiver.common.prerequisites import check_links_up
from tests.transceiver.common.verification import (
    capture_prefec_ber_baseline,
    check_prefec_ber_guard,
    standard_port_recovery_and_verification,
)

logger = logging.getLogger(__name__)

# Fallback values, used only if a port's SYSTEM_ATTRIBUTES omits the wait.
_DEFAULT_PORT_SHUTDOWN_WAIT_SEC = 5
_DEFAULT_PORT_STARTUP_WAIT_SEC = 60
_DEFAULT_PREFEC_BER_MEASURE_SEC = 30
_DEFAULT_PREFEC_BER_MAX = 1e-8
_DEFAULT_PREFEC_BER_DEGRADATION_FACTOR = 10


def test_system_port_shutdown(duthost, port_attributes_dict):
    """
    Shut down every transceiver port (bulk) and verify each one reaches
    oper-down within its configured wait.
    """
    ports = sorted(port_attributes_dict.keys())
    assert ports, "port_attributes_dict is empty - nothing to validate"

    logger.info("Recording link states for %d port(s)", len(ports))
    link_check = check_links_up(duthost, port_attributes_dict)
    failures = []
    if not link_check["passed"]:
        logger.error(
            "Validation on Start FAILED: some ports are down: %s",
            link_check["details"],
        )
        failures.append(f"[validation-on-start] {link_check['details']}")

    shutdown_wait = scenario_ops.scale_bulk_wait(
        max(
            port_attributes_dict[port].get(SYSTEM_ATTRIBUTES_KEY, {}).get(
                "port_shutdown_wait_sec", _DEFAULT_PORT_SHUTDOWN_WAIT_SEC
            )
            for port in ports
        ),
        len(ports),
    )

    logger.info("Shutting down %d port(s) (bulk)", len(ports))
    failures.extend(scenario_ops.perform_ports_shutdown(duthost, ports, shutdown_wait))

    if failures:
        pytest.fail(
            f"Port shutdown validation FAILED on {len(failures)} "
            "port(s):\n  - " + "\n  - ".join(failures)
        )


def test_system_port_startup(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping,
):
    """
    Start up every transceiver port (bulk), then run Standard Port
    Recovery and Verification across all ports.
    """
    ports = sorted(port_attributes_dict.keys())
    assert ports, "port_attributes_dict is empty - nothing to validate"

    health_baseline = capture_baseline(duthost)

    startup_wait = scenario_ops.scale_bulk_wait(
        max(
            port_attributes_dict[port].get(SYSTEM_ATTRIBUTES_KEY, {}).get(
                "port_startup_wait_sec", _DEFAULT_PORT_STARTUP_WAIT_SEC
            )
            for port in ports
        ),
        len(ports),
    )

    logger.info("Starting up %d port(s) (bulk)", len(ports))
    failures = scenario_ops.perform_ports_startup(duthost, ports, startup_wait)

    logger.info(
        "Running Standard Port Recovery and Verification for %d port(s)",
        len(ports),
    )
    result = standard_port_recovery_and_verification(
        duthost, ports, port_attributes_dict,
        link_up_timeout_sec=startup_wait,
        health_baseline=health_baseline,
        lport_to_first_subport_mapping=lport_to_first_subport_mapping,
        expected_pid_changes=expected_pid_changes,
    )
    if not result["passed"]:
        failures.append(f"[post-startup] {result['details']}")
        logger.warning("Post-startup validation FAILED: %s", result["details"])
    else:
        logger.info("Post-startup validation PASSED for %d port(s)", len(ports))

    if failures:
        pytest.fail(
            f"Port startup validation FAILED on {len(failures)} "
            "port(s):\n  - " + "\n  - ".join(failures)
        )


def test_system_prefec_ber_peer_side_flap(
    duthost, duthosts, conn_graph_facts, port_attributes_dict,
    expected_pid_changes, lport_to_first_subport_mapping,
):
    """
    Flap the peer side of each in-scope port and verify the DUT-side
    Pre-FEC BER stays within tolerance of baseline after the link recovers.

    Requires a peer SONiC device for at least one
    ``prefec_ber_check_supported`` port; self-loopback and non-DUT peers
    are excluded, and the test is skipped if no port qualifies.
    """
    candidate_ports = sorted(
        port for port, attrs in port_attributes_dict.items()
        if attrs.get(SYSTEM_ATTRIBUTES_KEY, {}).get("prefec_ber_check_supported", False)
    )
    if not candidate_ports:
        pytest.skip("prefec_ber_check_supported is False for every port - nothing to test")

    peers_by_port = {}
    for port in candidate_ports:
        peer_duthost, peer_port = resolve_peer_duthost_port(
            duthost, duthosts, conn_graph_facts, port
        )
        if peer_duthost is not None:
            peers_by_port[port] = (peer_duthost, peer_port)

    if not peers_by_port:
        pytest.skip(
            "No prefec_ber_check_supported port has a peer DUT in this "
            "testbed's connection graph - the Pre-FEC BER peer-side flap "
            "test requires a point-to-point topology with a second SONiC DUT"
        )

    system_attrs = {
        port: port_attributes_dict[port].get(SYSTEM_ATTRIBUTES_KEY, {})
        for port in peers_by_port
    }
    measure_sec = max(
        attrs.get("prefec_ber_measure_sec", _DEFAULT_PREFEC_BER_MEASURE_SEC)
        for attrs in system_attrs.values()
    )

    logger.info(
        "Capturing Pre-FEC BER baseline for %d candidate port(s)",
        len(peers_by_port),
    )
    baseline = capture_prefec_ber_baseline(duthost, sorted(peers_by_port), measure_sec)
    ports = sorted(baseline.keys())
    if not ports:
        pytest.skip(
            "fec_pre_ber is absent, N/A, or unparsable in 'show interfaces "
            "counters fec-stats' for every candidate port - nothing to guard"
        )

    skipped_no_peer_or_baseline = sorted(set(candidate_ports) - set(ports))
    if skipped_no_peer_or_baseline:
        logger.info(
            "Excluding from this run (no peer DUT, or fec_pre_ber absent/"
            "N/A/unparsable in CLI output): %s", ", ".join(skipped_no_peer_or_baseline),
        )

    health_baseline = capture_baseline(duthost)
    failures = []  # collected across every (port, step) tuple

    peer_ports_by_duthost = {}
    for port in ports:
        peer_duthost, peer_port = peers_by_port[port]
        peer_ports_by_duthost.setdefault(peer_duthost, []).append(peer_port)

    shutdown_wait = max(
        system_attrs[port].get(
            "port_shutdown_wait_sec", _DEFAULT_PORT_SHUTDOWN_WAIT_SEC
        )
        for port in ports
    )
    startup_wait = max(
        system_attrs[port].get(
            "port_startup_wait_sec", _DEFAULT_PORT_STARTUP_WAIT_SEC
        )
        for port in ports
    )

    for peer_duthost, peer_ports in peer_ports_by_duthost.items():
        logger.info(
            "Flapping %d peer port(s) on %s", len(peer_ports), peer_duthost.hostname,
        )
        shutdown_failures = scenario_ops.perform_ports_shutdown(
            peer_duthost, peer_ports, shutdown_wait
        )
        for failure in shutdown_failures:
            logger.warning("peer %s: %s", peer_duthost.hostname, failure)

        # Teardown contract: always attempt to restore the peer ports, even
        # if the shutdown above didn't fully settle.
        startup_failures = scenario_ops.perform_ports_startup(
            peer_duthost, peer_ports, startup_wait
        )
        if startup_failures:
            failures.extend(
                f"{peer_duthost.hostname}: {failure}" for failure in startup_failures
            )

    settle_wait = max(
        system_attrs[port].get(
            "port_startup_wait_sec", _DEFAULT_PORT_STARTUP_WAIT_SEC
        )
        for port in ports
    )
    logger.info(
        "Running Standard Port Recovery and Verification for %d port(s)",
        len(ports),
    )
    result = standard_port_recovery_and_verification(
        duthost, ports, {port: port_attributes_dict[port] for port in ports},
        link_up_timeout_sec=settle_wait,
        health_baseline=health_baseline,
        lport_to_first_subport_mapping=lport_to_first_subport_mapping,
        expected_pid_changes=expected_pid_changes,
    )
    if not result["passed"]:
        failures.append(f"[post-flap] {result['details']}")
        logger.warning("Post-flap validation FAILED: %s", result["details"])
    else:
        logger.info("Post-flap validation PASSED for %d port(s)", len(ports))

    logger.info("Running Pre-FEC BER Guard for %d port(s)", len(ports))
    prefec_ber_max = {
        port: system_attrs[port].get("prefec_ber_max", _DEFAULT_PREFEC_BER_MAX)
        for port in ports
    }
    prefec_ber_degradation_factor = {
        port: system_attrs[port].get(
            "prefec_ber_degradation_factor", _DEFAULT_PREFEC_BER_DEGRADATION_FACTOR
        )
        for port in ports
    }
    guard_results = check_prefec_ber_guard(
        duthost, ports, baseline, measure_sec,
        prefec_ber_max, prefec_ber_degradation_factor,
    )
    for guard_result in guard_results.values():
        if not guard_result["passed"]:
            failures.append(guard_result["details"])

    if failures:
        pytest.fail(
            f"Pre-FEC BER peer-side flap validation FAILED on "
            f"{len(failures)} item(s):\n  - " + "\n  - ".join(failures)
        )
