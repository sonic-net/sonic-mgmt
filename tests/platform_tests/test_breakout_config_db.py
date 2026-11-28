"""
Tests for ansible/library/breakout_config_db.py

Validates that the breakout config_db generator correctly transforms an existing
config_db.json into a breakout configuration, and that applying the result on a
real device brings all ports up with healthy critical services.

Targeted at TH5 (BCM7890 / "f90") SKUs.
"""

import json
import logging
import os
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
]

# Paths on the DUT
CONFIG_DB = "/etc/sonic/config_db.json"
CONFIG_DB_BAK = "/host/config_db.json.before_breakout_test"
BREAKOUT_SCRIPT_REMOTE = "/tmp/breakout_config_db.py"
BREAKOUT_OUTPUT = "/etc/sonic/config_db.breakout.json"
GOLDEN_CONFIG_DB = "/etc/sonic/golden_config_db.json"

# Local path (relative to repo root) for the breakout script
BREAKOUT_SCRIPT_LOCAL = os.path.join(
    os.path.dirname(__file__), os.pardir, os.pardir, "ansible", "library", "breakout_config_db.py"
)

MAX_WAIT_TIME_FOR_INTERFACES = 360
MAX_WAIT_TIME_FOR_CRITICAL_PROCESSES = 360


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def duthost(duthosts, rand_one_dut_hostname):
    """Convenience fixture to select a single DUT."""
    return duthosts[rand_one_dut_hostname]


@pytest.fixture(scope="module", autouse=True)
def skip_non_th5(duthost):
    """Skip the entire module unless the DUT has a TH5 ASIC."""
    asic_name = duthost.get_asic_name()
    if asic_name != "th5":
        pytest.skip("Test only supported on TH5 SKUs (detected ASIC: {})".format(asic_name))


# Default breakout configuration for TH5: 4x100G from 400G
DEFAULT_BREAKOUT_COUNT = 4
DEFAULT_BREAKOUT_SPEED = "100000"
DEFAULT_BASE_SPEED = "400000"


@pytest.fixture(scope="module")
def breakout_params(request):
    """Collect breakout parameters from CLI options or use TH5 defaults.

    Defaults to 4x100G breakout from 400G base ports. All parameters
    can be overridden via CLI options (e.g. --breakout-count 2).
    """
    return {
        "breakout_count": request.config.getoption("breakout_count") or DEFAULT_BREAKOUT_COUNT,
        "breakout_speed": request.config.getoption("breakout_speed") or DEFAULT_BREAKOUT_SPEED,
        "breakout_total": request.config.getoption("breakout_total"),
        "base_speed": request.config.getoption("base_speed") or DEFAULT_BASE_SPEED,
        "default_cable_length": request.config.getoption("default_cable_length"),
    }


@pytest.fixture(scope="module")
def backup_config(duthost):
    """Backup config_db.json before tests and restore it afterward."""
    logger.info("Backing up %s to %s", CONFIG_DB, CONFIG_DB_BAK)
    duthost.shell("cp {} {}".format(CONFIG_DB, CONFIG_DB_BAK))

    yield

    logger.info("Restoring %s from %s", CONFIG_DB, CONFIG_DB_BAK)
    duthost.shell("cp {} {}".format(CONFIG_DB_BAK, CONFIG_DB))
    # Also restore golden_config_db.json if it was overwritten
    duthost.shell("cp {} {}".format(CONFIG_DB_BAK, GOLDEN_CONFIG_DB), module_ignore_errors=True)
    duthost.shell("rm -f {}".format(CONFIG_DB_BAK))

    logger.info("Reloading config to restore original state")
    config_reload(duthost, config_source="config_db", wait=120, safe_reload=True, check_intf_up_ports=False)
    wait_critical_processes(duthost, timeout=MAX_WAIT_TIME_FOR_CRITICAL_PROCESSES)


@pytest.fixture(scope="module")
def original_config(duthost):
    """Read the original config_db.json from the DUT."""
    output = duthost.shell("cat {}".format(CONFIG_DB))
    return json.loads(output["stdout"])


@pytest.fixture(scope="module")
def deploy_script(duthost):
    """Copy the breakout_config_db.py script to the DUT."""
    local_path = os.path.normpath(BREAKOUT_SCRIPT_LOCAL)
    pytest_assert(os.path.isfile(local_path),
                  "Breakout script not found at {}".format(local_path))
    duthost.copy(src=local_path, dest=BREAKOUT_SCRIPT_REMOTE, mode="0755")
    yield
    duthost.shell("rm -f {}".format(BREAKOUT_SCRIPT_REMOTE), module_ignore_errors=True)


@pytest.fixture(scope="module")
def breakout_config(duthost, deploy_script, breakout_params, original_config):  # noqa: F811
    """Run breakout_config_db.py on the DUT and return the generated config.

    Note: deploy_script is declared as a dependency to ensure the script is
    copied to the DUT before this fixture executes.
    """
    params = breakout_params

    cmd = (
        "python3 {script}"
        " --in {input_path}"
        " --out {output_path}"
        " --breakout-count {count}"
        " --breakout-speed {speed}"
        " --base-speed {base_speed}"
    ).format(
        script=BREAKOUT_SCRIPT_REMOTE,
        input_path=CONFIG_DB,
        output_path=BREAKOUT_OUTPUT,
        count=params["breakout_count"],
        speed=params["breakout_speed"],
        base_speed=params["base_speed"],
    )

    if params["breakout_total"] is not None:
        cmd += " --breakout-total {}".format(params["breakout_total"])

    if params["default_cable_length"] is not None:
        cmd += " --default-cable-length {}".format(params["default_cable_length"])

    logger.info("Running breakout config generator: %s", cmd)
    result = duthost.shell(cmd)
    logger.info("breakout_config_db.py stderr:\n%s", result.get("stderr", ""))

    pytest_assert(result["rc"] == 0,
                  "breakout_config_db.py failed with rc={}: {}".format(
                      result["rc"], result.get("stderr", "")))

    output = duthost.shell("cat {}".format(BREAKOUT_OUTPUT))
    config = json.loads(output["stdout"])
    return config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_base_ports(original_config, base_speed, breakout_total, breakout_count):
    """Determine which ports the script should have used as base ports."""
    port_table = original_config.get("PORT", {})
    candidates = sorted(
        [name for name, entry in port_table.items() if entry.get("speed") == str(base_speed)],
        key=lambda n: int(n.replace("Ethernet", ""))
    )
    if breakout_total is not None:
        needed = breakout_total // breakout_count
        return candidates[:needed]
    return candidates


def _expected_new_ports(base_port, breakout_count):
    """Return the list of new port names for a given base port."""
    base_index = int(base_port.replace("Ethernet", ""))
    return ["Ethernet{}".format(base_index + i) for i in range(breakout_count)]


def _get_cable_length_tables(cable_length_data):
    """Extract cable length table(s) from the CABLE_LENGTH section."""
    if not isinstance(cable_length_data, dict):
        return []
    if any(isinstance(v, dict) for v in cable_length_data.values()):
        return [v for v in cable_length_data.values() if isinstance(v, dict)]
    return [cable_length_data]


def _find_port_in_cable_length(cable_length_data, port):
    """Check whether a port appears in any cable length table."""
    for table in _get_cable_length_tables(cable_length_data):
        if port in table:
            return True
    return False


# ---------------------------------------------------------------------------
# Tests — Config Validation (offline, before applying)
# ---------------------------------------------------------------------------

class TestBreakoutConfigGeneration:
    """Validate the structure of the generated breakout config_db.json."""

    def test_script_runs_successfully(self, breakout_config):
        """Verify the script produced a non-empty config."""
        pytest_assert(isinstance(breakout_config, dict), "Generated config is not a dict")
        pytest_assert("PORT" in breakout_config, "Generated config has no PORT table")

    def test_port_table_has_new_ports(self, breakout_config, original_config, breakout_params):
        """Verify new breakout ports exist in the PORT table."""
        params = breakout_params
        base_ports = _get_base_ports(
            original_config, params["base_speed"],
            params["breakout_total"], params["breakout_count"],
        )
        pytest_assert(len(base_ports) > 0,
                      "No base ports found with speed {}".format(params["base_speed"]))

        new_port_table = breakout_config["PORT"]
        for base_port in base_ports:
            expected = _expected_new_ports(base_port, params["breakout_count"])
            for port_name in expected:
                pytest_assert(port_name in new_port_table,
                              "Expected port {} missing from PORT table (base: {})".format(
                                  port_name, base_port))

    def test_port_speeds_correct(self, breakout_config, original_config, breakout_params):
        """Verify all breakout ports have the correct speed."""
        params = breakout_params
        base_ports = _get_base_ports(
            original_config, params["base_speed"],
            params["breakout_total"], params["breakout_count"],
        )
        port_table = breakout_config["PORT"]
        for base_port in base_ports:
            for port_name in _expected_new_ports(base_port, params["breakout_count"]):
                if port_name not in port_table:
                    continue
                actual_speed = port_table[port_name].get("speed")
                pytest_assert(
                    actual_speed == str(params["breakout_speed"]),
                    "Port {} speed is {} expected {}".format(
                        port_name, actual_speed, params["breakout_speed"]),
                )

    def test_port_lanes_split_correctly(self, breakout_config, original_config, breakout_params):
        """Verify lanes are correctly split among breakout ports."""
        params = breakout_params
        base_ports = _get_base_ports(
            original_config, params["base_speed"],
            params["breakout_total"], params["breakout_count"],
        )
        orig_port_table = original_config["PORT"]
        new_port_table = breakout_config["PORT"]

        for base_port in base_ports:
            orig_lanes = orig_port_table[base_port].get("lanes", "").split(",")
            pytest_assert(
                len(orig_lanes) % params["breakout_count"] == 0,
                "Base port {} lane count {} not divisible by breakout-count {}".format(
                    base_port, len(orig_lanes), params["breakout_count"]),
            )
            expected_per_port = len(orig_lanes) // params["breakout_count"]
            pytest_assert(expected_per_port > 0,
                          "Base port {} has no lanes to split".format(base_port))

            all_new_lanes = []
            for port_name in _expected_new_ports(base_port, params["breakout_count"]):
                if port_name not in new_port_table:
                    continue
                port_lanes = new_port_table[port_name].get("lanes", "").split(",")
                pytest_assert(
                    len(port_lanes) == expected_per_port,
                    "Port {} has {} lanes, expected {}".format(
                        port_name, len(port_lanes), expected_per_port),
                )
                all_new_lanes.extend(port_lanes)

            # All original lanes should be accounted for
            pytest_assert(
                sorted(all_new_lanes) == sorted(orig_lanes),
                "Lanes mismatch for base port {}: original={} combined_new={}".format(
                    base_port, orig_lanes, all_new_lanes),
            )

    def test_port_aliases_unique(self, breakout_config):
        """Verify all port aliases are unique."""
        port_table = breakout_config["PORT"]
        aliases = [entry.get("alias") for entry in port_table.values() if entry.get("alias")]
        duplicates = [a for a in aliases if aliases.count(a) > 1]
        pytest_assert(
            len(duplicates) == 0,
            "Duplicate aliases found: {}".format(set(duplicates)),
        )

    def test_cable_length_populated(self, breakout_config, original_config, breakout_params):
        """Verify CABLE_LENGTH entries exist for new breakout ports."""
        cable_data = breakout_config.get("CABLE_LENGTH")
        if not cable_data:
            pytest.skip("No CABLE_LENGTH section in config")

        params = breakout_params
        base_ports = _get_base_ports(
            original_config, params["base_speed"],
            params["breakout_total"], params["breakout_count"],
        )

        for base_port in base_ports:
            for port_name in _expected_new_ports(base_port, params["breakout_count"]):
                pytest_assert(
                    _find_port_in_cable_length(cable_data, port_name),
                    "Port {} missing from CABLE_LENGTH".format(port_name),
                )

    def test_buffer_pg_populated(self, breakout_config, original_config, breakout_params):
        """Verify BUFFER_PG entries exist for new breakout ports."""
        buffer_pg = breakout_config.get("BUFFER_PG")
        if not buffer_pg:
            pytest.skip("No BUFFER_PG section in config")

        params = breakout_params
        base_ports = _get_base_ports(
            original_config, params["base_speed"],
            params["breakout_total"], params["breakout_count"],
        )

        # Determine which PG suffixes the base port had
        orig_buffer_pg = original_config.get("BUFFER_PG", {})
        for base_port in base_ports:
            base_pg_suffixes = [
                key.split("|", 1)[1]
                for key in orig_buffer_pg
                if key.startswith(base_port + "|")
            ]
            if not base_pg_suffixes:
                continue

            for port_name in _expected_new_ports(base_port, params["breakout_count"]):
                for suffix in base_pg_suffixes:
                    key = "{}|{}".format(port_name, suffix)
                    pytest_assert(
                        key in buffer_pg,
                        "BUFFER_PG entry {} missing".format(key),
                    )

    def test_queue_table_populated(self, breakout_config, original_config, breakout_params):
        """Verify QUEUE entries exist for new breakout ports."""
        queue_table = breakout_config.get("QUEUE")
        if not queue_table:
            pytest.skip("No QUEUE section in config")

        params = breakout_params
        base_ports = _get_base_ports(
            original_config, params["base_speed"],
            params["breakout_total"], params["breakout_count"],
        )
        orig_queue = original_config.get("QUEUE", {})

        for base_port in base_ports:
            base_q_suffixes = [
                key.split("|", 1)[1]
                for key in orig_queue
                if key.startswith(base_port + "|")
            ]
            if not base_q_suffixes:
                continue

            for port_name in _expected_new_ports(base_port, params["breakout_count"]):
                for suffix in base_q_suffixes:
                    key = "{}|{}".format(port_name, suffix)
                    pytest_assert(
                        key in queue_table,
                        "QUEUE entry {} missing".format(key),
                    )

    def test_port_qos_map_populated(self, breakout_config, original_config, breakout_params):
        """Verify PORT_QOS_MAP entries exist for new breakout ports."""
        qos_map = breakout_config.get("PORT_QOS_MAP")
        if not qos_map:
            pytest.skip("No PORT_QOS_MAP section in config")

        params = breakout_params
        base_ports = _get_base_ports(
            original_config, params["base_speed"],
            params["breakout_total"], params["breakout_count"],
        )
        orig_qos_map = original_config.get("PORT_QOS_MAP", {})

        for base_port in base_ports:
            if base_port not in orig_qos_map:
                continue
            for port_name in _expected_new_ports(base_port, params["breakout_count"]):
                pytest_assert(
                    port_name in qos_map,
                    "PORT_QOS_MAP missing entry for {}".format(port_name),
                )

    def test_acl_table_updated(self, breakout_config, original_config, breakout_params):
        """Verify ACL_TABLE port lists include new breakout ports."""
        acl_table = breakout_config.get("ACL_TABLE")
        if not acl_table:
            pytest.skip("No ACL_TABLE section in config")

        params = breakout_params
        base_ports = _get_base_ports(
            original_config, params["base_speed"],
            params["breakout_total"], params["breakout_count"],
        )
        orig_acl_table = original_config.get("ACL_TABLE", {})

        for acl_name, acl_entry in orig_acl_table.items():
            orig_ports = acl_entry.get("ports", [])
            if not isinstance(orig_ports, list):
                continue

            new_acl_ports = set(acl_table.get(acl_name, {}).get("ports", []))
            for base_port in base_ports:
                if base_port not in orig_ports:
                    continue
                for port_name in _expected_new_ports(base_port, params["breakout_count"]):
                    pytest_assert(
                        port_name in new_acl_ports,
                        "ACL {} missing port {} (base: {})".format(
                            acl_name, port_name, base_port),
                    )

    def test_vlan_member_updated(self, breakout_config, original_config, breakout_params):
        """Verify VLAN_MEMBER entries include new breakout ports."""
        vlan_member = breakout_config.get("VLAN_MEMBER")
        if not vlan_member:
            pytest.skip("No VLAN_MEMBER section in config")

        params = breakout_params
        base_ports = _get_base_ports(
            original_config, params["base_speed"],
            params["breakout_total"], params["breakout_count"],
        )
        orig_vlan_member = original_config.get("VLAN_MEMBER", {})

        for key in orig_vlan_member:
            if "|" not in key:
                continue
            vlan_name, port = key.split("|", 1)
            if port not in base_ports:
                continue
            for port_name in _expected_new_ports(port, params["breakout_count"]):
                new_key = "{}|{}".format(vlan_name, port_name)
                pytest_assert(
                    new_key in vlan_member,
                    "VLAN_MEMBER entry {} missing".format(new_key),
                )

    def test_port_count_increased(self, breakout_config, original_config, breakout_params):
        """Verify the total port count has increased after breakout."""
        params = breakout_params
        orig_count = len(original_config.get("PORT", {}))
        new_count = len(breakout_config.get("PORT", {}))
        base_ports = _get_base_ports(
            original_config, params["base_speed"],
            params["breakout_total"], params["breakout_count"],
        )
        expected_added = len(base_ports) * (params["breakout_count"] - 1)
        pytest_assert(
            new_count == orig_count + expected_added,
            "Port count mismatch: original={}, new={}, expected_added={}".format(
                orig_count, new_count, expected_added),
        )


@pytest.fixture(scope="module")
def applied_breakout_config(duthost, breakout_config, backup_config):
    """Apply the generated breakout config on the DUT and reload.

    This fixture ensures the config is applied exactly once for the module.
    The backup_config fixture handles restore on teardown.
    """
    logger.info("Copying breakout config to %s", CONFIG_DB)
    duthost.shell("cp {} {}".format(BREAKOUT_OUTPUT, CONFIG_DB))
    # Also update golden_config_db.json so config reload does not revert
    duthost.shell("cp {} {}".format(BREAKOUT_OUTPUT, GOLDEN_CONFIG_DB),
                  module_ignore_errors=True)

    logger.info("Performing config reload")
    config_reload(duthost, config_source="config_db", wait=120,
                  safe_reload=True, check_intf_up_ports=False)
    return breakout_config


# ---------------------------------------------------------------------------
# Tests — Apply & Verify on Device
# ---------------------------------------------------------------------------

class TestBreakoutApplyAndVerify:
    """Apply the breakout config on the DUT and verify device health."""

    def test_critical_services_healthy(self, duthost, applied_breakout_config):
        """Verify all critical services come up after breakout config reload."""
        logger.info("Waiting for critical processes (timeout=%ds)", MAX_WAIT_TIME_FOR_CRITICAL_PROCESSES)
        wait_critical_processes(duthost, timeout=MAX_WAIT_TIME_FOR_CRITICAL_PROCESSES)

    def test_all_ports_come_up(self, duthost, applied_breakout_config):
        """Verify all admin-up ports are operationally up."""
        logger.info("Waiting up to %ds for all interfaces to come up",
                    MAX_WAIT_TIME_FOR_INTERFACES)
        pytest_assert(
            wait_until(MAX_WAIT_TIME_FOR_INTERFACES, 20, 0,
                       check_interface_status_of_up_ports, duthost),
            "Not all interfaces came up within {} seconds after breakout config reload".format(
                MAX_WAIT_TIME_FOR_INTERFACES),
        )

    def test_running_config_matches(self, duthost, breakout_params, applied_breakout_config):
        """Verify the running config PORT table reflects the breakout."""
        cfg_facts = duthost.get_running_config_facts()
        running_ports = cfg_facts.get("PORT", {})

        breakout_speed = str(breakout_params["breakout_speed"])
        breakout_ports = [
            name for name, entry in running_ports.items()
            if entry.get("speed") == breakout_speed
        ]
        logger.info("Found %d ports with breakout speed %s in running config",
                    len(breakout_ports), breakout_speed)
        pytest_assert(
            len(breakout_ports) > 0,
            "No ports with speed {} found in running config after breakout".format(
                breakout_speed),
        )
