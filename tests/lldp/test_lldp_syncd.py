# Test plan in docs/testplan/LLDP-syncd-test-plan.md
import pytest
import json
from tests.common.helpers.sonic_db import SonicDbCli
import logging
from tests.common.reboot import reboot, REBOOT_TYPE_COLD
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert


logger = logging.getLogger(__name__)

APPL_DB = "APPL_DB"

pytestmark = [
    pytest.mark.topology("any"),
]


@pytest.fixture(scope="function")
def ignore_expected_loganalyzer_exceptions(duthosts, loganalyzer):
    """Ignore expected failures logs during test execution."""
    if loganalyzer:
        for duthost in duthosts:
            loganalyzer[duthost.hostname].ignore_regex.extend(
                [
                    # Interface flaps in test_lldp_entry_table_after_flap can cause routeCheck to fail momentarily
                    r".*ERR.* 'routeCheck' status failed.*",
                ]
            )


@pytest.fixture(autouse="True")
def db_instance(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    appl_db = []
    for asic in duthost.asics:
        appl_db.append(SonicDbCli(asic, APPL_DB))
    # Cleanup code here
    return appl_db


# Helper function to get the LLDP_ENTRY_TABLE keys
def get_lldp_entry_keys(dbs):
    lldp_entries = []
    for db in dbs:
        items = db.get_keys("LLDP_ENTRY_TABLE*")
        lldp_entries.extend([key.split(":")[1] for key in items])
    logger.debug("lldp entry keys: {}".format(lldp_entries))
    return lldp_entries


# Helper function to get LLDP_ENTRY_TABLE content
def get_lldp_entry_content(dbs, interface):
    lldp_content = {}
    for db in dbs:
        lldp_content.update(db.hget_all("LLDP_ENTRY_TABLE:{}".format(interface)))
    logger.debug("lldp entry content: {}".format(lldp_content))
    return lldp_content


# Helper function to get lldptcl output
def get_lldpctl_facts_output(duthost, enum_frontend_asic_index):
    lldpctl_facts = duthost.lldpctl_facts(
        asic_instance_id=enum_frontend_asic_index,
        skip_interface_pattern_list=["Ethernet-BP", "Ethernet-IB"],
    )["ansible_facts"]
    return lldpctl_facts


def get_lldpctl_output(duthost):
    if duthost.is_multi_asic:
        resultDict = {}
        for asic in duthost.asics:
            result = duthost.shell(
                "docker exec lldp{} /usr/sbin/lldpctl -f json".format(asic.asic_index)
            )["stdout"]
            if not resultDict:
                resultDict = json.loads(result)
            else:
                resultDict["lldp"]["interface"].extend(
                    json.loads(result)["lldp"]["interface"]
                )
    else:
        result = duthost.shell("docker exec lldp /usr/sbin/lldpctl -f json")["stdout"]
        resultDict = json.loads(result)
    return resultDict


# Helper function to get show lldp table output
def get_show_lldp_table_output(duthost):
    lines = duthost.shell("show lldp table")["stdout"].split("\n")[3:-2]
    interface_list = [line.split()[0] for line in lines]
    return interface_list


def check_lldp_table_keys(duthost, db_instance):
    # Check if LLDP_ENTRY_TABLE keys match show lldp table output
    lldp_entry_keys = get_lldp_entry_keys(db_instance)
    show_lldp_table_int_list = get_show_lldp_table_output(duthost)
    return sorted(lldp_entry_keys) == sorted(show_lldp_table_int_list)


def assert_lldp_interfaces(
    lldp_entry_keys, show_lldp_table_int_list, lldpctl_interface
):
    # Verify LLDP_ENTRY_TABLE keys match show lldp table output
    pytest_assert(
        sorted(lldp_entry_keys) == sorted(show_lldp_table_int_list),
        "LLDP_ENTRY_TABLE keys do not match 'show lldp table' output",
    )

    # Verify LLDP_ENTRY_TABLE keys match lldpctl interface indexes
    # Handle cases where lldpctl_output["lldp"]["interface"] might be a list or dict
    if isinstance(lldpctl_interface, dict):
        lldpctl_interfaces = [interface for interface in lldpctl_interface.keys()]
    elif isinstance(lldpctl_interface, list):
        lldpctl_interfaces = [
            list(interface.keys())[0] for interface in lldpctl_interface
        ]
    else:
        raise TypeError(
            "Unexpected type for lldpctl interfaces: {}".format(type(lldpctl_interface))
        )

    pytest_assert(
        sorted(lldp_entry_keys) == sorted(lldpctl_interfaces),
        "LLDP_ENTRY_TABLE keys do not match lldpctl interface indexes",
    )


def assert_lldp_entry_content(interface, entry_content, lldpctl_interface):
    pytest_assert(
        lldpctl_interface,
        "No LLDP data found for {} in lldpctl output".format(interface),
    )

    chassis_info = lldpctl_interface["chassis"][entry_content["lldp_rem_sys_name"]]
    port_info = lldpctl_interface["port"]

    # Compare relevant fields between LLDP_ENTRY_TABLE and lldpctl output
    pytest_assert(
        entry_content["lldp_rem_chassis_id"] == chassis_info["id"]["value"],
        "lldp_rem_chassis_id does not match for {}".format(interface),
    )
    pytest_assert(
        entry_content["lldp_rem_port_id"] == port_info["id"]["value"],
        "lldp_rem_port_id does not match for {}".format(interface),
    )
    pytest_assert(
        entry_content["lldp_rem_sys_name"]
        == list(lldpctl_interface["chassis"].keys())[0],
        "lldp_rem_sys_name does not match for {}".format(interface),
    )
    pytest_assert(
        entry_content["lldp_rem_sys_desc"] == chassis_info.get("descr", ""),
        "lldp_rem_sys_desc does not match for {}".format(interface),
    )
    pytest_assert(
        entry_content["lldp_rem_port_desc"] == port_info.get("descr", ""),
        "lldp_rem_port_desc does not match for {}".format(interface),
    )
    if "," in entry_content["lldp_rem_man_addr"]:
        pytest_assert(
            entry_content["lldp_rem_man_addr"].split(",")
            == chassis_info.get("mgmt-ip", ""),
            "lldp_rem_man_addr does not match for {}, data from DB:{}, data from lldpctl:{}".format(
                interface,
                entry_content["lldp_rem_man_addr"],
                chassis_info.get("mgmt-ip", ""),
            ),
        )
    else:
        pytest_assert(
            entry_content["lldp_rem_man_addr"] == chassis_info.get("mgmt-ip", ""),
            "lldp_rem_man_addr does not match for {}, data from DB:{}, data from lldpctl:{}".format(
                interface,
                entry_content["lldp_rem_man_addr"],
                chassis_info.get("mgmt-ip", ""),
            ),
        )
    pytest_assert(
        entry_content["lldp_rem_sys_cap_supported"] == "28 00",
        "lldp_rem_sys_cap_supported does not match for {}".format(interface),
    )
    if interface == "eth0":
        expected_sys_cap_enable_result = (
            entry_content["lldp_rem_sys_cap_enabled"] == "28 00"
            or entry_content["lldp_rem_sys_cap_enabled"] == "20 00",
        )
    else:
        expected_sys_cap_enable_result = (
            entry_content["lldp_rem_sys_cap_enabled"] == "28 00"
        )
    pytest_assert(
        expected_sys_cap_enable_result,
        "lldp_rem_sys_cap_enabled does not match for {}".format(interface),
    )


def verify_lldp_entry(db_instance, interface):
    entry_content = get_lldp_entry_content(db_instance, interface)
    if entry_content:
        return True
    else:
        return False


def verify_lldp_table(duthost):
    output = duthost.shell("show lldp table")["stdout"]
    if "Total entries displayed" in output:
        return True
    else:
        return False


# Test case 1: Verify LLDP_ENTRY_TABLE keys match show lldp table output and lldpctl output
def test_lldp_entry_table_keys(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, db_instance
):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    lldp_entry_keys = get_lldp_entry_keys(db_instance)
    show_lldp_table_int_list = get_show_lldp_table_output(duthost)
    lldpctl_output = get_lldpctl_output(duthost)
    assert_lldp_interfaces(
        lldp_entry_keys, show_lldp_table_int_list, lldpctl_output["lldp"]["interface"]
    )


# Test case 2: Verify LLDP_ENTRY_TABLE content against lldpctl output
def test_lldp_entry_table_content(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, db_instance
):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    lldpctl_output = get_lldpctl_output(duthost)
    lldpctl_interfaces = lldpctl_output["lldp"]["interface"]

    for interface in get_lldp_entry_keys(db_instance):
        entry_content = get_lldp_entry_content(db_instance, interface)
        if isinstance(lldpctl_interfaces, dict):
            lldpctl_interface = lldpctl_interfaces.get(interface)
        elif isinstance(lldpctl_interfaces, list):
            for iface in lldpctl_interfaces:
                if list(iface.keys())[0].lower() == interface.lower():
                    lldpctl_interface = iface.get(list(iface.keys())[0])
                    logger.info("lldpctl_interface: {}".format(lldpctl_interface))
                    break
        assert_lldp_entry_content(interface, entry_content, lldpctl_interface)

        # Add assertions to compare specific fields between LLDP_ENTRY_TABLE and lldpctl output


# Test case 3: Verify LLDP_ENTRY_TABLE after interface flap
def test_lldp_entry_table_after_flap(
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    db_instance,
    ignore_expected_loganalyzer_exceptions,
):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    # Fetch interfaces from LLDP_ENTRY_TABLE
    lldp_entry_keys = get_lldp_entry_keys(db_instance)
    show_lldp_table_int_list = get_show_lldp_table_output(duthost)
    lldpctl_output = get_lldpctl_output(duthost)

    for interface in lldp_entry_keys:
        if interface == "eth0":
            # Skip test for 'eth0' interface
            continue
        # Shutdown and startup the interface
        asicStr = ""
        if duthost.is_multi_asic:
            asicStr = "-n {}".format(
                duthost.get_port_asic_instance(interface).get_asic_namespace()
            )
        duthost.shell("sudo config interface {} shutdown {}".format(asicStr, interface))
        duthost.shell("sudo config interface {} startup {}".format(asicStr, interface))
        result = wait_until(60, 2, 10, verify_lldp_entry, db_instance, interface)
        pytest_assert(
            result,
            "After interface {} flap, no LLDP_ENTRY_TABLE entry for it.".format(
                interface
            ),
        )
        lldpctl_interfaces = lldpctl_output["lldp"]["interface"]
        assert_lldp_interfaces(
            lldp_entry_keys, show_lldp_table_int_list, lldpctl_interfaces
        )
        entry_content = get_lldp_entry_content(db_instance, interface)
        logger.info("entry_content={}".format(entry_content))
        if isinstance(lldpctl_interfaces, dict):
            lldpctl_interface = lldpctl_interfaces.get(interface)
            logger.info(
                "lldpctl_interfaces type dict, lldpctl_interface: {}".format(
                    lldpctl_interface
                )
            )
        elif isinstance(lldpctl_interfaces, list):
            for iface in lldpctl_interfaces:
                if list(iface.keys())[0].lower() == interface.lower():
                    lldpctl_interface = iface.get(list(iface.keys())[0])
                    logger.info(
                        "lldpctl_interfaces type list, lldpctl_interface: {}".format(
                            lldpctl_interface
                        )
                    )
                    break
        assert_lldp_entry_content(interface, entry_content, lldpctl_interface)


# Test case 4: Verify LLDP_ENTRY_TABLE after system reboot
def test_lldp_entry_table_after_lldp_restart(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, db_instance
):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    lldp_entry_keys = get_lldp_entry_keys(db_instance)
    show_lldp_table_int_list = get_show_lldp_table_output(duthost)
    lldpctl_output = get_lldpctl_output(duthost)

    # Restart the LLDP service
    for asic in duthost.asics:
        duthost.shell("sudo systemctl restart {}".format(asic.get_service_name("lldp")))
    result = wait_until(
        60, 2, 20, verify_lldp_table, duthost
    )  # Adjust based on LLDP service restart time
    pytest_assert(result, "no output for show lldp table after restarting lldp")
    for asic in duthost.asics:
        result = duthost.shell(
            "sudo systemctl status {}".format(asic.get_service_name("lldp"))
        )["stdout"]
        pytest_assert(
            "active (running)" in result,
            "LLDP service is not running",
        )
    lldpctl_interfaces = lldpctl_output["lldp"]["interface"]
    assert_lldp_interfaces(
        lldp_entry_keys, show_lldp_table_int_list, lldpctl_interfaces
    )
    for interface in lldp_entry_keys:
        entry_content = get_lldp_entry_content(db_instance, interface)
        logger.debug("entry_content:{}".format(entry_content))
        if isinstance(lldpctl_interfaces, dict):
            lldpctl_interface = lldpctl_interfaces.get(interface)
        elif isinstance(lldpctl_interfaces, list):
            for iface in lldpctl_interfaces:
                if list(iface.keys())[0].lower() == interface.lower():
                    lldpctl_interface = iface.get(list(iface.keys())[0])
                    break
        assert_lldp_entry_content(interface, entry_content, lldpctl_interface)


# Test case 5: Verify LLDP_ENTRY_TABLE after reboot
@pytest.mark.disable_loganalyzer
def test_lldp_entry_table_after_reboot(
    localhost, duthosts, enum_rand_one_per_hwsku_frontend_hostname, db_instance
):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # Verify LLDP_ENTRY_TABLE keys match show lldp table output at the start of test
    keys_match = wait_until(30, 5, 0, check_lldp_table_keys, duthost, db_instance)
    if not keys_match:
        assert keys_match, "LLDP_ENTRY_TABLE keys do not match 'show lldp table' output"

    # reboot
    logging.info("Run cold reboot on DUT")
    reboot(
        duthost,
        localhost,
        reboot_type=REBOOT_TYPE_COLD,
        reboot_helper=None,
        reboot_kwargs=None,
        safe_reboot=True,
        check_intf_up_ports=True
    )
    lldp_entry_keys = get_lldp_entry_keys(db_instance)
    lldpctl_output = get_lldpctl_output(duthost)
    show_lldp_table_int_list = get_show_lldp_table_output(duthost)
    lldpctl_interfaces = lldpctl_output["lldp"]["interface"]
    assert_lldp_interfaces(
        lldp_entry_keys, show_lldp_table_int_list, lldpctl_interfaces
    )
    for interface in get_lldp_entry_keys(db_instance):
        entry_content = get_lldp_entry_content(db_instance, interface)

        if isinstance(lldpctl_interfaces, dict):
            lldpctl_interface = lldpctl_interfaces.get(interface)
        elif isinstance(lldpctl_interfaces, list):
            for iface in lldpctl_interfaces:
                if list(iface.keys())[0].lower() == interface.lower():
                    lldpctl_interface = iface.get(list(iface.keys())[0])
                    break
        assert_lldp_entry_content(interface, entry_content, lldpctl_interface)
