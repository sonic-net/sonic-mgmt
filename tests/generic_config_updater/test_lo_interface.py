import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

@pytest.fixture(scope="module", autouse=True)
def setup_env(duthosts, rand_one_dut_hostname, cfg_facts):
    """
    Setup/teardown fixture for loopback interface config
    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
        cfg_facts: config facts for selected DUT
    """
    duthost = duthosts[rand_one_dut_hostname]

    config_tmpfile = generate_tmpfile(duthost)
    logger.info("config_tmpfile {} Backing up config_db.json".format(config_tmpfile))
    duthost.shell("sudo cp /etc/sonic/config_db.json {}".format(config_tmpfile))

    # Cleanup LOOPBACK_INTERFACE config
    lo_interfaces = cfg_facts.get('LOOPBACK_INTERFACE', {})
    for lo_interface in lo_interfaces:
        del_loopback_interface = duthost.shell("sudo config loopback del {}".format(lo_interface),
            module_ignore_errors=True)
        pytest_assert(not del_loopback_interface['rc'],
            "Loopback interface '{}' is not deleted successfully".format(lo_interface))

    yield

    logger.info("Restoring config_db.json")
    duthost.shell("sudo cp {} /etc/sonic/config_db.json".format(config_tmpfile))
    delete_tmpfile(duthost, config_tmpfile)
    config_reload(duthost)

@pytest.mark.parametrize("op, name, dummy_lo_interface_v4, dummy_lo_interface_v6", [
    ("add", "Loopback0", "10.1.0.32/32", "FC00:1::32/128")
])
def test_syslog_server_tc1_add_init(duthost, op, name,
        dummy_lo_interface_v4, dummy_lo_interface_v6):
    """ Add v4 and v6 lo intf to config

    Sample output
    "LOOPBACK_INTERFACE": {
        "Loopback0": {},
        "Loopback0|10.1.0.32/32": {},
        "Loopback0|FC00:1::32/128": {}
    }
    """
    dummy_lo_interface_v4 = name + "|" + dummy_lo_interface_v4
    dummy_lo_interface_v6 = name + "|" + dummy_lo_interface_v6

    json_patch = [
        {
            "op": "{}".format(op),
            "path": "/LOOPBACK_INTERFACE",
            "value": {
                "{}".format(name): {},
                "{}".format(dummy_lo_interface_v4): {},
                "{}".format(dummy_lo_interface_v6): {}
            }
        }
    ]

    logger.info("json patch {}".format(json_patch))

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success(duthost, output)

    delete_tmpfile(duthost, tmpfile)

@pytest.mark.parametrize("op, name, dummy_lo_interface_v4, dummy_lo_interface_v6", [
    ("add", "Loopback0", "10.1.0.32~132", "FC00:1::32~1128")
])
def test_syslog_server_tc2_add_duplicate(duthost, op, name,
        dummy_lo_interface_v4, dummy_lo_interface_v6):
    """ Add v4 and v6 duplicate lo intf to config
    """
    dummy_lo_interface_v4 = name + "|" + dummy_lo_interface_v4
    dummy_lo_interface_v6 = name + "|" + dummy_lo_interface_v6

    json_patch = [
        {
            "op": "{}".format(op),
            "path": "/LOOPBACK_INTERFACE/{}".format(dummy_lo_interface_v4),
            "value": {}
        },
        {
            "op": "{}".format(op),
            "path": "/LOOPBACK_INTERFACE/{}".format(dummy_lo_interface_v6),
            "value": {}
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success(duthost, output)

    delete_tmpfile(duthost, tmpfile)

@pytest.mark.parametrize("op, name, dummy_lo_interface_v4, dummy_lo_interface_v6", [
    ("add", "Loopback0", "587.1.0.32~132", "FC00:1::32~1128"),
    ("add", "Loopback0", "10.1.0.32~132", "FC00:1::xyz~1128"),
    ("remove", "Loopback0", "10.1.0.33~132", "FC00:1::32~1128"),
    ("remove", "Loopback0", "10.1.0.32~132", "FC00:1::33~1128")
])
def test_syslog_server_tc3_xfail(duthost, op, name,
        dummy_lo_interface_v4, dummy_lo_interface_v6):
    """ Test expect fail testcase

    ("add", "Loopback0", "587.1.0.32~132", "FC00:1::32~1128"), ADD Invalid IPv4 address
    ("add", "Loopback0", "10.1.0.32~132", "FC00:1::xyz~1128"), ADD Invalid IPv6 address
    ("remove", "Loopback0", "10.1.0.33~132", "FC00:1::32~1128"), REMOVE Unexist IPv4 address
    ("remove", "Loopback0", "10.1.0.32~132", "FC00:1::33~1128") REMOVE Unexist IPv6 address
    """
    dummy_lo_interface_v4 = name + "|" + dummy_lo_interface_v4
    dummy_lo_interface_v6 = name + "|" + dummy_lo_interface_v6

    json_patch = [
        {
            "op": "{}".format(op),
            "path": "/LOOPBACK_INTERFACE/{}".format(dummy_lo_interface_v4),
            "value": {}
        },
        {
            "op": "{}".format(op),
            "path": "/LOOPBACK_INTERFACE/{}".format(dummy_lo_interface_v6),
            "value": {}
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_failure(output)

    delete_tmpfile(duthost, tmpfile)

@pytest.mark.parametrize("op, name, dummy_lo_interface_v4, dummy_lo_interface_v6", [
    ("remove", "Loopback0", "10.1.0.32~132", "FC00:1::32~1128")
])
def test_syslog_server_tc4_remove(duthost, op, name,
        dummy_lo_interface_v4, dummy_lo_interface_v6):
    """ Remove v4 and v6 loopback intf
    """
    json_patch = [
        {
            "op": "{}".format(op),
            "path": "/LOOPBACK_INTERFACE"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
    expect_op_success(duthost, output)

    delete_tmpfile(duthost, tmpfile)
