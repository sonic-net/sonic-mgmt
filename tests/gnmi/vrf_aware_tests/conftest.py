import pytest

from tests.common.utilities import DEFAULT_VRF_NAME, MGMT_VRF_NAME
from tests.gnmi.helper import is_mgmt_vrf_enabled


VRF_SCENARIOS = [
    {"name": "default_1", "vrf": None, "description": "Default (no VRF)"},
    {"name": "default_2", "vrf": DEFAULT_VRF_NAME, "description": f"Default (explicit '{DEFAULT_VRF_NAME}')"},
    {"name": "mgmt", "vrf": MGMT_VRF_NAME, "description": "Management VRF"},
]


@pytest.fixture(scope="module", params=VRF_SCENARIOS, ids=lambda scenario: f"vrf_{scenario['name']}")
def vrf_config(request, duthost, ptfhost):
    vrf_cfg = request.param.copy()
    vrf_cfg.update({
        "dut_ip": duthost.mgmt_ip,
        "ptf_ip": ptfhost.mgmt_ip,
        "dut_intf": "eth0",
        "ptf_intf": "mgmt",
    })
    return vrf_cfg


@pytest.fixture(scope="module", autouse=True)
def setup_vrf_configuration(duthosts, rand_one_dut_hostname, vrf_config):
    """
    This fixture runs before setup_gnmi_server to ensure VRF config is in place.
    Only default and mgmt VRFs are supported.

    While these GNMI tests do not depend on SNMP, some tests fail while waiting
    for all critical processes to be up and running. These are caused by SNMP
    agent address misconfiguration during VRF transition. Hence SNMP services
    are stopped before toggling mgmt VRF and restarted after.
    """
    duthost = duthosts[rand_one_dut_hostname]
    vrf_name = vrf_config["vrf"]
    mgmt_vrf_enabled = is_mgmt_vrf_enabled(duthost)

    try:
        if vrf_name == MGMT_VRF_NAME and not mgmt_vrf_enabled:
            duthost.shell('sudo systemctl stop snmpd snmp-subagent', module_ignore_errors=True)
            duthost.shell('sonic-db-cli CONFIG_DB hset "MGMT_VRF_CONFIG|vrf_global" "mgmtVrfEnabled" "true"')
            duthost.shell('sudo systemctl start snmpd snmp-subagent', module_ignore_errors=True)
        yield vrf_config

    finally:
        if vrf_name == MGMT_VRF_NAME and not mgmt_vrf_enabled:
            duthost.shell('sudo systemctl stop snmpd snmp-subagent', module_ignore_errors=True)
            duthost.shell('sonic-db-cli CONFIG_DB hset "MGMT_VRF_CONFIG|vrf_global" "mgmtVrfEnabled" "false"')
            duthost.shell('sonic-db-cli CONFIG_DB hdel "MGMT_VRF_CONFIG|vrf_global" "mgmtVrfEnabled"')
            duthost.shell('sudo systemctl start snmpd snmp-subagent', module_ignore_errors=True)
