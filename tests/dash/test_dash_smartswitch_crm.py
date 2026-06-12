import pytest
import time
import logging
import re

from copy import deepcopy
from collections import defaultdict
from jinja2 import Template
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.errors import RunAnsibleModuleFail
from gnmi_utils import apply_messages
from tests.common.helpers.crm import get_used_percent, CRM_UPDATE_TIME, CRM_POLLING_INTERVAL, \
    EXPECT_EXCEEDED, EXPECT_CLEAR, THR_VERIFY_CMDS
import configs.privatelink_config as pl
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("smartswitch"),
    pytest.mark.skip_check_dut_health
]


DASH_CRM_RES_LIST = ["dash_vnet", "dash_eni", "dash_eni_ether_address_map", "dash_ipv4_inbound_routing",
                     "dash_ipv6_inbound_routing", "dash_ipv4_outbound_routing", "dash_ipv6_outbound_routing",
                     "dash_ipv4_pa_validation", "dash_ipv6_pa_validation", "dash_ipv4_outbound_ca_to_pa",
                     "dash_ipv6_outbound_ca_to_pa", "dash_ipv4_acl_group", "dash_ipv6_acl_group"]
DASH_CRM_ACL_RULES_LIST = ["dash_ipv4_acl_rule", "dash_ipv6_acl_rule"]
DEFAULT_LOW_THR = defaultdict(lambda: 70)
DEFAULT_HIGH_THR = defaultdict(lambda: 85)
DEFAULT_THR_TYPE = "percentage"
DEFAULT_CRM_POLLING_INTERVAL = 300

DASH_THR_VERIFY_CMDS = deepcopy(THR_VERIFY_CMDS)
DASH_THR_VERIFY_CMDS.pop("exceeded_percentage")
DASH_THR_VERIFY_CMDS.pop("clear_percentage")


def build_privatelink_config_messages(dpuhost):
    """
    Same messages and order as tests/dash/test_dash_privatelink.py common_setup_teardown:
    base (appliance, routing type PL, vnet, route group, meter policy) ->
    routes + PE VNET mapping (optional bluefield inbound route rule) ->
    meter rules -> ENI -> ENI route group.
    """
    route_and_mapping = {
        **pl.PE_VNET_MAPPING_CONFIG,
        **pl.PE_SUBNET_ROUTE_CONFIG,
        **pl.VM_SUBNET_ROUTE_CONFIG,
    }
    if "bluefield" in dpuhost.facts.get("asic_type", ""):
        route_and_mapping = {**route_and_mapping, **pl.INBOUND_VNI_ROUTE_RULE_CONFIG}
    return {
        **pl.APPLIANCE_CONFIG,
        **pl.ROUTING_TYPE_PL_CONFIG,
        **pl.VNET_CONFIG,
        **pl.ROUTE_GROUP1_CONFIG,
        **pl.METER_POLICY_V4_CONFIG,
        **route_and_mapping,
        **pl.METER_RULE1_V4_CONFIG,
        **pl.METER_RULE2_V4_CONFIG,
        **pl.ENI_CONFIG,
        **pl.ENI_ROUTE_GROUP1_CONFIG,
    }


def wait_until_crm_dash_eni_applied(dpuhost, default_crm_facts, timeout=90, interval=1):
    """
    Privatelink config adds exactly one ENI. Poll CRM until dash_eni used increases by 1 vs
    baseline; that indicates the apply has been reflected (no fixed post-apply sleep).
    """
    base = default_crm_facts["resources"]["dash_eni"]["used"]
    expected = base + 1

    def _eni_visible():
        facts = get_crm_facts(dpuhost)
        row = facts.get("resources", {}).get("dash_eni")
        if not row:
            return False
        return row["used"] >= expected

    if not wait_until(timeout, interval, 0, _eni_visible):
        facts = get_crm_facts(dpuhost)
        used = facts.get("resources", {}).get("dash_eni", {}).get("used")
        raise AssertionError(
            "dash_eni CRM used did not reach baseline+1 (expected used>={}, baseline was {}); "
            "last used={} after {}s".format(expected, base, used, timeout))


@pytest.fixture(scope="class")
def set_polling_interval(dpuhost):
    """
    Set CRM polling interval
    """
    wait_time = 2
    dpuhost.shell(f"crm config polling interval {CRM_POLLING_INTERVAL}")

    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)

    yield

    dpuhost.shell(f"crm config polling interval {DEFAULT_CRM_POLLING_INTERVAL}")


@pytest.fixture(scope="class", autouse=True)
def disable_logrotate_cron(dpuhost):
    logging.info("Disable DPU logrotate cron task / systemd timer "
                 "and make sure the running logrotate is stopped.")
    dpuhost.shell("sudo systemctl stop logrotate.timer", module_ignore_errors=True)
    dpuhost.shell("sudo sed -i \'s/^/#/g\' /etc/cron.d/logrotate", module_ignore_errors=True)
    logging.info("Waiting for logrotate from previous cron task or systemd timer run to finish")
    end = time.time() + 60
    while time.time() < end:
        # Verify for exception because self.ansible_host automatically handle command return codes
        # and raise exception for none zero code
        try:
            dpuhost.shell("pgrep -f logrotate")
        except Exception:
            break
        else:
            time.sleep(5)
            continue
    else:
        logging.error("Logrotate from previous task was not finished during 60 seconds. The threshold tests may fail.")

    yield

    logging.info("Restore logrotate cron task and systemd timer.")
    dpuhost.shell("sudo sed -i \'s/^#//g\' /etc/cron.d/logrotate", module_ignore_errors=True)
    dpuhost.shell("sudo systemctl start logrotate.timer", module_ignore_errors=True)


def get_crm_facts(dpuhost):
    """Run various 'crm show' commands in the dpu and parse their output to gather CRM facts

    Executed commands:
        crm show summary
        crm show thresholds
        crm show resources all

    Example output:
        {
            "acl_group": [
                {
                    "resource name": "acl_group",
                    "bind point": "PORT",
                    "available count": "200",
                    "used count": "24",
                    "stage": "INGRESS"
                },
               ...
            ],
            "acl_table": [
                {
                    "table id": "",
                    "resource name": "",
                    "used count": "",
                    "available count": ""
                },
                ...
            ],
            "thresholds": {
                    "ipv4_route": {
                        "high": 85,
                        "type": "percentage",
                        "low": 70
                    },
                ...
            },
            "resources": {
                "ipv4_route": {
                    "available": 100000,
                    "used": 16
                },
                ...
            },
            "polling_interval": 300
        }

    Returns:
        dict: Gathered CRM facts.
    """
    crm_facts = {}

    # Get polling interval
    output = dpuhost.shell("crm show summary")['stdout']
    parsed = re.findall(r'Polling Interval: +(\d+) +second', output)
    if parsed:
        crm_facts['polling_interval'] = int(parsed[0])

    # Get thresholds
    crm_facts['thresholds'] = {}
    output = dpuhost.shell("crm show thresholds all")['stdout_lines']
    for line in output:
        match = re.search(r".*\s+.*\s+\d+\s+\d+", line)
        if match:
            threshold = re.split(r'\s+', match.group(0))
            crm_facts['thresholds'][threshold[0]] = {
                'type': threshold[1],
                'low': int(threshold[2]),
                'high': int(threshold[3])
            }

    def _show_and_parse_crm_resources():
        # Get output of all resources
        not_ready_prompt = "CRM counters are not ready"
        output = dpuhost.shell("crm show resources all")['stdout_lines']
        in_section = False
        sections = defaultdict(list)
        section_id = 0
        for line in output:
            if not_ready_prompt in line:
                return False
            if len(line.strip()) != 0:
                if not in_section:
                    in_section = True
                    section_id += 1
                sections[section_id].append(line)
            else:
                in_section = False
                continue
        # Output of 'crm show resources all' has 3 sections(4 on DPU platform).
        #   section 1: resources usage
        #   section 2: ACL group
        #   section 3: ACL table
        #   section 4: DASH(DPU) ACL rules
        if 1 in list(sections.keys()):
            crm_facts['resources'] = {}
            for line in sections[1]:
                match = re.search(r".*\s+\d+\s+\d+", line)
                if match:
                    resource = re.split(r'\s+', match.group(0))
                    crm_facts['resources'][resource[0]] = {
                        'used': int(resource[1]),
                        'available': int(resource[2])
                    }

        if 2 in list(sections.keys()):
            crm_facts['acl_group'] = []
            for line in sections[2]:
                match = re.search(r".*\s+.*\s+.*\s+\d+\s+\d+", line)
                if match:
                    acl_group = re.split(r'\s+', match.group(0))
                    crm_facts['acl_group'].append(
                        {
                            'stage': acl_group[0],
                            'bind_point': acl_group[1],
                            'resource_name': acl_group[2],
                            'used': int(acl_group[3]),
                            'available': int(acl_group[4])
                        })

        if 3 in list(sections.keys()):
            crm_facts['acl_table'] = []
            for line in sections[3]:
                match = re.search(r".*\s+.*\s+\d+\s+\d+", line)
                if match:
                    acl_table = re.split(r'\s+', match.group(0))
                    crm_facts['acl_table'].append(
                        {
                            'table_id': acl_table[0],
                            'resource_name': acl_table[1],
                            'used': int(acl_table[2]),
                            'available': int(acl_table[3])
                        })
        return True
    # Retry until crm resources are ready
    timeout = crm_facts['polling_interval'] + 10
    while timeout >= 0:
        ret = _show_and_parse_crm_resources()
        if ret:
            break
        logging.warning("CRM counters are not ready yet, will retry after 10 seconds")
        time.sleep(10)
        timeout -= 10
    assert timeout >= 0

    return crm_facts


@pytest.fixture(scope="class")
def default_crm_facts(dpuhost, set_polling_interval):
    """
    Get CRM configuration before test
    """
    crm_facts = get_crm_facts(dpuhost)
    yield crm_facts


@pytest.fixture(scope="class")
def apply_resources_configs(default_crm_facts, localhost, duthost, ptfhost, dpuhost):
    """
    Apply CRM configuration before run test
    """
    logger.info("Apply the Privatelink DASH configurations (aligned with test_dash_privatelink).")
    config_messages = build_privatelink_config_messages(dpuhost)
    apply_messages(localhost, duthost, ptfhost, config_messages, dpuhost.dpu_index, wait_after_apply=0)
    wait_until_crm_dash_eni_applied(dpuhost, default_crm_facts)
    pytest.crm_res_cleanup_required = True

    yield

    if pytest.crm_res_cleanup_required:
        config_reload(dpuhost, safe_reload=True, yang_validate=False)
    del pytest.crm_res_cleanup_required


@pytest.fixture(scope="class", autouse=True)
def cleanup(dpuhost):
    """
    Restore original CLI CRM thresholds
    """
    yield

    for resource in DASH_CRM_RES_LIST:
        with allure.step("Restoring original CRM thresholds for resource: {}".format(resource)):
            res_cli = get_dash_cli_crm_res_path(resource)
            cmd = f"crm config thresholds {res_cli} type {DEFAULT_THR_TYPE} && " \
                  f"crm config thresholds {res_cli} low {DEFAULT_LOW_THR[resource]} && " \
                  f"crm config thresholds {res_cli} high {DEFAULT_HIGH_THR[resource]}"
            dpuhost.shell(cmd)


class TestDashCRM:

    @pytest.fixture(autouse=True)
    def setup(self, localhost, duthost, ptfhost, default_crm_facts, apply_resources_configs, dpuhost):
        self.duthost = duthost
        self.dpuhost = dpuhost
        self.ptfhost = ptfhost
        self.localhost = localhost
        self.default_crm_facts = default_crm_facts
        self.crm_facts = get_crm_facts(dpuhost)
        self.dpu_index = dpuhost.dpu_index
        # Counts for CRM deltas vs privatelink_config (RouteGroup1: PE_CA_SUBNET + VM_CA_SUBNET routes)
        self.vnets_num = 1
        self.eni_num = 1
        self.eni_eth_addr_num = 1
        self.inbound_routes_num = 1
        self.outbound_routes_num = 2
        self.outbound_ca_to_pa_num = 1
        # INBOUND_VNI route rule only on bluefield (see test_dash_privatelink)
        self.pa_num = 1 if "bluefield" in dpuhost.facts.get("asic_type", "") else 0
        self.acl_groups_num = 2

    def do_crm_validation(self, crm_table_res_name, crm_res_test_count, **kwargs):
        """
        Do validation for CRM resources in CLI output and CRM thresholds via syslog message
        :param crm_table_res_name: CRM resource name
        :param crm_res_test_count: number of added CRM resources during test config
        :param kwargs: **kwargs
        """
        default_used_res = self.default_crm_facts["resources"][crm_table_res_name]["used"]
        default_available_res = self.default_crm_facts["resources"][crm_table_res_name]["available"]

        used_res = self.crm_facts["resources"][crm_table_res_name]["used"]
        available_res = self.crm_facts["resources"][crm_table_res_name]["available"]

        with allure.step("Check that after add {} resource it displayed correctly in CRM output".format(
                crm_table_res_name)):
            self.verify_cli_output(default_used_res, default_available_res, used_res, available_res, crm_res_test_count)

        with allure.step("Validate CRM thresholds"):
            verify_thresholds(self.dpuhost, res_name=crm_table_res_name,
                              crm_used=used_res, crm_avail=available_res, **kwargs)

    def verify_cli_output(self, default_used_res, default_available_res, used_res, available_res, crm_res_test_count):
        """
        Verify CRM resources
        :param default_used_res: value of used resources before apply test config
        :param default_available_res: value of available resources before apply test config
        :param used_res: value of used resources after apply test config
        :param available_res: value of used resources after apply test config
        :param crm_res_test_count: number of added CRM resources during test config
        """
        expected_used_res = default_used_res + crm_res_test_count
        assert used_res == expected_used_res, f"CRM used resources counter: {used_res} " \
                                              f"not equal to expected used resources counter: {expected_used_res}"
        expected_avail_res = default_available_res - crm_res_test_count
        assert available_res == expected_avail_res, f"CRM available resources counter: {available_res} not equal to " \
                                                    f"expected available resources counter: {expected_avail_res}"

    def test_dash_crm_default_config(self):
        """
        Validate default CRM configuration
        Note: validation for default polling interval skipped
        :return:
        """
        available_crm_res = self.crm_facts["resources"].keys()
        assert len(available_crm_res) == len(DASH_CRM_RES_LIST), \
            f"Available CRM resources: '{available_crm_res}' does not " \
            f"match expected CRM resources: '{DASH_CRM_RES_LIST}'"
        for res in DASH_CRM_RES_LIST:
            assert res in available_crm_res, f"CRM resource: '{res}' not found in CRM resources list."

        for res_name, res_data in self.crm_facts["thresholds"].items():
            th_type = res_data["type"]
            low_th = res_data["low"]
            high_th = res_data["high"]
            assert th_type == DEFAULT_THR_TYPE, f"Failed default CRM config validation for resource: '{res_name}', " \
                                                f"expected: '{DEFAULT_THR_TYPE}' found: '{th_type}'"
            assert low_th == DEFAULT_LOW_THR[res_name], \
                f"Failed default CRM config validation for resource: '{res_name}', expected: " \
                f"'{DEFAULT_LOW_THR[res_name]}' found: '{low_th}'"
            assert high_th == DEFAULT_HIGH_THR[res_name], \
                f"Failed default CRM config validation for resource: '{res_name}', expected: " \
                f"'{DEFAULT_HIGH_THR[res_name]}' found: '{high_th}'"

    def test_dash_crm_vnet(self):
        """
        Validate CRM thresholds for VNET
        :return:
        """
        self.do_crm_validation("dash_vnet", self.vnets_num)

    @pytest.mark.parametrize("resource_name", ["eni", "eni-ether-address"])
    def test_dash_crm_eni(self, resource_name):
        """
        Validate CRM thresholds for ENI/ENI Ether Address
        :param resource_name: string, CRM resource name
        """
        crm_table_res_name = "dash_eni" if resource_name == "eni-ether-address" else "dash_eni_ether_address_map"
        # Do percentage validation only for ENI CRM resource type(all resources uses the same logic under the hood)
        if resource_name == "eni":
            self.do_crm_validation(crm_table_res_name, self.eni_num, thr_verify_cmds=THR_VERIFY_CMDS)
        else:
            self.do_crm_validation(crm_table_res_name, self.eni_num)

    @pytest.mark.parametrize("ip_ver", ["ipv4", "ipv6"])
    @pytest.mark.parametrize("route_type", ["inbound", "outbound"])
    def test_dash_routing(self, ip_ver, route_type):
        """
        Validate CRM thresholds for routing
        :param ip_ver: string, ipv4 or ipv6
        """
        if ip_ver == "ipv6":
            pytest.skip("IPv6 not supported yet")

        crm_table_res_name = "dash_{}_{}_routing".format(ip_ver, route_type)
        routes_num_dict = {
            "ipv4": {
                "inbound": self.inbound_routes_num,
                "outbound": self.outbound_routes_num
            },
            "ipv6": {
                "inbound": self.inbound_routes_num,
                "outbound": self.outbound_routes_num
            }
        }
        self.do_crm_validation(crm_table_res_name, routes_num_dict[ip_ver][route_type])

    @pytest.mark.parametrize("ip_ver", ["ipv4", "ipv6"])
    def test_dash_pa_validation(self, ip_ver):
        """
        Validate CRM thresholds for PA
        :param ip_ver: string, ipv4 or ipv6
        """
        if ip_ver == "ipv6":
            pytest.skip("IPv6 not supported yet")

        crm_table_res_name = "dash_{}_pa_validation".format(ip_ver)
        self.do_crm_validation(crm_table_res_name, self.pa_num)

    @pytest.mark.parametrize("ip_ver", ["ipv4", "ipv6"])
    def test_dash_outbound_ca_to_pa(self, ip_ver):
        """
        Validate CRM thresholds for Outbound CA-to-PA
        :param ip_ver: string, ipv4 or ipv6
        """
        if ip_ver == "ipv6":
            pytest.skip("IPv6 not supported yet")

        crm_table_res_name = "dash_{}_outbound_ca_to_pa".format(ip_ver)
        self.do_crm_validation(crm_table_res_name, self.outbound_ca_to_pa_num)

    def test_dash_crm_cleanup(self):
        """
        Validate that after cleanup CRM resources - CRM output the same as it was before test case(without config)
        """
        apply_messages(self.localhost, self.duthost, self.ptfhost,
                       build_privatelink_config_messages(self.dpuhost), self.dpu_index, set_db=False)

        pytest.crm_res_cleanup_required = False

        time.sleep(CRM_UPDATE_TIME)
        crm_facts = get_crm_facts(self.dpuhost)
        assert crm_facts["resources"] == self.default_crm_facts["resources"], \
            "CRM resources after cleanup not equal to CRM resources before apply configuration.\nCRM resources " \
            "before apply config: {}\nCRM resources after cleanup: {}\n".format(self.default_crm_facts["resources"],
                                                                                crm_facts["resources"])


def rotate_dpu_syslog(dpuhost):
    logger.info("Rotate the DPU syslog")
    try:
        dpuhost.shell("sudo /usr/sbin/logrotate -f /etc/logrotate.conf > /dev/null 2>&1")
    except RunAnsibleModuleFail as e:
        logging.warning("logrotate is failed. Command returned:\n"
                        "Stdout: {}\n"
                        "Stderr: {}\n"
                        "Return code: {}".format(e.results["stdout"], e.results["stderr"], e.results["rc"]))


def validate_syslog(dpuhost, expect_regex):
    syslog = dpuhost.shell("sudo cat /var/log/syslog")['stdout']
    for pattern in expect_regex:
        assert re.search(pattern, syslog), f"The expected syslog item {pattern} is not found in the DPU syslog"


def verify_thresholds(dpuhost, **kwargs):
    """
    Verifies that WARNING message logged if there are any resources that exceeds a pre-defined threshold value.
    Verifies the following threshold parameters: actual used, actual free
    """

    loganalyzer = LogAnalyzer(ansible_host=dpuhost, marker_prefix='dash_crm_test')
    thr_verify_cmds = kwargs.get("thr_verify_cmds", DASH_THR_VERIFY_CMDS)

    for key, value in list(thr_verify_cmds.items()):
        with allure.step("Verifying CRM threshold '{}'".format(key)):
            template = Template(value, autoescape=True)
            if "exceeded" in key:
                if "exceeded_used" in key and kwargs.get("ex_us_exp_regexp_list"):
                    loganalyzer.expect_regex = kwargs.get("ex_us_exp_regexp_list")
                elif "exceeded_free" in key and kwargs.get("ex_free_exp_regexp_list"):
                    loganalyzer.expect_regex = kwargs.get("ex_free_exp_regexp_list")
                else:
                    loganalyzer.expect_regex = [EXPECT_EXCEEDED]
            elif "clear" in key:
                if "clear_used" in key and kwargs.get("cl_us_exp_regexp_list"):
                    loganalyzer.expect_regex = kwargs.get("cl_us_exp_regexp_list")
                elif "clear_free" in key and kwargs.get("cl_free_exp_regexp_list"):
                    loganalyzer.expect_regex = kwargs.get("cl_free_exp_regexp_list")
                else:
                    loganalyzer.expect_regex = [EXPECT_CLEAR]

            if "percentage" in key:
                used_percent = get_used_percent(kwargs["crm_used"], kwargs["crm_avail"])
                if key == "exceeded_percentage":
                    kwargs["th_lo"] = max(used_percent - 1, 0)
                    kwargs["th_hi"] = max(used_percent, 0)
                    loganalyzer.expect_regex = [EXPECT_EXCEEDED]
                elif key == "clear_percentage":
                    kwargs["th_lo"] = min(used_percent, 100)
                    kwargs["th_hi"] = min(used_percent + 1, 100)
                    loganalyzer.expect_regex = [EXPECT_CLEAR]

            kwargs["crm_cli_res"] = get_dash_cli_crm_res_path(kwargs["res_name"])
            cmd = template.render(**kwargs)

            with loganalyzer:
                logger.info("Change the threshold and validate the expected syslog info")
                dpuhost.shell(cmd)
                # Make sure CRM counters updated
                time.sleep(CRM_UPDATE_TIME)


def get_dash_cli_crm_res_path(res_name):
    """
    Get part of CLI command based on CRM resource name
    :param res_name: CRM resource name
    :return: string, CLI path to CRM resource config
    """
    cli_res_path = "dash "
    if res_name == "dash_eni_ether_address_map":
        cli_res_path += "eni-ether-address"
    elif res_name == "dash_ipv4_pa_validation":
        cli_res_path += "ipv4 pa-validation"
    elif res_name == "dash_ipv6_pa_validation":
        cli_res_path += "ipv6 pa-validation"
    elif res_name == "dash_ipv4_outbound_ca_to_pa":
        cli_res_path += "ipv4 outbound ca-to-pa"
    elif res_name == "dash_ipv6_outbound_ca_to_pa":
        cli_res_path += "ipv6 outbound ca-to-pa"
    else:
        cli_res_path = res_name.replace("_", " ")

    return cli_res_path
