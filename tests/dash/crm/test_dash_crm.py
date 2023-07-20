import pytest
import time
import logging

import os
from copy import deepcopy
from jinja2 import Template
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from dash_utils import apply_swssconfig_file
from tests.common.helpers.crm import get_used_percent, CRM_UPDATE_TIME, CRM_POLLING_INTERVAL, \
    EXPECT_EXCEEDED, EXPECT_CLEAR, THR_VERIFY_CMDS

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("appliance")
]


DASH_CRM_RES_LIST = ["dash_vnet", "dash_eni", "dash_eni_ether_address_map", "dash_ipv4_inbound_routing",
                     "dash_ipv6_inbound_routing", "dash_ipv4_outbound_routing", "dash_ipv6_outbound_routing",
                     "dash_ipv4_pa_validation", "dash_ipv6_pa_validation", "dash_ipv4_outbound_ca_to_pa",
                     "dash_ipv6_outbound_ca_to_pa", "dash_ipv4_acl_group", "dash_ipv6_acl_group"]
DASH_CRM_ACL_RULES_LIST = ["dash_ipv4_acl_rule", "dash_ipv6_acl_rule"]
DEFAULT_LOW_THR = 70
DEFAULT_HIGH_THR = 85
DEFAULT_THR_TYPE = "percentage"
DEFAULT_CRM_POLLING_INTERVAL = 300

DASH_THR_VERIFY_CMDS = deepcopy(THR_VERIFY_CMDS)
DASH_THR_VERIFY_CMDS.pop("exceeded_percentage")
DASH_THR_VERIFY_CMDS.pop("clear_percentage")


@pytest.fixture(scope="class")
def set_polling_interval(duthost):
    """
    Set CRM polling interval
    :param duthost: duthost object
    """
    wait_time = 2
    duthost.command("crm config polling interval {}".format(CRM_POLLING_INTERVAL))
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)

    yield

    duthost.command("crm config polling interval {}".format(DEFAULT_CRM_POLLING_INTERVAL))


@pytest.fixture(scope="class")
def default_crm_facts(duthost, set_polling_interval):
    """
    Get CRM configuration before test
    :param duthost: duthost object
    :param set_polling_interval: fixture
    :return: CRM resources data collected before apply config
    """
    crm_facts = duthost.get_crm_facts()
    yield crm_facts


@pytest.fixture(scope="class")
def apply_resources_configs(default_crm_facts, duthost):
    """
    Apply CRM configuration before run test
    :param default_crm_facts: CRM resources data collected before apply config
    :param duthost: duthost object
    """
    set_config = "set_dash_crm_config.json"
    del_config = "del_dash_crm_config.json"
    for config in [set_config, del_config]:
        src_path = os.path.join(os.path.abspath(""), "dash/crm/files/{}".format(config))
        duthost.copy(src=src_path, dest=config)
    pytest.crm_res_cleanup_required = True
    apply_swssconfig_file(duthost, set_config)

    yield set_config, del_config

    if pytest.crm_res_cleanup_required:
        apply_swssconfig_file(duthost, del_config)

    duthost.shell("rm -f {}".format(set_config))
    duthost.shell("rm -f {}".format(del_config))


@pytest.fixture(scope="class", autouse=True)
def cleanup(duthost):
    """
    Restore original CLI CRM thresholds
    :param duthost: duthost object
    """
    yield

    for resource in DASH_CRM_RES_LIST + DASH_CRM_ACL_RULES_LIST:
        with allure.step("Restoring original CRM thresholds for resource: {}".format(resource)):
            res_cli = get_dash_cli_crm_res_path(resource)
            cmd = "crm config thresholds {res_cli_path} type {def_type} && " \
                  "crm config thresholds {res_cli_path} low {def_low} && " \
                  "crm config thresholds {res_cli_path} high {def_high}".format(res_cli_path=res_cli,
                                                                                def_type=DEFAULT_THR_TYPE,
                                                                                def_low=DEFAULT_LOW_THR,
                                                                                def_high=DEFAULT_HIGH_THR)
            duthost.shell(cmd=cmd)


class TestDashCRM:

    @pytest.fixture(autouse=True)
    def setup(self, duthost, default_crm_facts, apply_resources_configs):
        self.duthost = duthost
        self.default_crm_facts = default_crm_facts
        self.crm_facts = self.duthost.get_crm_facts()
        self.set_config, self.del_config = apply_resources_configs

        self.vnets_num = 2
        self.eni_num = 1
        self.eni_eth_addr_num = 1
        self.inbound_routes_num = 1
        self.outbound_routes_num = 1
        self.outbound_ca_to_pa_num = 1
        self.pa_num = 1
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
            verify_thresholds(self.duthost, res_name=crm_table_res_name, crm_used=used_res, crm_avail=available_res,
                              **kwargs)

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
        assert used_res == expected_used_res, "CRM used resources counter: {} not equal to expected used resources " \
                                              "counter: {}".format(used_res, expected_used_res)
        expected_avail_res = default_available_res - crm_res_test_count
        assert available_res == expected_avail_res, "CRM available resources counter: {} not equal to expected " \
                                                    "available resources counter: {}".format(available_res,
                                                                                             expected_avail_res)

    def test_dash_crm_default_config(self):
        """
        Validate default CRM configuration
        Note: validation for default polling interval skipped
        :return:
        """
        available_crm_res = self.crm_facts["resources"].keys()
        assert len(available_crm_res) == len(DASH_CRM_RES_LIST), \
            "Available CRM resources: '{}' does not match expected CRM resources: '{}'".format(available_crm_res,
                                                                                               DASH_CRM_RES_LIST)
        for res in DASH_CRM_RES_LIST:
            assert res in available_crm_res, "CRM resource: '{}' not found in CRM resources list.".format(res)

        for res_name, res_data in self.crm_facts["thresholds"].items():
            th_type = res_data["type"]
            low_th = res_data["low"]
            high_th = res_data["high"]
            assert th_type == DEFAULT_THR_TYPE, "Failed default CRM config validation for resource: '{}', expected: " \
                                                "'{}' found: '{}'".format(res_name, DEFAULT_THR_TYPE, th_type)
            assert low_th == DEFAULT_LOW_THR, "Failed default CRM config validation for resource: '{}', expected: " \
                                              "'{}' found: '{}'".format(res_name, DEFAULT_LOW_THR, low_th)
            assert high_th == DEFAULT_HIGH_THR, "Failed default CRM config validation for resource: '{}', expected: " \
                                                "'{}' found: '{}'".format(res_name, DEFAULT_HIGH_THR, high_th)

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
        self.do_crm_validation(crm_table_res_name, self.inbound_routes_num)

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

    @pytest.mark.parametrize("ip_ver", ["ipv4", "ipv6"])
    def test_dash_acl_group(self, ip_ver):
        """
        Validate CRM thresholds for ACL groups
        :param ip_ver: string, ipv4 or ipv6
        """
        if ip_ver == "ipv6":
            pytest.skip("IPv6 not supported yet")

        crm_table_res_name = "dash_{}_acl_group".format(ip_ver)
        self.do_crm_validation(crm_table_res_name, self.acl_groups_num)

    @pytest.mark.parametrize("ip_ver", ["ipv4", "ipv6"])
    def test_dash_acl_rules(self, ip_ver):
        """
        Validate CRM thresholds for ACL rules in different ACL groups
        Create additional ACL group which has 2 ACL rules
        Verify thresholds for first ACL rules group
        Verify thresholds for second ACL rules group
        :param ip_ver: string, ipv4 or ipv6
        """
        if ip_ver == "ipv6":
            pytest.skip("IPv6 not supported yet")

        crm_table_res_name = "dash_{}_acl_rule".format(ip_ver)
        crm_facts = self.duthost.get_crm_facts()
        dash_acl_group = crm_facts["dash_acl_group"]

        assert len(dash_acl_group) == self.acl_groups_num, \
            "Unexpected number of ACL groups. Expected: {}, found:  {}".format(self.acl_groups_num, len(dash_acl_group))

        groups_data = parse_acl_groups_info(dash_acl_group)

        with allure.step("Validate CRM thresholds ACL group 1"):
            used, avail = groups_data["group1"]["used count"], groups_data["group1"]["available count"]

            # We expect message for both ACL groups
            ex_us_exp_regexp_list = [
                r".*ACL_RULE THRESHOLD_EXCEEDED for TH_USED 0% Used count 1 free count \d+",
                r".*ACL_RULE THRESHOLD_EXCEEDED for TH_USED 0% Used count 2 free count \d+"
            ]
            # We expect message for only one ACL group
            cl_us_exp_regexp_list = [
                r".*ACL_RULE THRESHOLD_CLEAR for TH_USED 0% Used count 1 free count \d+"
            ]

            verify_thresholds(self.duthost, res_name=crm_table_res_name, crm_used=used, crm_avail=avail,
                              ex_us_exp_regexp_list=ex_us_exp_regexp_list,
                              cl_us_exp_regexp_list=cl_us_exp_regexp_list)

        with allure.step("Validate CRM thresholds ACL group 2"):
            used, avail = groups_data["group2"]["used count"], groups_data["group2"]["available count"]

            verify_thresholds(self.duthost, res_name=crm_table_res_name, crm_used=used, crm_avail=avail)

    def test_dash_crm_cleanup(self):
        """
        Validate that after cleanup CRM resources - CRM output the same as it was before test case(without config)
        """
        apply_swssconfig_file(self.duthost, self.del_config)
        pytest.crm_res_cleanup_required = False

        time.sleep(CRM_UPDATE_TIME)
        crm_facts = self.duthost.get_crm_facts()

        assert crm_facts["resources"] == self.default_crm_facts["resources"], \
            "CRM resources after cleanup not equal to CRM resources before apply configuration.\nCRM resources " \
            "before apply config: {}\nCRM resources after cleanup: {}\n".format(self.default_crm_facts["resources"],
                                                                                crm_facts["resources"])


def parse_acl_groups_info(dash_acl_group):
    """
    Parse ACL rules per groups info
    :param dash_acl_group: dict with available ACL groups and rules info
    :return: dict, with available/used counts for ACL rules per ACL group
    """
    groups_data_dict = {"group1": {}, "group2": {}}
    for acl_group in dash_acl_group:
        available = int(acl_group["available count"])

        if int(acl_group["used count"]) == 1:
            groups_data_dict["group1"]["used count"] = 1
            groups_data_dict["group1"]["available count"] = available

        if int(acl_group["used count"]) == 2:
            groups_data_dict["group2"]["used count"] = 2
            groups_data_dict["group2"]["available count"] = available
    return groups_data_dict


def verify_thresholds(duthost, **kwargs):
    """
    Verifies that WARNING message logged if there are any resources that exceeds a pre-defined threshold value.
    Verifies the following threshold parameters: actual used, actual free
    """
    thr_verify_cmds = kwargs.get("thr_verify_cmds", DASH_THR_VERIFY_CMDS)
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="dash_crm_test")

    for key, value in list(thr_verify_cmds.items()):
        with allure.step("Verifying CRM threshold '{}'".format(key)):
            template = Template(value)
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
                    kwargs["th_lo"] = used_percent - 1
                    kwargs["th_hi"] = used_percent
                    loganalyzer.expect_regex = [EXPECT_EXCEEDED]
                elif key == "clear_percentage":
                    kwargs["th_lo"] = used_percent
                    kwargs["th_hi"] = used_percent + 1
                    loganalyzer.expect_regex = [EXPECT_CLEAR]

            kwargs["crm_cli_res"] = get_dash_cli_crm_res_path(kwargs["res_name"])
            cmd = template.render(**kwargs)

            with loganalyzer:
                duthost.command(cmd)
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
