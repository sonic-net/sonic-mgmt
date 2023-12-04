import pytest
import copy
import abc
import logging
import time
from collections.abc import Iterable

from constants import *  # noqa: F403
from dash_utils import render_template_to_host
from gnmi_utils import apply_gnmi_file
import packets
import ptf.testutils as testutils

logger = logging.getLogger(__name__)

ACL_GROUP_TEMPLATE = "dash_acl_group"
ACL_RULE_TEMPLATE = "dash_acl_rule"
BIND_ACL_IN = "dash_bind_acl_in"
BIND_ACL_OUT = "dash_bind_acl_out"
DEFAULT_ACL_GROUP = "default_acl_group"


def apply_acl_config(duthost, ptfhost, template_name, acl_config_info, op):
    template_file = "{}.j2".format(template_name)
    dest_path = "/tmp/{}.json".format(template_name)
    render_template_to_host(template_file, duthost, dest_path, acl_config_info, op=op)
    # apply_swssconfig_file(duthost, dest_path)
    apply_gnmi_file(duthost, ptfhost, dest_path)


class AclGroup(object):
    def __init__(self, duthost, ptfhost, acl_group, eni, ip_version="ipv4"):
        self.duthost = duthost
        self.ptfhost = ptfhost
        self.acl_group = acl_group
        self.eni = eni
        self.ip_version = ip_version
        self.group_conf = {
            ACL_GROUP: self.acl_group,
            IP_VERSION: self.ip_version
        }
        apply_acl_config(self.duthost, self.ptfhost, ACL_GROUP_TEMPLATE, self.group_conf, op="SET")

    def __del__(self):
        apply_acl_config(self.duthost, self.ptfhost, ACL_GROUP_TEMPLATE, self.group_conf, op="DEL")

    def bind(self, stage):
        self.stage = stage
        self.bind_conf = {
            ENI: self.eni,
            ACL_GROUP: self.acl_group,
            ACL_STAGE: self.stage,
        }
        apply_acl_config(self.duthost, self.ptfhost, BIND_ACL_OUT, self.bind_conf, op="SET")
        apply_acl_config(self.duthost, self.ptfhost, BIND_ACL_IN, self.bind_conf, op="SET")

    def unbind(self):
        apply_acl_config(self.duthost, self.ptfhost, BIND_ACL_OUT, self.bind_conf, op="DEL")
        apply_acl_config(self.duthost, self.ptfhost, BIND_ACL_IN, self.bind_conf, op="DEL")


class AclTestPacket(object):
    def __init__(self,
                 dash_config_info,
                 inner_extra_conf={},
                 expected_receiving=True,
                 description=""):
        self.dash_config_info = dash_config_info
        self.inner_extra_conf = inner_extra_conf
        self.expected_receiving = expected_receiving
        self.description = description + "_" + str(self.inner_extra_conf)

    def get_description(self):
        return self.description


class AclTestCase(object):
    def __init__(self, duthost, ptfhost, dash_config_info):
        __metaclass__ = abc.ABCMeta  # noqa: F841
        self.duthost = duthost
        self.ptfhost = ptfhost
        self.dash_config_info = dash_config_info
        self.test_pkts = []

    @abc.abstractmethod
    def config(self):
        pass

    @abc.abstractmethod
    def teardown(self):
        pass


class AclRuleTest(AclTestCase):
    def __init__(self, duthost, ptfhost, dash_config_info, default_action="deny"):
        super(AclRuleTest, self).__init__(duthost, ptfhost, dash_config_info)
        self.default_action = default_action
        self.rule_confs = []

    def add_rule(self, rule_conf):
        rule_conf[ACL_RULE] = self.__class__.__name__ + "_" + rule_conf[ACL_RULE]
        apply_acl_config(self.duthost, self.ptfhost, ACL_RULE_TEMPLATE, rule_conf, op="SET")
        self.rule_confs.append(rule_conf)

    def add_test_pkt(self, test_pkt):
        test_pkt.description = self.__class__.__name__ + "_" + str(len(self.test_pkts) + 1) + "_" + test_pkt.description
        self.test_pkts.append(test_pkt)

    def teardown(self):
        for rule_conf in self.rule_confs:
            apply_acl_config(self.duthost, self.ptfhost, ACL_RULE_TEMPLATE, rule_conf, op="DEL")
        self.rule_confs = []


class DefaultAclRule(AclRuleTest):
    def __init__(self, duthost, ptfhost, dash_config_info, default_action):
        super(DefaultAclRule, self).__init__(duthost, ptfhost, dash_config_info, default_action)
        self.acl_group = DEFAULT_ACL_GROUP

    def config(self):
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "default_rule",
            ACL_PRIORITY: 255,
            ACL_ACTION: self.default_action,
            ACL_TERMINATING: "false",
            ACL_PROTOCOL: "17",
        })


class AclPriorityTest(AclRuleTest):
    def __init__(self, duthost, ptfhost, dash_config_info, default_action):
        super(AclPriorityTest, self).__init__(duthost, ptfhost, dash_config_info, default_action)
        self.acl_group = DEFAULT_ACL_GROUP
        self.src_ip = "10.0.0.2"
        self.src_ip_prefix = self.src_ip + "/32"

    def config(self):
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "priority_1_deny_port1",
            ACL_PRIORITY: 1,
            ACL_ACTION: "deny",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: "1"
        })
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "priority_2_allow_port1",
            ACL_PRIORITY: 2,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: "1"
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 1},
                                        expected_receiving=False))
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "priority_3_allow_port2",
            ACL_PRIORITY: 3,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: "2"
        })
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "priority_4_deny_port2",
            ACL_PRIORITY: 4,
            ACL_ACTION: "deny",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: "2"
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 2},
                                        expected_receiving=True))


class AclProtocolTest(AclRuleTest):
    def __init__(self, duthost, ptfhost, dash_config_info, default_action):
        super(AclProtocolTest, self).__init__(duthost, ptfhost, dash_config_info, default_action)
        self.acl_group = DEFAULT_ACL_GROUP
        self.src_ip = "0.0.0.0"
        self.src_ip_prefix = self.src_ip + "/0"

    def config(self):
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "protocol_allow_port18,19",
            ACL_PRIORITY: 10,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "18, 19",
            ACL_SRC_ADDR: self.src_ip_prefix,
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"proto": 18},
                                        expected_receiving=True))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"proto": 19},
                                        expected_receiving=True))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"proto": 20},
                                        expected_receiving=False))


class AclAddressTest(AclRuleTest):
    def __init__(self, duthost, ptfhost, dash_config_info, default_action):
        super(AclAddressTest, self).__init__(duthost, ptfhost, dash_config_info, default_action)
        self.acl_group = DEFAULT_ACL_GROUP

    def config(self):
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "address_allow_10.0.0.2/32,10.0.0.3/32",
            ACL_PRIORITY: 20,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: "10.0.0.2/32,10.0.0.3/32",
            ACL_SRC_PORT: "6"
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = "10.0.0.2"
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 6},
                                        expected_receiving=True))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = "10.0.0.3"
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 6},
                                        expected_receiving=True))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = "10.0.0.4"
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 6},
                                        expected_receiving=self.default_action == "allow"))
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "address_allow_10.0.1.0/30",
            ACL_PRIORITY: 21,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: "10.0.1.0/30",
            ACL_SRC_PORT: "6"
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = "10.0.1.0"
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 6},
                                        expected_receiving=True))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = "10.0.1.1"
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 6},
                                        expected_receiving=True))
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "address_deny_dst_ip",
            ACL_PRIORITY: 22,
            ACL_ACTION: "deny",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_DST_ADDR: self.dash_config_info[REMOTE_CA_IP] + "/32",
            ACL_SRC_ADDR: "10.0.1.3/32",
            ACL_SRC_PORT: "7"
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = "10.0.1.3"
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 7},
                                        expected_receiving=False))
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "address_allow_dst_ip",
            ACL_PRIORITY: 23,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_DST_ADDR: self.dash_config_info[REMOTE_CA_IP] + "/32",
            ACL_SRC_ADDR: "10.0.1.4/32",
            ACL_SRC_PORT: "7"
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = "10.0.1.4"
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 7},
                                        expected_receiving=True))


class AclPortTest(AclRuleTest):
    def __init__(self, duthost, ptfhost, dash_config_info, default_action):
        super(AclPortTest, self).__init__(duthost, ptfhost, dash_config_info, default_action)
        self.acl_group = DEFAULT_ACL_GROUP
        self.src_ip = "10.0.0.2"
        self.src_ip_prefix = self.src_ip + "/32"

    def config(self):
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "port_allow_port7-10,12",
            ACL_PRIORITY: 30,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: "8-10,12"
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 8},
                                        expected_receiving=True))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 9},
                                        expected_receiving=True))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 10},
                                        expected_receiving=True))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 11},
                                        expected_receiving=self.default_action == "allow"))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 12},
                                        expected_receiving=True))
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "port_allow_dport7",
            ACL_PRIORITY: 31,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_DST_PORT: "7"
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_dport": 7},
                                        expected_receiving=True))
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "port_deny_dport8",
            ACL_PRIORITY: 32,
            ACL_ACTION: "deny",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_DST_PORT: "8"
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_dport": 8},
                                        expected_receiving=False))


@pytest.fixture(scope="function", params=["allow", "deny"])
def acl_fields_test(request, apply_vnet_configs, duthost, ptfhost, dash_config_info):
    testcases = []

    default_acl_group = AclGroup(duthost, ptfhost, DEFAULT_ACL_GROUP, dash_config_info[ENI])
    default_action = request.param
    default_acl_rule = DefaultAclRule(duthost, ptfhost, dash_config_info, default_action)
    default_action = default_acl_rule.default_action

    testcases.append(default_acl_rule)
    testcases.append(AclPriorityTest(duthost, ptfhost, dash_config_info, default_action))
    testcases.append(AclProtocolTest(duthost, ptfhost, dash_config_info, default_action))
    testcases.append(AclAddressTest(duthost, ptfhost, dash_config_info, default_action))
    testcases.append(AclPortTest(duthost, ptfhost, dash_config_info, default_action))

    for t in testcases:
        t.config()
    default_acl_group.bind(1)

    yield testcases

    default_acl_group.unbind()
    for t in reversed(testcases):
        t.teardown()
    del default_acl_group


STAGE_1_ACL_GROUP = "stage_1_acl_group"
STAGE_2_ACL_GROUP = "stage_2_acl_group"


class AclMultiStageTest(AclRuleTest):
    def __init__(self, duthost, ptfhost, dash_config_info):
        super(AclMultiStageTest, self).__init__(duthost, ptfhost, dash_config_info)
        self.acl_group_1 = STAGE_1_ACL_GROUP
        self.acl_group_2 = STAGE_2_ACL_GROUP
        self.src_ip = "10.0.0.2"
        self.src_ip_prefix = self.src_ip + "/32"

    def config(self):
        self.add_rule({
            ACL_GROUP: self.acl_group_1,
            ACL_RULE: "multi_stage_1_allow_port13",
            ACL_PRIORITY: 2,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "false",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: 13
        })
        self.add_rule({
            ACL_GROUP: self.acl_group_2,
            ACL_RULE: "multi_stage_2_deny_port13",
            ACL_PRIORITY: 1,
            ACL_ACTION: "deny",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: 13
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 13},
                                        expected_receiving=False))

        self.add_rule({
            ACL_GROUP: self.acl_group_1,
            ACL_RULE: "multi_stage_1_deny_port14",
            ACL_PRIORITY: 4,
            ACL_ACTION: "deny",
            ACL_TERMINATING: "false",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: 14
        })
        self.add_rule({
            ACL_GROUP: self.acl_group_2,
            ACL_RULE: "multi_stage_2_allow_port14",
            ACL_PRIORITY: 3,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: 14
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 14},
                                        expected_receiving=True))

        self.add_rule({
            ACL_GROUP: self.acl_group_1,
            ACL_RULE: "multi_stage_1_deny_port15",
            ACL_PRIORITY: 6,
            ACL_ACTION: "deny",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: 15
        })
        self.add_rule({
            ACL_GROUP: self.acl_group_2,
            ACL_RULE: "multi_stage_2_allow_port15",
            ACL_PRIORITY: 5,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "false",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: 15
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 15},
                                        expected_receiving=False))

        self.add_rule({
            ACL_GROUP: self.acl_group_1,
            ACL_RULE: "multi_stage_1_allow_port16",
            ACL_PRIORITY: 8,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: 16
        })
        self.add_rule({
            ACL_GROUP: self.acl_group_2,
            ACL_RULE: "multi_stage_2_deny_port16",
            ACL_PRIORITY: 7,
            ACL_ACTION: "deny",
            ACL_TERMINATING: "false",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: 16
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 16},
                                        expected_receiving=True))


@pytest.fixture(scope="function")
def acl_multi_stage_test(duthost, apply_vnet_configs, ptfhost, dash_config_info):
    group_1 = AclGroup(duthost, ptfhost, STAGE_1_ACL_GROUP, dash_config_info[ENI])
    group_2 = AclGroup(duthost, ptfhost, STAGE_2_ACL_GROUP, dash_config_info[ENI])
    test = AclMultiStageTest(duthost, ptfhost, dash_config_info)

    test.config()
    group_1.bind(1)
    group_2.bind(2)

    yield test

    group_1.unbind()
    group_2.unbind()
    test.teardown()
    del group_1
    del group_2


def check_dataplane(ptfadapter, testcases):
    test_pkts = []
    if isinstance(testcases, Iterable):
        for t in testcases:
            test_pkts.extend(t.test_pkts)
    else:
        test_pkts = testcases.test_pkts
    for pkt in test_pkts:
        logger.info("Testing packet: {}".format(pkt.get_description()))
        _, vxlan_packet, expected_packet = packets.outbound_vnet_packets(pkt.dash_config_info,
                                                                         pkt.inner_extra_conf)
        testutils.send(ptfadapter,
                       pkt.dash_config_info[LOCAL_PTF_INTF],
                       vxlan_packet, 1)
        if pkt.expected_receiving:
            testutils.verify_packets_any(ptfadapter,
                                         expected_packet,
                                         ports=pkt.dash_config_info[REMOTE_PTF_INTF])
        else:
            testutils.verify_no_packet_any(ptfadapter,
                                           expected_packet,
                                           ports=pkt.dash_config_info[REMOTE_PTF_INTF])
        time.sleep(0.1)
