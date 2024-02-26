import pytest
import copy
import abc
import logging
import time
import ipaddress
import random
from collections.abc import Iterable
from constants import *  # noqa: F403
from dash_utils import render_template
from gnmi_utils import apply_gnmi_file
import packets
import ptf.testutils as testutils

logger = logging.getLogger(__name__)

ACL_GROUP_TEMPLATE = "dash_acl_group"
ACL_RULE_TEMPLATE = "dash_acl_rule"
ACL_TAG_TEMPLATE = "dash_acl_tag"
BIND_ACL_IN = "dash_bind_acl_in"
BIND_ACL_OUT = "dash_bind_acl_out"
DEFAULT_ACL_GROUP = "default_acl_group"
SRC_IP_RANGE = ['24.0.0.0', '24.255.255.255']
BASE_SRC_SCALE_IP = '8.0.0.0'
SCALE_TAGS = 4096
SCALE_TAG_IPS = 1
WAIT_AFTER_CONFIG = 5


def apply_acl_config(localhost, duthost, ptfhost, template_name, acl_config_info, op):
    template_file = "{}.j2".format(template_name)
    config_json = render_template(template_file, acl_config_info, op=op)
    # apply_swssconfig_file(duthost, dest_path)
    apply_gnmi_file(localhost, duthost, ptfhost, config_json=config_json, wait_after_apply=0)


class AclGroup(object):
    def __init__(self, localhost, duthost, ptfhost, acl_group, eni, ip_version="ipv4"):
        self.duthost = duthost
        self.ptfhost = ptfhost
        self.localhost = localhost
        self.acl_group = acl_group
        self.eni = eni
        self.ip_version = ip_version
        self.group_conf = {
            ACL_GROUP: self.acl_group,
            IP_VERSION: self.ip_version
        }
        apply_acl_config(self.localhost, self.duthost, self.ptfhost, ACL_GROUP_TEMPLATE, self.group_conf, op="SET")

    def __del__(self):
        apply_acl_config(self.localhost, self.duthost, self.ptfhost, ACL_GROUP_TEMPLATE, self.group_conf, op="DEL")

    def bind(self, stage):
        self.stage = stage
        self.bind_conf = {
            ENI: self.eni,
            ACL_GROUP: self.acl_group,
            ACL_STAGE: self.stage,
        }
        apply_acl_config(self.localhost, self.duthost, self.ptfhost, BIND_ACL_OUT, self.bind_conf, op="SET")
        apply_acl_config(self.localhost, self.duthost, self.ptfhost, BIND_ACL_IN, self.bind_conf, op="SET")

    def unbind(self):
        apply_acl_config(self.localhost, self.duthost, self.ptfhost, BIND_ACL_OUT, self.bind_conf, op="DEL")
        apply_acl_config(self.localhost, self.duthost, self.ptfhost, BIND_ACL_IN, self.bind_conf, op="DEL")


class AclTag(object):
    def __init__(self, localhost, duthost, ptfhost, acl_tag, acl_prefix_list, ip_version="ipv4"):
        self.duthost = duthost
        self.ptfhost = ptfhost
        self.localhost = localhost
        self.tag_conf = {
            ACL_TAG: acl_tag,
            IP_VERSION: ip_version,
            ACL_PREFIX_LIST: acl_prefix_list
        }
        apply_acl_config(self.localhost, self.duthost, self.ptfhost, ACL_TAG_TEMPLATE, self.tag_conf, op="SET")

    def __del__(self):
        apply_acl_config(self.localhost, self.duthost, self.ptfhost, ACL_TAG_TEMPLATE, self.tag_conf, op="DEL")


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
    def __init__(self, localhost, duthost, ptfhost, dash_config_info):
        __metaclass__ = abc.ABCMeta  # noqa: F841
        self.duthost = duthost
        self.ptfhost = ptfhost
        self.localhost = localhost
        self.dash_config_info = dash_config_info
        self.test_pkts = []

    @abc.abstractmethod
    def config(self):
        pass

    @abc.abstractmethod
    def teardown(self):
        pass

    def get_random_ip(self):
        """
        Generate a random IP from ip range
        """
        length = int(ipaddress.ip_address(SRC_IP_RANGE[1])) - int(ipaddress.ip_address(SRC_IP_RANGE[0]))
        return str(ipaddress.ip_address(SRC_IP_RANGE[0]) + random.randint(0, length))


class AclRuleTest(AclTestCase):
    def __init__(self, localhost, duthost, ptfhost, dash_config_info, default_action="deny"):
        super(AclRuleTest, self).__init__(localhost, duthost, ptfhost, dash_config_info)
        self.default_action = default_action
        self.rule_confs = []

    def add_rule(self, rule_conf):
        rule_conf[ACL_RULE] = self.__class__.__name__ + "_" + rule_conf[ACL_RULE]
        apply_acl_config(self.localhost, self.duthost, self.ptfhost, ACL_RULE_TEMPLATE, rule_conf, op="SET")
        self.rule_confs.append(rule_conf)

    def add_test_pkt(self, test_pkt):
        test_pkt.description = self.__class__.__name__ + "_" + str(len(self.test_pkts) + 1) + "_" + test_pkt.description
        self.test_pkts.append(test_pkt)

    def teardown(self):
        for rule_conf in self.rule_confs:
            apply_acl_config(self.localhost, self.duthost, self.ptfhost, ACL_RULE_TEMPLATE, rule_conf, op="DEL")
        self.rule_confs = []


class DefaultAclRule(AclRuleTest):
    def __init__(self, localhost, duthost, ptfhost, dash_config_info, default_action):
        super(DefaultAclRule, self).__init__(localhost, duthost, ptfhost, dash_config_info, default_action)
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
    def __init__(self, localhost, duthost, ptfhost, dash_config_info, default_action):
        super(AclPriorityTest, self).__init__(localhost, duthost, ptfhost, dash_config_info, default_action)
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
    def __init__(self, localhost, duthost, ptfhost, dash_config_info, default_action):
        super(AclProtocolTest, self).__init__(localhost, duthost, ptfhost, dash_config_info, default_action)
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
    def __init__(self, localhost, duthost, ptfhost, dash_config_info, default_action):
        super(AclAddressTest, self).__init__(localhost, duthost, ptfhost, dash_config_info, default_action)
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
    def __init__(self, localhost, duthost, ptfhost, dash_config_info, default_action):
        super(AclPortTest, self).__init__(localhost, duthost, ptfhost, dash_config_info, default_action)
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


class AclTagTest(AclRuleTest):
    def __init__(self, localhost, duthost, ptfhost, dash_config_info):
        super(AclTagTest, self).__init__(localhost, duthost, ptfhost, dash_config_info)
        self.ptfhost = ptfhost
        self.acl_group = DEFAULT_ACL_GROUP
        self.src_ip1 = self.get_random_ip()
        self.src_ip2 = self.get_random_ip()
        self.src_ip_prefix1 = self.src_ip1 + "/32"
        self.src_ip_prefix2 = self.src_ip2 + "/32"

    def config(self):
        self.acl_tag = AclTag(self.localhost, self.duthost, self.ptfhost, "AclTag",
                              [",".join([self.src_ip_prefix1, self.src_ip_prefix2])])
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "allow_tag",
            ACL_PRIORITY: 1,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_TAG: "AclTag1",
            ACL_SRC_PORT: "13"
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip1
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 13},
                                        expected_receiving=True))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip2
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 13},
                                        expected_receiving=True))

    def teardown(self):
        super(AclTagTest, self).teardown()
        del self.acl_tag


class AclMultiTagTest(AclRuleTest):
    def __init__(self, localhost, duthost, ptfhost, dash_config_info):
        super(AclMultiTagTest, self).__init__(localhost, duthost, ptfhost, dash_config_info)
        self.ptfhost = ptfhost
        self.acl_group = DEFAULT_ACL_GROUP
        self.src_ip1 = self.get_random_ip()
        self.src_ip2 = self.get_random_ip()
        self.src_ip_prefix1 = self.src_ip1 + "/32"
        self.src_ip_prefix2 = self.src_ip2 + "/32"

    def config(self):
        self.acl_tag = AclTag(self.localhost, self.duthost, self.ptfhost, "AclMultiTag",
                              [self.src_ip_prefix1, self.src_ip_prefix2])
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "allow_multi_tag",
            ACL_PRIORITY: 1,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_TAG: "AclMultiTag1,AclMultiTag2",
            ACL_SRC_PORT: "15"
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip1
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 15},
                                        expected_receiving=True))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip2
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 15},
                                        expected_receiving=True))

    def teardown(self):
        super(AclMultiTagTest, self).teardown()
        del self.acl_tag


class AclTagNotExistsTest(AclRuleTest):
    def __init__(self, localhost, duthost, ptfhost, dash_config_info):
        super(AclTagNotExistsTest, self).__init__(localhost, duthost, ptfhost, dash_config_info)
        self.ptfhost = ptfhost
        self.acl_group = DEFAULT_ACL_GROUP
        self.acl_tag = None
        self.src_ip = self.get_random_ip()

    def config(self):
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "allow_tag_order",
            ACL_PRIORITY: 1,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_TAG: "AclTagOrder1",
            ACL_SRC_PORT: "17"
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 17},
                                        expected_receiving=False))


class AclTagOrderTest(AclRuleTest):
    def __init__(self, localhost, duthost, ptfhost, dash_config_info):
        super(AclTagOrderTest, self).__init__(localhost, duthost, ptfhost, dash_config_info)
        self.ptfhost = ptfhost
        self.acl_group = DEFAULT_ACL_GROUP
        self.acl_tag = None
        self.src_ip = self.get_random_ip()
        self.src_ip_prefix = self.src_ip + "/32"

    def config(self):
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "allow_tag_order",
            ACL_PRIORITY: 1,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_TAG: "AclTagOrder1",
            ACL_SRC_PORT: "17"
        })
        self.acl_tag = AclTag(self.localhost, self.duthost, self.ptfhost, "AclTagOrder", [self.src_ip_prefix])
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 17},
                                        expected_receiving=True))

    def teardown(self):
        del self.acl_tag
        super(AclTagOrderTest, self).teardown()


class AclMultiTagOrderTest(AclRuleTest):
    def __init__(self, localhost, duthost, ptfhost, dash_config_info):
        super(AclMultiTagOrderTest, self).__init__(localhost, duthost, ptfhost, dash_config_info)
        self.ptfhost = ptfhost
        self.acl_group = DEFAULT_ACL_GROUP
        self.src_ip1 = self.get_random_ip()
        self.src_ip2 = self.get_random_ip()
        self.src_ip_prefix1 = self.src_ip1 + "/32"
        self.src_ip_prefix2 = self.src_ip2 + "/32"

    def config(self):
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "allow_multi_tag_order",
            ACL_PRIORITY: 1,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_TAG: "AclMultiTagOrder1,AclMultiTagOrder2",
            ACL_SRC_PORT: "18"
        })
        self.acl_tag = AclTag(
            self.localhost, self.duthost, self.ptfhost, "AclMultiTagOrder", [self.src_ip_prefix1, self.src_ip_prefix2])
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip1
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 18},
                                        expected_receiving=True))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip2
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 18},
                                        expected_receiving=True))

    def teardown(self):
        del self.acl_tag
        super(AclMultiTagOrderTest, self).teardown()


class AclTagUpdateIpTest(AclRuleTest):
    def __init__(self, localhost, duthost, ptfhost, dash_config_info):
        super(AclTagUpdateIpTest, self).__init__(localhost, duthost, ptfhost, dash_config_info)
        self.ptfhost = ptfhost
        self.acl_group = DEFAULT_ACL_GROUP
        self.src_ip1 = self.get_random_ip()
        self.src_ip2 = self.get_random_ip()
        self.src_ip_prefix1 = self.src_ip1 + "/32"
        self.src_ip_prefix2 = self.src_ip2 + "/32"

    def config(self):
        self.acl_tag1 = AclTag(self.localhost, self.duthost, self.ptfhost, "AclTagUpdateIp", [self.src_ip_prefix1])
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "allow_update_ip_tag",
            ACL_PRIORITY: 1,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_TAG: "AclTagUpdateIp1",
            ACL_SRC_PORT: "19"
        })
        self.acl_tag2 = AclTag(self.localhost, self.duthost, self.ptfhost, "AclTagUpdateIp", [self.src_ip_prefix2])
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip1
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 19},
                                        expected_receiving=False))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip2
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 19},
                                        expected_receiving=True))

    def teardown(self):
        super(AclTagUpdateIpTest, self).teardown()
        del self.acl_tag1
        del self.acl_tag2


class AclTagRemoveIpTest(AclRuleTest):
    def __init__(self, localhost, duthost, ptfhost, dash_config_info):
        super(AclTagRemoveIpTest, self).__init__(localhost, duthost, ptfhost, dash_config_info)
        self.ptfhost = ptfhost
        self.acl_group = DEFAULT_ACL_GROUP
        self.src_ip1 = self.get_random_ip()
        self.src_ip2 = self.get_random_ip()
        self.src_ip_prefix1 = self.src_ip1 + "/32"
        self.src_ip_prefix2 = self.src_ip2 + "/32"

    def config(self):
        self.acl_tag1 = AclTag(self.localhost, self.duthost, self.ptfhost, "AclTagRemoveIp",
                               [",".join([self.src_ip_prefix1, self.src_ip_prefix2])])
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "allow_remove_ip_tag",
            ACL_PRIORITY: 1,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_TAG: "AclTagRemoveIp1",
            ACL_SRC_PORT: "20"
        })
        self.acl_tag2 = AclTag(self.localhost, self.duthost, self.ptfhost, "AclTagRemoveIp", [self.src_ip_prefix1])
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip1
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 20},
                                        expected_receiving=True))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip2
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 20},
                                        expected_receiving=False))

    def teardown(self):
        super(AclTagRemoveIpTest, self).teardown()
        del self.acl_tag1
        del self.acl_tag2


class AclTagScaleTest(AclRuleTest):
    def __init__(self, localhost, duthost, ptfhost, dash_config_info):
        super(AclTagScaleTest, self).__init__(localhost, duthost, ptfhost, dash_config_info)
        self.ptfhost = ptfhost
        self.acl_group = DEFAULT_ACL_GROUP
        self.ip_list = self.random_scale_ip_list()
        self.src_ip_list = random.choices(self.ip_list, k=100)
        self.src_ip_prefix_list = self.get_scale_prefixes_list()
        self.tag_names_list = ",".join(["AclTagScale{}".format(tag_num) for tag_num in range(1, SCALE_TAGS+1)])

    def config(self):
        self.acl_tag = AclTag(self.localhost, self.duthost, self.ptfhost, "AclTagScale", self.src_ip_prefix_list)
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "allow_scale_tag",
            ACL_PRIORITY: 1,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_TAG: self.tag_names_list,
            ACL_SRC_PORT: "21"
        })
        for src_ip in self.src_ip_list:
            dash_config_info = copy.deepcopy(self.dash_config_info)
            dash_config_info[LOCAL_CA_IP] = src_ip
            self.add_test_pkt(AclTestPacket(dash_config_info,
                                            inner_extra_conf={"udp_sport": 21},
                                            expected_receiving=True))

    def teardown(self):
        super(AclTagScaleTest, self).teardown()
        del self.acl_tag

    @staticmethod
    def random_scale_ip_list(ip_type='ipv4'):
        ip_list = []
        if ip_type == 'ipv4':
            address_type = ipaddress.IPv4Address
        else:
            address_type = ipaddress.IPv6Address
        first_ip = address_type(BASE_SRC_SCALE_IP)
        last_ip = first_ip + (SCALE_TAGS * SCALE_TAG_IPS) - 1
        summarized_range = ipaddress.summarize_address_range(first_ip, last_ip)
        for subnet in summarized_range:
            for ip_address in subnet:
                ip_list.append(str(ip_address))
        random.shuffle(ip_list)
        return ip_list

    def get_scale_prefixes_list(self):
        prefixes_list = []
        begin_index = 0
        for _ in range(SCALE_TAGS):
            end_index = begin_index + SCALE_TAG_IPS
            ip_list = self.ip_list[begin_index:end_index]
            prefixes_list.append("/32,".join(ip_list) + "/32")
            begin_index += SCALE_TAG_IPS
        return prefixes_list


@pytest.fixture(scope="function", params=["allow", "deny"])
def acl_fields_test(request, apply_vnet_configs, localhost, duthost, ptfhost, dash_config_info):
    testcases = []

    default_acl_group = AclGroup(localhost, duthost, ptfhost, DEFAULT_ACL_GROUP, dash_config_info[ENI])
    default_action = request.param
    default_acl_rule = DefaultAclRule(localhost, duthost, ptfhost, dash_config_info, default_action)

    testcases.append(default_acl_rule)
    testcases.append(AclPriorityTest(localhost, duthost, ptfhost, dash_config_info, default_action))
    testcases.append(AclProtocolTest(localhost, duthost, ptfhost, dash_config_info, default_action))
    testcases.append(AclAddressTest(localhost, duthost, ptfhost, dash_config_info, default_action))
    testcases.append(AclPortTest(localhost, duthost, ptfhost, dash_config_info, default_action))

    for t in testcases:
        t.config()
    default_acl_group.bind(1)
    time.sleep(WAIT_AFTER_CONFIG)

    yield testcases

    default_acl_group.unbind()
    for t in reversed(testcases):
        t.teardown()
    del default_acl_group
    time.sleep(WAIT_AFTER_CONFIG)


def acl_tag_test_config(localhost, duthost, ptfhost, dash_config_info, testcase):
    testcases = []

    default_acl_group = AclGroup(localhost, duthost, ptfhost, DEFAULT_ACL_GROUP, dash_config_info[ENI])
    default_acl_rule = DefaultAclRule(localhost, duthost, ptfhost, dash_config_info, 'deny')
    testcases.append(default_acl_rule)
    testcases.append(testcase)

    for t in testcases:
        t.config()
    default_acl_group.bind(1)
    time.sleep(WAIT_AFTER_CONFIG)
    return testcases, default_acl_group


def acl_tag_test_teardown(default_acl_group, testcases):
    default_acl_group.unbind()
    for t in reversed(testcases):
        t.teardown()
    del default_acl_group
    time.sleep(WAIT_AFTER_CONFIG)


@pytest.fixture(scope="function")
def acl_tag_test(apply_vnet_configs, localhost, duthost, ptfhost, dash_config_info):
    testcases, default_acl_group = acl_tag_test_config(localhost, duthost, ptfhost, dash_config_info,
                                                       AclTagTest(localhost, duthost, ptfhost, dash_config_info))

    yield testcases

    acl_tag_test_teardown(default_acl_group, testcases)


@pytest.fixture(scope="function")
def acl_multi_tag_test(apply_vnet_configs, localhost, duthost, ptfhost, dash_config_info):
    testcases, default_acl_group = acl_tag_test_config(localhost, duthost, ptfhost, dash_config_info,
                                                       AclMultiTagTest(localhost, duthost, ptfhost, dash_config_info))

    yield testcases

    acl_tag_test_teardown(default_acl_group, testcases)


@pytest.fixture(scope="function")
def acl_tag_not_exists_test(apply_vnet_configs, localhost, duthost, ptfhost, dash_config_info):
    testcases, default_acl_group = acl_tag_test_config(localhost, duthost, ptfhost, dash_config_info,
                                                       AclTagNotExistsTest(
                                                           localhost, duthost, ptfhost, dash_config_info))

    yield testcases

    acl_tag_test_teardown(default_acl_group, testcases)


@pytest.fixture(scope="function")
def acl_tag_order_test(apply_vnet_configs, localhost, duthost, ptfhost, dash_config_info):
    testcases, default_acl_group = acl_tag_test_config(localhost, duthost, ptfhost, dash_config_info,
                                                       AclTagOrderTest(localhost, duthost, ptfhost, dash_config_info))

    yield testcases

    acl_tag_test_teardown(default_acl_group, testcases)


@pytest.fixture(scope="function")
def acl_multi_tag_order_test(apply_vnet_configs, localhost, duthost, ptfhost, dash_config_info):
    testcases, default_acl_group = acl_tag_test_config(localhost, duthost, ptfhost, dash_config_info,
                                                       AclMultiTagOrderTest(localhost, duthost,
                                                                            ptfhost, dash_config_info))

    yield testcases

    acl_tag_test_teardown(default_acl_group, testcases)


@pytest.fixture(scope="function")
def acl_tag_update_ip_test(apply_vnet_configs, localhost, duthost, ptfhost, dash_config_info):
    testcases, default_acl_group = acl_tag_test_config(localhost, duthost, ptfhost, dash_config_info,
                                                       AclTagUpdateIpTest(localhost, duthost,
                                                                          ptfhost, dash_config_info))

    yield testcases

    acl_tag_test_teardown(default_acl_group, testcases)


@pytest.fixture(scope="function")
def acl_tag_remove_ip_test(apply_vnet_configs, localhost, duthost, ptfhost, dash_config_info):
    testcases, default_acl_group = acl_tag_test_config(localhost, duthost, ptfhost, dash_config_info,
                                                       AclTagRemoveIpTest(localhost, duthost,
                                                                          ptfhost, dash_config_info))

    yield testcases

    acl_tag_test_teardown(default_acl_group, testcases)


@pytest.fixture(scope="function")
def acl_tag_scale_test(apply_vnet_configs, localhost, duthost, ptfhost, dash_config_info):
    testcases, default_acl_group = acl_tag_test_config(localhost, duthost, ptfhost, dash_config_info,
                                                       AclTagScaleTest(localhost, duthost,
                                                                       ptfhost, dash_config_info))

    yield testcases

    acl_tag_test_teardown(default_acl_group, testcases)


STAGE_1_ACL_GROUP = "stage_1_acl_group"
STAGE_2_ACL_GROUP = "stage_2_acl_group"


class AclMultiStageTest(AclRuleTest):
    def __init__(self, localhost, duthost, ptfhost, dash_config_info):
        super(AclMultiStageTest, self).__init__(localhost, duthost, ptfhost, dash_config_info)
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
def acl_multi_stage_test(localhost, duthost, apply_vnet_configs, ptfhost, dash_config_info):
    group_1 = AclGroup(localhost, duthost, ptfhost, STAGE_1_ACL_GROUP, dash_config_info[ENI])
    group_2 = AclGroup(localhost, duthost, ptfhost, STAGE_2_ACL_GROUP, dash_config_info[ENI])
    test = AclMultiStageTest(localhost, duthost, ptfhost, dash_config_info)

    test.config()
    group_1.bind(1)
    group_2.bind(2)
    time.sleep(WAIT_AFTER_CONFIG)

    yield test

    group_1.unbind()
    group_2.unbind()
    test.teardown()
    del group_1
    del group_2
    time.sleep(WAIT_AFTER_CONFIG)


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
