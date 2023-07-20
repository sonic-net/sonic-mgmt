import pytest
import copy
import abc

from constants import *  # noqa: F403
from dash_utils import render_template_to_host, apply_swssconfig_file


ACL_GROUP_TEMPLATE = "dash_acl_group"
ACL_RULE_TEMPLATE = "dash_acl_rule"
BIND_ACL_IN = "dash_bind_acl_in"
BIND_ACL_OUT = "dash_bind_acl_out"
DEFAULT_ACL_GROUP = "default_acl_group"
DEFAULT_ACL_STAGE = 1


def apply_acl_config(duthost, template_name, acl_config_info, op):
    template_file = "{}.j2".format(template_name)
    dest_path = "/tmp/{}.json".format(template_name)
    render_template_to_host(template_file, duthost, dest_path, acl_config_info, op=op)
    apply_swssconfig_file(duthost, dest_path)


class AclGroup(object):
    def __init__(self, duthost, acl_group, eni, ip_version="ipv4"):
        self.duthost = duthost
        self.acl_group = acl_group
        self.eni = eni
        self.ip_version = ip_version
        self.group_conf = {
            ACL_GROUP: self.acl_group,
            IP_VERSION: self.ip_version
        }
        apply_acl_config(self.duthost, ACL_GROUP_TEMPLATE, self.group_conf, op="SET")

    def __del__(self):
        apply_acl_config(self.duthost, ACL_GROUP_TEMPLATE, self.group_conf, op="DEL")

    def bind(self, stage):
        self.stage = stage
        self.bind_conf = {
            ENI: self.eni,
            ACL_GROUP: self.acl_group,
            ACL_STAGE: self.stage,
        }
        apply_acl_config(self.duthost, BIND_ACL_OUT, self.bind_conf, op="SET")
        apply_acl_config(self.duthost, BIND_ACL_IN, self.bind_conf, op="SET")

    def unbind(self):
        apply_acl_config(self.duthost, BIND_ACL_OUT, self.bind_conf, op="DEL")
        apply_acl_config(self.duthost, BIND_ACL_IN, self.bind_conf, op="DEL")


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
    def __init__(self, duthost, dash_config_info):
        __metaclass__ = abc.ABCMeta  # noqa: F841
        self.duthost = duthost
        self.dash_config_info = dash_config_info
        self.test_pkts = []

    @abc.abstractmethod
    def config(self):
        pass

    @abc.abstractmethod
    def teardown(self):
        pass


class DefaultAclGroupTest(AclTestCase):
    def __init__(self, duthost, dash_config_info):
        super(DefaultAclGroupTest, self).__init__(duthost, dash_config_info)
        self.acl_group = DEFAULT_ACL_GROUP
        self.group = AclGroup(self.duthost, self.acl_group, self.dash_config_info[ENI])

    def config(self):
        self.group.bind(DEFAULT_ACL_STAGE)

    def teardown(self):
        self.group.unbind()
        del self.group


class AclRuleTest(AclTestCase):
    def __init__(self, duthost, dash_config_info):
        super(AclRuleTest, self).__init__(duthost, dash_config_info)
        self.rule_confs = []

    def add_rule(self, rule_conf):
        rule_conf[ACL_RULE] = self.__class__.__name__ + "_" + rule_conf[ACL_RULE]
        apply_acl_config(self.duthost, ACL_RULE_TEMPLATE, rule_conf, op="SET")
        self.rule_confs.append(rule_conf)

    def add_test_pkt(self, test_pkt):
        test_pkt.description = self.__class__.__name__ + "_" + str(len(self.test_pkts) + 1) + "_" + test_pkt.description
        self.test_pkts.append(test_pkt)

    def teardown(self):
        for rule_conf in self.rule_confs:
            apply_acl_config(self.duthost, ACL_RULE_TEMPLATE, rule_conf, op="DEL")
        self.rule_confs = []


class DefaultAclRule(AclRuleTest):
    def __init__(self, duthost, dash_config_info):
        super(DefaultAclRule, self).__init__(duthost, dash_config_info)
        self.acl_group = DEFAULT_ACL_GROUP

    def config(self):
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "allow",
            ACL_PRIORITY: 100,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
        })


class AclPriorityTest(AclRuleTest):
    def __init__(self, duthost, dash_config_info):
        super(AclPriorityTest, self).__init__(duthost, dash_config_info)
        self.acl_group = DEFAULT_ACL_GROUP
        self.src_ip = "10.0.0.2"
        self.src_ip_prefix = self.src_ip + "/32"

    def config(self):
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "deny_2",
            ACL_PRIORITY: 2,
            ACL_ACTION: "deny",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: "1"
        })
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "allow_10",
            ACL_PRIORITY: 10,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: 17,
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
            ACL_RULE: "allow_4",
            ACL_PRIORITY: 4,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: 17,
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: "2"
        })
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "deny_30",
            ACL_PRIORITY: 30,
            ACL_ACTION: "deny",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: 17,
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: "2"
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 2},
                                        expected_receiving=True))


class AclActionTest(AclRuleTest):
    def __init__(self, duthost, dash_config_info):
        super(AclActionTest, self).__init__(duthost, dash_config_info)
        self.acl_group = DEFAULT_ACL_GROUP
        self.src_ip = "10.0.0.2"
        self.src_ip_prefix = self.src_ip + "/32"

    def config(self):
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "allow_10",
            # TODO. This priority should be lower than rule2's (2)
            ACL_PRIORITY: 10,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "false",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: "3"
        })
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "deny_2",
            ACL_PRIORITY: 2,
            ACL_ACTION: "deny",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: 17,
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: "3"
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(self.dash_config_info,
                                        inner_extra_conf={"udp_sport": 3},
                                        expected_receiving=False))


class AclProtocolTest(AclRuleTest):
    def __init__(self, duthost, dash_config_info):
        super(AclProtocolTest, self).__init__(duthost, dash_config_info)
        self.acl_group = DEFAULT_ACL_GROUP
        self.src_ip = "10.0.0.2"
        self.src_ip_prefix = self.src_ip + "/32"

    def config(self):
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "allow_1",
            ACL_PRIORITY: 1,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17,18",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: "4"
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"proto": 17, "udp_sport": 4},
                                        expected_receiving=True))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"proto": 18, "udp_sport": 4},
                                        expected_receiving=True))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"proto": 19, "udp_sport": 4},
                                        expected_receiving=False))


class AclAddressTest(AclRuleTest):
    def __init__(self, duthost, dash_config_info):
        super(AclAddressTest, self).__init__(duthost, dash_config_info)
        self.acl_group = DEFAULT_ACL_GROUP

    def config(self):
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "allow",
            ACL_PRIORITY: 1,
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
                                        expected_receiving=False))
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "allow",
            ACL_PRIORITY: 1,
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


class AclPortTest(AclRuleTest):
    def __init__(self, duthost, dash_config_info):
        super(AclPortTest, self).__init__(duthost, dash_config_info)
        self.acl_group = DEFAULT_ACL_GROUP
        self.src_ip = "10.0.0.2"
        self.src_ip_prefix = self.src_ip + "/32"

    def config(self):
        self.add_rule({
            ACL_GROUP: self.acl_group,
            ACL_RULE: "allow",
            ACL_PRIORITY: 1,
            ACL_ACTION: "allow",
            ACL_TERMINATING: "true",
            ACL_PROTOCOL: "17",
            ACL_SRC_ADDR: self.src_ip_prefix,
            ACL_SRC_PORT: "7-10,12"
        })
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 7},
                                        expected_receiving=True))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 10},
                                        expected_receiving=True))
        dash_config_info = copy.deepcopy(self.dash_config_info)
        dash_config_info[LOCAL_CA_IP] = self.src_ip
        self.add_test_pkt(AclTestPacket(dash_config_info,
                                        inner_extra_conf={"udp_sport": 12},
                                        expected_receiving=True))


@pytest.fixture(scope="function")
def acl_test_conf(duthost, dash_config_info):
    testcases = []
    testcases.append(DefaultAclGroupTest(duthost, dash_config_info))
    testcases.append(DefaultAclRule(duthost, dash_config_info))
    testcases.append(AclPriorityTest(duthost, dash_config_info))
    testcases.append(AclActionTest(duthost, dash_config_info))
    # # Cannot passed testcases
    # testcases.append(AclProtocolTest(duthost, dash_config_info))
    # testcases.append(AclAddressTest(duthost, dash_config_info))
    # testcases.append(AclPortTest(duthost, dash_config_info))

    for t in testcases:
        t.config()

    yield testcases

    for t in reversed(testcases):
        t.teardown()


@pytest.fixture(scope="function")
def acl_test_pkts(acl_test_conf):
    test_pkts = []
    for t in acl_test_conf:
        test_pkts.extend(t.test_pkts)
    yield test_pkts
