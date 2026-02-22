import pytest


@pytest.fixture
def acl_rule_fixture_npu1_dpu1(npu1_ip, dpu1_ip):
    """
    Fixture to return ACL_RULE dictionary using NPU1 and DPU1 IPs.
    """
    acl_rule = {
        "ACL_RULE": {
            "ACL_LINK_DROP_TEST|LOCAL_PROBE_DROP1": {
                "PACKET_ACTION": "DROP",
                "PRIORITY": "1",
                "SRC_IP": npu1_ip,
                "DST_IP": dpu1_ip,
                "IP_TYPE": "IP",
                "L4_SRC_PORT": "3784"
            },
            "ACL_LINK_DROP_TEST|LOCAL_PROBE_DROP2": {
                "PACKET_ACTION": "DROP",
                "PRIORITY": "1",
                "SRC_IP": dpu1_ip,
                "DST_IP": npu1_ip,
                "IP_TYPE": "IP",
                "L4_SRC_PORT": "3784"
            }
        }
    }
    return acl_rule


@pytest.fixture
def acl_rule_fixture_npu2_dpu2(npu2_ip, dpu2_ip):
    """
    Fixture to return ACL_RULE dictionary using NPU2 and DPU2 IPs.
    """
    acl_rule = {
        "ACL_RULE": {
            "ACL_LINK_DROP_TEST|LOCAL_PROBE_DROP1": {
                "PACKET_ACTION": "DROP",
                "PRIORITY": "1",
                "SRC_IP": npu2_ip,
                "DST_IP": dpu2_ip,
                "IP_TYPE": "IP",
                "L4_SRC_PORT": "3784"
            },
            "ACL_LINK_DROP_TEST|LOCAL_PROBE_DROP2": {
                "PACKET_ACTION": "DROP",
                "PRIORITY": "1",
                "SRC_IP": dpu2_ip,
                "DST_IP": npu2_ip,
                "IP_TYPE": "IP",
                "L4_SRC_PORT": "3784"
            }
        }
    }
    return acl_rule
