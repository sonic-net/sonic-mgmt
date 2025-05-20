import pytest


# npu_ip and dpu_ip fixured already commited
@pytest.fixture
def acl_rule_fixture(npu_ip, dpu_ip):
    """
    Fixture to return ACL_RULE dictionary using real NPU and DPU IPs.
    """
    acl_rule = {
        "ACL_RULE": {
            "ACL_LINK_DROP_TEST|LOCAL_PROBE_DROP1": {
                "PACKET_ACTION": "DROP",
                "PRIORITY": "1",
                "SRC_IP": npu_ip,
                "DST_IP": dpu_ip,
                "IP_TYPE": "IP",
                "L4_SRC_PORT": "3784"
            },
            "ACL_LINK_DROP_TEST|LOCAL_PROBE_DROP2": {
                "PACKET_ACTION": "DROP",
                "PRIORITY": "1",
                "SRC_IP": dpu_ip,
                "DST_IP": npu_ip,
                "IP_TYPE": "IP",
                "L4_SRC_PORT": "3784"
            }
        }
    }

    return acl_rule
