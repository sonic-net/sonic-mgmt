from dataclasses import dataclass
from typing import List

ALL_ATTRIBUTES = "all"


@dataclass
class ConsistencyCheckQueryKey:
    key: str
    attributes: List[str]


BROADCOM_KEYS: List[ConsistencyCheckQueryKey] = [
    ConsistencyCheckQueryKey("ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_POOL:*", attributes=[ALL_ATTRIBUTES]),
    ConsistencyCheckQueryKey("ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:*", attributes=[ALL_ATTRIBUTES]),
    ConsistencyCheckQueryKey("ASIC_STATE:SAI_OBJECT_TYPE_SWITCH:*", attributes=[ALL_ATTRIBUTES]),
    ConsistencyCheckQueryKey("ASIC_STATE:SAI_OBJECT_TYPE_WRED:*", attributes=[ALL_ATTRIBUTES]),
    ConsistencyCheckQueryKey(
        "ASIC_STATE:SAI_OBJECT_TYPE_PORT:*",
        attributes=[
            "SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP",
            "SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP",
            "SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_QUEUE_MAP",
            "SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP",
            "SAI_PORT_ATTR_MTU",
            "SAI_PORT_ATTR_INGRESS_ACL",
            "SAI_PORT_ATTR_AUTO_NEG_MODE",
            "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL",
            "SAI_PORT_ATTR_ADMIN_STATE",
            "SAI_PORT_ATTR_FEC_MODE",
            # The "get" implementation of the SAI_PORT_ATTR_SPEED attribute sometimes has a side effect of changing
            # the port speed. Consistency-checker should not change the state of the DUT, so we ignore this attribute
            # "SAI_PORT_ATTR_SPEED",
            # This attribute doesn't match between ASIC_DB and ASIC SAI and the test fails the assertion
            # "SAI_PORT_ATTR_PORT_VLAN_ID",
        ]
    ),
]


# The list of platforms and versions that have been tested to work with the consistency checker
SUPPORTED_PLATFORMS_AND_VERSIONS = {
    "x86_64-arista_7060_cx32s": {
        "202305": BROADCOM_KEYS,
        "202311": BROADCOM_KEYS,
    },
    "x86_64-arista_7260cx3_64": {
        "202305": BROADCOM_KEYS,
        "202311": BROADCOM_KEYS,
    },
}
