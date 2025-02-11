from dataclasses import dataclass
from typing import List

ALL_ATTRIBUTES = "all"


@dataclass
class ConsistencyCheckQueryKey:
    key: str
    attributes: List[str]


ARISTA_KEYS: List[ConsistencyCheckQueryKey] = [
    ConsistencyCheckQueryKey("ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_POOL:*", attributes=[ALL_ATTRIBUTES]),
    ConsistencyCheckQueryKey("ASIC_STATE:SAI_OBJECT_TYPE_BUFFER_PROFILE:*", attributes=[ALL_ATTRIBUTES]),
    ConsistencyCheckQueryKey("ASIC_STATE:SAI_OBJECT_TYPE_SWITCH:*", attributes=[ALL_ATTRIBUTES]),
    ConsistencyCheckQueryKey("ASIC_STATE:SAI_OBJECT_TYPE_WRED:*", attributes=[ALL_ATTRIBUTES]),
]


# The list of platforms and versions that have been tested to work with the consistency checker
SUPPORTED_PLATFORMS_AND_VERSIONS = {
    "x86_64-arista_7060_cx32s": {
        "202305": ARISTA_KEYS,
        "202311": ARISTA_KEYS,
    },
    "x86_64-arista_7260cx3_64": {
        "202305": ARISTA_KEYS,
        "202311": ARISTA_KEYS,
    },
}
