from typing import Dict, List

"""
key: DUT Name
value: List of routes (IP addresses) from which we don't expect reorigination
        to occur for routes of type 5, type 4 and type 1 respectively.
"""
no_reorigination_routes: Dict[str, List[str]] = {
    "dc1gw1": [
        "102.102.102.102",
        "103.103.103.103",
        "fd28::233:d0c6:fed7",
        "fd29::233:d0c6:fed8",

    ],
    "dc1gw2": [
        "102.102.102.102",
        "103.103.103.103",
        "fd28::233:d0c6:fed7",
        "fd29::233:d0c6:fed8",
    ],
    "dc2gw1": [
        "101.101.101.101",
        "103.103.103.103",
        "fd27::233:d0c6:fed5",
        "fd27::233:d0c6:fed6",
        "fd29::233:d0c6:fed8",
    ],
    "dc3gw1": [
        "101.101.101.101",
        "102.102.102.102",
        "fd27::233:d0c6:fed5",
        "fd27::233:d0c6:fed6",
        "fd28::233:d0c6:fed7",
    ],
}
