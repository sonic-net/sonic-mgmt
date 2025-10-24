from typing import Dict, List
CONFIG_FILE_PATH_DEFAULT = "dci/device_configs/config.yaml"

DCI_CLIS: Dict[str, List[str]] = {
        "add":[
            "neighbor OVERLAY_DC domain vxlan-local",
            "neighbor OVERLAY_DC reoriginate vxlan-remote",
            "neighbor OVERLAY_WAN domain vxlan-remote",
            "neighbor OVERLAY_WAN reoriginate vxlan-local",
            "exit"
        ],
        "del": [
            "no neighbor OVERLAY_DC domain vxlan-local",
            "no neighbor OVERLAY_DC reoriginate vxlan-remote",
            "no neighbor OVERLAY_WAN domain vxlan-remote",
            "no neighbor OVERLAY_WAN reoriginate vxlan-local",
            "exit"
        ]
    }


DCI_VLAN_VNI_MAPPING_DEL: Dict[str, Dict[str, List[str]]] = {
    "dc1gw1": 
    {
        "add":[
            "sudo config vxlan map add vxlan-local 10 5010",
            "sudo config vxlan map add vxlan-local 20 5020",
            "sudo config vxlan map add vxlan-remote 10 5011",
            "sudo config vxlan map add vxlan-remote 20 5021"
        ],
        "del":[
            "sudo config vxlan map del vxlan-local 10 5010",
            "sudo config vxlan map del vxlan-local 20 5020",
            "sudo config vxlan map del vxlan-remote 10 5011",
            "sudo config vxlan map del vxlan-remote 20 5021"
        ],
    },
    "dc1gw2": {
        "add": [
            "sudo config vxlan map add vxlan-local 10 5010",
            "sudo config vxlan map add vxlan-local 20 5020",
            "sudo config vxlan map add vxlan-remote 10 5011",
            "sudo config vxlan map add vxlan-remote 20 5021"
        ],
        "del":[
            "sudo config vxlan map del vxlan-local 10 5010",
            "sudo config vxlan map del vxlan-local 20 5020",
            "sudo config vxlan map del vxlan-remote 10 5011",
            "sudo config vxlan map del vxlan-remote 20 5021"
        ],
    },
    "dc2gw1": {
        "add": [
            "sudo config vxlan map add vxlan-local 10 7010",
            "sudo config vxlan map add vxlan-local 20 7020",
            "sudo config vxlan map add vxlan-remote 10 5011",
            "sudo config vxlan map add vxlan-remote 20 5021"
        ],
        "del": [
            "sudo config vxlan map del vxlan-local 10 7010",
            "sudo config vxlan map del vxlan-local 20 7020",
            "sudo config vxlan map del vxlan-remote 10 5011",
            "sudo config vxlan map del vxlan-remote 20 5021"
        ],
    },
    "dc3gw1": {
        "add": [
            "sudo config vxlan map add vxlan-local 10 8010",
            "sudo config vxlan map add vxlan-local 20 8020",
            "sudo config vxlan map add vxlan-remote 10 5011",
            "sudo config vxlan map add vxlan-remote 20 5021"
        ],
        "del": [
            "sudo config vxlan map del vxlan-local 10 8010",
            "sudo config vxlan map del vxlan-local 20 8020",
            "sudo config vxlan map del vxlan-remote 10 5011",
            "sudo config vxlan map del vxlan-remote 20 5021"
        ]
    },
}
