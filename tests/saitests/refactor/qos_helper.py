#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import sys
import logging


def log_message(message, level="info", to_stderr=False):
    if to_stderr:
        sys.stderr.write(message + "\n")
    log_funcs = {
        "debug": logging.debug,
        "info": logging.info,
        "warning": logging.info,
        "error": logging.error,
        "critical": logging.error,
    }
    log_fn = log_funcs.get(level.lower(), logging.info)
    log_fn(message)


def qos_test_assert(ptftest, condition, message=None):
    try:
        assert condition, message
    except AssertionError:
        summarize_diag_counter(ptftest)
        raise  # Re-raise the assertion error to maintain the original assert behavior


def find_subclass(base_class, target_name, attr_name="platform_name"):
    # Dynamically find a subclass of base_class where the attr_name matches target_name
    for subclass in base_class.__subclasses__():
        if target_name in getattr(subclass, attr_name, []):
            return subclass
    return base_class


#
# Deprecated dynamic subclass instantiation based on attributes implement in find_subclass().
# Switched to static lookup table to avoid syntax errors in one platform affecting others.
#

PLATFORM_MAPPING = {
    "PlatformQosCisco": {
        "file": "platform_qos_cisco",
        "supported_skus": ["Cisco-8102-C64"],
    },
    "PlatformQosBroadcom": {
        "file": "platform_qos_broadcom",
        "supported_skus": [],
    },
    "PlatformQosTomhawk": {
        "file": "platform_qos_tomhawk",
        "supported_skus": [],
    },
    "PlatformQosTh3": {
        "file": "platform_qos_th3",
        "supported_skus": [],
    },
    "PlatformQosKvm": {
        "file": "platform_qos_kvm",
        "supported_skus": ["kvm"],
    },
}


TOPOLOGY_MAPPING = {
    "TopologyQosTierOne": {
        "file": "topology_qos_tier_one",
        "supported_topologies": ["t1"],
    },
    "TopologyQosTierOne64Lag": {
        "file": "topology_qos_tier_one_64lag",
        "supported_topologies": ["t1-64-lag"],
    },
}


def instantiate_helper(testcase_instance, hwsku_name, topology_name):
    from platform_qos_base import PlatformQosBase
    from topology_qos_base import TopologyQosBase

    # Factory method to instantiate platform and topology
    # Previously, we used a dynamic approach to find and instantiate subclasses based on attributes.
    # However, this approach had a significant drawback: if any module contained syntax errors or other issues,
    # it could break the entire dynamic lookup process, causing failures even for unrelated platforms.
    # To mitigate this issue, we switched to a static lookup table (mapping) approach.

    platform_class_name = None
    topology_class_name = None

    for class_name, info in PLATFORM_MAPPING.items():
        if hwsku_name in info["supported_skus"]:
            platform_class_name = class_name
            platform_file = info["file"]
            break

    for class_name, info in TOPOLOGY_MAPPING.items():
        if topology_name in info["supported_topologies"]:
            topology_class_name = class_name
            topology_file = info["file"]
            break

    if not platform_class_name or not topology_class_name:
        raise ValueError(f"Unsupported hwsku_name: {hwsku_name} or topology_name: {topology_name}")

    platform_module = __import__(platform_file, fromlist=[platform_class_name])
    topology_module = __import__(topology_file, fromlist=[topology_class_name])

    platform_class = getattr(platform_module, platform_class_name)
    topology_class = getattr(topology_module, topology_class_name)

    platform_instance = platform_class()
    topology_instance = topology_class()

    testcase_instance.platform = platform_instance
    testcase_instance.topology = topology_instance
    platform_instance.testcase = testcase_instance
    platform_instance.topology = topology_instance
    topology_instance.testcase = testcase_instance
    topology_instance.platform = platform_instance
