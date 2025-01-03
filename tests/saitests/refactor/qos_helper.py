#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import sys
import logging


def log_message(message, level='info', to_stderr=False):
    if to_stderr:
        sys.stderr.write(message + "\n")
    log_funcs = {'debug':    logging.debug,
                 'info':     logging.info,
                 'warning':  logging.info,
                 'error':    logging.error,
                 'critical': logging.error}
    log_fn = log_funcs.get(level.lower(), logging.info)
    log_fn(message)







def find_subclass(base_class, target_name, attr_name="platform_name"):
    # Dynamically find a subclass of base_class where the attr_name matches target_name
    for subclass in base_class.__subclasses__():
        if target_name in getattr(subclass, attr_name, []):
            return subclass
    return base_class


def associate_helper(instance, helper):
    # Associate helper with an instance
    instance.helper = helper


def instantiate_helper(case_instance, hwsku_name, topology_name):
    from platform_qos_base import PlatformQosBase
    from topology_qos_base import TopologyQosBase
    # Factory method to instantiate QosHelper with platform and topology
    platform_class = find_subclass(PlatformQosBase, hwsku_name, attr_name="hwsku_name")
    topology_class = find_subclass(TopologyQosBase, topology_name, attr_name="topology_name")
    platform_instance = platform_class()
    topology_instance = topology_class()
    helper = QosHelper(case_instance, platform_instance, topology_instance)
    associate_helper(platform_instance, helper)
    associate_helper(topology_instance, helper)
    return helper


#
# wrappers
#

def get_case(instance):
    helper = instance.helper if instance and hasattr(instance, 'helper') else None
    return helper.case if helper and hasattr(helper, 'case') else None


def get_platform(instance):
    helper = instance.helper if instance and hasattr(instance, 'helper') else None
    return helper.platform if helper and hasattr(helper, 'platform') else None


def get_topology(instance):
    helper = instance.helper if instance and hasattr(instance, 'helper') else None
    return helper.topology if helper and hasattr(helper, 'topology') else None


class QosHelper():

    def __init__(self, case, platform, topology):
        self.case = case
        self.platform = platform
        self.topology = topology


    #
    # dynamic proxy
    #

    def __getattr__(self, name):
        # Dynamic proxy to delegate calls to platform or topology based on method availability
        if hasattr(self.platform, name):
            return getattr(self.platform, name)
        elif hasattr(self.topology, name):
            return getattr(self.topology, name)
        raise AttributeError(f"'{name}' not found in either platform or topology")
