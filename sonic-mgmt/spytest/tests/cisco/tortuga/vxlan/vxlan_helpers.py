import time
import json
import logging
import tempfile
import re
import allure
from spytest import st

from datetime import datetime

import pytest

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory, change_mac_addresses
from tests.common.config_reload import config_reload


def add_config():
    pass

def remove_config():
    pass

def add_vlan():
    pass

def remove_vlan():
    pass

def add_vlan_member():
    pass

def remove_vlan_member():
    pass

def add_bgp_config():
    pass

def remove_bgp_config():
    pass

def add_vxlan_vtep():
    pass

def remove_vxlan_vtep():
    pass

def add_loopback():
    pass

def remove_loopback():
    pass

def add_vlan_vni_map():
    pass

def remove_vlan_vni_map():
    pass

def add_vrf_vni_map():
    pass

def remove_vrf_vni_map():
    pass

def add_svi_interface():
    pass

def remove_svi_interface():
    pass

def bring_up_interface(dut, ifaces):
    for iface in ifaces:
        st.config(leaf0, 'sudo config interface startup {}'.format(iface))

def bring_down_interface():
    for iface in ifaces:
        st.config(leaf0, 'sudo config interface shutdown {}'.format(iface))
