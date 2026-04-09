import os
import re

from tests.platform_tests.mellanox.interface_utils import get_physical_index_to_interfaces_map

SC_ENABLED = 1

PLATFORM_FOLDER_PATH = "/usr/share/sonic/device/"
SAI_PROFILE_FILE_NAME = "sai.profile"
SC_SAI_ATTRIBUTE_NAME = "SAI_INDEPENDENT_MODULE_MODE"

PLATFORM_GENERATION = ['4280', '4700', '5600', '5610', '5640']


def check_sc_sai_attribute_value(duthost):
    """
    @summary: This method is for checking if Software Control SAI attribute set to 1 in sai.profile
    @param: duthosts: duthosts fixture
    """
    dut_hwsku = duthost.facts['hwsku']
    dut_platfrom = duthost.facts['platform']
    sai_profile_path = os.path.join(PLATFORM_FOLDER_PATH, dut_platfrom, dut_hwsku, SAI_PROFILE_FILE_NAME)
    cmd = duthost.shell('cat {}'.format(sai_profile_path))
    if SC_SAI_ATTRIBUTE_NAME in cmd['stdout']:
        sc_enabled_in_sai = re.search(f"{SC_SAI_ATTRIBUTE_NAME}=(\\d?)", cmd['stdout']).group(1)
        if sc_enabled_in_sai == '1':
            return True
    return False


def get_ports_supporting_sc(duthost, only_ports_index_up=False):
    """
    @summary: This method is for get DUT ports supporting Software Control
    @param: duthost: duthost fixture
    @param: enum_frontend_asic_index: enum_frontend_asic_index fixture
    @return: list of Software Control ports supported
    """
    physical_ports_map = get_physical_index_to_interfaces_map(duthost, only_ports_index_up=only_ports_index_up)
    cmd = 'for i in /sys/module/sx_core/asic0/module*/control; do echo -n "$(basename $(dirname $i)): "; cat $i; done'
    res = duthost.shell(cmd)['stdout'].splitlines()
    ports_with_sc_support = []
    for module_sc_status in res:
        module_number, sc_status = re.findall(r'module(\d+): (\d+)', module_sc_status)[0]
        port_number = int(module_number) + 1
        if int(sc_status) == SC_ENABLED and str(port_number) in physical_ports_map:
            ports_with_sc_support.extend(physical_ports_map[str(port_number)])
    return ports_with_sc_support


def sc_ms_sku(duthost):
    """
    @summary: This method checking if HWSKU is Microsoft
    @param: duthost: duthost fixture
    @return: True if HWSKU is in platform generation supporting Software Control feature
    """
    return any(item in duthost.facts['hwsku'] for item in PLATFORM_GENERATION)


def is_spc1(duthost):
    """
    @summary: This method checking if platform is SPC1
    @param: duthost: duthost fixture
    @return: True if platform is SPC1 else false
    """
    return True if "sn2" in duthost.facts["platform"] else False


def is_spc2(duthost):
    """
    @summary: This method checking if platform is SPC2
    @param: duthost: duthost fixture
    @return: True if platform is SPC2 else false
    """
    return True if "sn3" in duthost.facts["platform"] else False


def sc_supported(duthost):
    """
    @summary: This method checking if platform supports Software Control feature
    @param: duthost: duthost fixture
    @return: True if platform supports Software Control feature else false
    """
    return True if not is_spc1(duthost) and not is_spc2(duthost) else False
