"""
PDDF / PDDF BMC Feature library functions.
Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
"""

import random
from spytest import st
from spytest.dicts import SpyTestDict
import apis.system.box_services as bsapi
import apis.system.basic as baapi
import apis.system.interface as intapi
import apis.system.reboot as rbapi
import utilities.utils as utils
from utilities.common import make_list, filter_and_select


pddf_data = SpyTestDict()


def init_vars():
    global vars
    vars = st.ensure_min_topology("D1")


def initialize_variables(feature):
    pddf_data.clear()
    pddf_data.feature = feature
    pddf_data.hw_constants = st.get_datastore(vars.D1, "constants")
    pddf_data.support = {"PDDF": "PDDF_SUPPORTED_PLATFORMS",
                         "PDDF_BMC": "PDDF_BMC_SUPPORTED_PLATFORMS"}
    pddf_data.version = '2.0'
    get_params()
    return pddf_data


def get_params():
    pddf_data.base_mac_address = baapi.get_ifconfig_ether(vars.D1, "eth0")
    pddf_data.platform_name_summary = baapi.get_platform_summary(vars.D1)
    pddf_data.platform_hwsku = pddf_data.platform_name_summary["hwsku"].lower()
    platform_check()
    pddf_data.platform_name = pddf_data.platform_name_summary["platform"]
    pddf_data.serial_number = baapi.show_version(vars.D1)['serial_number']
    pddf_data.platform_constants = st.get_datastore(vars.D1, "constants", pddf_data.platform_hwsku)
    pddf_data.fan_list = pddf_data.platform_constants.get("PDDF_FANS_LIST", None)
    pddf_data.psu_list = pddf_data.platform_constants.get("PDDF_PSU_LIST", None)
    pddf_data.thermal_list = pddf_data.platform_constants.get("PDDF_THERMAL_LIST", None)
    pddf_data.manufacturer = pddf_data.platform_constants.get("Manufacturer", None)
    if not all([pddf_data.fan_list, pddf_data.psu_list, pddf_data.thermal_list, pddf_data.manufacturer]):
        st.report_env_fail("pddf_get_constanc_fail", pddf_data.feature, pddf_data.platform_hwsku)
    pddf_data.up_port_list = intapi.get_up_interfaces(vars.D1)
    if not pddf_data.up_port_list:
        st.report_env_fail("up_interface_not_found", pddf_data.feature)
    pddf_data.up_port = get_sfpytils_supported_up_interface()
    if any("/" in interface for interface in make_list(pddf_data.up_port_list)):
        pddf_data.up_port_list = st.get_other_names(vars.D1, make_list(pddf_data.up_port_list))
        pddf_data.alias_up_port = st.get_other_names(vars.D1, make_list(pddf_data.up_port))[0]
    else:
        pddf_data.alias_up_port = pddf_data.up_port
    #Removed Warm reboot as it's not supported in Buzznik+
    pddf_data.reboot_cause_dict = {'warm': 'warm-reboot', 'fast': 'fast-reboot', 'normal': "issued 'reboot'"}
    pddf_data.reboot_type = random.sample(pddf_data.reboot_cause_dict.keys(), k=1)[0]
    if pddf_data.platform_hwsku not in pddf_data.hw_constants['WARM_REBOOT_SUPPORTED_PLATFORMS']:
        pddf_data.reboot_cause_dict.pop('warm')
        pddf_data.reboot_type = random.sample(pddf_data.reboot_cause_dict.keys(), k=1)[0]


def get_sfpytils_supported_up_interface():
    """
    This function return the First UP interface which supports SFP utils.
    :return:
    """
    out = bsapi.show_sfputil(vars.D1, 'lpmode')
    for port in pddf_data.up_port_list:
        if "/" in port:
            port = st.get_other_names(vars.D1, make_list(port))[0]
        if filter_and_select(out, None, {'port': port}):
            return port


def report_pass(msgid, *argv):
    st.report_pass(msgid, pddf_data.feature, *argv)


def report_fail(msgid, *argv):
    st.report_fail(msgid, pddf_data.feature, *argv)


def log(msg):
    st.log("{}: {}".format(pddf_data.feature, msg))


def platform_check():
    if pddf_data.platform_hwsku not in pddf_data.hw_constants[pddf_data.support[pddf_data.feature]]:
        st.report_unsupported('pddf_unsupported', pddf_data.feature, pddf_data.platform_hwsku)


def pddf_module_prolog():
    log("Configuring on DUT")
    if not bsapi.config_pddf_mode(vars.D1, module_name="switch-pddf", iteration=300):
        report_fail("pddf_mode_set_failed", 'Enable')
    st.wait(2)


def pddf_module_epilog():
    log("Un configuring on DUT")
    if not bsapi.config_pddf_mode(vars.D1, module_name="switch-nonpddf"):
        report_fail("pddf_mode_set_failed", 'Disable')


def verify_pddf_running():
    log("Checking PDDF is running on DUT")
    if not bsapi.is_service_active(vars.D1, service="pddf"):
        st.report_fail("pddf_service_is_not_running")


def verify_syseeprom_values(output):
    """
    Common function to verify the syseeprom values
    """
    log("Checking platform syseeprom with data ..")
    log("OUTPUT : {}".format(output))
    if not utils.check_empty_values_in_dict(output):
        report_fail("empty_values_observed", 'platform syseeprom')
    if output.get("Base MAC Address").lower() != pddf_data.base_mac_address.lower():
        report_fail("value_mismatch", "Base MAC Address")
    if output.get('Platform Name') != pddf_data.platform_name:
        st.log("Observed mismatch in platform name check, moving to BMC check")
        platform_name = output.get('Platform Name').split("_")
        syseeprom_pltf_name = pddf_data.platform_name.split("_")
        diff = utils.list_diff(platform_name, syseeprom_pltf_name)
        if diff:
            index = platform_name.index(diff[0])
            if index:
                platform_name[index] = "common"
                new_pltf_name = "_".join(platform_name)
                st.log("PLATFORM NAME FOR BCM -- {}".format(new_pltf_name))
                if output.get('Platform Name') != new_pltf_name:
                    report_fail("value_mismatch", "Platform Name")
    if output.get('Manufacturer').lower() != pddf_data.manufacturer.lower():
        report_fail("value_mismatch", "Manufacturer")
    if output.get('Serial Number') != pddf_data.serial_number:
        report_fail("value_mismatch", "Serial Number")


def lib_ft_show_platform_syseeprom():
    """
    Verify the output of 'show platform syseeprom' command.
    """
    log("Getting platform syseeprom details ...")
    output = baapi.get_platform_syseeprom_as_dict(vars.D1, tlv_name=None, key='value', decode=False)
    verify_syseeprom_values(output)
    report_pass("show_platform_syseeprom_command_verified")


def lib_ft_decode_syseeprom():
    """
    Verify the output of "decode-syseeprom" command.
    """
    log("Getting platform syseeprom details using decode option ...")
    output = baapi.get_platform_syseeprom_as_dict(vars.D1, tlv_name=None, key='value', decode=True)
    verify_syseeprom_values(output)
    report_pass("decode_syseeprom_command_verified")


def lib_ft_pddf_fan_status_util():
    """
    Verify the output of 'show platform fanstatus' command.
    Verify the output of "pddf_fanutil" command.
    """
    result = dict()
    log("Verfying platform fanstatus details.")
    if not bsapi.verify_platform_fan_params(vars.D1, pddf_data.fan_list):
        report_fail("fan_params_verification_failed")
    log("Verifying fanutil direction.")
    mode_list = ["direction", "getspeed", "numfans", "status", "version"]
    for mode in mode_list:
        if not bsapi.verify_pddf_fanutil(vars.D1, mode, pddf_data.fan_list, version=pddf_data.version):
            result[mode] = True
    for key, value in result.items():
        if not value:
            report_fail("pddf_fanutil_verification_failed", key)
    report_pass("pddf_fanstatus_verification_success")


def lib_ft_pddf_psu_summary_util():
    """
    Verify the output of "psuutil" command.
    Verify the output of 'show platform psusummary' command.
    Verify the output of "pddf_psuutil" command.
    """
    log("Verifying the PSU-SUMMARY data")
    if not bsapi.verify_platform_psu_params(vars.D1):
        report_fail("platform_psu_summary_verification_failed")
    log("Verifying the PSU-Util data")
    if not bsapi.verify_psuutil_data(vars.D1, 'status', 'numpsus',  psu_list=pddf_data.psu_list):
        report_fail("pddf_psu_util_verification_failed")
    log("Verifying the PDDF_MFR_info data")
    if not bsapi.verify_pddf_psuutils(vars.D1, 'status', 'numpsus', 'mfrinfo', 'seninfo', psu_list=pddf_data.psu_list):
        report_fail("pddf_psu_mfr_info_verification_failed", vars.D1)
    report_pass("pddf_psu_summary_util_verification_success")


def lib_ft_pddf_show_sfputil():
    """
    Verify the output of "sfputil" command.
    Verify the output of "show interface transceiver eeprom" command.
    Verify the output of "show interface transceiver presence" command.
    """
    log("Verifying the SFPUTIL data")
    log("Enabling and disabling SFP lp-mode on the interface")
    bsapi.config_sfputil(vars.D1, mode='lpmode', action='on', interface=pddf_data.up_port)
    if not bsapi.verify_sfputil_show_interface_tranceiver(vars.D1, mode='lpmode', port=pddf_data.up_port,
                                                          lpmode='On', cmd='utils'):
        report_fail("sfp_lp_mode_x_failed", 'enable', pddf_data.up_port)
    bsapi.config_sfputil(vars.D1, mode='lpmode', action='off', interface=pddf_data.up_port)
    if not bsapi.verify_sfputil_show_interface_tranceiver(vars.D1, mode='lpmode', port=pddf_data.up_port,
                                                          lpmode='Off', cmd='utils'):
        report_fail("sfp_lp_mode_x_failed", 'disable', pddf_data.up_port)

    log("Verifying SFP presense status on the interface")
    if not bsapi.verify_sfputil_show_interface_tranceiver(vars.D1, mode='presence', port=pddf_data.alias_up_port,
                                                          presence='Present', cmd='utils'):
        report_fail("sfp_presence_not_found", pddf_data.up_port)

    if not bsapi.verify_sfputil_show_interface_tranceiver(vars.D1, mode='presence', port=pddf_data.alias_up_port,
                                                          presence='Present', cmd='show'):
        report_fail("sfp_presence_not_found", pddf_data.up_port)

    log("Performing sfp reset on the interface...")
    if not bsapi.config_sfputil(vars.D1, mode='reset', interface=pddf_data.up_port):
        report_fail("sfp_reset_failed", pddf_data.up_port)

    log("Verifying SFP EEPROM detection on the interface")
    if not bsapi.verify_sfputil_show_interface_tranceiver(vars.D1, mode='eeprom', port=pddf_data.alias_up_port,
                                                          eeprom_status='SFP EEPROM detected'):
        report_fail("sfp_eeprom_detection_failed", pddf_data.up_port)
    if not bsapi.verify_sfputil_show_interface_tranceiver(vars.D1, mode='eeprom', port=pddf_data.alias_up_port,
                                                          eeprom_status='SFP EEPROM detected', cmd='show'):
        report_fail("sfp_eeprom_detection_failed", pddf_data.up_port)
    report_pass("pddf_show_sfputil_verification_success")


def lib_ft_pddf_led_util():
    """
    Verify the output of "pddf_ledutil" command.
    """
    pddf_data.led_test = {'LOC_LED': {'on': ['STATUS_LED_COLOR_BLUE', 'True', 'blue'],
                                      'faulty': ['STATUS_LED_COLOR_RED', 'False', 'blue'],
                                      'off': ['STATUS_LED_COLOR_OFF', 'True', 'off']},
                          'DIAG_LED': {'on': ['STATUS_LED_COLOR_GREEN', 'True', 'green'],
                                       'faulty': ['STATUS_LED_COLOR_RED', 'True', 'red'],
                                       'off': ['STATUS_LED_COLOR_OFF', 'True', 'off']}}
    log("Validating LED UTILs commands")
    if not bsapi.verify_pddf_ledutil(vars.D1, pddf_data.led_test):
        report_fail("pddf_led_validation_failed")
    report_pass("pddf_led_validation_success")


def lib_ft_pddf_thermal_util():
    """
    Verify the output of "pddf_thermalutil" command.
    """
    log("Validating the THERMAL UTILs commands")
    if not bsapi.verify_pddf_thermalutil(vars.D1, 'gettemp', pddf_data.thermal_list):
        report_fail("pddf_thermalutil_validation_failed", "gettemp")
    if not bsapi.verify_pddf_thermalutil(vars.D1, 'numthermals', pddf_data.thermal_list):
        report_fail("pddf_thermalutil_validation_failed", "numthermals")
    if not bsapi.verify_pddf_thermalutil(vars.D1, 'version', pddf_data.thermal_list, version=pddf_data.version):
        report_fail("pddf_thermalutil_validation_failed", "version")
    report_pass("pddf_thermalutil_validation_success")


def lib_ft_pddf_verify_sys_environment():
    """
    Verify the output of "show environment" command.
    """
    log("Verifying the show environment data ")
    if pddf_data.feature == 'PDDF':
        fanlist_env = ["fan{}".format(i) for i in range(1, len(pddf_data.fan_list) + 1)]
    else:
        fanlist_env = pddf_data.fan_list + pddf_data.thermal_list + ['PSU']
    if not bsapi.verify_show_environment(vars.D1, fanlist_env):
        report_fail("show_environment_o/p_validation_failed")
    report_pass("show_environment_o/p_validation_success")


def lib_ft_pddf_debug_command():
    """
    Verify that system should be stable after executing all PDDF debug commands.
    """
    log("Validating the debug commands")
    bsapi.run_debug_commands(vars.D1)
    if not baapi.get_system_status(vars.D1):
        report_fail("system_down_status_observed")
    report_pass("system_status_up_post_pddf_debug")


def lib_ft_pddf_reboot_cause():
    """
    Verify the output of "show reboot-cause" command.
    """
    log("# Device is rebooting - Type = {}".format(pddf_data.reboot_type))
    st.reboot(vars.D1, pddf_data.reboot_type)
    if not pddf_data.reboot_cause_dict[pddf_data.reboot_type] in rbapi.get_reboot_cause(vars.D1)[0]['message']:
        report_fail("pddf_reboot_cause_validation_failed", pddf_data.reboot_type)
    report_pass("pddf_reboot_cause_validation_success", pddf_data.reboot_type)
