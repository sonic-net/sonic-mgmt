import re
import logging
import ast


def check_sfp_eeprom_info(duthost, sfp_eeprom_info, is_support_dom, show_eeprom_cmd, is_flat_memory):
    """
    This method is check sfp info is correct or not.
    1. Check if all expected keys exist in the sfp_eeprom_info
    2. Check if Check Vendor name is Mellnaox and Vendor OUI is 00-02-c9
    3. When cable support dom, check the corresponding keys related to monitor exist,
       and the the corresponding value has correct format
    """
    logging.info("Check all expected keys exist in sfp info")
    expected_keys = set(["Application Advertisement", "Connector", "Encoding", "Extended Identifier",
                         "Extended RateSelect Compliance", "Identifier", "Nominal Bit Rate(100Mbs)",
                         "Specification compliance", "Vendor Date Code(YYYY-MM-DD Lot)",
                         "Vendor Name", "Vendor OUI", "Vendor PN", "Vendor Rev", "Vendor SN", "ChannelMonitorValues",
                         "ChannelThresholdValues", "ModuleMonitorValues", "ModuleThresholdValues"])
    excluded_keys = set()
    if "202012" in duthost.os_version and show_eeprom_cmd == "sudo sfputil show eeprom -d":
        if "TypeOfTransceiver" in sfp_eeprom_info and sfp_eeprom_info["TypeOfTransceiver"] == "SFP/SFP+/SFP28":
            # There is a bug:https://github.com/sonic-net/sonic-buildimage/issues/12357
            # So for SFP/SFP+/SFP28, we need do special handle
            expected_keys = set(["Connector", "EncodingCodes", "ExtIdentOfTypeOfTransceiver",
                                 "NominalSignallingRate(UnitsOf100Mbd)", "RateIdentifier",
                                 "ReceivedPowerMeasurementType",
                                 "VendorDataCode(YYYY-MM-DD Lot)", "TypeOfTransceiver", "TransceiverCodes",
                                 "VendorName", "VendorOUI", "VendorPN", "VendorRev", "VendorSN"])
            is_support_dom = False
        else:
            excluded_keys = set(
                ["Application Advertisement", "ChannelThresholdValues", "ModuleThresholdValues"])
            expected_keys = expected_keys - excluded_keys

    if "Identifier" in sfp_eeprom_info and sfp_eeprom_info["Identifier"] == "SFP/SFP+/SFP28":
        excluded_keys = excluded_keys | {"ChannelMonitorValues", "ChannelThresholdValues", "ModuleMonitorValues",
                                         "ModuleThresholdValues"}
        expected_keys = (expected_keys | {
                         "MonitorData", "ThresholdData"}) - excluded_keys

    if is_flat_memory and show_eeprom_cmd == "sudo sfputil show eeprom -d":
        logging.info("SKip dom parameters check due to port with flat memory")
        excluded_keys = excluded_keys | {"ChannelMonitorValues", "ChannelThresholdValues", "ModuleMonitorValues",
                                         "ModuleThresholdValues"}
        expected_keys = expected_keys - excluded_keys

    for key in expected_keys:
        assert key in sfp_eeprom_info, "key {} doesn't exist in {}".format(
            key, sfp_eeprom_info)

    # For the parameter of Length, there are many different value for different cable,
    # So here we just check if there is a key including the prefix of Length
    is_length_key_exist = False
    for key in list(sfp_eeprom_info.keys()):
        if key.startswith("Length"):
            is_length_key_exist = True
            break
    assert is_length_key_exist, "Key related to Length doesn't exist in {} ".format(
        sfp_eeprom_info)

    if is_support_dom:
        pattern_power = r"^(?P<digit>-[0-9\.]+|[0-9.]+|-inf)(?P<unit>dBm$)"
        pattern_bias = r"^(?P<digit>-[0-9\.]+|[0-9.]+)(?P<unit>mA$)"
        pattern_temp = r"^(?P<digit>-[0-9\.]+|[0-9.]+)(?P<unit>[Cc]$)"
        pattern_vcc = r"^(?P<digit>-[0-9\.]+|[0-9.]+)(?P<unit>Volts$)"

        expected_channel_threshold_values_keys_and_value_pattern = {"RxPowerHighAlarm": pattern_power,
                                                                    "RxPowerHighWarning": pattern_power,
                                                                    "RxPowerLowAlarm": pattern_power,
                                                                    "RxPowerLowWarning": pattern_power,
                                                                    "TxBiasHighAlarm": pattern_bias,
                                                                    "TxBiasHighWarning": pattern_bias,
                                                                    "TxBiasLowAlarm": pattern_bias,
                                                                    "TxBiasLowWarning": pattern_bias}
        expected_module_threshold_values_keys_and_value_pattern = {"TempHighAlarm": pattern_temp,
                                                                   "TempHighWarning": pattern_temp,
                                                                   "TempLowAlarm": pattern_temp,
                                                                   "TempLowWarning": pattern_temp,
                                                                   "VccHighAlarm": pattern_vcc,
                                                                   "VccHighWarning": pattern_vcc,
                                                                   "VccLowAlarm": pattern_vcc,
                                                                   "VccLowWarning": pattern_vcc}
        expected_module_monitor_values_keys_and_pattern = {
            "Temperature": pattern_temp, "Vcc": pattern_vcc}

        if sfp_eeprom_info["Identifier"] == "SFP/SFP+/SFP28":
            expected_monitor_data_keys_and_pattern = {"RXPower": pattern_power, "TXBias": pattern_bias,
                                                      "TXPower": pattern_power, "Temperature": pattern_temp,
                                                      "Vcc": pattern_vcc}
            expected_threshold_data_keys_and_pattern = {"TxPowerHighAlarm": pattern_power,
                                                        "TxPowerHighWarning": pattern_power,
                                                        "TxPowerLowAlarm": pattern_power,
                                                        "TxPowerLowWarning": pattern_power}
            expected_threshold_data_keys_and_pattern.update(
                expected_channel_threshold_values_keys_and_value_pattern)
            expected_threshold_data_keys_and_pattern.update(
                expected_module_threshold_values_keys_and_value_pattern)

            logging.info(
                "Check if MonitorData's keys exist and the corresponding value format is correct")
            check_dom_monitor_key_and_data_format(expected_monitor_data_keys_and_pattern,
                                                  sfp_eeprom_info["MonitorData"])

            logging.info(
                "check if ThresholdData's keys exist and the corresponding value format is correct")
            check_dom_monitor_key_and_data_format(expected_threshold_data_keys_and_pattern,
                                                  sfp_eeprom_info["ThresholdData"])

        else:
            if "ChannelThresholdValues" not in excluded_keys:
                logging.info(
                    "Check if ChannelThresholdValues' keys exist and the corresponding value format is correct")
                check_dom_monitor_key_and_data_format(expected_channel_threshold_values_keys_and_value_pattern,
                                                      sfp_eeprom_info["ChannelThresholdValues"])

            if "ModuleThresholdValues" not in excluded_keys:
                logging.info(
                    "Check if ModuleThresholdValues' keys exist and the corresponding format is correct")
                check_dom_monitor_key_and_data_format(expected_module_threshold_values_keys_and_value_pattern,
                                                      sfp_eeprom_info["ModuleThresholdValues"])

            logging.info(
                "Check if ChannelMonitorValues's value format is correct")
            for k, v in list(sfp_eeprom_info["ChannelMonitorValues"].items()):
                pattern = pattern_power if "Power" in k else pattern_bias
                assert re.match(
                    pattern, v), "Value of {}:{} format is not correct. pattern is {}".format(k, v, pattern)

            logging.info(
                "Check ModuleMonitorValues keys exist and the corresponding value format is correct")
            check_dom_monitor_key_and_data_format(expected_module_monitor_values_keys_and_pattern,
                                                  sfp_eeprom_info["ModuleMonitorValues"])


def check_dom_monitor_key_and_data_format(expected_keys_and_pattern_dict, dom_monitor_data):
    for key, pattern in list(expected_keys_and_pattern_dict.items()):
        assert key in dom_monitor_data, "Key {} doesn't exist in {}".format(
            key, dom_monitor_data)
        assert re.match(pattern, dom_monitor_data[key]), \
            "Value of {}:{} format is not correct. pattern is {}".format(
                key, dom_monitor_data[key], pattern)


def is_support_dom(duthost, port_index, pic_cr0_path):
    """
    This method is to check if cable support dom
    1. For 202012 branch(It not support mlxlink tool, so use get_transceiver_bulk_status to judge if it support dom)
      1) Get get transceiver bulk status
      2) Return True, When any one value for all parameters including power, bias,temperature and voltage is not in
         ['N/A', '0.0', 0.0, '0.0000mA', '-inf'], else False.
    2. For other branches apart from 202012
      1) Get the pci_cro info by mlxlink tool
      2) Return false, when all values of 5 fields
       (Temperature|Voltage|Bias Current|Rx Power Current|Tx Power Current) are N/A, else True
    """
    if duthost.sonic_release in ["202012"]:
        bulk_status_str = get_transceiver_bulk_status(duthost, port_index)
        bulk_status_str = bulk_status_str.replace('-inf', '\'-inf\'')
        bulk_status_dict = ast.literal_eval(bulk_status_str)
        for k, v in list(bulk_status_dict.items()):
            if "power" in k or "bias" in k or "temperature" in k or "voltage" in k:
                if v not in ['N/A', '0.0', 0.0, '0.0000mA', '-inf']:
                    logging.info("Port {} support dom".format(port_index))
                    return True
        logging.info("Port {} doesn't support dom".format(port_index))
        return False
    else:
        pattern_for_dom_check = r'^(Temperature|Voltage|Bias Current|Rx Power Current|Tx Power Current).*: N\/A.*'
        pci_cr0 = get_mlxlink_pci_cr0(duthost, pic_cr0_path, port_index)

        check_support_dom_filed_number = 5
        not_support_dom_field_counter = 0
        for line in pci_cr0.split("\n"):
            res = re.match(pattern_for_dom_check, line)
            if res:
                not_support_dom_field_counter += 1
                logging.info(
                    "Find {} Value is N/A: {}".format(not_support_dom_field_counter, line))
            if not_support_dom_field_counter >= check_support_dom_filed_number:
                logging.info("Port {} doesn't support dom".format(port_index))
                return False
        logging.info("Port {} support dom".format(port_index))
        return True


def get_transceiver_bulk_status(duthost, port_index):
    """
    This method is to get transceiver bulk status
    """
    cmd = """
cat << EOF > get_transceiver_bulk_status.py
import sonic_platform.platform as P
info = P.Platform().get_chassis().get_sfp({}).get_transceiver_bulk_status()
print(info)
EOF
""".format(port_index)
    duthost.shell(cmd)
    return duthost.command("python3 get_transceiver_bulk_status.py")["stdout"]


def get_mlxlink_pci_cr0(duthost, pci_cr0_path, port_index):
    """
    This method is to get the info of /dev/mst/*_pci_cr0
    """
    cmd = "sudo mlxlink -d {} -p {} -m".format(pci_cr0_path, port_index)
    return duthost.command(cmd)["stdout"]


def get_pci_cr0_path(duthost):
    """
    This method is to get path for /dev/mst/*_pci_cr0
    """
    return duthost.shell('ls /dev/mst/*_pci_cr0')['stdout'].strip()


def get_pciconf0_path(duthost):
    """
    This method is to get path for /dev/mst/*_pciconf0
    """
    return duthost.shell('ls /dev/mst/*_pciconf0')['stdout'].strip()
