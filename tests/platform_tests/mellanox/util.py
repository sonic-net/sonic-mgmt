import re
import logging
import ast

pattern_top_layer_key_value = r"^(?P<key>Ethernet\d+):(?P<value>.*)"
pattern_second_layer_key_value = r"(^\s{8}|\t{1})(?P<key>[a-zA-Z0-9][a-zA-Z0-9\s\/\(\)-]+):(?P<value>.*)"
pattern_third_layer_key_value = r"(^\s{16}|\t{2})(?P<key>[a-zA-Z0-9][a-zA-Z0-9\s\/]+):(?P<value>.*)"

pattern_digit_unit = r"^(?P<digit>-[0-9\.]+|[0-9.]+)(?P<unit>dBm|mA|C|c|Volts)"


def parse_one_sfp_eeprom_info(sfp_eeprom_info):
    """
    Parse the one sfp eeprom info, return top_key, sfp_eeprom_info_dict
    e.g
    sfp_info:
    Ethernet0: SFP EEPROM detected
        Application Advertisement: N/A
        Connector: No separable connector
        Encoding: 64B/66B
        Extended Identifier: Power Class 3 Module (2.5W max.),
                             No CLEI code present in Page 02h, CDR present in TX, CDR present in RX
        Extended RateSelect Compliance: Unknown
        Identifier: QSFP28 or later
        Length Cable Assembly(m): 3.0
        Nominal Bit Rate(100Mbs): 255
        Specification compliance:
                10/40G Ethernet Compliance Code: Extended
                Extended Specification Compliance: 100G AOC (Active Optical Cable) or 25GAUI C2M AOC
                Fibre Channel Link Length: Unknown
                Fibre Channel Speed: Unknown
                Fibre Channel Transmission Media: Unknown
                Fibre Channel Transmitter Technology: Unknown
                Gigabit Ethernet Compliant Codes: Unknown
                SAS/SATA Compliance Codes: Unknown
                SONET Compliance Codes: Unknown
        Vendor Date Code(YYYY-MM-DD Lot): 2019-01-17
        Vendor Name: Mellanox
        Vendor OUI: 00-02-c9
        Vendor PN: MFA1A00-C003
        Vendor Rev: B2
        Vendor SN: MT1903FT05965
        ChannelMonitorValues:
                RX1Power: 0.927dBm
                RX2Power: 0.938dBm
                RX3Power: 0.912dBm
                RX4Power: 0.95dBm
                TX1Bias: 6.75mA
                TX1Power: 1.071dBm
                TX2Bias: 6.75mA
                TX2Power: 1.04dBm
                TX3Bias: 6.75mA
                TX3Power: 1.039dBm
                TX4Bias: 6.75mA
                TX4Power: 1.031dBm
        ChannelThresholdValues:
                RxPowerHighAlarm  : 5.4dBm
                RxPowerHighWarning: 2.4dBm
                RxPowerLowAlarm   : -13.307dBm
                RxPowerLowWarning : -10.301dBm
                TxBiasHighAlarm   : 8.5mA
                TxBiasHighWarning : 8.0mA
                TxBiasLowAlarm    : 5.492mA
                TxBiasLowWarning  : 6.0mA
        ModuleMonitorValues:
                Temperature: 43.105C
                Vcc: 3.235Volts
        ModuleThresholdValues:
                TempHighAlarm  : 80.0C
                TempHighWarning: 70.0C
                TempLowAlarm   : -10.0C
                TempLowWarning : 0.0C
                VccHighAlarm   : 3.5Volts
                VccHighWarning : 3.465Volts
                VccLowAlarm    : 3.1Volts
                VccLowWarning  : 3.135Volts
    top_key, sfp_eeprom_info_dict:
    Ethernet0,
    {
        'Ethernet0': 'SFP EEPROM detected',
        'Application Advertisement': 'N/A',
        'Connector': 'No separable connector',
        'Encoding': '64B/66B',
        'Extended Identifier': 'Power Class 3 Module (2.5W max.),
                               No CLEI code present in Page 02h, CDR present in TX, CDR present in RX',
        'Extended RateSelect Compliance': 'Unknown',
        'Identifier': 'QSFP28 or later',
        'Length Cable Assembly(m)': '3.0',
        'Nominal Bit Rate(100Mbs)': '255',
        'Specification compliance': {
            '10/40G Ethernet Compliance Code': 'Extended',
            'Extended Specification Compliance': '100G AOC (Active Optical Cable) or 25GAUI C2M AOC',
            'Fibre Channel Link Length': 'Unknown',
            'Fibre Channel Speed': 'Unknown',
            'Fibre Channel Transmission Media': 'Unknown',
            'Fibre Channel Transmitter Technology': 'Unknown',
            'Gigabit Ethernet Compliant Codes': 'Unknown',
            'SAS/SATA Compliance Codes': 'Unknown',
            'SONET Compliance Codes': 'Unknown'
        },
        'Vendor Date Code(YYYY-MM-DD Lot)': '2019-01-17',
        'Vendor Name': 'Mellanox',
        'Vendor OUI': '00-02-c9',
        'Vendor PN': 'MFA1A00-C003',
        'Vendor Rev': 'B2',
        'Vendor SN': 'MT1903FT05965',
        'ChannelMonitorValues': {
            'RX1Power': '0.927dBm',
            'RX2Power': '0.938dBm',
            'RX3Power': '0.912dBm',
            'RX4Power': '0.95dBm',
            'TX1Bias': '6.75mA',
            'TX1Power': '1.071dBm',
            'TX2Bias': '6.75mA',
            'TX2Power': '1.04dBm',
            'TX3Bias': '6.75mA',
            'TX3Power': '1.039dBm',
            'TX4Bias': '6.75mA',
            'TX4Power': '1.031dBm'
        },
        'ChannelThresholdValues': {
            'RxPowerHighAlarm': '5.4dBm',
            'RxPowerHighWarning': '2.4dBm',
            'RxPowerLowAlarm': '-13.307dBm',
            'RxPowerLowWarning': '-10.301dBm',
            'TxBiasHighAlarm': '8.5mA',
            'TxBiasHighWarning': '8.0mA',
            'TxBiasLowAlarm': '5.492mA',
            'TxBiasLowWarning': '6.0mA'
        },
        'ModuleMonitorValues': {
            'Temperature': '43.105C',
            'Vcc': '3.235Volts'
        },
        'ModuleThresholdValues': {
            'TempHighAlarm': '80.0C',
            'TempHighWarning': '70.0C',
            'TempLowAlarm': '-10.0C',
            'TempLowWarning': '0.0C',
            'VccHighAlarm': '3.5Volts',
            'VccHighWarning': '3.465Volts',
            'VccLowAlarm': '3.1Volts',
            'VccLowWarning': '3.135Volts'
        }
    }
    """
    one_sfp_eeprom_info_dict = {}
    second_layer_dict = {}
    previous_key = ""
    top_key = ""
    for line in sfp_eeprom_info.split("\n"):
        res1 = re.match(pattern_top_layer_key_value, line)
        if res1:
            top_key = res1.groupdict()["key"].strip()
            one_sfp_eeprom_info_dict[top_key] = res1.groupdict()["value"].strip()
            continue
        res2 = re.match(pattern_second_layer_key_value, line)
        if res2:
            if second_layer_dict and previous_key:
                one_sfp_eeprom_info_dict[previous_key] = second_layer_dict
                second_layer_dict = {}
            one_sfp_eeprom_info_dict[res2.groupdict()["key"].strip()] = res2.groupdict()["value"].strip()
            previous_key = res2.groupdict()["key"].strip()
        else:
            res3 = re.match(pattern_third_layer_key_value, line)
            if res3:
                second_layer_dict[res3.groupdict()["key"].strip()] = res3.groupdict()["value"].strip()
    if second_layer_dict and previous_key:
        one_sfp_eeprom_info_dict[previous_key] = second_layer_dict

    return top_key, one_sfp_eeprom_info_dict


def parse_sfp_eeprom_infos(eeprom_infos):
    """
    This method is to pares sfp eeprom infos, and return sfp_eeprom_info_dict
    """
    sfp_eeprom_info_dict = {}
    for sfp_info in eeprom_infos.split("\n\n"):
        intf, eeprom_info = parse_one_sfp_eeprom_info(sfp_info)
        sfp_eeprom_info_dict[intf] = eeprom_info
    return sfp_eeprom_info_dict


def check_sfp_eeprom_info(duthost, sfp_eeprom_info, is_support_dom, show_eeprom_cmd):
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
            excluded_keys = set(["Application Advertisement", "ChannelThresholdValues", "ModuleThresholdValues"])
            expected_keys = expected_keys - excluded_keys

    if "Identifier" in sfp_eeprom_info and sfp_eeprom_info["Identifier"] == "SFP/SFP+/SFP28":
        excluded_keys = excluded_keys | {"ChannelMonitorValues", "ChannelThresholdValues", "ModuleMonitorValues",
                                         "ModuleThresholdValues"}
        expected_keys = (expected_keys | {"MonitorData", "ThresholdData"}) - excluded_keys

    for key in expected_keys:
        assert key in sfp_eeprom_info, "key {} doesn't exist in {}".format(key, sfp_eeprom_info)

    # For the parameter of Length, there are many different value for different cable,
    # So here we just check if there is a key including the prefix of Length
    is_length_key_exist = False
    for key in list(sfp_eeprom_info.keys()):
        if key.startswith("Length"):
            is_length_key_exist = True
            break
    assert is_length_key_exist, "Key related to Length doesn't exist in {} ".format(sfp_eeprom_info)

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
        expected_module_monitor_values_keys_and_pattern = {"Temperature": pattern_temp, "Vcc": pattern_vcc}

        if sfp_eeprom_info["Identifier"] == "SFP/SFP+/SFP28":
            expected_monitor_data_keys_and_pattern = {"RXPower": pattern_power, "TXBias": pattern_bias,
                                                      "TXPower": pattern_power, "Temperature": pattern_temp,
                                                      "Vcc": pattern_vcc}
            expected_threshold_data_keys_and_pattern = {"TxPowerHighAlarm": pattern_power,
                                                        "TxPowerHighWarning": pattern_power,
                                                        "TxPowerLowAlarm": pattern_power,
                                                        "TxPowerLowWarning": pattern_power}
            expected_threshold_data_keys_and_pattern.update(expected_channel_threshold_values_keys_and_value_pattern)
            expected_threshold_data_keys_and_pattern.update(expected_module_threshold_values_keys_and_value_pattern)

            logging.info("Check if MonitorData's keys exist and the corresponding value format is correct")
            check_dom_monitor_key_and_data_format(expected_monitor_data_keys_and_pattern,
                                                  sfp_eeprom_info["MonitorData"])

            logging.info("check if ThresholdData's keys exist and the corresponding value format is correct")
            check_dom_monitor_key_and_data_format(expected_threshold_data_keys_and_pattern,
                                                  sfp_eeprom_info["ThresholdData"])

        else:
            if "ChannelThresholdValues" not in excluded_keys:
                logging.info(
                    "Check if ChannelThresholdValues' keys exist and the corresponding value format is correct")
                check_dom_monitor_key_and_data_format(expected_channel_threshold_values_keys_and_value_pattern,
                                                      sfp_eeprom_info["ChannelThresholdValues"])

            if "ModuleThresholdValues" not in excluded_keys:
                logging.info("Check if ModuleThresholdValues' keys exist and the corresponding format is correct")
                check_dom_monitor_key_and_data_format(expected_module_threshold_values_keys_and_value_pattern,
                                                      sfp_eeprom_info["ModuleThresholdValues"])

            logging.info("Check if ChannelMonitorValues's value format is correct")
            for k, v in list(sfp_eeprom_info["ChannelMonitorValues"].items()):
                pattern = pattern_power if "Power" in k else pattern_bias
                assert re.match(pattern, v), "Value of {}:{} format is not correct. pattern is {}".format(k, v, pattern)

            logging.info("Check ModuleMonitorValues keys exist and the corresponding value format is correct")
            check_dom_monitor_key_and_data_format(expected_module_monitor_values_keys_and_pattern,
                                                  sfp_eeprom_info["ModuleMonitorValues"])


def check_dom_monitor_key_and_data_format(expected_keys_and_pattern_dict, dom_monitor_data):
    for key, pattern in list(expected_keys_and_pattern_dict.items()):
        assert key in dom_monitor_data, "Key {} doesn't exist in {}".format(key, dom_monitor_data)
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
                logging.info("Find {} Value is N/A: {}".format(not_support_dom_field_counter, line))
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
