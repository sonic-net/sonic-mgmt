from spytest.utils import filter_and_select
from spytest import st
from apis.system.basic import poll_for_system_status
import utilities.utils as utils
import utilities.common as cutils
import re


def get_system_uptime_in_seconds(dut):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :return:
    """
    command = "show uptime"
    output = st.show(dut, command)
    if output[0]["years"]:
        years = int(output[0]["years"]) * 3600 * 24 * 365.25
    else:
        years = 0
    if output[0]["months"]:
        months = int(output[0]["months"]) * 2629746
    else:
        months = 0
    if output[0]["days"]:
        days = int(output[0]["days"]) * 3600 * 24
    else:
        days = 0
    if output[0]["hours"]:
        hours = int(output[0]["hours"]) * 3600
    else:
        hours = 0
    if output[0]["minutes"]:
        minutes = int(output[0]["minutes"]) * 60
    else:
        minutes = 0
    retval = years + months + days + hours + minutes
    print(retval)
    return retval


def show_interfaces_transceiver_presence(dut, intf=None):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param intf:
    :return:
    """
    command = "show interfaces transceiver presence"
    output = st.show(dut, command)
    if intf is not None:
        entries = filter_and_select(output, ["port", "presence"], {"port": intf})
    else:
        entries = filter_and_select(output, ["port", "presence"])
    return entries


def verify_interfaces_transceiver_presence(dut, intf, status):
    """
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param intf:
    :param status:
    :return:
    """
    output = show_interfaces_transceiver_presence(dut, intf)
    retval = filter_and_select(output, ["presence"], {"port": intf})
    if retval[0]["presence"].lower() == status.lower():
        return True
    else:
        return False


def get_platform_fan_status(dut, fan=None):
    """
    To Get Platform Fan Status
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param fan:
    :return:
    """

    command = "show platform fanstatus"
    output = st.show(dut, command)
    if fan:
        return filter_and_select(output, None, {"fan": fan})
    else:
        return output


def verify_platform_fan_params(dut, fan_list):
    """
    To Verify platform Fan status parameters
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param fan_list:
    :return:
    """
    fans = fan_list if isinstance(fan_list, list) else [fan_list]
    output = get_platform_fan_status(dut)
    if not output:
        st.log("Platform fan details not found")
        return False
    cnt = 0
    for data in output:
        if data["fan"] not in fans:
            st.error("Invalid FAN detected - {}".format(data["fan"]))
            cnt += 1
        if data["status"] != "OK":
            st.error("Invalid FAN status detected - {}".format(data["status"]))
            cnt += 1
        if data["direction"] not in ["INTAKE", "EXHAUST"]:
            st.error("Invalid FAN direction detected - {}".format(data["direction"]))
            cnt += 1
        if data["speed"] in ['0', 'N/A']:
            st.error("Invalid FAN speed detected - {}".format(data["speed"]))
            cnt += 1
    if cnt > 0:
        st.log("Fan parameters verification failed ..")
        return False
    return True


def verify_platform_fan_status(dut, fan, **kwargs):
    """
    To Verify Platform Fan Status
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param fan:
    :return:
    """
    output = get_platform_fan_status(dut, fan)
    result = True
    for each in kwargs:
        if not filter_and_select(output, None, {each: kwargs[each]}):
            st.error("No match for {} = {} in table".format(each, kwargs[each]))
            result = False
    return result


def get_platform_psu_summary(dut, psu=None):
    """
    To Get Platform PSU Status
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param psu:
    :return:
    """
    command = "show platform psusummary"
    output = st.show(dut, command)
    if psu:
        return filter_and_select(output, None, {"psu": psu})
    else:
        return output


def verify_platform_psu_params(dut):
    """
    API to verify the Platform psu params
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :return:
    """
    output = get_platform_psu_summary(dut)
    if not output:
        st.error("Output not found")
        return False
    psu_data = None
    for data in output:
        if data["psu_status"] == "OK":
            psu_data = data
            break
    if psu_data and utils.check_empty_values_in_dict(psu_data):
        st.log("PSU verification success")
        return True
    else:
        st.log("Verification failed for psu data")
        return False


def verify_platform_psu_summary(dut, psu=None, **kwargs):
    """
    To Verify Platform PSU Status
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param :dut:
    :param :fan:
    :return:
    """
    output = get_platform_psu_summary(dut, psu)
    result = True
    for each in kwargs:
        if filter_and_select(output, None, {each: kwargs[each]}):
            st.error("No match for {} = {} in table".format(each, kwargs[each]))
            result = False
    return result


def config_pddf_mode(dut, file_path="/usr/local/bin/pddf_util.py", module_name="switch-pddf", iteration=150, delay=2):
    """
    API to enable / disable PDDF on the switch
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param file_path:
    :param module_name:
    :param iteration:
    :param delay:
    :return:
    """
    command = "{} {}".format(file_path, module_name)
    output = st.config(dut, command)
    st.log("OUTPUT : {}".format(output))
    if module_name == "switch-pddf":
        if 'REBOOT IS REQUIRED IMMEDIATELY' in output:
            st.reboot(dut, skip_fallback=True)
            if not poll_for_system_status(dut, iteration=iteration, delay=delay):
                st.log("System status is not up ...")
                return False
        if not is_service_active(dut):
            st.log("PDDF service is not active ...")
            return False
    else:
        if is_service_active(dut):
            st.log("PDDF service is still active ...")
            return False
    return True


def is_service_active(dut, service="pddf"):
    """
    API to check whether service is active or not
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param service:
    :return:
    """
    command = "systemctl | grep -i {}".format(service)
    output = st.config(dut, command)
    if "active" not in output:
        return False
    return True


def get_psuutil_data(dut, mode="status"):
    """
    API to get psuutil data based on type of the command
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param mode:
    :return:
    """
    if mode not in ["status", "numpsus", "version"]:
        st.log("Unsupported command type")
        return False
    command = "sudo psuutil {}".format(mode)
    skip_tmpl = False
    if mode == "numpsus":
        skip_tmpl = True
    output = st.show(dut, command, skip_tmpl=skip_tmpl)
    if mode == "numpsus":
        return {"numpsus": utils.remove_last_line_from_string(output)}
    else:
        return output


def verify_psuutil_data(dut, *argv, **kwargs):
    """
    API to get psuutil data based on type of the command
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param argv:
    :param kwargs:
    :return:
    """
    result = True
    for each_mode in argv:
        output = get_psuutil_data(dut, each_mode)
        if "numpsus" in each_mode and int(output['numpsus']) != len(kwargs['psu_list']):
            st.error("Incorrect Number of PSUs detected.")
            result = False

        if "status" in each_mode:
            psu_li = cutils.dicts_list_values(output, "psu")
            for psu in kwargs['psu_list']:
                if psu not in psu_li:
                    st.error("PSU - {} is not present in DUT.")
                    result = False

            status_li = cutils.dicts_list_values(output, "status")
            for status in status_li:
                if status not in ['NOT OK', 'OK']:
                    st.error("Invalid PSU status in DUT.")
                    result = False

            if "OK" not in status_li:
                st.error("None of the PSU status is - OK")
                result = False
    return result


def config_sfputil(dut, **kwargs):
    """
    API to config sfputils
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    """
    if kwargs.get("mode"):
        mode = kwargs.get("mode")
        if mode in ["lpmode", "reset"]:
            if not kwargs.get("interface"):
                st.log("Interface should be provided for {}".format(mode))
                return False
        if mode == "lpmode":
            if not kwargs.get("action"):
                st.log("Action should be provided for {}".format(mode))
                return False
            if kwargs.get("action") not in ["on", "off"]:
                st.log("Unsupported actions provided for {}".format(mode))
                return False
            command = "sudo sfputil {} {} {}".format(mode, kwargs.get("action"), kwargs.get("interface"))
            output = st.config(dut, command)
            if "OK" in output:
                return True
            else:
                return False
        elif mode == "reset":
            command = "sudo sfputil {} {}".format(mode, kwargs.get("interface"))
            output = st.config(dut, command)
            if "OK" in output:
                return True
            else:
                return False
        else:
            st.log("Unsupported modes provided")
            return False
    else:
        st.log("MODE NOT PROVIDED ..")
        return False


def show_sfputil(dut, mode, interface=None):
    """
    API to get the sfputil output
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param interface:
    :param mode: eeprom, presence, lpmode
    :return:
    """
    if mode not in ["lpmode", "presence", "eeprom"]:
        st.log("Unsupported mode provided")
        return False
    command = "sudo sfputil show {}".format(mode)
    if interface:
        command = "sudo sfputil show {} | grep -w {}".format(mode, interface)
    output = st.show(dut, command)
    return output


def verify_sfputil_show_interface_tranceiver(dut, mode, **kwargs):
    """
    To Verify sfputil
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param mode:
    :param kwargs:
    :return:
    """
    cmd = 'utils'
    if 'cmd' in kwargs:
        cmd = kwargs['cmd']
        kwargs.pop('cmd')
    if cmd == 'utils':
        output = show_sfputil(dut, mode, interface=kwargs.get('port'))
    else:
        output = show_interface_transceiver(dut, mode, interface=kwargs.get('port'))
    result = True
    for each in kwargs:
        if not filter_and_select(output, None, {each: kwargs[each]}):
            st.error("No match for {} = {} in table".format(each, kwargs[each]))
            result = False
    return result


def show_interface_transceiver(dut, mode, interface=None):
    """
    API to get the interface transceiver eeprom details
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param mode: eeprom , presence
    :param interface:
    :return:
    """
    if mode not in ["eeprom", "presence"]:
        st.log("Unsupported modes provided ...")
        return False
    command = "show interface transceiver {}".format(mode)
    if interface:
        command = "show interface transceiver {} | grep -w {}".format(mode, interface)
    return st.show(dut, command)


def show_pddf_psuutils(dut, mode):
    """
    API to get PDDF PSUUTIL DATA based on type of mode
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param mode:
    :return:
    """
    if mode not in ["numpsus", "status", "mfrinfo", "seninfo", "version"]:
        st.log("Unsupported modes provided ")
        return False
    skip_tmpl = False
    if mode == "numpsus":
        skip_tmpl = True
    command = "sudo pddf_psuutil {}".format(mode)
    output = st.show(dut, command, skip_tmpl=skip_tmpl)
    if mode == "numpsus":
        return {"numpsus": utils.remove_last_line_from_string(output)}
    else:
        return output


def verify_pddf_psuutils(dut, *argv, **kwargs):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param argv:
    :return:
    """
    result = True
    for each_mode in argv:
        output = show_pddf_psuutils(dut, each_mode)
        if "numpsus" in each_mode and int(output['numpsus']) != len(kwargs['psu_list']):
            st.error("Incorrect Number of PSUs detected.")
            result = False

        if "status" in each_mode:
            psu_li = cutils.dicts_list_values(output, "psu")
            for psu in kwargs['psu_list']:
                if psu not in psu_li:
                    st.error("PSU - {} is not present in DUT.")
                    result = False

            status_li = cutils.dicts_list_values(output, "status")
            for status in status_li:
                if status not in ['NOT OK', 'OK']:
                    st.error("Invalid PSU status in DUT.")
                    result = False

            if "OK" not in status_li:
                st.error("None of the PSU status is - OK")
                result = False

        if "mfrinfo" in each_mode:
            status_li = cutils.dicts_list_values(output, "psu_status")
            if "OK" not in status_li:
                st.error("None of the PSU status is - OK")
                result = False

        if 'seninfo' in each_mode:
            status_li = cutils.dicts_list_values(output, "psu_status")
            if "OK" not in status_li:
                st.error("None of the PSU status is - OK")
                result = False
            for each in ['voltage', 'current', 'power']:
                if '0.0' in cutils.dicts_list_values(output, "each"):
                    st.error("{} in 'seninfo' is 0.0".format(each))
                    result = False
            if '0' in cutils.dicts_list_values(output, "fan_speed"):
                st.error("fan_speed in 'seninfo' is 0.0")
                result = False

    return result


def show_pddf_fanutil(dut, mode):
    """
    API to get PDDF FANUTIL DATA based on type of mode
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param mode:
    :return:
    """
    if mode not in ["direction", "getspeed", "numfans", "status", "version"]:
        st.log("Unsupported modes provided ")
        return False
    skip_tmpl = False
    if mode == "numfans":
        skip_tmpl = True
    command = "sudo pddf_fanutil {}".format(mode)
    output = st.show(dut, command, skip_tmpl=skip_tmpl)
    if mode == "numfans":
        return {"numfans": utils.remove_last_line_from_string(output)}
    else:
        return output


def verify_pddf_fanutil(dut, mode, fan_list, version="2.0"):
    """
    API to verify the fan util output for the given fan list
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param mode:
    :param fan_list:
    :param version:
    :return:
    """
    fans = fan_list if isinstance(fan_list, list) else [fan_list]
    output = show_pddf_fanutil(dut, mode)
    if not output:
        st.error("PDDF FAN UTIL DATA NOT FOUND")
        return False
    for data in output:
        count = 0
        for fan in fans:
            if mode == "direction":
                if fan == data["fan"] and data["direction"] not in ["INTAKE", "EXHAUST"]:
                    st.error("Invalid FAN direction detected - {}".format(data["direction"]))
                    count += 1
            elif mode == "getspeed":
                if fan == data["fan"] and int(data["speed"]) == 0:
                    st.error("Invalid FAN speed detected - {}".format(data["speed"]))
                    count += 1
            elif mode == "numfans":
                if str(len(fan_list)) != str(output[data]):
                    st.error("Incorrect FAN numbers detected - {}".format(output[data]))
                    count += 1
            elif mode == "status":
                if fan == data["fan"] and data["status"] != "OK":
                    st.error("Invalid FAN status detected - {}".format(data["status"]))
                    count += 1
            elif mode == "version":
                if str(data["version"]) != str(version):
                    st.error("Invalid FAN version detected - {}".format(data["version"]))
                    count += 1
        if count:
            st.error("Mismatch in PDDF FAN UTIL data")
            return False
    return True


def config_pddf_fanutil(dut, speed):
    """
    API to set PDDF FANUTIL speed
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param speed:
    :return:
    """
    command = "sudo pddf_fanutil setspeed {}".format(speed)
    output = st.config(dut, command)
    if "Successful" not in utils.remove_last_line_from_string(output):
        st.log("Configuration of fan speed failed")
        return False
    return True


def run_debug_commands(dut, mode=None, module="pddf"):
    """
    API to execute debug commands
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param mode:
    :param module:
    :return:
    """
    if mode:
        modes = cutils.make_list(mode)
    else:
        modes = ["lsmode", "systemctl", "pddf_fanutil", "pddf_psuutil"]
    for each_mode in modes:
        if each_mode in ["lsmode", "systemctl"]:
            command = "{} | grep -i {}".format(each_mode, module)
        if each_mode in ["pddf_fanutil", "pddf_psuutil"]:
            command = "sudo {} debug dump_sysfs".format(each_mode)
        output = st.config(dut, command)
    return utils.remove_last_line_from_string(output)


def generate_tech_support(dut):
    """
    To Generate tech support and return the error if occurs.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    command = "show techsupport > /dev/null"
    return utils.remove_last_line_from_string(st.config(dut, command))


def verify_show_environment(dut, verify_str_list):
    """
    To get show environment.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    command = "show environment"
    output = utils.remove_last_line_from_string(st.show(dut, command, skip_tmpl=True))
    result = True
    for item in verify_str_list:
        if not re.findall(item, output, re.IGNORECASE):
            st.error("Item '{}' is NOT found".format(item))
            result = False
    return result


def config_pddf_ledutil(dut, mode, led_type, state=None):
    """
    API to set PDDF LEDUTIL
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param mode:
    :param led_type:
    :param state:
    :return:
    """
    command = "sudo pddf_ledutil getstatusled {}".format(led_type)
    if mode.lower() == 'set':
        command = "sudo pddf_ledutil setstatusled {} {}".format(led_type, state)
    output = st.config(dut, command)
    return utils.remove_last_line_from_string(output)


def verify_pddf_ledutil(dut, data):
    """
    Verify PDDF LEDUTIL
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param data:
    :return:
    """
    result = True
    for each_led in data:
        st.banner("Validating - {} ".format(each_led))
        for each_test in data[each_led]:
            st.log("Validating - {} - mode '{}'".format(each_led, each_test))
            set_out = config_pddf_ledutil(dut, 'set', each_led, data[each_led][each_test][0])
            if data[each_led][each_test][1] not in set_out:
                st.error(">>>> {} != {}".format(set_out, data[each_led][each_test][1]))
                st.error("Failed to SET - {} mode '{}'".format(each_led, each_test))
                result = False
            get_out = config_pddf_ledutil(dut, 'get', each_led)
            if get_out != data[each_led][each_test][2]:
                st.error(">>>> {} != {}".format(get_out, data[each_led][each_test][2]))
                st.error("Get Validation failed - {} mode '{}'".format(each_led, each_test))
                result = False
    return result


def show_pddf_thermalutil(dut, mode):
    """
    API to get PDDF thermal util DATA based on type of mode
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param mode:
    :return:
    """
    if mode not in ["gettemp", "numthermals",  "version"]:
        st.log("Unsupported modes provided ")
        return False
    skip_tmpl = False
    if mode in ["numthermals", 'version']:
        skip_tmpl = True
    command = "sudo pddf_thermalutil {}".format(mode)
    output = st.show(dut, command, skip_tmpl=skip_tmpl)
    if mode == "numthermals":
        return {"numthermals": utils.remove_last_line_from_string(output)}
    elif mode == "version":
        return {"version": utils.remove_last_line_from_string(output)}
    else:
        return output


def verify_pddf_thermalutil(dut, mode, thermal_list, version="2.0"):
    """
    API to verify the thermal util output for the given thermal list
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param mode:
    :param thermal_list:
    :param version:
    :return:
    """
    thermal_li = thermal_list if isinstance(thermal_list, list) else [thermal_list]
    output = show_pddf_thermalutil(dut, mode)
    if not output:
        st.error("PDDF THERMAL UTIL DATA NOT FOUND")
        return False
        count = 0
        if mode == "gettemp":
            for data in output:
                for each_thermal in thermal_li:
                    if each_thermal != data["temp_sensor"]:
                        st.error("Invalid Temp Sensor detected - {}".format(data["temp_sensor"]))
                        count += 1
        elif mode == "numthermals":
            if str(len(thermal_list)) != str(output[data]):
                st.error("Incorrect Thermal sensors numbers detected - {}".format(output[data]))
                count += 1
        elif mode == "version":
            if str(version) not in str(data["version"]):
                st.error("Invalid Thermal version detected - {}".format(data["version"]))
                count += 1
        if count:
            st.error("Mismatch in PDDF Thermal UTIL data")
            return False
    return True
