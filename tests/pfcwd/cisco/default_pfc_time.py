# Verified on Q200 @ 100G port speed. e.g. 687 is bit time to pause for 50ms (clock at 900Mhz).
import traceback
from common import is_graphene2, is_palladium2, tree, is_gr, port_to_sai_lane_map, \
    sai_lane_to_slice_ifg_pif, dd0, is_pac, is_gb, sdk, get_mac_port, d0, is_g2ll

# Input parameters replaced via 'sed'
param_interfaces = __PARAM_INTERFACES__  # noqa: F821
param_success = __PARAM_SUCCESS__  # noqa: F821


def get_ifg_reg_list(slice_idx):
    """Gr2 does not have an ifg list, listify"""
    if is_graphene2 or is_palladium2:
        ifg_root = [tree.slice[slice_idx].ifg]
    else:
        ifg_root = tree.slice[slice_idx].ifg
    return ifg_root


def get_ifgb(ifg_root):
    """Complex tree register differences for ifgb per asic.
    Takes tree.slice[slice_idx].ifg[ifg_idx]"""
    if is_graphene2 or is_palladium2:
        ifgb = ifg_root.ifgbe_ra
    elif is_gr:
        ifgb = ifg_root.ifgbe_mac
    else:
        ifgb = ifg_root.ifgb
    return ifgb


def get_fc_port_cfg0(ifg_root, lane):
    if is_g2ll:
        return ifg_root.mac_pool8[lane // 8].fc_port_cfg0[lane % 8]
    return get_ifgb(ifg_root).fc_port_cfg0[lane]


def set_pfc_512bit_time(interface, bit_time, num_serdes_lanes):
    sai_lane = port_to_sai_lane_map[interface]
    slice_idx, ifg_idx, serdes_idx = sai_lane_to_slice_ifg_pif(sai_lane)
    for i in range(num_serdes_lanes):
        ifg_root = get_ifg_reg_list(slice_idx)[ifg_idx]
        reg = get_fc_port_cfg0(ifg_root, serdes_idx + i)
        print("[DEBUG-REGPATH] {} slice={} ifg={} lane={} reg_type={}".format(
            interface, slice_idx, ifg_idx, serdes_idx + i, type(reg).__name__))
        regval = dd0.read_register(reg)
        regval.port_512bit_time = bit_time
        dd0.write_register(reg, regval)


def compute_fractional_512bit_value(mac_freq_khz, port_gbps):
    ''' For G100 and G200 '''
    cycles_per_512bits = 512.0 * (mac_freq_khz / 1000000.) / port_gbps
    print("Cycles per 512bits: {}".format(cycles_per_512bits))
    int_part = int(cycles_per_512bits)
    float_part = cycles_per_512bits - int_part
    print("Integer: {}".format(int_part))
    print("Fraction: {}".format(float_part))
    bit_time = (int_part << 10) + int(float_part * 1024)
    return bit_time


def find_default_bit_time(interface):
    bit_time = None
    if is_pac or is_gb:
        bit_time = 5
    elif is_gr or is_graphene2 or is_g2ll or is_palladium2:
        mac_freq_khz = d0.get_int_property(sdk.la_device_property_e_MAC_FREQUENCY)
        print("Mac frequency khz: {}".format(mac_freq_khz))
        mac_port = get_mac_port(interface)
        mac_port_speed_enum_val = mac_port.get_speed()

        # Find matching speed enum
        speed = None
        for field in dir(mac_port):
            starter_str = "port_speed_e_E_"
            if field.startswith(starter_str):
                poss_speed_enum_val = getattr(mac_port, field)
                if mac_port_speed_enum_val == poss_speed_enum_val:
                    speed = field[len(starter_str):]
                    break
        assert speed is not None, "Failed to find matching speed for mac port enum value {}".format(
            mac_port_speed_enum_val
        )
        print("Speed string: {}".format(speed))
        assert speed[-1] == "G", "Unexpected speed, expected trailing 'G'"
        gbps_str = speed[:-1]
        assert gbps_str.isdigit(), "Non-digit speed {}".format(gbps_str)
        gbps = int(gbps_str)
        if is_palladium2 and gbps == 800:
            print("Reducing 800G to 400G for P200 PFC 512 bit time calculation")
            gbps = 400
        print("Port speed gbps: {}".format(gbps))
        bit_time = compute_fractional_512bit_value(mac_freq_khz, gbps)
    assert bit_time is not None, "Failed to find an appropriate 512bit time on this device"
    return bit_time


if __name__ == "__main__":
    try:
        asic_product = (
            "G200X" if is_g2ll else
            "G200" if is_graphene2 else
            "P200" if is_palladium2 else
            "G100" if is_gr else
            "Q200" if is_gb else
            "Q100" if is_pac else
            "unknown"
        )
        print("[DEBUG-ASIC] product={}".format(asic_product))
        for intf in param_interfaces:
            bit_time = find_default_bit_time(intf)
            print("Setting 512bit register to normal value {}".format(bit_time))
            set_pfc_512bit_time(intf, bit_time, 1)
        print(param_success)
    except Exception as e:
        print("Failed to set default PFC time: {}".format(e))
        tb = traceback.format_exc()
        for line in tb.splitlines():
            print(line)
