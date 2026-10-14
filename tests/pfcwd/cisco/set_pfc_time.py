import math
import traceback
from common import is_graphene2, is_palladium2, tree, is_gr, port_to_sai_lane_map, \
    sai_lane_to_slice_ifg_pif, dd0, is_pac, is_gb, sdk, d0, is_g2ll

# Input parameters replaced via 'sed'
param_interfaces = __PARAM_INTERFACES__  # noqa: F821
param_success = __PARAM_SUCCESS__  # noqa: F821

# Note: If is_g2ll == True, then is_graphene2 == True. See common.py.


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
    print("Setting bit_time (number of clocks) to {}".format(bit_time))
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


def find_pfc_512bit_time(time_sec):
    if is_gb or is_pac:
        khz = d0.get_int_property(sdk.la_device_property_e_DEVICE_FREQUENCY)
        print("Device frequency khz: {}".format(khz))
    elif is_gr or is_graphene2 or is_palladium2:
        khz = d0.get_int_property(sdk.la_device_property_e_MAC_FREQUENCY)
        print("Mac frequency khz: {}".format(khz))
    else:
        assert False, "Unsupported device type"
    clock_time = 1. / (khz * 1000)
    num_clocks_float = time_sec / (65535 * clock_time)

    if is_gb or is_pac:
        return math.ceil(num_clocks_float)
    if is_gr or is_graphene2 or is_palladium2:
        int_part = int(num_clocks_float)
        float_part = num_clocks_float - int_part
        print("Integer: {}".format(int_part))
        print("Float: {}".format(float_part))
        bit_time = (int_part << 10) + int(float_part * 1024)
        if bit_time >= 2**18:
            print("Maxed out, setting bit time {} instead of {}".format((2**18) - 1, bit_time))
            bit_time = (2**18) - 1
        return bit_time


def set_pfc512_bit_sec(interface, time_sec):
    bit_time = find_pfc_512bit_time(time_sec)
    set_pfc_512bit_time(interface, bit_time, num_serdes_lanes=1)


if __name__ == "__main__":
    # Increase PFC pause time
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
        num_ms = 50
        print("Setting PFC frame time to {}ms".format(num_ms))
        for intf in param_interfaces:
            set_pfc512_bit_sec(intf, num_ms / 1000)
        print(param_success)
    except Exception as e:
        print("Failed to set PFC frame time: {}".format(e))
        tb = traceback.format_exc()
        for line in tb.splitlines():
            print(line)
