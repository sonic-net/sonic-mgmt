# Verified on Q200 @ 100G port speed. e.g. 687 is bit time to pause for 50ms (clock at 900Mhz).

def get_ifg_reg_list(slice_idx):
    ''' Gr2 does not have an ifg list, listify '''
    if is_graphene2:                                 # noqa: F821
        ifg_root = [tree.slice[slice_idx].ifg]       # noqa: F821
    else:
        ifg_root = tree.slice[slice_idx].ifg       # noqa: F821
    return ifg_root


def get_ifgb(ifg_root):
    ''' Complex tree register differences for ifgb per asic.
            Takes tree.slice[slice_idx].ifg[ifg_idx] '''
    if is_graphene2:                               # noqa: F821
        ifgb = ifg_root.ifgbe_ra
    elif is_gr:                               # noqa: F821
        ifgb = ifg_root.ifgbe_mac
    else:
        ifgb = ifg_root.ifgb
    return ifgb


def set_pfc_512bit_time(interface, bit_time, num_serdes_lanes):
    sai_lane = port_to_sai_lane_map[interface]                               # noqa: F821
    slice_idx, ifg_idx, serdes_idx = sai_lane_to_slice_ifg_pif(sai_lane)     # noqa: F821
    for i in range(num_serdes_lanes):
        ifg_root = get_ifg_reg_list(slice_idx)[ifg_idx]
        ifg_mac = get_ifgb(ifg_root)
        regval = dd0.read_register(ifg_mac.fc_port_cfg0[serdes_idx + i])     # noqa: F821
        regval.port_512bit_time = bit_time
        dd0.write_register(ifg_mac.fc_port_cfg0[serdes_idx + i], regval)     # noqa: F821


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


bit_time = None
if is_pac or is_gb:                                                       # noqa: F821
    bit_time = 5
elif is_gr or is_graphene2:                                               # noqa: F821
    mac_freq_khz = d0.get_int_property(sdk.la_device_property_e_MAC_FREQUENCY)      # noqa: F821
    print("Mac frequency khz: {}".format(mac_freq_khz))

    mac_port = get_mac_port(INTERFACE)                                    # noqa: F821
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
    assert speed is not None, "Failed to find matching speed for mac port enum value {}".format(mac_port_speed_enum_val)
    print("Speed string: {}".format(speed))
    assert speed[-1] == "G", "Unexpected speed, expected trailing 'G'"
    gbps_str = speed[:-1]
    assert gbps_str.isdigit(), "Non-digit speed {}".format(gbps_str)
    gbps = int(gbps_str)
    print("Port speed gbps: {}".format(gbps))
    bit_time = compute_fractional_512bit_value(mac_freq_khz, gbps)


assert bit_time is not None, "Failed to find an appropriate 512bit time on this device"
print("Setting 512bit register to normal value {}".format(bit_time))
set_pfc_512bit_time("INTERFACE", bit_time, 1)
print("Done")
