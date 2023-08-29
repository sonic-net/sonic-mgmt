

def _port_alias_to_name_map_50G(all_ports, s100G_ports,):
    new_map = {}
    # 50G ports
    s50G_ports = list(set(all_ports) - set(s100G_ports))

    for i in s50G_ports:
        new_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 1) * 4)
        new_map["Ethernet%d/3" % i] = "Ethernet%d" % ((i - 1) * 4 + 2)

    for i in s100G_ports:
        new_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 1) * 4)

    return new_map


def get_port_alias_to_name_map(hwsku, asic_name=None):
    port_alias_to_name_map = {}
    port_alias_asic_map = {}
    port_name_to_index_map = {}
    HWSKU_WITH_PORT_INDEX_FROM_PORT_CONFIG = ["Cisco-88-LC0-36FH-M-O36",
                                              "Cisco-88-LC0-36FH-O36",
                                              "Cisco-8800-LC-48H-C48"]
    try:
        from sonic_py_common import multi_asic
        from ansible.module_utils.multi_asic_utils import load_db_config
        load_db_config()
        ports_info = multi_asic.get_port_table(namespace=asic_name)
        for port, port_data in ports_info.items():
            if "alias" in port_data:
                port_alias_to_name_map[port_data["alias"]] = port
            if "asic_port_name" in port_data:
                port_alias_asic_map[port_data["asic_port_name"]] = port
            if "index" in port_data and hwsku in HWSKU_WITH_PORT_INDEX_FROM_PORT_CONFIG:
                port_name_to_index_map[port] = int(port_data["index"])
    except ImportError:
        if hwsku == "Force10-S6000":
            for i in range(0, 128, 4):
                port_alias_to_name_map["fortyGigE0/%d" % i] = "Ethernet%d" % i
        elif hwsku == "Force10-S6100":
            for i in range(0, 4):
                for j in range(0, 16):
                    port_alias_to_name_map["fortyGigE1/%d/%d" % (i + 1, j + 1)] = "Ethernet%d" % (i * 16 + j)
        elif hwsku == "Force10-Z9100":
            for i in range(0, 128, 4):
                port_alias_to_name_map["hundredGigE1/%d" % (i / 4 + 1)] = "Ethernet%d" % i
        # TODO: Come up with a generic formula for generating etp style aliases based on number of ports and lanes
        elif hwsku == "DellEMC-Z9332f-M-O16C64":
            # 100G ports
            s100G_ports = [x for x in range(0, 96, 2)] + [x for x in range(128, 160, 2)]

            # 400G ports
            s400G_ports = [x for x in range(96, 128, 8)] + [x for x in range(160, 256, 8)]

            # 10G ports
            s10G_ports = [x for x in range(256, 258)]

            for i in s100G_ports:
                alias = "etp{}{}".format(((i + 8) // 8), chr(ord('a') + (i // 2) % 4))
                port_alias_to_name_map[alias] = "Ethernet{}".format(i)
            for i in s400G_ports:
                alias = "etp{}".format((i // 8) + 1)
                port_alias_to_name_map[alias] = "Ethernet{}".format(i)
            for i in s10G_ports:
                alias = "etp{}".format(33 if i == 256 else 34)
                port_alias_to_name_map[alias] = "Ethernet{}".format(i)
        elif hwsku == "DellEMC-Z9332f-O32" or hwsku == "DellEMC-Z9332f-C32":
            for i in range(0, 256, 8):
                alias = "etp{}".format((i // 8) + 1)
                port_alias_to_name_map[alias] = "Ethernet{}".format(i)
            for i in range(256, 258):
                alias = "etp{}".format(33 if i == 256 else 34)
                port_alias_to_name_map[alias] = "Ethernet{}".format(i)
        elif hwsku == "Arista-7050-QX32":
            for i in range(1, 25):
                port_alias_to_name_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 1) * 4)
            for i in range(25, 33):
                port_alias_to_name_map["Ethernet%d" % i] = "Ethernet%d" % ((i - 1) * 4)
        elif hwsku == "Arista-7050-QX-32S" or hwsku == "Arista-7050QX-32S-S4Q31":
            for i in range(0, 4):
                port_alias_to_name_map["Ethernet%d" % (i + 1)] = "Ethernet%d" % i
            for i in range(6, 29):
                port_alias_to_name_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 5) * 4)
            for i in range(29, 37):
                port_alias_to_name_map["Ethernet%d" % i] = "Ethernet%d" % ((i - 5) * 4)
        elif hwsku == "Arista-7050QX32S-Q32":
            for i in range(5, 29):
                port_alias_to_name_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 5) * 4)
            for i in range(29, 37):
                port_alias_to_name_map["Ethernet%d" % i] = "Ethernet%d" % ((i - 5) * 4)
        elif hwsku == "Arista-7280CR3-C40":
            for i in range(1, 33):
                port_alias_to_name_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 1) * 4)
            for i in range(33, 41, 2):
                port_alias_to_name_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 1) * 4)
                port_alias_to_name_map["Ethernet%d/5" % i] = "Ethernet%d" % (i * 4)
        elif hwsku == "Arista-7260CX3-C64" or hwsku == "Arista-7170-64C" or hwsku == "Arista-7260CX3-Q64":
            for i in range(1, 65):
                port_alias_to_name_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 1) * 4)
        elif hwsku == "Arista-7060CX-32S-C32" or hwsku == "Arista-7060CX-32S-Q32" \
                or hwsku == "Arista-7060CX-32S-C32-T1" or hwsku == "Arista-7170-32CD-C32" \
                or hwsku == "Arista-7050CX3-32S-C32":
            for i in range(1, 33):
                port_alias_to_name_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 1) * 4)
        elif hwsku == "Arista-7060DX5-64S":
            for i in range(1, 65):
                port_alias_to_name_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 1) * 8)
        elif hwsku == "Mellanox-SN2700-D40C8S8":
            # 10G ports
            s10G_ports = range(0, 4) + range(8, 12)

            # 50G ports
            s50G_ports = [x for x in range(16, 24, 2)] + [x for x in range(40, 88, 2)] + [x for x in range(104, 128, 2)]

            # 100G ports
            s100G_ports = [x for x in range(24, 40, 4)] + [x for x in range(88, 104, 4)]

            for i in s10G_ports:
                alias = "etp%d" % (i / 4 + 1) + chr(ord('a') + i % 4)
                port_alias_to_name_map[alias] = "Ethernet%d" % i
            for i in s50G_ports:
                alias = "etp%d" % (i / 4 + 1) + ("a" if i % 4 == 0 else "b")
                port_alias_to_name_map[alias] = "Ethernet%d" % i
            for i in s100G_ports:
                alias = "etp%d" % (i / 4 + 1)
                port_alias_to_name_map[alias] = "Ethernet%d" % i
        elif hwsku == "Mellanox-SN2700-D44C10":
            # 50G ports
            s50G_ports = [x for x in range(8, 24, 2)] + [x for x in range(40, 88, 2)] + [x for x in range(104, 128, 2)]

            # 100G ports
            s100G_ports = [0, 4] + [x for x in range(24, 40, 4)] + [x for x in range(88, 104, 4)]

            for i in s50G_ports:
                alias = "etp%d" % (i / 4 + 1) + ("a" if i % 4 == 0 else "b")
                port_alias_to_name_map[alias] = "Ethernet%d" % i
            for i in s100G_ports:
                alias = "etp%d" % (i / 4 + 1)
                port_alias_to_name_map[alias] = "Ethernet%d" % i
        elif hwsku == "Mellanox-SN2700-D48C8":
            # 50G ports
            s50G_ports = [x for x in range(0, 24, 2)] + [x for x in range(40, 88, 2)] + [x for x in range(104, 128, 2)]

            # 100G ports
            s100G_ports = [x for x in range(24, 40, 4)] + [x for x in range(88, 104, 4)]

            for i in s50G_ports:
                alias = "etp%d" % (i / 4 + 1) + ("a" if i % 4 == 0 else "b")
                port_alias_to_name_map[alias] = "Ethernet%d" % i
            for i in s100G_ports:
                alias = "etp%d" % (i / 4 + 1)
                port_alias_to_name_map[alias] = "Ethernet%d" % i
        elif hwsku == "Mellanox-SN2700" or hwsku == "ACS-MSN2700":
            for i in range(1, 33):
                port_alias_to_name_map["etp%d" % i] = "Ethernet%d" % ((i - 1) * 4)
        elif hwsku == "Arista-7060CX-32S-D48C8":
            # All possible breakout 50G port numbers:
            all_ports = [x for x in range(1, 33)]

            # 100G ports
            s100G_ports = [x for x in range(7, 11)]
            s100G_ports += [x for x in range(23, 27)]

            port_alias_to_name_map = _port_alias_to_name_map_50G(all_ports, s100G_ports)
        elif hwsku == "Arista-7260CX3-D108C8":
            # All possible breakout 50G port numbers:
            all_ports = [x for x in range(1, 65)]

            # 100G ports
            s100G_ports = [x for x in range(13, 21)]

            port_alias_to_name_map = _port_alias_to_name_map_50G(all_ports, s100G_ports)
        elif hwsku == "Arista-7800R3-48CQ-LC" or hwsku == "Arista-7800R3K-48CQ-LC":
            for i in range(1, 48):
                port_alias_to_name_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 1) * 4)
        elif hwsku == "INGRASYS-S9100-C32":
            for i in range(1, 33):
                port_alias_to_name_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 1) * 4)
        elif hwsku == "INGRASYS-S9100-C32" or hwsku == "INGRASYS-S9130-32X" or hwsku == "INGRASYS-S8810-32Q":
            for i in range(1, 33):
                port_alias_to_name_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 1) * 4)
        elif hwsku == "INGRASYS-S8900-54XC":
            for i in range(1, 49):
                port_alias_to_name_map["Ethernet%d" % i] = "Ethernet%d" % (i - 1)
            for i in range(49, 55):
                port_alias_to_name_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 49) * 4 + 48)
        elif hwsku == "INGRASYS-S8900-64XC":
            for i in range(1, 49):
                port_alias_to_name_map["Ethernet%d" % i] = "Ethernet%d" % (i - 1)
            for i in range(49, 65):
                port_alias_to_name_map["Ethernet%d/1" % i] = "Ethernet%d" % ((i - 49) * 4 + 48)
        elif hwsku == "Accton-AS7712-32X":
            for i in range(1, 33):
                port_alias_to_name_map["hundredGigE%d" % i] = "Ethernet%d" % ((i - 1) * 4)
        elif hwsku == "Accton-AS7726-32X":
            for i in range(1, 33):
                port_alias_to_name_map["hundredGigE%d" % i] = "Ethernet%d" % ((i - 1) * 4)
        elif hwsku == "montara":
            for i in range(1, 33):
                port_alias_to_name_map["hundredGigE%d" % i] = "Ethernet%d" % ((i - 1) * 4)
        elif hwsku == "Celestica-DX010-C32":
            for i in range(1, 33):
                port_alias_to_name_map["etp%d" % i] = "Ethernet%d" % ((i - 1) * 4)
        elif hwsku == "Celestica-DX010-D48C8":
            for i in range(1, 21):
                port_alias_to_name_map["etp{}{}".format((i + 1)//2, "a" if i % 2 == 1 else "b")] = \
                    "Ethernet%d" % ((i - 1) * 2)
            for i in range(21, 25):
                port_alias_to_name_map["etp{}".format(i - 10)] = "Ethernet%d" % ((i - 10 - 1) * 4)
            for i in range(25, 33):
                port_alias_to_name_map["etp{}{}".format((i + 4 + 1)//2, "a" if i % 2 == 1 else "b")] = \
                    "Ethernet%d" % ((i + 4 - 1) * 2)
            for i in range(33, 37):
                port_alias_to_name_map["etp{}".format(i - 14)] = "Ethernet%d" % ((i - 14 - 1) * 4)
            for i in range(37, 57):
                port_alias_to_name_map["etp{}{}".format((i + 8 + 1)//2, "a" if i % 2 == 1 else "b")] = \
                    "Ethernet%d" % ((i + 8 - 1) * 2)
        elif hwsku == "Seastone-DX010":
            for i in range(1, 33):
                port_alias_to_name_map["Eth%d" % i] = "Ethernet%d" % ((i - 1) * 4)
        elif hwsku in ["Celestica-E1031-T48S4", "Nokia-7215", "Nokia-M0-7215"]:
            for i in range(1, 53):
                port_alias_to_name_map["etp%d" % i] = "Ethernet%d" % ((i - 1))
        elif hwsku == "et6448m":
            for i in range(0, 52):
                port_alias_to_name_map["Ethernet%d" % i] = "Ethernet%d" % i
        elif hwsku == "Nokia-IXR7250E-36x400G" or hwsku == "Nokia-IXR7250E-36x100G":
            for i in range(1, 37):
                sonic_name = "Ethernet%d" % ((i - 1) * 8)
                port_alias_to_name_map["Ethernet{}/{}".format(i, 1)] = sonic_name
        elif hwsku == 'Nokia-IXR7250E-SUP-10':
            port_alias_to_name_map = {}
        elif hwsku == "newport":
            for i in range(0, 256, 8):
                port_alias_to_name_map["Ethernet%d" % i] = "Ethernet%d" % i
        elif hwsku == "32x100Gb":
            for i in range(0, 32):
                port_alias_to_name_map["Ethernet%d" % i] = "Ethernet%d" % i
        elif hwsku == "36x100Gb":
            for i in range(0, 36):
                port_alias_to_name_map["Ethernet%d" % i] = "Ethernet%d" % i
        elif hwsku == "Cisco-8102-C64":
            for i in range(0, 64):
                port_alias_to_name_map["etp%d" % i] = "Ethernet%d" % (i * 4)
        elif hwsku == "Cisco-8101-T32":
            for i in range(0, 32):
                port_alias_to_name_map["etp%d" % i] = "Ethernet%d" % (i * 8)
        elif hwsku == "Cisco-8101-C48T8":
            for i in range(0, 24, 2):
                port_alias_to_name_map["etp%d" % i] = "Ethernet%d" % (i * 4)
                port_alias_to_name_map["etp%d" % (i+1)] = "Ethernet%d" % ((i+1) * 4)
            for i in range(0, 8):
                port_alias_to_name_map["etp%d" % (i+24)] = "Ethernet%d" % ((i+12) * 8)
            for i in range(0, 24, 2):
                port_alias_to_name_map["etp%d" % (i+32)] = "Ethernet%d" % ((i+40) * 4)
                port_alias_to_name_map["etp%d" % (i+33)] = "Ethernet%d" % ((i+41) * 4)
        elif hwsku == "Cisco-8101-C64":
            for i in range(0, 64):
                port_alias_to_name_map["etp%d" % i] = "Ethernet%d" % (i * 4)
        elif hwsku in ["Cisco-8800-LC-48H-C48"]:
            for i in range(0, 48, 1):
                port_alias_to_name_map["Ethernet%d" % i] = "Ethernet%d" % (i * 4)
        elif hwsku in ["Cisco-88-LC0-36FH-M-O36", "Cisco-88-LC0-36FH-O36"]:
            for i in range(0, 36, 1):
                port_alias_to_name_map["Ethernet%d" % i] = "Ethernet%d" % (i * 8)
        elif hwsku in ["msft_multi_asic_vs"]:
            for i in range(1, 65):
                port_alias_to_name_map["Ethernet1/%d" % i] = "Ethernet%d" % ((i - 1) * 4)
        elif hwsku == "msft_four_asic_vs":
            for i in range(1, 9):
                port_alias_to_name_map["Ethernet1/%d" % i] = "Ethernet%d" % ((i - 1) * 4)
        elif hwsku == "B6510-48VS8CQ" or hwsku == "RA-B6510-48V8C":
            for i in range(1, 49):
                port_alias_to_name_map["twentyfiveGigE0/%d" % i] = "Ethernet%d" % i
            for i in range(49, 57):
                port_alias_to_name_map["hundredGigE0/%d" % (i-48)] = "Ethernet%d" % i
        elif hwsku == "RA-B6510-32C":
            for i in range(1, 33):
                port_alias_to_name_map["hundredGigE%d" % i] = "Ethernet%d" % i
        elif hwsku == "RA-B6910-64C":
            for i in range(1, 65):
                port_alias_to_name_map["hundredGigE%d" % i] = "Ethernet%d" % i
        elif hwsku == "RA-B6920-4S":
            for i in range(1, 129):
                port_alias_to_name_map["hundredGigE%d" % i] = "Ethernet%d" % i
        elif hwsku in ["Wistron_sw_to3200k_32x100", "Wistron_sw_to3200k"]:
            for i in range(0, 256, 8):
                port_alias_to_name_map["Ethernet%d" % i] = "Ethernet%d" % i
        elif hwsku == "Arista-720DT-48S" or hwsku == "Arista-720DT-G48S4":
            for i in range(1, 53):
                port_alias_to_name_map["etp%d" % i] = "Ethernet%d" % (i - 1)
        else:
            for i in range(0, 128, 4):
                port_alias_to_name_map["Ethernet%d" % i] = "Ethernet%d" % i

    return port_alias_to_name_map, port_alias_asic_map, port_name_to_index_map


def get_port_indices_for_asic(asic_id, port_name_list_sorted):
    front_end_port_name_list = [p for p in port_name_list_sorted if 'BP' not in p and 'IB' not in p and 'Rec' not in p]
    back_end_port_name_list = [p for p in port_name_list_sorted if 'BP' in p or 'IB' in p or 'Rec' in p]
    index_offset = 0
    # Create mapping between port alias and physical index
    port_index_map = {}
    if asic_id:
        index_offset = int(asic_id) * len(front_end_port_name_list)
    for idx, val in enumerate(front_end_port_name_list, index_offset):
        port_index_map[val] = idx
    for idx, val in enumerate(back_end_port_name_list, index_offset):
        port_index_map[val] = idx

    return port_index_map
