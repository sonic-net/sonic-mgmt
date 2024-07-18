'''
In this file user can modify the line_card_choice and it chooses the corresponding hostname
and asic values from the config_set hostnames can be modified according to the dut hostname mentioned
in the snappi_sonic_devices.csv and asic values based on if its a chassis based dut

    chassis_single_line_card_single_asic : this option selects the ports form the
                                           hostname and its respective asic value

    chassis_single_line_card_multi_asic : this option selects the ports from the hostname
                                          and minimum of 1 port from each of the asic values

    chassis_multi_line_card_single_asic : this option selects min 1 port from each of
                                          the hostnames and its asic value

    chassis_multi_line_card_multi_asic : this option selects min of 1 port from hostname1
                                         and asic1 and 1 port from hostname2 and asic2

    non_chassis_multi_line_card : this option selects min of 1 port from hostname1
                                  and 1 port from hostname2

    non_chassis_single_line_card : this option selects all the ports from the hostname

'''
line_card_choice = 'chassis_multi_line_card_multi_asic'
config_set = {
                "chassis_single_line_card_single_asic": {
                    'hostname': ["sonic-s6100-dut1"],
                    'asic': ["asic0"]
                },
                "chassis_single_line_card_multi_asic": {
                    'hostname': ["sonic-s6100-dut1"],
                    'asic': ["asic0", "asic1"]
                },
                "chassis_multi_line_card_single_asic": {
                    'hostname': ["sonic-s6100-dut1", "sonic-s6100-dut2"],
                    'asic': ["asic1"]
                },
                "chassis_multi_line_card_multi_asic": {
                    'hostname': ["sonic-s6100-dut1", "sonic-s6100-dut2"],
                    'asic': ["asic0", "asic1"]
                },
                "non_chassis_multi_line_card": {
                    'hostname': ["sonic-s6100-dut1", "sonic-s6100-dut2"],
                    'asic': [None]
                },
                "non_chassis_single_line_card": {
                    'hostname': ["sonic-s6100-dut1"],
                    'asic': [None]
                }
            }

dut_ip_start = '20.1.1.0'
snappi_ip_start = '20.1.1.1'
prefix_length = 31

dut_ipv6_start = '2000:1::1'
snappi_ipv6_start = '2000:1::2'
v6_prefix_length = 126

pfcQueueGroupSize = 8  # can have values 4 or 8
pfcQueueValueDict = {0: 0,
                     1: 1,
                     2: 0,
                     3: 3,
                     4: 2,
                     5: 0,
                     6: 1,
                     7: 0}
