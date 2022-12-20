from natsort import natsorted


def get_common_supported_speeds(duthost, dut_port_name, fanout, fanout_port_name):
    """Get supported speeds list for a given port. The supported speeds list is 
       a intersection of DUT port supported speeds, fanout port supported speeds,
       and cable supported speeds.

    Args:
        duthost: DUT object
        dut_port_name (str): DUT interface name
        fanout: Fanout object
        fanout_port_name (str): The name of fanout port which connected to the DUT port

    Returns:
        list: A sorted list of supported speed strings
    """

    dut_current_port_speed = duthost.get_speed(dut_port_name)
    dut_supported_speeds = duthost.get_supported_speeds(dut_port_name)
    if not dut_supported_speeds:
        dut_supported_speeds = [dut_current_port_speed]

    fanout_supported_speeds = fanout.get_supported_speeds(fanout_port_name)
    if not fanout_supported_speeds:
        dut_supported_speeds = [dut_current_port_speed]

    # get supported speeds for the cable
    cable_supported_speeds = get_cable_supported_speeds(duthost, dut_port_name)
    if not cable_supported_speeds:
        dut_supported_speeds = [dut_current_port_speed]

    supported_speeds = set(dut_supported_speeds) & set(fanout_supported_speeds) & set(cable_supported_speeds)
    if not supported_speeds:
        # Since the port link is up before the test, we should not hit this branch
        # However, in case we hit here, we use current actual speed as supported speed
        supported_speeds = [dut_current_port_speed]
    
    supported_speeds = natsorted(supported_speeds)
    return supported_speeds


def get_cable_supported_speeds(duthost, dut_port_name):
    """Get cable supported speeds. As there is no SONiC CLI to get supported speeds for
       a given cable, this function depends on vendor implementation. 
       A sample: MlnxCableSupportedSpeedsHelper.

    Args:
        duthost: DUT object
        dut_port_name (str): DUT interface name

    Returns:
        list: A list of supported speed strings
    """
    helper = get_cable_supported_speeds_helper(duthost)
    return helper.get_cable_supported_speeds(duthost, dut_port_name) if helper else None

def get_cable_supported_speeds_helper(duthost):
    """Get a cable supported speeds helper

    Args:
        duthost: DUT object

    Returns:
        object: A helper class or instance
    """
    asic_type = duthost.facts["asic_type"]

    if asic_type == "mellanox":
        return MlnxCableSupportedSpeedsHelper
    elif asic_type == "barefoot":
        return BfnCableSupportedSpeedsHelper
    else:
        return None

class MlnxCableSupportedSpeedsHelper(object):
    # To avoid getting ports list again and again, use a class level variable to save
    # all sorted ports.
    # Key: dut host object, value: a sorted list of interface name
    sorted_ports = {}

    # Key: tuple of dut host object and interface name, value: supported speed list
    supported_speeds = {}

    device_path = None

    @classmethod
    def get_cable_supported_speeds(cls, duthost, dut_port_name):
        """Helper function to get supported speeds for a cable

        Args:
            duthost: DUT object
            dut_port_name (str): DUT interface name

        Returns:
            list: A list of supported speed strings
        """
        if (duthost, dut_port_name) in cls.supported_speeds:
            return cls.supported_speeds[duthost, dut_port_name]

        if duthost not in cls.sorted_ports:
            int_status = duthost.show_interface(command="status")["ansible_facts"]['int_status']
            ports = natsorted([port_name for port_name in int_status.keys()])
            cls.sorted_ports[duthost] = ports

        if not cls.device_path:
            cls.device_path = duthost.shell('ls /dev/mst/*_pci_cr0')['stdout'].strip()
        port_index = cls.sorted_ports[duthost].index(dut_port_name) + 1
        cmd = 'mlxlink -d {} -p {} | grep "Supported Cable Speed"'.format(cls.device_path, port_index)
        output = duthost.shell(cmd)['stdout'].strip()
        # Valid output should be something like "Supported Cable Speed:0x68b1f141 (100G,56G,50G,40G,25G,10G,1G)"
        if not output:
            return None
        pos = output.rfind('(')
        if pos == -1:
            return None
        speeds_str = output[pos+1:-1]
        speeds = list(set([speed.split('G')[0] + '000' for speed in speeds_str.split(',')]))
        cls.supported_speeds[(duthost, dut_port_name)] = speeds
        return speeds

class BfnCableSupportedSpeedsHelper(object):

    @classmethod
    def get_cable_supported_speeds(cls, duthost, dut_port_name):
        
        return duthost.get_supported_speeds(dut_port_name)

def is_sfp_speed_supported(duthost, if_name, port_speed):
    pam4_supporting_sfps = [
        'QSFP56',
        'QSFP112',
        'SFP-DD',
        'OSFP',
    ]
    
    sfp_type = duthost.get_sfp_type(if_name)
    if not sfp_type:
        return True
    
    n_lanes = duthost.count_portlanes(if_name)
    per_lane_speed = int(port_speed) // n_lanes
    return per_lane_speed <= 25000 or sfp_type in pam4_supporting_sfps
