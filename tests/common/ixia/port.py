import enum

class IxiaPortType(enum.Enum):
    """
    IXIA port type
    """
    IPInterface = 1
    PortChannelMember = 2
    VlanMember = 3

class IxiaPortConfig:
    """
    IXIA port configuration information
    """
    def __init__(self, id, ip, mac, gw, gw_mac, prefix_len, port_type, peer_port):
        self.id = id
        self.ip = ip
        self.mac = mac
        self.gateway = gw
        self.gateway_mac = gw_mac
        self.prefix_len = prefix_len
        self.type = port_type
        self.peer_port = peer_port

def select_ports(port_config_list, pattern, rx_port_id):
    """
    Given a traffic pattern, select IXIA ports to send and receive traffic

    Args:
        port_config_list (list of IxiaPortConfig):
        pattern (str): traffic pattern, "many to one" or "all to all"
        rx_port_id (int): ID of the port that should receive traffic, e.g.,
        recever in "many to one" traffic pattern

    Returns:
        tx_port_id_list (list): IDs of IXIA ports to send traffic
        rx_port_id_list (list): IDs of IXIA ports to receive traffic
    """
    tx_port_id_list = []
    rx_port_id_list = []

    patterns = ['all to all', 'many to one']
    if pattern not in patterns:
        raise ValueError('invalid traffic pattern passed in "{}", must be {}'.format(
            pattern, ' or '.join(['"{}"'.format(src) for src in patterns])))

    rx_port_config = next((x for x in port_config_list if x.id == rx_port_id), None)
    if rx_port_config is None:
        raise ValueError('Fail to find configuration for RX port')

    if pattern == "many to one":
        rx_port_id_list = [rx_port_id]
        """ Interfaces in the same portchannel cannot send traffic to each other """
        if rx_port_config.type == IxiaPortType.PortChannelMember:
            tx_port_id_list = [x.id for x in port_config_list \
                               if x.ip != rx_port_config.ip]
        else:
            tx_port_id_list = [x.id for x in port_config_list if x.id != rx_port_id]

    elif pattern == "all to all":
        """ Interfaces in the same portchannel cannot send traffic to each other """
        if rx_port_config.type == IxiaPortType.PortChannelMember:
            tx_port_id_list = [x.id for x in port_config_list \
                               if x.ip != rx_port_config.ip]
            tx_port_id_list.append(rx_port_id)
        else:
            tx_port_id_list = [x.id for x in port_config_list]

        rx_port_id_list = [x for x in tx_port_id_list]

    return tx_port_id_list, rx_port_id_list

def select_tx_port(tx_port_id_list, rx_port_id):
    """
    Select an IXIA port to send traffic

    Args:
        tx_port_id_list (list): IDs of ports that can send traffic
        rx_port_id (int): ID of the port that should receive traffic

    Returns:
        ID of the port to send traffic (int) or None (if we fail to find it)
    """
    if len(tx_port_id_list) == 0:
        return None

    max_tx_port_id = max(tx_port_id_list)
    if  max_tx_port_id < rx_port_id:
        return max_tx_port_id
    else:
        return min(x for x in tx_port_id_list if x > rx_port_id)
