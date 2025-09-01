import enum


class SnappiPortType(enum.Enum):
    """
    Snappi port type
    """
    IPInterface = 1
    PortChannelMember = 2
    VlanMember = 3


class SnappiPortConfig:
    """
    Snappi port configuration information
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

    def __str__(self):
        return "<SnappiPortConfig id: {}, ip: {}, mac: {}, gw: {}, gw_mac: {}, \
                prefix_len: {}, type: {}, peer_port: {}>".format(
                self.id, self.ip, self.mac, self.gateway, self.gateway_mac,
                self.prefix_len, self.type, self.peer_port)

    def __repr__(self):
        return self.__str__()


def select_ports(port_config_list, pattern, rx_port_id):
    """
    Given a traffic pattern, select Snappi ports to send and receive traffic

    Args:
        port_config_list (list of SnappiPortConfig):
        pattern (str): traffic pattern, "many to one" or "all to all"
        rx_port_id (int): ID of the port that should receive traffic, e.g.,
        recever in "many to one" traffic pattern

    Returns:
        tx_port_id_list (list): IDs of Snappi ports to send traffic
        rx_port_id_list (list): IDs of Snappi ports to receive traffic
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
        if rx_port_config.type == SnappiPortType.PortChannelMember:
            tx_port_id_list = [x.id for x in port_config_list
                               if x.ip != rx_port_config.ip]
        else:
            tx_port_id_list = [x.id for x in port_config_list if x.id != rx_port_id]

    elif pattern == "all to all":
        """ Interfaces in the same portchannel cannot send traffic to each other """
        if rx_port_config.type == SnappiPortType.PortChannelMember:
            tx_port_id_list = [x.id for x in port_config_list
                               if x.ip != rx_port_config.ip]
            tx_port_id_list.append(rx_port_id)
        else:
            tx_port_id_list = [x.id for x in port_config_list]

        rx_port_id_list = [x for x in tx_port_id_list]

    return tx_port_id_list, rx_port_id_list


def select_tx_port(tx_port_id_list, rx_port_id, num_tx_ports=1):
    """
    Select one or more Snappi ports to send traffic.

    Args:
        tx_port_id_list (list): IDs of ports that can send traffic
        rx_port_id (int): ID of the port that should receive traffic
        num_tx_ports (int): Number of TX ports to select (default: 1)

    Returns:
        int or list: ID of the port to send traffic (int) if num_tx_ports==1,
                     or list of port IDs if num_tx_ports > 1.
                     Returns None if no TX ports are available.

    Raises:
        ValueError: If num_tx_ports > number of available TX ports.
    """
    if not tx_port_id_list or len(tx_port_id_list) == 0:
        return None

    if num_tx_ports < 1:
        raise ValueError("num_tx_ports must be at least 1")

    if num_tx_ports > len(tx_port_id_list):
        raise ValueError(
            f"Requested {num_tx_ports} TX ports, but only {len(tx_port_id_list)} available"
        )

    sorted_tx_ports = sorted(tx_port_id_list)
    # Find all TX ports with ID greater than RX port ID
    tx_ports_gt_rx = [x for x in sorted_tx_ports if x > rx_port_id]
    tx_ports_lt_rx = [x for x in sorted_tx_ports if x < rx_port_id]

    selected_ports = []

    # Prefer ports with ID greater than RX port ID, then wrap around if needed
    if len(tx_ports_gt_rx) >= num_tx_ports:
        selected_ports = tx_ports_gt_rx[:num_tx_ports]
    else:
        selected_ports = tx_ports_gt_rx + tx_ports_lt_rx[:num_tx_ports - len(tx_ports_gt_rx)]

    if num_tx_ports == 1:
        return selected_ports[0]
    else:
        return selected_ports
