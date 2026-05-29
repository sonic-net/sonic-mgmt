# Populate FDB Args file

def add_populate_fdb_args(parser):
    '''
        Adding arguments required for populate fdb test cases

        Args:
            parser: pytest parser object

        Returns:
            None
    '''
    parser.addoption(
        '--mac_to_ip_ratio',
        action='store',
        type=str,
        default='100:1',
        help='Ratio of distinct MAC addresses to distinct IP addresses assigned to VM',
    )

    parser.addoption(
        '--start_mac',
        action='store',
        type=str,
        default='00:25:ae:22:11:00',
        help='VM start MAC address. Subsequent MAC addresses are increment of 1 on top of start MAC',
    )

    parser.addoption(
        '--packet_count',
        action='store',
        type=int,
        default=2000,
        help='Number of packets to be created and sent to DUT',
    )
