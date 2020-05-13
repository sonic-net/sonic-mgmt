# WR-ARP Args file

def add_wr_arp_args(parser):
    '''
        Adding arguments required for wr arp test cases

       Args:
            parser: pytest parser object

        Returns:
            None
    '''
    parser.addoption(
        "--test_duration",
        action="store",
        type=int,
        default=370,
        help="Test duration",
    )
