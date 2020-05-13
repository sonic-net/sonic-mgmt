from args.wr_arp_args import add_wr_arp_args

# WR-ARP pytest arguments
def pytest_addoption(parser):
    '''
        Adds option to FDB pytest

        Args:
            parser: pytest parser object

        Returns:
            None
    '''
    add_wr_arp_args(parser)
