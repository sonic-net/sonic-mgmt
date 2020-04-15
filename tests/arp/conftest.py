import pytest
from args.wr_arp_args import add_wr_arp_args

# WR-ARP pytest arguments
def pytest_addoption(parser):

    add_wr_arp_args(parser)
