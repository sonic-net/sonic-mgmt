from .args.qos_sai_args import add_qos_sai_args

# WR-ARP pytest arguments
def pytest_addoption(parser):
    '''
        Adds option to QoS pytest

        Args:
            parser: pytest parser object

        Returns:
            None
    '''
    add_qos_sai_args(parser)
