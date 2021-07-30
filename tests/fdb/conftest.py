from .args.fdb_args import add_fdb_mac_expire_args

# FDB pytest arguments
def pytest_addoption(parser):
    '''
        Adds option to FDB pytest

        Args:
            parser: pytest parser object

        Returns:
            None
    '''
    add_fdb_mac_expire_args(parser)
