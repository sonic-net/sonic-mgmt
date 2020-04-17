from args.populate_fdb_args import add_populate_fdb_args

# FDB pytest arguments
def pytest_addoption(parser):
    '''
        Adds option to FDB pytest

        Args:
            parser: pytest parser object

        Returns:
            None
    '''
    add_populate_fdb_args(parser)
