from ecn_args.ecn_args import add_ecn_args


def pytest_addoption(parser):
    '''
    Add option to ECN pytest
    Args:
        parser: pytest parser object
    Returns:
        None
    '''
    add_ecn_args(parser)
