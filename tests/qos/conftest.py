from .args.qos_sai_args import add_qos_sai_args
from .args.buffer_args import add_dynamic_buffer_calculation_args

# QoS pytest arguments
def pytest_addoption(parser):
    '''
        Adds option to QoS pytest

        Args:
            parser: pytest parser object

        Returns:
            None
    '''
    add_qos_sai_args(parser)
    add_dynamic_buffer_calculation_args(parser)
