# Dynamic buffer calculation args file

def add_dynamic_buffer_calculation_args(parser):
    """
        Adding arguments required for dynamic buffer calculation test cases

       Args:
            parser: pytest parser object

        Returns:
            None
    """
    dynamic_buffer_calculation_group = parser.getgroup("Dynamic buffer calculation test suite options")

    dynamic_buffer_calculation_group.addoption(
        "--enable_shared_headroom_pool",
        action="store",
        type=bool,
        default=False,
        help="Whether the shared headroom pool should be enabled before dynamic buffer calculation test",
    )
