def add_counterpoll_cpu_usage_args(parser):
    '''
    Adding arguments required for counterpoll cpu usage test
    '''
    parser.addoption(
        "--port_buffer_drop_cpu_usage_threshold",
        action="store",
        type=int,
        default=10,
        help="Port buffer drop cpu usage threshold",
    )
