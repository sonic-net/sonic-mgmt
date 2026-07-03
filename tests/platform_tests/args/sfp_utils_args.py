def add_limited_sfp_ports_args(parser):
    '''
    Adding arguments required for counterpoll cpu usage test
    '''
    parser.addoption("--limited_sfp_ports", action="store_true", help="Test with limited number of ports")
