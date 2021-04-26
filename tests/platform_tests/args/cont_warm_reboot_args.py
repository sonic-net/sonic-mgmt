def add_cont_warm_reboot_args(parser):
    '''
    Adding arguments required for continuous warm-reboot test case
    '''
    parser.addoption(
        "--continuous_reboot_count",
        action="store",
        type=int,
        default=3,
        help="Number of iterations of warm-reboot",
    )

    parser.addoption(
        "--continuous_reboot_delay",
        action="store",
        type=int,
        default=300,
        help="Delay period in seconds between subsequent reboots",
    )

    parser.addoption(
        "--reboot_type",
        action="store",
        default="warm",
        help="Reboot type - warm/fast",
    )

    parser.addoption(
        "--image_location",
        action="store",
        default="",
        help="Path to image(s) to be installed",
    )

    parser.addoption(
        "--image_list",
        action="store",
        default="current",
        help="Comma separated list of images to be installed during continuous reboot test",
    )

