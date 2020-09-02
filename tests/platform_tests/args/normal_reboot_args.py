def add_normal_reboot_args(parser):
    #########################
    #   reboot test options #
    #########################

    # Allow user to specify the power off delay in seconds. User can use it lie:
    # "--power_off_delay=5,15"
    # If this option is not specified, [5, 15] will be used by default, see function pytest_generate_tests in
    # tests/platform_tests/conftest.py
    parser.addoption("--power_off_delay", action="store", type=str, default='5,15',
                     help="Power off delay seconds for test_power_off_reboot")
