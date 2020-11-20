def add_api_sfp_args(parser):
    ############################
    # platform sfp api options #
    ############################

    # Allow user to skip the absent sfp modules. User can use it like below:
    # "--skip_absent_sfp=True"
    # If this option is not specified, False will be used by default.
    parser.addoption(
        "--skip_absent_sfp", 
        action="store", 
        type=bool, 
        default=False, 
        help="Skip test on absent SFP",
    )
