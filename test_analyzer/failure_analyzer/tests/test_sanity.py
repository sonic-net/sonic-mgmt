def test_pytest_args(
    logger,
    excluded_testbed_keywords, 
    excluded_testbed_keywords_setup_error,
    included_branch,
    released_branch
):
    '''
    Small sanity test to demonstrate the use of arguments as expected by certain functions, provided via the command line.

    Parsing is accomplished via the session fixtures in `tests/conftest.py`, and should always mirror the parsing in `main.py`.
    
    In pipeline runs, these variables should be extracted from the NIGHTLY_HAWK variable library.
    '''
    logger.info(excluded_testbed_keywords)
    logger.info(excluded_testbed_keywords_setup_error)
    logger.info(included_branch)
    logger.info(released_branch)

    assert isinstance(excluded_testbed_keywords, list)
    assert isinstance(excluded_testbed_keywords_setup_error, list)
    assert isinstance(included_branch, list)
    assert isinstance(released_branch, list)
