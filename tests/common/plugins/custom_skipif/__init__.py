import multiprocessing
import yaml
import pytest
import logging
import os
import sys
import subprocess


logger = logging.getLogger()


def pytest_collection(session):
    initialize_cached_variables(session)


def initialize_cached_variables(session):
    custom_skip_if_dict = 'custom_skip_if_dict'
    dynamic_tests_skip_platform_type = 'dynamic_tests_skip_platform_type'
    session.config.cache.set(custom_skip_if_dict, None)
    session.config.cache.set(dynamic_tests_skip_platform_type, None)


def pytest_runtest_setup(item):
    """
    Skip tests conditionally based on the user_tests_to_be_skipped list
    """
    skip_tests_file_path = get_tests_to_be_skipped_path()
    if os.path.exists(skip_tests_file_path):
        skip_tests_dict = read_skip_file(item, skip_tests_file_path)
        platform_type = get_platform_type(item)
        update_syspath_for_dynamic_import()

        for test_prefix, skip_dict in skip_tests_dict.items():
            if str(item.nodeid).startswith(test_prefix):
                logger.debug('Found custom skip condition: {}'.format(test_prefix))
                skip_checkers_list = prepare_checkers(skip_dict, platform_type)
                skip_dict_result = run_checkers_in_parallel(skip_checkers_list)
                make_skip_decision(skip_dict_result, skip_dict)


def get_platform_type(item):
    """
    Get current platform type using ansible and store it in pytest.session.config.cache
    :param item: pytest test item
    :return: platform_type - string with current platform type
    """
    dynamic_tests_skip_platform_type = 'dynamic_tests_skip_platform_type'
    platform_type = item.session.config.cache.get(dynamic_tests_skip_platform_type, None)
    if not platform_type:
        host = item.session.config.option.ansible_host_pattern
        inventory = item.session.config.option.ansible_inventory
        inv = get_inventory_argument(inventory)
        show_platform_cmd = 'ansible {} {} -a "show platform summary"'.format(host, inv)

        try:
            show_platform_summary_raw_output = subprocess.check_output(show_platform_cmd, shell=True)
            for line in show_platform_summary_raw_output.splitlines():
                if 'Platform:' in line:
                    platform_type = line.split()[1:][0]  # get platform, example: x86_64-mlnx_msn2700-r0
                    item.session.config.cache.set(dynamic_tests_skip_platform_type, platform_type)
                    break
        except Exception as err:
            logger.error('Unable to get platform type. Custom skip by platform impossible. Error: {}'.format(err))

    logger.debug('Current platform type is: {}'.format(platform_type))
    return platform_type


def get_inventory_argument(inventory):
    """Get Ansible inventory arguments"""
    inv = ''
    for inv_item in inventory.split(','):
        inv += ' -i {}'.format(inv_item)
    return inv


def read_skip_file(item, skip_tests_file_path):
    """
    Read yaml file with list of test cases which should be skipped
    :param item: pytest test item
    :param skip_tests_file_path: path to file where stored list of test cases which should be skipped
    :return: yaml loaded dictionary
    """
    custom_skip_if_dict = 'custom_skip_if_dict'
    skip_dictionary = item.session.config.cache.get(custom_skip_if_dict, None)
    if not skip_dictionary:
        with open(skip_tests_file_path) as skip_data:
            logger.debug('Reading dynamic skip file: {}'.format(skip_tests_file_path))
            skip_dictionary = yaml.load(skip_data, Loader=yaml.FullLoader)
            item.session.config.cache.set(custom_skip_if_dict, skip_dictionary)
    return skip_dictionary


def get_tests_to_be_skipped_path(skip_tests_file='tests_to_be_skipped_conditionally.yaml'):
    """
    Get path to file with dynamic skip information
    :param skip_tests_file: skip test file name
    :return: full path to skip test file name
    """
    custom_skip_folder_path = os.path.dirname(__file__)
    custom_skip_tests_file_path = os.path.join(custom_skip_folder_path, skip_tests_file)
    return custom_skip_tests_file_path


def update_syspath_for_dynamic_import():
    """
    Update sys.path by current folder to have possibility to load python modules dynamically
    """
    if os.path.dirname(__file__) not in sys.path:
        sys.path.append(os.path.dirname(__file__))


def prepare_checkers(skip_dict, current_platform):
    """
    Import dynamically checker modules and initialize them
    :param skip_dict: dictionary with skip test case skip conditions
    :param current_platform: string with current platform, example: x86_64-mlnx_msn2700-r0
    :return: list with checkers objects
    """
    skip_checkers_list = []
    extra_params = {'current_platform': current_platform}
    for skip_by in skip_dict:
        logger.debug('Importing dynamic skip module: {}'.format(skip_by))
        try:
            skip_module = __import__(skip_by)  # lgtm[py/unused-import]
            skip_module_obj = eval(
                'skip_module.{}({}, {})'.format(skip_by, skip_dict[skip_by], extra_params))
            skip_checkers_list.append(skip_module_obj)
        except Exception as err:
            logger.error('Unable to load dynamically skip object: {}'.format(err))
    return skip_checkers_list


def run_checkers_in_parallel(skip_checkers_list):
    """
    Run checkers in parallel and return results
    :param skip_checkers_list: list with checkers objects
    :return: dictionary with checkers result
    """
    manager = multiprocessing.Manager()
    skip_dict_result = manager.dict()

    proc_list = list()

    for skip_check in skip_checkers_list:
        skip_dict_result[skip_check.name] = None
        proc_list.append(multiprocessing.Process(target=skip_check.is_skip_required, args=(skip_dict_result,)))

    for proc in proc_list:
        proc.start()
    for proc in proc_list:
        proc.join(timeout=60)

    return skip_dict_result


def make_skip_decision(skip_dict_result, current_skip_dict):
    """
    Make a final decision about whether to skip the test by combining the results of all the skip statements.
    :param skip_dict_result: dictionary with checkers result
    :param current_skip_dict: dictionary with skip test case data
    :return: None or pytest.skip in case when need to skip test case
    """
    skip_reason = ''

    skip_by_issue, skip_reason = is_skip_by_issue_required(skip_dict_result, skip_reason)
    skip_by_platform, platform_expression, skip_reason = is_skip_by_platform_required(skip_dict_result,
                                                                                      current_skip_dict,
                                                                                      skip_reason)

    eval_expression = '{} {} {}'.format(skip_by_issue, platform_expression, skip_by_platform)
    logger.debug('Evaluating skip expression: {}'.format(eval_expression))
    is_skip_required = eval(eval_expression)

    if is_skip_required:
        pytest.skip(skip_reason)


def is_skip_by_issue_required(skip_dict_result, skip_reason):
    """
    Make decision about skip by issue or not
    :param skip_dict_result: dictionary with checkers result
    :param skip_reason: string with skip reasons
    :return: True, 'string with skip reason' - in case when skip required, False, '' in case when skip not required
    """
    is_skip_required = False

    for checker, checker_result in skip_dict_result.items():
        if checker != 'Platform':
            if checker_result:
                is_skip_required = True
                skip_reason += '\nTest skipped by {} issue: {}'.format(checker, checker_result)

    return is_skip_required, skip_reason


def is_skip_by_platform_required(skip_dict_result, current_skip_dict, skip_reason):
    """
    Make decision about skip by issue or not
    :param skip_dict_result: dictionary with checkers result
    :param current_skip_dict: dictionary with skip test case data
    :param skip_reason: string with skip reasons
    :return: True, expression, 'string with skip reason' - in case when skip required by platform,
             False, expression, '' in case when skip not required by platform
    """
    platform = 'Platform'
    is_skip_required = False
    expression = 'or'

    if platform in current_skip_dict:
        expression = current_skip_dict[platform].get('operand', 'or')

        if skip_dict_result.get(platform):
            skip_reason += '\nTest skipped due to Platform: {}'.format(skip_dict_result[platform])
            is_skip_required = True

    return is_skip_required, expression, skip_reason
