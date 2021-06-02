import multiprocessing
import yaml
import pytest
import logging
import os
import sys

from abc import ABCMeta, abstractmethod

logger = logging.getLogger()

CUSTOM_SKIP_IF_DICT = 'custom_skip_if_dict'
CUSTOM_TEST_SKIP_PLATFORM_TYPE = 'dynamic_tests_skip_platform_type'
PLATFORM = 'Platform'


def pytest_collection(session):
    initialize_cached_variables(session)


def initialize_cached_variables(session):
    session.config.cache.set(CUSTOM_SKIP_IF_DICT, None)
    session.config.cache.set(CUSTOM_TEST_SKIP_PLATFORM_TYPE, None)


def pytest_runtest_setup(item):
    """
    Skip tests conditionally based on the user_tests_to_be_skipped list
    """
    skip_tests_file_path = get_tests_to_be_skipped_path()
    if os.path.exists(skip_tests_file_path):
        skip_tests_dict = read_skip_file(item, skip_tests_file_path)
        update_syspath_for_dynamic_import()

        for test_prefix, skip_dict in skip_tests_dict.items():
            if str(item.nodeid).startswith(test_prefix):
                logger.debug('Found custom skip condition: {}'.format(test_prefix))
                skip_checkers_list = prepare_checkers(skip_dict, item)
                skip_dict_result = run_checkers_in_parallel(skip_checkers_list)
                make_skip_decision(skip_dict_result, skip_dict)


def read_skip_file(item, skip_tests_file_path):
    """
    Read yaml file with list of test cases which should be skipped
    :param item: pytest test item
    :param skip_tests_file_path: path to file where stored list of test cases which should be skipped
    :return: yaml loaded dictionary
    """
    skip_dictionary = item.session.config.cache.get(CUSTOM_SKIP_IF_DICT, None)
    if not skip_dictionary:
        with open(skip_tests_file_path) as skip_data:
            logger.debug('Reading dynamic skip file: {}'.format(skip_tests_file_path))
            skip_dictionary = yaml.load(skip_data, Loader=yaml.FullLoader)
            item.session.config.cache.set(CUSTOM_SKIP_IF_DICT, skip_dictionary)
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


def prepare_checkers(skip_dict, pytest_item_obj):
    """
    Import dynamically checker modules and initialize them
    :param skip_dict: dictionary with skip test case skip conditions
    :param pytest_item_obj: pytest build in
    :return: list with checkers objects
    """
    skip_checkers_list = []
    for skip_by in skip_dict:
        logger.debug('Importing dynamic skip module: {}'.format(skip_by))
        try:
            skip_module_obj = __import__(skip_by).SkipIf(skip_dict[skip_by], pytest_item_obj)
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
    is_skip_by_platform_required = False
    is_skip_by_issue_required = False
    operand = 'or'

    for checker, checker_result in skip_dict_result.items():
        if checker == PLATFORM:
            operand = current_skip_dict[PLATFORM].get('operand', 'or')
            if checker_result:
                skip_reason += '\nTest skipped due to Platform: {}'.format(checker_result)
                is_skip_by_platform_required = True
        else:
            if checker_result:
                is_skip_by_issue_required = True
                skip_reason += '\nTest skipped by {} issue: {}'.format(checker, checker_result)

    logger.debug('Making decision about skip test or run. '
                 'Skip by issue: {}, Skip by Platform: {}, Operand: {}'.format(is_skip_by_issue_required,
                                                                               is_skip_by_platform_required,
                                                                               operand))

    if operand == 'or':
        is_skip_required = is_skip_by_issue_required or is_skip_by_platform_required
    elif operand == 'and':
        is_skip_required = is_skip_by_issue_required and is_skip_by_platform_required
    else:
        raise AssertionError('Operand "{}" is not supported'.format(operand))

    if is_skip_required:
        pytest.skip(skip_reason)


class CustomSkipIf:
    __metaclass__ = ABCMeta

    def __init__(self, ignore_list, pytest_item_obj):
        # self.name = 'CustomSkipIf'  # Example: Platform, Jira, Redmine - should be defined in each child class
        self.ignore_list = ignore_list
        self.pytest_item_obj = pytest_item_obj

    @abstractmethod
    def is_skip_required(self, skip_dict_result):
        """
        Decide whether or not to skip a test
        :param skip_dict_result: shared dictionary with data about skip test
        :return: updated skip_dict
        """
        return skip_dict_result
