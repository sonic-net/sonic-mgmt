"""Plugin for adding any mark to specified test cases based on conditions in a centralized file.

This plugin supports adding any mark to specified test cases based on conditions. All the information of test cases,
marks, and conditions can be specified in a centralized file.
"""
import imp
import json
import logging
import os
import re
import subprocess
import yaml
import glob

import pytest

from .issue import check_issues

logger = logging.getLogger(__name__)

DEFAULT_CONDITIONS_FILE = 'common/plugins/conditional_mark/tests_mark_conditions*.yaml'
ASIC_NAME_PATH = '/../../../../ansible/group_vars/sonic/variables'


def pytest_addoption(parser):
    """Add options for the conditional mark plugin.
    """
    parser.addoption(
        '--mark-conditions-files',
        action='append',
        dest='mark_conditions_files',
        default=[],
        help="Location of your own mark conditions file. If it is not specified, the default file will be used.")

    parser.addoption(
        '--ignore-conditional-mark',
        action='store_true',
        dest='ignore_conditional_mark',
        default=False,
        help="Ignore the conditional mark plugin. No conditional mark will be added.")

    parser.addoption(
        '--customize_inventory_file',
        action='store',
        dest='customize_inventory_file',
        default=False,
        help="Location of your custom inventory file. If it is not specified, and inv_name not in testbed.csv, 'lab' will be used")

def load_conditions(session):
    """Load the content from mark conditions file

    Args:
        session (obj): The pytest session object.

    Returns:
        dict or None: Return the mark conditions dict or None if there something went wrong.
    """
    conditions_list = list()

    conditions_files = session.config.option.mark_conditions_files
    for condition in conditions_files:
        if '*' in condition:
            conditions_files.remove(condition)
            files = glob.glob(condition)
            for file in files:
                if file not in conditions_files:
                    conditions_files.append(file)

    if not conditions_files:
        conditions_files = glob.glob(DEFAULT_CONDITIONS_FILE)

    conditions_files = [f for f in conditions_files if os.path.exists(f)]
    if not conditions_files:
        pytest.fail('There is no conditions files')

    try:
        logger.debug('Trying to load test mark conditions files: {}'.format(conditions_files))
        for conditions_file in conditions_files:
            with open(conditions_file) as f:
                logger.debug('Loaded test mark conditions file: {}'.format(conditions_file))
                conditions = yaml.safe_load(f)
                for key, value in conditions.items():
                    conditions_list.append({key: value})
    except Exception as e:
        logger.error('Failed to load {}, exception: {}'.format(conditions_files, repr(e)), exc_info=True)
        pytest.fail('Loading conditions file "{}" failed. Possibly invalid yaml file.'.format(conditions_files))

    return conditions_list

def read_asic_name(hwsku):
    '''
    Get asic generation name from file 'ansible/group_vars/sonic/variables'

    Args:
        hwsku (str): Dut hwsku name

    Returns:
        str or None: Return the asic generation name or None if something went wrong or nothing found in the file.

    '''
    asic_name_file = os.path.dirname(__file__) + ASIC_NAME_PATH
    try:
        with open(asic_name_file) as f:
            asic_name = yaml.safe_load(f)
            logger.info(asic_name)

        for key, value in asic_name.items():
            if ('td' not in key) and ('th' not in key):
                asic_name.pop(key)

        for name, hw in asic_name.items():
            if hwsku in hw:
                return name.split('_')[1]

        return "unknown"

    except IOError as e:
        return None


def get_http_proxies(inv_name):
    INV_ENV_FILE = '../../../../ansible/group_vars/{}/env.yml'.format(inv_name)
    PUBLIC_ENV_FILE = '../../../../ansible/group_vars/all/env.yml'
    base_path = os.path.dirname(__file__)
    inv_env_path = os.path.join(base_path, INV_ENV_FILE)
    public_env_path = os.path.join(base_path, PUBLIC_ENV_FILE)
    proxies = {}

    if os.path.isfile(public_env_path):
        try:
            with open(public_env_path) as env_file:
                proxy_env = yaml.safe_load(env_file)
                if proxy_env is not None:
                    proxy = proxy_env.get("proxy_env", {})
                    http_proxy = proxy.get('http_proxy', '')
                    proxies = {'http': http_proxy, 'https': http_proxy}
                else:
                    proxies = {'http': '', 'https': ''}
        except Exception as e:
            logger.error('Load proxy env from {} failed with error: {}'.format(public_env_path, repr(e)))

    if os.path.isfile(inv_env_path):
        try:
            with open(inv_env_path) as env_file:
                proxy_env = yaml.safe_load(env_file)
                if proxy_env is not None:
                    proxy = proxy_env.get("proxy_env", {})
                    http_proxy = proxy.get('http_proxy', '')
                    proxies = {'http': http_proxy, 'https': http_proxy}
        except Exception as e:
            logger.error('Load proxy env from {} failed with error: {}'.format(inv_env_path, repr(e)))

    return proxies


def load_dut_basic_facts(session):
    """Run 'ansible -m dut_basic_facts' command to get some basic DUT facts.

    The facts will be a 1 level dictionary. The dict keys can be used as variables in condition statements evaluation.

    Args:
        session (obj): The pytest session object.

    Returns:
        dict or None: Return the dut basic facts dict or None if something went wrong.
    """
    results = {}
    logger.info('Getting dut basic facts')
    try:
        testbed_name = session.config.option.testbed
        testbed_file = session.config.option.testbed_file

        testbed_module = imp.load_source('testbed', 'common/testbed.py')
        tbinfo = testbed_module.TestbedInfo(testbed_file).testbed_topo.get(testbed_name, None)

        results['topo_type'] = tbinfo['topo']['type']
        results['topo_name'] = tbinfo['topo']['name']

        dut_name = tbinfo['duts'][0]
        if session.config.option.customize_inventory_file:
            inv_name = session.config.option.customize_inventory_file
        elif 'inv_name' in tbinfo.keys():
            inv_name = tbinfo['inv_name']
        else:
            inv_name = 'lab'
        proxies = get_http_proxies(inv_name)
        session.config.cache.set('PROXIES', proxies)

        inv_full_path = os.path.join(os.path.dirname(__file__), '../../../../ansible', inv_name)
        ansible_cmd = 'ansible -m dut_basic_facts -i {} {} -o'.format(inv_full_path, dut_name)

        raw_output = subprocess.check_output(ansible_cmd.split()).decode('utf-8')
        logger.debug('raw dut basic facts:\n{}'.format(raw_output))
        output_fields = raw_output.split('SUCCESS =>', 1)
        if len(output_fields) >= 2:
            results.update(json.loads(output_fields[1].strip())['ansible_facts']['dut_basic_facts'])
            results['asic_gen'] = read_asic_name(results['hwsku'])
    except Exception as e:
        logger.error('Failed to load dut basic facts, exception: {}'.format(repr(e)))

    return results


def load_basic_facts(session):
    """Load some basic facts that can be used in condition statement evaluation.

    The facts will be a 1 level dictionary. The dict keys can be used as variables in condition statements evaluation.

    Args:
        session (obj): Pytest session object.

    Returns:
        dict: Dict of facts.
    """
    results = {}

    # Load DUT basic facts
    _facts = load_dut_basic_facts(session)
    if _facts:
        results.update(_facts)

    # Load possible other facts here

    return results

def find_longest_matches(nodeid, conditions):
    """Find the longest matches of the given test case name in the conditions list.

    This is similar to longest prefix match in routing table. The longest match takes precedence.

    Args:
        nodeid (str): Full test case name
        conditions (list): List of conditions

    Returns:
        str: Longest match test case name or None if not found
    """
    longest_matches = []
    max_length = -1
    for condition in conditions:
        # condition is a dict which has only one item, so we use condition.keys()[0] to get its key.
        if nodeid.startswith(condition.keys()[0]):
            length = len(condition)
            if length > max_length:
                max_length = length
                longest_matches = []
                longest_matches.append(condition)
            elif length == max_length:
                longest_matches.append(condition)
    return longest_matches

def update_issue_status(condition_str, session):
    """Replace issue URL with 'True' or 'False' based on its active state.

    If there is an issue URL is found, this function will try to query state of the issue and replace the URL
    in the condition string with 'True' or 'False' based on its active state.

    The issue URL may be Github, Jira, Redmine, etc.

    Args:
        condition_str (str): Condition string that may contain issue URLs.
        session (obj): Pytest session object, for getting cached data.

    Returns:
        str: New condition string with issue URLs already replaced with 'True' or 'False'.
    """
    issues = re.findall('https?://[^ )]+', condition_str)
    if not issues:
        logger.debug('No issue specified in condition')
        return condition_str

    issue_status_cache = session.config.cache.get('ISSUE_STATUS', {})
    proxies = session.config.cache.get('PROXIES', {})

    unknown_issues = [issue_url for issue_url in issues if issue_url not in issue_status_cache]
    if unknown_issues:
        results = check_issues(unknown_issues, proxies=proxies)
        issue_status_cache.update(results)
        session.config.cache.set('ISSUE_STATUS', issue_status_cache)

    for issue_url in issues:
        if issue_url in issue_status_cache:
            replace_str = str(issue_status_cache[issue_url])
        else:
            # Consider the issue as active anyway if unable to get issue state
            replace_str = 'True'

        condition_str = condition_str.replace(issue_url, replace_str)
    return condition_str


def evaluate_condition(condition, basic_facts, session):
    """Evaluate a condition string based on supplied basic facts.

    Args:
        condition (str): A raw condition string that can be evaluated using python "eval()" function. The raw condition
            string may contain issue URLs that need further processing.
        basic_facts (dict): A one level dict with basic facts. Keys of the dict can be used as variables in the
            condition string evaluation.
        session (obj): Pytest session object, for getting cached data.

    Returns:
        bool: True or False based on condition string evaluation result.
    """
    if condition is None or condition.strip() == '':
        return True    # Empty condition item will be evaluated as True. Equivalent to be ignored.

    condition_str = update_issue_status(condition, session)
    try:
        return bool(eval(condition_str, basic_facts))
    except Exception as e:
        logger.error('Failed to evaluate condition, raw_condition={}, condition_str={}'.format(
            condition,
            condition_str))
        return False


def evaluate_conditions(conditions, basic_facts, session, conditions_logical_operator):
    """Evaluate all the condition strings.

    Evaluate a single condition or multiple conditions. If multiple conditions are supplied, apply AND or OR
    logical operation to all of them based on conditions_logical_operator(by default AND).

    Args:
        conditions (str or list): Condition string or list of condition strings.
        basic_facts (dict): A one level dict with basic facts. Keys of the dict can be used as variables in the
            condition string evaluation.
        session (obj): Pytest session object, for getting cached data.
        conditions_logical_operator (str): logical operator which should be applied to conditions(by default 'AND')

    Returns:
        bool: True or False based on condition strings evaluation result.
    """
    if isinstance(conditions, list):
        # Apply 'AND' or 'OR' operation to list of conditions based on conditions_logical_operator(by default 'AND')
        if conditions_logical_operator == 'OR':
            return any([evaluate_condition(c, basic_facts, session) for c in conditions])
        else:
            return all([evaluate_condition(c, basic_facts, session) for c in conditions])
    else:
        if conditions is None or conditions.strip() == '':
            return True
        return evaluate_condition(conditions, basic_facts, session)


def pytest_collection(session):
    """Hook for loading conditions and basic facts.

    The pytest session.config.cache is used for caching loaded conditions and basic facts for later use.

    Args:
        session (obj): Pytest session object.
    """

    # Always clear cached conditions and basic facts of previous run.
    session.config.cache.set('TESTS_MARK_CONDITIONS', None)
    session.config.cache.set('BASIC_FACTS', None)

    if session.config.option.ignore_conditional_mark:
        logger.info('Ignore conditional mark')
        return

    conditions = load_conditions(session)
    if conditions:
        session.config.cache.set('TESTS_MARK_CONDITIONS', conditions)

        # Only load basic facts if conditions are defined.
        basic_facts = load_basic_facts(session)
        session.config.cache.set('BASIC_FACTS', basic_facts)

def pytest_collection_modifyitems(session, config, items):
    """Hook for adding marks to test cases based on conditions defind in a centralized file.

    Args:
        session (obj): Pytest session object.
        config (obj): Pytest config object.
        items (obj): List of pytest Item objects.
    """
    conditions = config.cache.get('TESTS_MARK_CONDITIONS', None)
    if not conditions:
        logger.debug('No mark condition is defined')
        return

    basic_facts = config.cache.get('BASIC_FACTS', None)
    if not basic_facts:
        logger.debug('No basic facts')
        return
    logger.info('Available basic facts that can be used in conditional skip:\n{}'.format(
        json.dumps(basic_facts, indent=2)))

    for item in items:
        longest_matches = find_longest_matches(item.nodeid, conditions)

        if longest_matches:
            logger.debug('Found match "{}" for test case "{}"'.format(longest_matches, item.nodeid))

            for match in longest_matches:
                # match is a dict which has only one item, so we use match.values()[0] to get its value.
                for mark_name, mark_details in match.values()[0].items():

                    add_mark = False
                    if not mark_details:
                        add_mark = True
                    else:
                        mark_conditions = mark_details.get('conditions', None)
                        if not mark_conditions:
                            # Unconditionally add mark
                            add_mark = True
                        else:
                            conditions_logical_operator = mark_details.get('conditions_logical_operator', 'AND').upper()
                            add_mark = evaluate_conditions(mark_conditions, basic_facts, session, conditions_logical_operator)

                    if add_mark:
                        reason = ''
                        if mark_details:
                            reason = mark_details.get('reason', '')

                        if mark_name == 'xfail':
                            strict = False
                            if mark_details:
                                strict = mark_details.get('strict', False)
                            mark = getattr(pytest.mark, mark_name)(reason=reason, strict=strict)
                            # To generate xfail property in the report xml file
                            item.user_properties.append(('xfail', strict))
                        else:
                            mark = getattr(pytest.mark, mark_name)(reason=reason)

                        logger.debug('Adding mark {} to {}'.format(mark, item.nodeid))
                        item.add_marker(mark)
