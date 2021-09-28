import logging
import re

from CustomSkipIf import CustomSkipIf, run_cmd_on_dut, CUSTOM_TEST_SKIP_BRANCH_NAME

logger = logging.getLogger()


class SkipIf(CustomSkipIf):
    def __init__(self, ignore_list, pytest_item_obj):
        super(SkipIf, self).__init__(ignore_list, pytest_item_obj)
        self.name = 'Branch'

    def is_skip_required(self, skip_dict_result):
        """
        Make decision about ignore - is it required or not
        :param skip_dict_result: shared dictionary with data about skip test
        :return: updated skip_dict
        """
        current_branch = get_branch_name(self.pytest_item_obj)
        for branch in self.ignore_list:
            if str(branch) == current_branch:
                skip_dict_result[self.name] = branch
                break

        return skip_dict_result


def get_branch_name(pytest_item_obj):
    """
    Get current branch name using ansible and store it in pytest.session.config.cache
    :param pytest_item_obj: pytest test item
    :return: platform_type - string with current branch name
    """
    branch_name = pytest_item_obj.session.config.cache.get(CUSTOM_TEST_SKIP_BRANCH_NAME, None)
    if not branch_name:
        logger.debug('Getting branch name from DUT')
        try:
            show_version_raw_output = run_cmd_on_dut(pytest_item_obj, 'show version')
            branch_name = get_branch_from_version(show_version_raw_output)
            pytest_item_obj.session.config.cache.set(CUSTOM_TEST_SKIP_BRANCH_NAME, branch_name)
        except Exception as err:
            logger.error('Unable to get branch name. Custom skip by branch impossible. Error: {}'.format(err))
    else:
        logger.debug('Getting branch from pytest cache')

    logger.debug('Current branch is: {}'.format(branch_name))
    return branch_name


def get_branch_from_version(version_output):
    """
    Get branch name from 'show version' output
    :param version_output: 'show version' command output
    :return: string with branch name, example: '202012'
    """
    image_ver = re.search(r'SONiC\sSoftware\sVersion:\s(.*)', version_output, re.IGNORECASE).group(1)
    branch = re.search(r'SONiC\.(.*)\.', image_ver, re.IGNORECASE).group(1)
    return branch
