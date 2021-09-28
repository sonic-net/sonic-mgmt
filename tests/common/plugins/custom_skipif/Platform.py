import logging
import re

from CustomSkipIf import CustomSkipIf, run_cmd_on_dut, CUSTOM_TEST_SKIP_PLATFORM_TYPE

logger = logging.getLogger()


class SkipIf(CustomSkipIf):
    def __init__(self, ignore_list, pytest_item_obj):
        super(SkipIf, self).__init__(ignore_list, pytest_item_obj)
        self.name = 'Platform'

    def is_skip_required(self, skip_dict_result):
        """
        Make decision about ignore - is it required or not
        :param skip_dict_result: shared dictionary with data about skip test
        :return: updated skip_dict
        """
        current_platform = get_platform_type(self.pytest_item_obj)
        for platform in self.ignore_list:
            if str(platform) in current_platform:
                skip_dict_result[self.name] = platform
                break

        return skip_dict_result


def get_platform_type(pytest_item_obj):
    """
    Get current platform type using ansible and store it in pytest.session.config.cache
    :param pytest_item_obj: pytest test item
    :return: platform_type - string with current platform type
    """
    platform_type = pytest_item_obj.session.config.cache.get(CUSTOM_TEST_SKIP_PLATFORM_TYPE, None)
    if not platform_type:
        logger.debug('Getting platform from DUT')
        try:
            show_platform_summary_raw_output = run_cmd_on_dut(pytest_item_obj, 'show platform summary')
            platform_type = get_platform_from_platform_summary(show_platform_summary_raw_output)
            pytest_item_obj.session.config.cache.set(CUSTOM_TEST_SKIP_PLATFORM_TYPE, platform_type)
        except Exception as err:
            logger.error('Unable to get platform type. Custom skip by platform impossible. Error: {}'.format(err))
    else:
        logger.debug('Getting platform from pytest cache')

    logger.debug('Current platform type is: {}'.format(platform_type))
    return platform_type


def get_platform_from_platform_summary(platform_output):
    """
    Get platform from 'show platform summary' output
    :param platform_output: 'show platform summary' command output
    :return: string with platform name, example: 'x86_64-mlnx_msn3420-r0'
    """
    platform = re.search(r'Platform:\s(.*)', platform_output, re.IGNORECASE).group(1)
    return platform
