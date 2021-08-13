import logging
import subprocess

from CustomSkipIf import CustomSkipIf, CUSTOM_TEST_SKIP_PLATFORM_TYPE

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
        host = pytest_item_obj.session.config.option.ansible_host_pattern
        inventory = pytest_item_obj.session.config.option.ansible_inventory
        inv = get_inventory_argument(inventory)
        show_platform_cmd = 'ansible {} {} -a "show platform summary"'.format(host, inv)

        try:
            show_platform_summary_raw_output = subprocess.check_output(show_platform_cmd, shell=True)
            for line in show_platform_summary_raw_output.splitlines():
                if 'Platform:' in line:
                    platform_type = line.split()[1:][0]  # get platform, example: x86_64-mlnx_msn2700-r0
                    pytest_item_obj.session.config.cache.set(CUSTOM_TEST_SKIP_PLATFORM_TYPE, platform_type)
                    break
        except Exception as err:
            logger.error('Unable to get platform type. Custom skip by platform impossible. Error: {}'.format(err))
    else:
        logger.debug('Getting platform from pytest cache')

    logger.debug('Current platform type is: {}'.format(platform_type))
    return platform_type


def get_inventory_argument(inventory):
    """Get Ansible inventory arguments"""
    inv = ''

    if type(inventory) is list:
        for inv_item in inventory:
            inv += ' -i {}'.format(inv_item)
    else:
        for inv_item in inventory.split(','):
            inv += ' -i {}'.format(inv_item)

    return inv
