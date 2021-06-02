import logging

from CustomSkipIf import CustomSkipIf

logger = logging.getLogger()


class Platform(CustomSkipIf):
    def __init__(self, ignore_list, extra_params):
        self.name = __name__
        self.ignore_list = ignore_list
        self.extra_params = extra_params

    def is_skip_required(self, skip_dict_result):
        """
        Make decision about ignore - is it required or not
        :param skip_dict_result: shared dictionary with data about skip test
        :return: updated skip_dict
        """
        for platform in self.ignore_list['platforms']:
            if platform in self.extra_params['current_platform']:
                skip_dict_result[self.name] = platform
                break

        return skip_dict_result
