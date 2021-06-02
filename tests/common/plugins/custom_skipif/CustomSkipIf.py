from abc import ABCMeta, abstractmethod


class CustomSkipIf:
    __metaclass__ = ABCMeta
    # def __init__(self, ignore_list, extra_params):
    #     self.name = __name__
    #     self.ignore_list = ignore_list
    #     self.extra_params = extra_params

    @abstractmethod
    def is_skip_required(self, skip_dict_result):
        """
        Decide whether or not to skip a test
        :param skip_dict_result: shared dictionary with data about skip test
        :return: updated skip_dict
        """
        return skip_dict_result
