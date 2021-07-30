from abc import ABCMeta, abstractmethod

class BaseFanoutHandler(object):
    __metaclass__ = ABCMeta
    def __init__(self):
        pass

    @abstractmethod
    def update_config(self):
        pass

    @abstractmethod
    def restore_config(self):
        pass
