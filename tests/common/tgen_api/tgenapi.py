""" The abstract Test Generator API
"""
#from abc import ABC, abstractmethod
from abc import ABCMeta, abstractmethod
from typing import Union, List, Dict
from tgenmodels import Config


class TgenApi():
   # __slots__ = ['config']
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, **kwargs):
        super().__init__() 
        pass

    @abstractmethod
    def init_tgen(self, config):
        """Initialize your traffic configuration
        """
        pass

    @abstractmethod
    def connect(self, host):
        """Information for establishing a connection to the test tool
        """
        pass

    @abstractmethod
    def configure(self, config = None):
        """Configure the test tool using the data from the Config
        """
        pass

    @abstractmethod
    def deconfigure(self):
        """Deconfigure the test tool
        """
        pass

    @abstractmethod
    def start(self):
        """Start traffic on the test tool
        """
        pass

    @abstractmethod
    def stop(self):
        """Stop traffic on the test tool
        """
        pass

    @abstractmethod
    def json_config(self):
        """Get the json representation of the Config object
        
        Returns:  
            str: A json string representation of the Config object
        """
        pass

    def __str__(self):
        raise NotImplementedError

