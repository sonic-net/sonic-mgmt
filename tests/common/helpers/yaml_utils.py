import yaml
from yaml import Dumper
from yaml.representer import Representer

# PyYaml default dump the key with empty values to null, like:
# dict = {"key1": None, "key2": "val2"}  ->
# key1: null
# key2: val2
# If we want to keep it as the blank values rather than null, like:
# key1:
# key2: val2
# Need to use this Representer
# refs to: https://stackoverflow.com/a/67524482/25406083


class BlankNone(Representer):
    """Print None as blank when used as context manager"""
    def represent_none(self, *_):
        return self.represent_scalar(u'tag:yaml.org,2002:null', u'')

    def __enter__(self):
        self.prior = Dumper.yaml_representers[type(None)]
        yaml.add_representer(type(None), self.represent_none)

    def __exit__(self, exc_type, exc_val, exc_tb):
        Dumper.yaml_representers[type(None)] = self.prior
