import os
from spytest.ordyaml import OrderedYaml

root = os.path.join(os.path.dirname(__file__), '..', "datastore")

class DataMap(object):

    def __init__(self, name, version=None):
        self.name = name
        self.version = version
        self.valid = False
        self.dmap = dict()
        self.errs = []
        self.file_path = os.path.join(root, name, "{}.yaml".format(name))
        if not os.path.isfile(self.file_path):
            self.errs.append("Failed to locate: {}".format(self.file_path))
            print(self.errs)
            return
        oyaml = OrderedYaml(self.file_path)
        self.data = oyaml.get_data()
        if name not in self.data:
            self.errs.append("Failed to locate {} section".format(self.name))
            print(self.errs)
            return
        self.valid = True

    def __del__(self):
        pass

    def _load(self, d, version):
        for section in self.data[self.name][version]:
            if section in self.data and self.data[section]:
                for tok, value in self.data[section].items():
                    d[tok] = value

    def get(self, version=None):
        if not self.valid:
            print(self.errs)
            return None
        if not version:
            version = "default"
        if version in self.dmap:
            return self.dmap[version]
        if version not in self.data[self.name]:
            print("version {} missing in {} section".format(version, self.name))
            return None
        self.dmap[version] = dict()
        self._load(self.dmap[version], "default")
        if version != "default":
            self._load(self.dmap[version], version)
        return self.dmap[version]

