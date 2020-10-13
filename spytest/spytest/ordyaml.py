import os
import sys
import yaml

from spytest.dicts import SpyTestDict
import utilities.common as utils

class OrderedYaml(object):

    def _locate(self, filename):
        for path in self._paths:
            filename1 = os.path.join(path, filename)
            if os.path.isfile(filename1):
                return filename1
        if os.path.isfile(filename):
            return filename
        return None

    def _load(self, stream, file_dict=dict(), Loader=yaml.Loader,
              object_pairs_hook=SpyTestDict):
        def _yaml_include(loader, node):
            filename = self._locate(node.value)
            if not filename:
                msg = "Failed to locate included file '{}'".format(node.value)
                self.errs.append(msg)
                return None
            file_dict[filename] = 1
            with utils.open_file(filename) as inputfile:
                return yaml.load(inputfile, Loader)

        def _construct_mapping(loader, node):
            loader.flatten_mapping(node)
            return object_pairs_hook(loader.construct_pairs(node))

        Loader.add_constructor(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
            _construct_mapping)

        Loader.add_constructor("!include", _yaml_include)
        return yaml.load(stream, Loader)

    def _dump(self, data, stream=None, Dumper=yaml.Dumper, **kwds):
        def _dict_representer(dumper, data):
            return dumper.represent_mapping(
                yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
                data.items())

        Dumper.add_representer(SpyTestDict, _dict_representer)
        return yaml.dump(data, stream, Dumper, **kwds)

    def _init_paths(self, filename, paths):
        self._paths = []
        self._paths.append(os.path.dirname(filename))
        self._paths.extend(paths)

    def __init__(self, filename, paths=[], content=""):
        self._paths = []
        self.errs = []
        self.valid = False
        self.obj = None
        self.all_files = dict()
        self.file_path = None
        if filename:
            self.file_path = self.init_file(filename, paths)
        else:
            self.init_content(content)

    def init_content(self, content):
        all_files = dict()
        try:
            self.text0 = content
            self.text1 = self._load(self.text0, all_files, yaml.SafeLoader)
            self.text1 = self._dump(self.text1)
            self.obj = self._load(self.text1, all_files, yaml.SafeLoader)
            self.valid = True
            return all_files
        except Exception as e:
            self.errs.append(e)
            raise(e)

    def init_file(self, filename, paths=[]):
        self._init_paths(filename, paths)
        file_path = self._locate(filename)
        if not file_path:
            self.errs.append("File {} not found".format(filename))
            return None
        fh = utils.open_file(file_path)
        if not fh:
            self.errs.append("Failed to open {}".format(filename))
            return None
        try:
            text0 = fh.read()
            fh.close()
            self.all_files = self.init_content(text0)
            self.all_files[file_path] = 1
            return file_path
        except Exception as e:
            self.errs.append(e)
            raise(e)

    def get_raw(self, expanded=False):
        return self.text1 if expanded else self.text0

    def get_file_path(self):
        return self.file_path

    def get_data(self):
        return self.obj

    def is_valid(self):
        return self.valid

    def get_files(self):
        return self.all_files

    def get_errors(self):
        return self.errs

if __name__ == "__main__":
    def_filename = "../testbeds/lvn_regression.yaml"
    file_name = sys.argv[1] if len(sys.argv) >= 2 else def_filename
    dmap = OrderedYaml(file_name)
    utils.print_yaml(dmap.get_data(), "")

