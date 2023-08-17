import re
import os
import copy
import yaml

from spytest.dicts import SpyTestDict
import utilities.common as utils
from utilities.profile import get_cache, set_cache


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


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
            file_path = self._locate(node.value)
            if not file_path:
                msg = "Failed to locate included file '{}'".format(node.value)
                self.errs.append(msg)
                return None
            file_dict[file_path] = 1
            rv = get_cache("ordyaml.include", file_path, None)
            if rv:
                if not self.expand_include:
                    rv = self._add_include_map(node, rv)
                return rv
            text = self.read_file(file_path)
            rv = yaml.load(text, Loader)
            set_cache("ordyaml.include", file_path, rv)
            if not self.expand_include:
                rv = self._add_include_map(node, rv)
            return rv

        def _construct_mapping(loader, node):
            loader.flatten_mapping(node)
            return object_pairs_hook(loader.construct_pairs(node))

        Loader.add_constructor(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
            _construct_mapping)

        Loader.add_constructor("!include", _yaml_include)
        self.expand_include = False
        obj = yaml.load(stream, Loader)
        self.expand_include = True
        self._replace_include_map(obj)
        obj = yaml.load(stream, Loader)
        return obj

    def _add_include_map(self, node, rv):
        map_name = "{}{}".format(self.include_tok_prefix, len(self.include_map))
        self.include_map[map_name] = [node.value, rv, []]
        return map_name

    def _replace_include_map(self, obj, parents=[]):
        for k, v in obj.items():
            if isinstance(v, dict):
                parents.append(k)
                self._replace_include_map(v, parents)
                parents.pop()
            elif not isinstance(v, str):
                pass
            elif v.startswith(self.include_tok_prefix):
                obj[k] = self.include_map[v][1]
                path = []
                for p in parents:
                    if p:
                        path.append(p)
                path.append(k)
                self.include_map[v][2] = path

    def _dump(self, data, stream=None, Dumper=None, use_aliases=True, **kwds):
        def _dict_representer(dumper, data):
            return dumper.represent_mapping(
                yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
                data.items())

        Dumper0 = yaml.Dumper if use_aliases else NoAliasDumper
        Dumper = Dumper or Dumper0
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
        self.obj = SpyTestDict()
        self.all_files = dict()
        self.file_path = None
        self.include_map = dict()
        self.expand_include = True
        self.include_tok_prefix = "InCLudEd_FiLe_"
        if filename:
            self.file_path = self.init_file(filename, paths)
        else:
            self.init_content(content)

    def init_content(self, content, for_file=None):
        all_files = dict()
        try:
            self.text0 = content
            rv1 = get_cache("ordyaml.init_content.load", for_file, None) if for_file else None
            rv2 = get_cache("ordyaml.init_content.dump", for_file, None) if for_file else None
            if None not in [rv1, rv2]:
                self.obj = copy.deepcopy(rv1)
                self.text1 = copy.deepcopy(rv2)
            else:
                self.obj = self._load(self.text0, all_files, yaml.SafeLoader)
                self.text1 = self._dump(self.obj)
                set_cache("ordyaml.init_content.load", for_file, self.obj)
                set_cache("ordyaml.init_content.dump", for_file, self.text1)
            self.valid = True
            return all_files
        except Exception as e:
            self.errs.append(e)
            raise (e)

    def read_file(self, file_path):
        fh = utils.open_file(file_path)
        if not fh:
            return None
        text = fh.read()
        text = re.sub(r"[\"|']!include (.*).yaml[\"|']", r"!include \1.yaml", text)
        fh.close()
        return text

    def init_file(self, filename, paths=[]):
        self._init_paths(filename, paths)
        file_path = self._locate(filename)
        if not file_path:
            self.errs.append("File {} not found".format(filename))
            return None
        try:
            text = get_cache("ordyaml.init", file_path, None)
            if text is None:
                text = self.read_file(file_path)
                if text is None:
                    self.errs.append("Failed to open {}".format(filename))
                    return None
                set_cache("ordyaml.init", file_path, text)
            self.all_files = self.init_content(text, file_path)
            self.all_files[file_path] = 1
            return file_path
        except Exception as e:
            self.errs.append(e)
            raise (e)

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

    def dump(self, obj_in=None, expanded=True, use_aliases=True, **kwargs):
        obj = obj_in if obj_in else self.obj
        if expanded:
            return self._dump(obj, use_aliases=use_aliases, **kwargs)
        if not obj_in:
            obj = copy.deepcopy(obj)
        files = []
        for f, _, path in self.include_map.values():
            if not path:
                continue
            obj1, last_index = obj, len(path) - 1
            for index in range(last_index):
                obj1 = obj1[path[index]]
            obj1[path[last_index]] = "!include {}".format(f)
            files.append(f)
        rv = self._dump(obj, use_aliases=use_aliases, **kwargs)
        for f in files:
            value = "!include {}".format(f)
            rv = rv.replace("'{}'".format(value), value)
        return rv
