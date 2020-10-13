import os
import glob
import requests
import warnings
import jsonpatch

from jinja2 import Environment

from spytest.dicts import SpyTestDict
from utilities import common as utils
from utilities import json_helpers as json

class Rest(object):

    def __init__(self, logger=None):
        self.base_url = os.getenv("SPYTEST_REST_TEST_URL")
        self.session = None
        self.logger = logger
        self.timeout = 1
        self.protocol = "https"
        self.ip = None
        self.username = None
        self.password = None
        self.altpassword = None
        self.curr_pwd = None
        self.cli_data = SpyTestDict()

    def reinit(self, ip, username, password, altpassword):
        self.ip = ip
        self.base_url = "{}://{}".format(self.protocol, ip)
        try:
            self._set_auth(username, password, altpassword)
        except:
            pass
        return self

    def reset_curr_pwd(self):
        self.curr_pwd = None

    def _set_auth(self, username, password, altpassword):
        self.username = username
        if not self.curr_pwd:
            if password and altpassword:
                self.password = password
                self.altpassword = altpassword
                for pwd in [password, altpassword]:
                    tmp_session = self._get_session()
                    tmp_session.auth = (self.username, pwd)
                    tmp_session.verify = False
                    tmp_url = self._get_url("/restconf/data/openconfig-system:system")
                    iter_count = 3
                    while iter_count > 0:
                        iter_count -= 1
                        try:
                            retval = tmp_session.get(tmp_url, verify=False, timeout=self.timeout)
                            self._log("Using '{}' '{}' : '{}'".format(username, pwd, retval.status_code))
                            if retval.status_code == 200:
                                self.curr_pwd = pwd
                                break
                        except Exception as e:
                            self._log("Exception '{}' '{}' : '{}'".format(username, pwd, e))
                    if self.curr_pwd:
                        break
            elif password:
                self.password = password
                self.curr_pwd = password
            elif altpassword:
                self.altpassword = altpassword
                self.curr_pwd = altpassword
            msg = "Rest details '{}' '{}' '{}' '{}' '{}'".format(
                self.ip, self.username, self.password, self.altpassword, self.curr_pwd)
            self._log(msg)

    def _create_session(self):
        self.session = requests.session()
        self.headers = {"Accept": "application/yang-data+json",
                        "Content-type": "application/yang-data+json"}
        self.session.headers.update(self.headers)
        if self.curr_pwd:
            self.session.auth = (self.username, self.curr_pwd)
            self.session.verify = False
        warnings.filterwarnings('ignore', message='Unverified HTTPS request')

    def _get_credentials(self):
        return [self.username, self.curr_pwd]

    def _get_session(self):
        self._create_session()
        if not self.session:
            self._create_session()
        return self.session

    def _log(self, msg):
        if self.logger:
            self.logger.debug(msg)
        else:
            print(msg)

    def _dump(self, data):
        self._log(json.dumps(data))

    def _get_url(self, path, *args, **kwargs):
        params = []
        for key, value in kwargs.items():
            if value:
                value = value.replace(" ", "%20")
                params.append('{}={}'.format(key, value))
            else:
                params.append(key)

        if path.startswith("/"):
            path = path[1:]

        if params:
            url = "{}/{}/{}".format(self.base_url, path, ",".join(params))
        else:
            url = "{}/{}".format(self.base_url, path)

        for entry in args:
            url = "{}/{}".format(url, entry)

        return url

    def _json(self, retval, default={}):
        try:
            return retval.json()
        except Exception as exp:
            print(utils.stack_trace(exp))
            return default

    def _result(self, operation, retval, inp):
        resp = SpyTestDict()
        resp.url = retval.url
        resp.operation = operation
        resp.status = retval.status_code
        resp.input = inp
        resp.output = self._json(retval)
        self._log(json.dumps(resp))
        return resp

    def post(self, path, data, *args, **kwargs):
        session = self._get_session()
        try:
            url = self._get_url(path, *args, **kwargs)
            retval = session.post(url, json.dumps(data), verify=False, timeout=self.timeout)
            return self._result("POST", retval, data)
        except Exception as e:
            print(e)
            raise e

    def put(self, path, data, *args, **kwargs):
        session = self._get_session()
        try:
            url = self._get_url(path, *args, **kwargs)
            retval = session.put(url, json.dumps(data), verify=False, timeout=self.timeout)
            return self._result("PUT", retval, data)
        except Exception as e:
            print(e)
            raise e

    def patch(self, path, data, *args, **kwargs):
        session = self._get_session()
        try:
            url = self._get_url(path, *args, **kwargs)
            retval = session.patch(url, json.dumps(data), verify=False, timeout=self.timeout)
            return self._result("PATCH", retval, data)
        except Exception as e:
            print(e)
            raise e

    def delete(self, path, *args, **kwargs):
        session = self._get_session()
        try:
            url = self._get_url(path, *args, **kwargs)
            retval = session.delete(url, verify=False, timeout=self.timeout)
            return self._result("DELETE", retval, None)
        except Exception as e:
            print(e)
            raise e

    def get(self, path, *args, **kwargs):
        session = self._get_session()
        try:
            url = self._get_url(path, *args, **kwargs)
            retval = session.get(url, verify=False, timeout=self.timeout)
            return self._result("GET", retval, None)
        except Exception as e:
            print(utils.stack_trace(e))
            raise e

    def parse(self, filepath=None, all_sections=False, paths=[], **kwargs):
        assert filepath, "File Path must be provided"
        root = None
        if "::" in filepath: [filepath, root] = filepath.split("::", 2)
        if not isinstance(paths, list) and isinstance(paths, str):
            paths = [paths]
        filepath = utils.find_file(filepath, paths)
        text = "\n".join(utils.read_lines(filepath))
        tmpl = Environment().from_string(text)
        if root:
            block = tmpl.blocks[root]
            text = "\n".join(block(tmpl.new_context(kwargs)))
            return json.fix(text, "Invalid json file supplied", True, object_pairs_hook=SpyTestDict)
        if not all_sections or not tmpl.blocks:
            text = Environment().from_string(text).render(**kwargs)
            return json.fix(text, "Invalid json file supplied", True, object_pairs_hook=SpyTestDict)
        retval = SpyTestDict()
        for root in tmpl.blocks:
            block = tmpl.blocks[root]
            text = "\n".join(block(tmpl.new_context(**kwargs)))
            retval[root] = json.fix(text, "Invalid json file supplied", True, object_pairs_hook=SpyTestDict)
        return retval

    def load_cli(self, filepath):
        self.cli_data = self.parse(filepath)
        for req_list in self.cli_data.values():
            for req in req_list:
                for key, cli in req.items():
                    print("{} -- {} -- {}".format(cli.view, cli.cmd, key))

    def search_cli(self, key):
        for req_list in self.cli_data.values():
            for req in req_list:
                if key in req:
                    return req[key]
        return None

    def search_cli_data(self, data):
        print(json.dumps(data))

    def cli(self, request, sections=None, operations=None):
        retval = SpyTestDict()
        map_operations={"create":"post", "read":"get", "update":"put", "modify":"patch", "delete":"delete"}
        if operations: operations = utils.make_list(operations)
        for index, ent in enumerate(utils.make_list(request)):
            key = ent.path.replace("/restconf/data", map_operations[ent.operation])
            key = key.replace("-", "_").replace(":", "_").replace("/", "_")
            cli = self.search_cli(key)
            if not cli:
                print("Rest2CLI Fail: {} {}".format(key, ent.path))
                self.search_cli_data(request.data)
                continue
            print("Rest2CLI PASS: {} {}".format(key, cli.cmd))
        return retval

    def apply(self, request, sections=None, operations=None, ui="rest"):
        if ui == "cli": return self.cli(request, sections, operations)
        retval = SpyTestDict()
        if operations: operations = utils.make_list(operations)
        for index, ent in enumerate(utils.make_list(request)):
            enable = ent.get("enable", 1)
            if not enable: continue
            operation = ent["operation"]
            if operations and operation not in operations: continue
            instance = ent.get("instance", dict())
            data = ent.get("data", dict())
            path = ent.get("path", "")
            name = ent.get("name", "{}".format(index))
            if operation == "read" or operation == "get":
                retval[name] = self.get(path, **instance)
            elif operation == "configure" or operation == "patch":
                retval[name] = self.patch(path, data, **instance)
            elif operation == "unconfigure" or operation == "delete":
                retval[name] = self.delete(path, **instance)
            elif operation == "post":
                retval[name] = self.post(path, data, **instance)
            elif operation == "put":
                retval[name] = self.put(path, data, **instance)
            elif operation == "verify":
                resp = self.get(path, **instance)
                result = [True, []]
                for pe in jsonpatch.make_patch(data, resp.output):
                    result[1].append(pe)
                    if pe["op"] != "add":
                        result[0] = False
                retval[name] = result
        return retval

if __name__ == "__main__":
    def _main():
        r = Rest().reinit("10.52.129.47", "admin", "broadcom", "broadcom2")
        r.load_cli('../datastore/samples/all.cli')
        for filepath in glob.glob('../datastore/samples/*.j2'):
            #if "openconfig-system.j2" not in filepath: continue
            msg = "Rest {}".format(filepath)
            utils.banner(msg, tnl=False)
            d = r.parse(filepath, all_sections=True)
            for name, section in d.items():
                if section.operation == "read": continue
                msg = "{}::{} {}".format(filepath, name, section.operation)
                utils.banner(msg, tnl=False)
                r.apply(section, ui="rest")
                break
    def _main2():
        r = Rest().reinit("10.59.143.100", "admin", "broadcom", "broadcom2")
        url = "/restconf/data/openconfig-interfaces:interfaces"
        print(r.get(url, "openconfig-vxlan:vxlan-if", interface="vtep1"))
    _main2()

