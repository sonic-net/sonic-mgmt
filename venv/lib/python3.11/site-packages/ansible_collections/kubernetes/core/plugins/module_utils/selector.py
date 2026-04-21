# Copyright [2021] [Red Hat, Inc.]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re


class Selector(object):
    equality_based_operators = ("==", "!=", "=")

    def __init__(self, data):
        self._operator = None
        self._data = None
        if not self.parse_set_based_requirement(data):
            no_whitespace_data = data.replace(" ", "")
            for op in self.equality_based_operators:
                idx = no_whitespace_data.find(op)
                if idx != -1:
                    self._operator = "in" if op == "==" or op == "=" else "notin"
                    self._key = no_whitespace_data[0:idx]
                    # fmt: off
                    self._data = [no_whitespace_data[idx + len(op):]]
                    # fmt: on
                    break

    def parse_set_based_requirement(self, data):
        m = re.match(
            r"( *)([a-z0-9A-Z][a-z0-9A-Z\._-]*[a-z0-9A-Z])( +)(notin|in)( +)\((.*)\)( *)",
            data,
        )
        if m:
            self._set_based_requirement = True
            self._key = m.group(2)
            self._operator = m.group(4)
            self._data = [x.replace(" ", "") for x in m.group(6).split(",") if x != ""]
            return True
        elif all(x not in data for x in self.equality_based_operators):
            self._key = data.rstrip(" ").lstrip(" ")
            if self._key.startswith("!"):
                self._key = self._key[1:].lstrip(" ")
                self._operator = "!"
            return True
        return False

    def isMatch(self, labels):
        if self._operator == "in":
            return self._key in labels and labels.get(self._key) in self._data
        elif self._operator == "notin":
            return self._key not in labels or labels.get(self._key) not in self._data
        else:
            return (
                self._key not in labels
                if self._operator == "!"
                else self._key in labels
            )


class LabelSelectorFilter(object):
    def __init__(self, label_selectors):
        self.selectors = [Selector(data) for data in label_selectors]

    def isMatching(self, definition):
        if "metadata" not in definition or "labels" not in definition["metadata"]:
            return False
        labels = definition["metadata"]["labels"]
        if not isinstance(labels, dict):
            return None
        return all(sel.isMatch(labels) for sel in self.selectors)
