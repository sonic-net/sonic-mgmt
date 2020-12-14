import re
import json

from collections import OrderedDict

class _Exception(Exception):
    def __init__(self, data, exp, msg):
       super(_Exception, self).__init__(msg)
       self.exp = exp
       self.msg = msg
       self.data = data

    def __str__(self):
       output = [""]
       lines=self.data.split("\n")
       for index, line in enumerate(lines):
           output.append("{}: {}".format(index+1, line))
       if self.exp:
           output.append(str(self.exp))
       if self.msg:
           output.append(str(self.msg))
       return "\n".join(output)

def loads(text, object_pairs_hook=OrderedDict):
    return json.loads(text, object_pairs_hook=object_pairs_hook)

def dumps(data):
    return (json.dumps(data, indent=2, separators=(',', ': ')))

def fix(text, msg="invalid json text", load=False, object_pairs_hook=OrderedDict):

    try:
        obj = json.loads(text, object_pairs_hook=object_pairs_hook)
        return obj if load else text
    except Exception:
        pass

    # remove trailing object comma
    regex = re.compile(r'(,)\s*}(?=([^"\\]*(\\.|"([^"\\]*\\.)*[^"\\]*"))*[^"]*$)')
    text = regex.sub("}", text)
    # remove trailing array comma
    regex = re.compile(r'(,)\s*\](?=([^"\\]*(\\.|"([^"\\]*\\.)*[^"\\]*"))*[^"]*$)')
    text = regex.sub("]", text)

    try:
        obj = json.loads(text, object_pairs_hook=object_pairs_hook)
        return obj if load else text
    except Exception as exp:
        raise _Exception(text, exp, msg)

