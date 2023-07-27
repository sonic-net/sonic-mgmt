import re
import unicodedata

def _remove(s):
  no_change_list = ['\r', '\n']
  no_output_list = ['\a', u'\u200a']
  try:
    s = str(s)
    s = s.decode('utf-8', 'ignore')
  except Exception: pass
  rv = []
  for ch in s:
    if ch in no_output_list:
        pass
    elif ch in no_change_list:
        rv.append(ch)
    elif unicodedata.category(ch)[0]!="C":
        rv.append(ch)
  return "".join(rv)

def tostring(msg, default="non-ascii characters", dbg=True):
  try:
    try: msg = str(msg)
    except Exception: pass
    msg = re.sub(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]', ' ', msg)
    msg = re.sub(r'[^\x00-\x7F]+', ' ', msg)
    return msg.encode('ascii', 'ignore').decode('ascii')
  except Exception as exp:
    if dbg: print("Exception-tostring({})".format(str(exp)))
  return msg if default is None else default

def remove(*args):
  rv = []
  for arg in args:
    arg = tostring(arg, None, False)
    rv.append(_remove(arg))
  rv = " ".join(rv)
  return rv
