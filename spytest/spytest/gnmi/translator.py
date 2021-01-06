import re, copy

try:
    from urllib.parse import unquote, quote
except Exception:
    from urlparse import unquote

RestDataPrefix = '/restconf/data'
RestOperPrefix = '/restconf/operations'
ActionMap = {
    'get': 'GET',
    'read': 'GET',
    'put': 'REPLACE',
    'post': 'CREATE',
    'patch': 'UPDATE',
    'delete': 'DELETE'
}

MethodMap = {
    'get': 'GET',
    'create': 'POST',
    'replace': 'PUT',
    'update': 'PATCH',
    'delete': 'DELETE'
}

def unescape(txt=''):
    tmp = ''
    while txt and txt != tmp:
        tmp = str(txt)
        try: txt = unquote(tmp)
        except Exception: pass
    return txt.replace(u"\u200b", '')

def escapeKeyValue(val):
    return str(val).replace("\\", "\\\\").replace("]", "\\]")

def getAttrValLists(path, var):
    attrs = re.findall(r'\{(\S+?)\}', path)
    vals = [''] * len(attrs)
    if isinstance(var, dict):
        idxs = {}
        vList = {}
        for k, v in var.items():
            if isinstance(v, list):
                vList[k] = v
            else:
                vList[k] = [v]
        for i, name in enumerate(attrs):
            idx = idxs.get(name, 0)
            l = vList.get(name, [])
            if idx < len(l):
                vals[i] = l[idx]
            else:
                vals[i] = ''
            idxs[name] = idx+1
    elif isinstance(var, list):
        for i, name in enumerate(attrs):
            if i < len(var):
                vals[i] = var[i]
            else:
                vals[i] = ''
    return attrs, vals

def toRest(path='', var={}, method='get', json=None):
    ''' Covert template path to Rest path '''
    method = toMethod(method)
    body = copy.deepcopy(json)
    isOper = unescape(path).startswith(RestOperPrefix)
    path = unescape(path).replace(RestDataPrefix, '').replace(RestOperPrefix, '').strip()
    attrs, vals = getAttrValLists(path, var)
    for i, attr in enumerate(attrs):
        val = escapeKeyValue(unescape(vals[i]))
        try:
	        val = quote(val, safe=':')
        except Exception:
            pass
        path = path.replace('{{{}}}'.format(attr), val, 1)
    return "{}{}".format(RestOperPrefix if isOper else RestDataPrefix, path), method, body

def toGNMI(path='', var={}, action='get', data=None):
    ''' Convert templat path to gNMI path '''
    action = toAction(action)
    path = unescape(path).replace(RestDataPrefix, '').replace(RestOperPrefix, '').strip()
    attrs, vals = getAttrValLists(path, var)
    body = copy.deepcopy(data)
    if (action.lower() == 'create'):
        action = 'UPDATE'
        if isinstance(body, dict):
            tk = [t for t in path.split('/') if t and len(t)]
            tk = tk[-1] if tk else ""
            if tk:
                m = re.search(r'^\s*(\S+)=\{', tk)
                if m and m.group(1):
                    rAttrs = attrs[::-1]
                    rVals = vals[::-1]
                    for a in re.findall(r'\{(\S+?)\}', tk):
                        if a in rAttrs:
                            body[a] = rVals[rAttrs.index(a)]
                    body = {m.group(1): [body]}
                else:
                    body = {tk: body}
    path = path.replace("={", "{").replace("},{", "}{")
    for i, attr in enumerate(attrs):
        val = escapeKeyValue(unescape(vals[i]))
        path = path.replace('{{{}}}'.format(attr), '[{}={}]'.format(attr, val), 1)
    return path if action.lower() == 'get' else cleanGnmiPath(path), action, body

def cleanGnmiPath(path):
    ''' Remove duplicated openconfig struture from path '''
    idx = 0
    cmp = re.split(r'(/openconfig-[^/:]+:)', path)
    for i, v in enumerate(cmp):
        if v.startswith('/openconfig-'):
            if idx: cmp[i] = '/'
            idx += 1
    return ''.join(cmp)

def toAction(act=''):
    ''' return proper action for gNMI '''
    if str(act).lower() not in ActionMap and str(act).upper() not in ActionMap.values(): act = 'GET'
    return ActionMap.get(act.lower(), act)

def toMethod(met=''):
    ''' return proper method for Rest '''
    if str(met).lower() not in MethodMap and str(met).upper() not in MethodMap.values(): met = 'GET'
    return MethodMap.get(met.lower(), met)

