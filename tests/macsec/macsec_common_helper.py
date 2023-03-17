
def convert_on_off_to_boolean(obj):
    for k, v in list(obj.items()):
        if v == "on":
            obj[k] = True
        elif v == "off":
            obj[k] = False
        elif isinstance(v, dict):
            obj[k] = convert_on_off_to_boolean(v)
    return obj
