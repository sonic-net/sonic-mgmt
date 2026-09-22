def str2bool(s):
    if isinstance(s, bool):
        return s
    if s is None:
        return False
    return s.lower() in ['yes', 'true', 't', 'y', '1']
