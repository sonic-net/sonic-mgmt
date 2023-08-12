
def read_lines(filename, default=None):
    try:
        fh = open(filename, 'r')
        data = fh.readlines()
        fh.close()
        return map(str.strip, data)
    except Exception:
        return default
