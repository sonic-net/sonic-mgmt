from collections import OrderedDict


class SpyTestDict(OrderedDict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        if not name.startswith('_OrderedDict__'):
            self[name] = value
        else:
            OrderedDict.__setattr__(self, name, value)

    def __delattr__(self, name):
        try:
            self.pop(name)
        except KeyError:
            OrderedDict.__delattr__(self, name)

    # compare
    def __eq__(self, other):
        return dict.__eq__(self, other)

    # stringify
    def __str__(self):
        try:
            import json
            return json.dumps(self)
        except Exception:
            return '{%s}' % ', '.join('%r: %r' % item for item in self.items())

    # for PrettyPrinter
    __repr__ = OrderedDict.__repr__
