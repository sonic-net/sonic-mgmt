
import os
import sys
import threading

class Tracer(object):
    def __init__(self):
        self.callbacks = []
        self.root = os.path.join(os.path.dirname(__file__), '..')
        self.root = os.path.abspath(self.root)
        #print("Tracer root={}".format(self.root))
        threading.setprofile(self._impl)
        sys.setprofile(self._impl)

    @staticmethod
    def register(callback, data, exclude=None, include=None, root=None):
        objName = "TracerObject"
        # nosemgrep-next-line
        obj = globals().get(objName, None)
        if not obj:
            obj = Tracer()
            globals()[objName] = obj
        if include and not isinstance(include, list): include = [include]
        if exclude and not isinstance(exclude, list): exclude = [exclude]
        l_include, l_exclude = [], []
        for loc in include or []: l_include.append(os.path.abspath(loc))
        for loc in exclude or []: l_exclude.append(os.path.abspath(loc))
        if root: root = os.path.abspath(root)
        obj.callbacks.append([callback, data, l_exclude, l_include, root])

    def _impl(self, frame, event, *args, **kwargs):
        co_filename = frame.f_code.co_filename
        if event != "call" or co_filename.startswith("<"):
            return self._impl
        for callback, data, exclude, include, root in self.callbacks:
            root = root or self.root
            co_filename = os.path.abspath(co_filename)
            if not co_filename.startswith(root):
                continue
            if exclude and co_filename in exclude:
                continue
            if include and co_filename not in include:
                continue
            args, kwargs = [], {}
            for k, v in frame.f_locals.items():
                if isinstance(v, tuple):
                    for vv in v:
                        args.append(vv)
                elif isinstance(v, dict):
                    for k, v in v.items():
                        kwargs[k] = v
            rpath = os.path.relpath(co_filename, root)
            callback(event, data, rpath, frame.f_code.co_name, *args, **kwargs)
        return self._impl
