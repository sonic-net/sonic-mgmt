# -----------------------------------------------------------------------------
# Copyright 2015-2025 by PyCLibrary Authors, see AUTHORS for more details.
#
# Distributed under the terms of the MIT/X11 license.
#
# The full license is in the file LICENCE, distributed with this software.
# -----------------------------------------------------------------------------
"""
Proxy to library object, allowing automatic type conversion and
function calling based on C header definitions.

"""

import logging
import os
import sys
from inspect import cleandoc
from threading import RLock
from weakref import WeakValueDictionary

from .c_parser import CParser
from .utils import LibraryPath, find_library

logger = logging.getLogger(__name__)


def make_mess(mess):
    return cleandoc(mess).replace("\n", " ")


class CLibraryMeta(type):
    """Meta class responsible for determining the backend and ensuring no
    duplicates libraries exists.

    """

    backends: dict[str, type["CLibrary"]] = {}
    libs: WeakValueDictionary[str, "CLibrary"] = WeakValueDictionary()

    def __new__(meta, name, bases, dct):
        if name == "CLibrary":
            return super(CLibraryMeta, meta).__new__(meta, name, bases, dct)
        if "backend" not in dct:
            mess = make_mess("""{} does not declare a backend name, it cannot
                              be registered.""")
            logger.warning(mess.format(name))
            return None

        cls = super(CLibraryMeta, meta).__new__(meta, name, bases, dct)
        meta.backends[cls.backend] = cls

        return cls

    def __call__(cls, lib, *args, **kwargs):
        # Identify the library path.
        if isinstance(lib, str):
            if os.sep not in lib:
                lib_path = find_library(lib).path
            else:
                lib_path = os.path.realpath(lib)
                assert os.path.isfile(lib_path), (
                    "Provided path does not point to a file"
                )
            backend_cls = cls.backends[kwargs.get("backend", "ctypes")]

            lib_arch = LibraryPath(lib_path).arch
            py_bitness = 64 if sys.maxsize > 2**32 else 32
            if lib_arch and py_bitness not in lib_arch:
                raise OSError("Library bitness does not match Python's")
            lib = lib_path
        else:
            from .backends import get_library_path, identify_library

            backend = identify_library(lib)
            backend_cls = cls.backends[backend]
            lib_path = get_library_path(lib, backend)

        # Check whether or not this library has already been opened.
        if lib_path in cls.libs:
            return cls.libs[lib_path]

        else:
            obj = super(CLibraryMeta, backend_cls).__call__(lib, *args, **kwargs)
            cls.libs[lib_path] = obj
            return obj


class CLibrary(object, metaclass=CLibraryMeta):
    """The CLibrary class is intended to automate much of the work in using
    ctypes by integrating header file definitions from CParser. This class
    serves as a proxy to a backend, adding a few features:

        - allows easy access to values defined via CParser.
        - automatic type conversions for function calls using CParser function
          signatures.
        - creates ctype classes based on type definitions from CParser.

    Initialize using a ctypes shared object and a CParser:
    >>> headers = CParser.winDefs()
    >>> lib = CLibrary(windll.User32, headers)

    There are 3 ways to access library elements:

    - lib(type, name):
        type can be one of 'values', 'functions', 'types', 'structs',
        'unions', or 'enums'. Returns an object matching name. For values,
        the value from the headers is returned. For functions, a callable
        object is returned that handles automatic type conversion for
        arguments and return values. For structs, types, and enums, a
        ctypes class is returned matching the type specified.

    - lib.name:
        searches in order through values, functions, types, structs,
        unions, and enums from header definitions and returns an object for
        the first match found. The object returned is the same as returned
        by lib(type, name). This is the preferred way to access elements
        from CLibrary, but may not work in some situations (for example, if
        a struct and variable share the same name).

    - lib[type]:
        Accesses the header definitions directly, returns definition
        dictionaries based on the type requested. This is equivalent to
        headers.defs[type].

    Parameters
    ----------
    lib:
        Library object.

    headers : unicode or CParser
        Path to the header files or CParser holding all the definitions.

    prefix : unicode, optional
        Prefix to remove from all definitions.

    lock_calls : bool, optional
        Whether or not to lock the calls to the underlying library. This should
        be used only if the underlying library is not thread safe.

    convention : {'cdll', 'windll', 'oledll'}
        Calling convention to use. Not all backends supports all calling
        conventions.

    backend : unicode, optional
        Name of the backend to use. This is ignored if an already initialised
        library object is passed.
        NB : this kwarg is used by the metaclass.

    kwargs :
        Additional keywords argument which are passed to the CParser if one
        is created.

    """

    #: Private flag allowing to know if the class has been initiliased.
    _init = False

    #: Balise to use when a NULL pointer is needed
    Null = object()

    def __init__(
        self,
        lib,
        headers,
        prefix=None,
        lock_calls=False,
        convention="cdll",
        backend="ctypes",
        **kwargs,
    ):
        # name everything using underscores to avoid name collisions with
        # library

        # Build or store the parser from the header files.
        if isinstance(headers, list):
            self._headers_ = self._build_parser(headers, kwargs)
        elif isinstance(headers, CParser):
            self._headers_ = headers
        else:
            msg = "Expected a CParser instance or list for headers, not {}"
            raise ValueError(msg.format(type(headers)))
        self._defs_ = self._headers_.defs

        # Create or store the internal representation of the library.
        if isinstance(lib, str):
            self._lib_ = self._link_library(lib, convention)
        else:
            self._lib_ = lib

        # Store the list of prefix.
        if prefix is None:
            self._prefix_ = []
        elif isinstance(prefix, list):
            self._prefix_ = prefix
        else:
            self._prefix_ = [prefix]

        self._lock_calls_ = lock_calls
        if lock_calls:
            self._lock_ = RLock()

        self._objs_ = {}
        for k in ["values", "functions", "types", "structs", "unions", "enums"]:
            self._objs_[k] = {}
        self._all_objs_ = {}
        self._structs_ = {}
        self._unions_ = {}

    def __call__(self, typ, name):
        if typ not in self._objs_:
            typs = self._objs_.keys()
            raise KeyError("Type must be one of {}".format(typs))

        if name not in self._objs_[typ]:
            self._objs_[typ][name] = self._make_obj_(typ, name)

        return self._objs_[typ][name]

    def __getattr__(self, name):
        """Used to retrieve any type of definition from the headers.

        Searches for the name in this order:
        values, functions, types, structs, unions, enums.

        """
        if name not in self._all_objs_:
            names = self._all_names_(name)
            for k in [
                "values",
                "functions",
                "types",
                "structs",
                "unions",
                "enums",
                None,
            ]:
                if k is None:
                    raise NameError(name)
                obj = None
                for n in names:
                    if n in self._defs_[k]:
                        obj = self(k, n)
                        break
                if obj is not None:
                    break
            self._all_objs_[name] = obj
        return self._all_objs_[name]

    def __getitem__(self, name):
        """Used to retrieve a specific dictionary from the headers."""
        return self._defs_[name]

    # --- Private API ---------------------------------------------------------

    def _all_names_(self, name):
        """Build a list of all possible names by taking into account that
        the user omitted a prefix.

        """
        return [name] + [p + name for p in self._prefix_]

    def _make_obj_(self, typ, name):
        """Build the correct C-like object from the header definitions."""
        names = self._all_names_(name)
        objs = self._objs_[typ]

        for n in names:
            if n in objs:
                return self.objs[n]

        for n in names:  # try with and without prefix
            if n not in self._defs_[typ] and not (
                typ in ["structs", "unions", "enums"] and n in self._defs_["types"]
            ):
                continue

            if typ == "values":
                return self._defs_[typ][n]
            elif typ == "functions":
                return self._get_function(n)
            elif typ == "types":
                obj = self._defs_[typ][n]
                return self._get_type(obj)
            elif typ == "structs":
                return self._get_struct("structs", n)
            elif typ == "unions":
                return self._get_struct("unions", n)
            elif typ == "enums":
                # Allow automatic resolving of typedefs that alias enums
                if n not in self._defs_["enums"]:
                    if n not in self._defs_["types"]:
                        raise KeyError('No enums named "{}"'.format(n))
                    typ = self._headers_.eval_type([n])[0]
                    if typ[:5] != "enum ":
                        raise KeyError('No enums named "{}"'.format(n))
                    # Look up internal name of enum
                    n = self._defs_["types"][typ][1]
                obj = self._defs_["enums"][n]

                return obj
            else:
                raise KeyError("Unknown type {}".format(typ))

        raise NameError(name)

    def __repr__(self):
        return "<CLibrary instance: %s>" % str(self._lib_)

    def _build_parser(self, headers, kwargs):
        """Find the headers and parse them to extract the definitions."""
        return CParser(headers, **kwargs)

    def _link_library(self, lib_path, convention):
        """Find and link the external library if only a path was provided.

        Parameters
        ----------
        lib_path : unicode
            Path to the library to link.

        convention : {'cdll', 'windll', 'oleddl'}
            Calling convention to use.

        """
        raise NotImplementedError()

    def _extract_val_(self, obj):
        """Extract a python representation from a function return value."""
        raise NotImplementedError()

    def _get_function(self, func_name):
        """Return a CFuntion instance."""
        try:
            func = getattr(self._lib_, func_name)
        except Exception:
            mess = "Function name '{}' appears in headers but not in library!"
            raise KeyError(mess.format(func_name))

        return CFunction(
            self,
            func,
            self._defs_["functions"][func_name],
            func_name,
            self._lock_calls_,
        )

    def _init_function(self, function):
        """Finish the function wrapper initialisation.

        This is expected to be implemented by backends for which the default
        behavior is not sufficient.

        """
        pass

    def _get_type(self, typ, pointers=True):
        """Return an object representing the named type.

        If pointers is True, the class returned includes all pointer/array
        specs provided. Otherwise, the class returned is just the base type
        with no pointers.

        """
        raise NotImplementedError()

    def _get_struct(self, str_type, str_name):
        """Return an object representing the named structure or union."""
        raise NotImplementedError()

    def _get_pointer(self, arg_type):
        """Build an uninitialised pointer for the given type."""
        raise NotImplementedError()

    def _get_array(self, typ, size, obj):
        """Build an array of the specified type and size."""
        raise NotImplementedError()

    def _resolve_struct_alias(self, str_type, str_name):
        """Resolve struct name--typedef aliases."""
        if str_name not in self._defs_[str_type]:
            if str_name not in self._defs_["types"]:
                mess = 'No struct/union named "{}"'
                raise KeyError(mess.format(str_name))

            typ = self._headers_.eval_type([str_name])[0]
            if typ[:7] != "struct " and typ[:6] != "union ":
                mess = 'No struct/union named "{}"'
                raise KeyError(mess.format(str_name))

            return self._defs_["types"][typ][1]

        else:
            return str_name


class CFunction(object):
    """Wrapper object for a function from the library."""

    def __init__(self, lib, func, sig, name, lock_call):
        self.lock_call = lock_call
        self.lib = lib
        self.func = func

        # looks like [return_type, [(argName, type, default),
        #                           (argName, type, default), ...]]
        self.sig = list(sig)

        # remove void args from list
        self.sig[1] = [s for s in sig[1] if s[1] != ("void",)]
        for conv in ["__stdcall", "__cdecl"]:
            if conv in self.sig[0]:
                self.sig[0].remove(conv)
        self.name = name
        self.res_type = lib._get_type(self.sig[0])
        self.arg_types = [lib._get_type(s[1]) for s in self.sig[1]]
        self.req_args = [x[0] for x in self.sig[1] if x[2] is None]
        # Mapping from argument names to indices
        self.arg_inds = {s[0]: i for i, s in enumerate(self.sig[1])}

        self.lib._init_function(self)

    def __call__(self, *args, **kwargs):
        """Invoke the SO or dll function referenced, converting all arguments
        to the correct type.

        Keyword arguments are allowed as long as the header specifies the
        argument names. Arguments which are passed byref may be omitted
        entirely, and will be automaticaly generated. To pass a NULL pointer,
        give None as the argument.
        Returns the return value of the function call as well as all of the
        arguments (so that objects passed by reference can be retrieved).

        """
        # We'll need at least this many arguments.
        arg_list = [None] * max(len(self.req_args), len(args))

        # First fill in args
        for i in range(len(args)):
            if args[i] is None:
                arg_list[i] = self.lib.Null
            else:
                arg_list[i] = args[i]

        # Next fill in kwargs
        for k in kwargs:
            if k not in self.arg_inds:
                mess = "Function signature has no argument named '{}'"
                raise TypeError(mess.format(k))

            ind = self.arg_inds[k]
            # Stretch argument list if needed
            if ind >= len(arg_list):  #
                arg_list += [None] * (ind - len(arg_list) + 1)
            if kwargs[k] is None:
                arg_list[ind] = self.lib.Null
            else:
                arg_list[ind] = kwargs[k]

        guessed_args = []
        # Finally, fill in remaining arguments if they are pointers to
        # int/float/void*/struct values (we assume these are to be modified by
        # the function and their initial value is not important)
        missings = {
            i: arg
            for i, arg in enumerate(arg_list)
            if arg is None or arg is self.lib.Null
        }
        for i, arg in missings.items():
            try:
                sig = self.sig[1][i][1]
                arg_type = self.lib._headers_.eval_type(sig)

                # request to build a null pointer
                if arg is self.lib.Null:
                    if len(arg_type) < 2:
                        mess = make_mess("""Cannot create NULL for
                                        non-pointer argument type: {}""")
                        raise TypeError(mess.format(arg_type))
                    arg_list[i] = self.lib._get_type(sig)()

                else:
                    arg_list[i] = self.lib._get_pointer(arg_type, sig)
                    guessed_args.append(i)

            except Exception:
                if sys.exc_info()[0] is not AssertionError:
                    raise
                mess = "Function call '{}' missing required argument {} {}"
                raise TypeError(mess.format(self.name, i, self.sig[1][i][0]))

        try:
            if self.lock_call:
                with self.lib.lock:
                    res = self.func(*arg_list)
            else:
                res = self.func(*arg_list)
        except Exception:
            logger.error(
                "Function call failed. Signature is: {}".format(self.pretty_signature())
            )
            logger.error("Arguments: {}".format(arg_list))
            logger.error("Argtypes: {}".format(self.func.argtypes))
            raise

        cr = CallResult(self.lib, res, arg_list, self.sig, guessed=guessed_args)
        return cr

    def arg_c_type(self, arg):
        """Return the type required for the specified argument.

        Parameters
        ----------
        arg : int or unicode
            Name or index of the argument whose type should be returned.

        """
        if isinstance(arg, str):
            arg = self.arg_inds[arg]
        return self.lib._get_type(self.sig[1][arg][1])

    def pretty_signature(self):
        args = (
            "".join(self.sig[0]),
            self.name,
            ", ".join(["{} {}".format(s[1], s[0]) for s in self.sig[1]]),
        )
        return "{} {}({})".format(*args)


class CallResult(object):
    """Class for bundling results from C function calls.

    Allows access to the function  value as well as all of the arguments, since
    the function call will often return extra values via these arguments:

      - Original ctype objects can be accessed via result.rval or result.args
      - Python values carried by these objects can be accessed using ()

    To access values:

      - The return value: ()
      - The nth argument passed: [n]
      - The argument by name: ['name']
      - All values that were auto-generated: .auto()

    The class can also be used as an iterator, so that tuple unpacking is
    possible:

         >>> ret, (arg1, arg2) = lib.run_some_function(...)

    Attributes
    ----------
    lib: CLibrary
        Reference to the CLibrary to which the function that created this
        object balongs.

    rval :
        Value returned by the C function.

    args : tuple
        Arguments passed to the C function.

    sig :
        Signature of the function which created this object.

    guessed : tuple
        Pointers that were created on the fly.

    """

    def __init__(self, lib, rval, args, sig, guessed):
        self.lib = lib
        self.rval = rval  # return value of function call
        self.args = args  # list of arguments to function call
        self.sig = sig  # function signature
        self.guessed = guessed  # list of arguments that were auto-generated

    def __call__(self):
        if self.sig[0] == ["void"]:
            return None
        return self.lib._extract_val_(self.rval)

    def __getitem__(self, n):
        if isinstance(n, int):
            arg = self.args[n]
        elif isinstance(n, str):
            n = self.find_arg(n)
            arg = self.args[n]
        else:
            raise ValueError("Index must be int or str.")

        if n in self.guessed:
            arg = arg[0]

        return self.lib._extract_val_(arg)

    def __setitem__(self, n, val):
        if type(n) is int:
            self.args[n] = val
        elif type(n) is str:
            ind = self.find_arg(n)
            self.args[ind] = val
        else:
            raise ValueError("Index must be int or str.")

    def find_arg(self, arg):
        """Find argument based on name."""
        for i, a in enumerate(self.sig[1]):
            if a[0] == arg:
                return i
        mess = make_mess("""Can't find argument '{}' in function signature.
                         Arguments are: {}""")
        raise KeyError(mess.format(arg, str([a[0] for a in self.sig[1]])))

    def __iter__(self):
        yield self()
        yield (self[i] for i in range(len(self.args)))

    def auto(self):
        """Return a list of all the auto-generated values.

        Pointers are dereferenced.

        """
        return [self[n] for n in self.guessed]


def cast_to(lib, obj, typ):
    """Cast obj to a new type.

    Parameters
    ----------
    lib : CLibrary
        Reference to the library to which the object 'belongs'. This is needed
        as the way to get the address depends on the backend.

    obj :
        Object whose address should be returned.

     type : type or string
        Type object or string which will be used to determine the type of
        the array elements.

    """
    return lib._cast_to(obj, typ)


def build_array(lib, typ, size, vals=None):
    """Build an array of the specified type and the specified size.

    Parameters
    ----------

    lib : CLibrary
        Reference to the library with which this object will be used. This is
        needed as the way to build the array depends on the backend.

    type : type or string
        Type object or string which will be used to determine the type of
        the array elements.

    size : int or tuple
        Dimensions of the array to create.

    vals : list, optional
        Initial values with which to fill the array.

    """
    return lib._get_array(typ, size, vals)
