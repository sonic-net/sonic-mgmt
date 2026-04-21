# -----------------------------------------------------------------------------
# Copyright 2015-2025 by PyCLibrary Authors, see AUTHORS for more details.
#
# Distributed under the terms of the MIT/X11 license.
#
# The full license is in the file LICENCE, distributed with this software.
# -----------------------------------------------------------------------------
"""
Proxy to both CHeader and ctypes, allowing automatic type conversion and
function calling based on C header definitions.

"""

import logging
import os
import sys
from ctypes import (
    CDLL,
    CFUNCTYPE,
    POINTER,
    Structure,
    Union,
    c_bool,
    c_char,
    c_char_p,
    c_double,
    c_float,
    c_int,
    c_int8,
    c_int16,
    c_int32,
    c_int64,
    c_long,
    c_longdouble,
    c_longlong,
    c_short,
    c_size_t,
    c_ssize_t,
    c_ubyte,
    c_uint,
    c_uint8,
    c_uint16,
    c_uint32,
    c_uint64,
    c_ulong,
    c_ulonglong,
    c_ushort,
    c_void_p,
    c_wchar,
    c_wchar_p,
    cast,
    cdll,
    pointer,
)
from inspect import cleandoc

if sys.platform == "win32":
    from ctypes import HRESULT, WINFUNCTYPE, oledll, windll

if sys.version_info >= (3, 12):
    from ctypes import c_time_t

from ..c_library import CLibrary
from ..errors import DefinitionError
from ..utils import find_library

logger = logging.getLogger(__name__)


def make_mess(mess):
    return cleandoc(mess).replace("\n", " ")


class CTypesCLibrary(CLibrary):
    """The CLibrary class is intended to automate much of the work in using
    ctypes by integrating header file definitions from CParser.

    This class serves as a proxy to a ctypes object, adding a few features:
      - allows easy access to values defined via CParser
      - automatic type conversions for function calls using CParser function
        signatures
      - creates ctype classes based on type definitions from CParser

    Initialize using a ctypes shared object and a CParser:
       headers = CParser.winDefs()
       lib = CLibrary(windll.User32, headers)

    There are 3 ways to access library elements:
        lib(type, name):
            type can be one of 'values', 'functions', 'types', 'structs',
            'unions', or 'enums'. Returns an object matching name. For values,
            the value from the headers is returned. For functions, a callable
            object is returned that handles automatic type conversion for
            arguments and return values. For structs, types, and enums, a
            ctypes class is returned matching the type specified.

        lib.name:
            searches in order through values, functions, types, structs,
            unions, and enums from header definitions and returns an object for
            the first match found. The object returned is the same as returned
            by lib(type, name). This is the preferred way to access elements
            from CLibrary, but may not work in some situations (for example, if
            a struct and variable share the same name).

        lib[type]:
            Accesses the header definitions directly, returns definition
            dictionaries based on the type requested. This is equivalent to
            headers.defs[type].

    Parameters
    ----------
    lib:
        Library object.

    headers : CParser
        CParser holding all the definitions.

    prefix : unicode
        Prefix to remove from all definitions.

    fix_case : bool
        Should name be converted from camelCase to python PEP8 compliants
        names.

    """

    #: Private flag allowing to know if the class has been initiliased.
    _init = False

    #: Balise to use when a NULL pointer is needed
    Null = object()

    #: Id of the backend
    backend = "ctypes"

    #: Types (filled by init_clibrary)
    _types_: dict[str, type] = {}

    #: Types for which ctypes provides a special pointer type.
    _ptr_types_ = {
        "char": c_char_p,
        "wchar": c_wchar_p,
        "wchar_t": c_wchar_p,
        "void": c_void_p,
    }

    def __repr__(self):
        return "<CTypesCLibrary instance: %s>" % str(self._lib_)

    def _link_library(self, lib_path, convention):
        """Find and link the external librairy if only a path was provided."""
        if convention == "cdll":
            return cdll.LoadLibrary(lib_path)
        elif convention == "windll":
            return windll.LoadLibrary(lib_path)
        elif convention == "oledll":
            return oledll.LoadLibrary(lib_path)
        else:
            raise ValueError("Convention cannot be {}".format(convention))

    def _extract_val_(self, obj):
        """Extract a Python value from a ctype object.

        Does not try to be smart about pointer object as we are likely to get
        it wrong (a pointer being often an array).

        """
        if not hasattr(obj, "value"):
            return obj

        return obj.value

    def _get_type(self, typ, pointers=True):  # noqa
        """Return a ctype object representing the named type.

        If pointers is True, the class returned includes all pointer/array
        specs provided. Otherwise, the class returned is just the base type
        with no pointers.

        """
        try:
            typ = list(self._headers_.eval_type(typ))
            mods = typ[1:][:]

            # Create the initial type
            # Some types like ['char', '*'] have a specific ctype (c_char_p)
            # (but only do this if pointers == True)
            if (
                pointers
                and len(typ) > 1
                and typ[1] == "*"
                and typ[0] in self._ptr_types_
            ):
                cls = self._ptr_types_[typ[0]]
                mods = typ[2:]

            # If the base type is in the list of existing ctypes:
            elif typ[0] in self._types_:
                cls = self._types_[typ[0]]

            # structs, unions, enums:
            elif typ[0][:7] == "struct ":
                cls = self._get_struct("structs", self._defs_["types"][typ[0]][1])
            elif typ[0][:6] == "union ":
                cls = self._get_struct("unions", self._defs_["types"][typ[0]][1])
            elif typ[0][:5] == "enum ":
                cls = c_int

            # void
            elif typ[0] == "void":
                cls = None
            else:
                raise KeyError("Can't find base type for {}".format(typ))

            if not pointers:
                return cls

            n_mods = []
            # Go through the modifier looking for array modifiers.
            # Array modifiers are list and if we find consecutive modifiers we merge
            # them. This allows to iterate on them in reverse order to create the
            # proper ctypes type
            if len(mods):
                seen = mods[0]
                for m in mods[1:]:
                    if isinstance(seen, list) and isinstance(m, list):
                        seen += m
                    else:
                        n_mods.append(seen)
                        seen = m
                n_mods.append(seen)
            mods = n_mods

            # Apply pointers and arrays
            while len(mods) > 0:
                m = mods.pop(0)
                if isinstance(m, str):  # pointer or reference
                    if m[0] == "*" or m[0] == "&":
                        for i in m:
                            cls = POINTER(cls)

                elif isinstance(m, list):  # array
                    # Go in reverse order to get nd array to work properly
                    for i in reversed(m):
                        # -1 indicates an 'incomplete type' like "int
                        # variable[]"
                        if i == -1:
                            # which we should interpret like "int *variable"
                            cls = POINTER(cls)
                        else:
                            cls = cls * i

                # Probably a function pointer
                elif isinstance(m, tuple):
                    # Find pointer and calling convention
                    is_ptr = False
                    conv = "__cdecl"
                    if len(mods) == 0:
                        mess = "Function signature with no pointer:"
                        raise DefinitionError(mess, m, mods)
                    for i in [0, 1]:
                        if len(mods) < 1:
                            break
                        if mods[0] == "*":
                            mods.pop(0)
                            is_ptr = True
                        elif mods[0] in ["__stdcall", "__cdecl"]:
                            conv = mods.pop(0)
                        else:
                            break
                    if not is_ptr:
                        mess = make_mess("""Not sure how to handle type
                            (function without single pointer): {}""")
                        raise DefinitionError(mess.format(typ))

                    if conv == "__stdcall":
                        mkfn = WINFUNCTYPE

                    else:
                        mkfn = CFUNCTYPE

                    args = [self._get_type(arg[1]) for arg in m]
                    cls = mkfn(cls, *args)

                else:
                    mess = "Not sure what to do with this type modifier: '{}'"
                    raise TypeError(mess.format(m))
            return cls

        except:
            logger.error("Error while processing type: {}".format(typ))
            raise

    def _get_struct(self, str_type, str_name):
        if str_name not in self._structs_:
            str_name = self._resolve_struct_alias(str_type, str_name)

            # Pull struct definition
            defn = self._defs_[str_type][str_name]

            # create ctypes class
            defs = defn["members"][:]
            if str_type == "structs":

                class s(Structure):
                    def __repr__(self):
                        return "<ctypes struct '%s'>" % str_name
            elif str_type == "unions":

                class s(Union):
                    def __repr__(self):
                        return "<ctypes union '%s'>" % str_name

            # Must register struct here to allow recursive definitions.
            self._structs_[str_name] = s

            if defn["pack"] is not None:
                s._pack_ = defn["pack"]

            # Assign names to anonymous members
            members = []
            anon = []
            for i, d in enumerate(defs):
                if d[0] is None:
                    c = 0
                    while True:
                        name = "anon_member%d" % c
                        if name not in members:
                            d = (name, *d[1:])
                            defs[i] = d
                            anon.append(name)
                            break
                        c += 1
                members.append(d[0])

            s._anonymous_ = anon
            # Handle bit field specifications, ctypes only supports bit fields
            # for integer but I am not sure how to test for it in a nice
            # fashion.
            s._fields_ = [
                (m[0], self._get_type(m[1]))
                if m[2] is None
                else (m[0], self._get_type(m[1]), m[2])
                for m in defs
            ]
            s._defaults_ = [m[2] for m in defs]

        return self._structs_[str_name]

    def _get_pointer(self, arg_type, sig):
        """Build an uninitialised pointer for the given type."""
        # Must be 2-part type, second part must be '*' or '**'
        assert 2 <= len(arg_type) <= 3 and set(arg_type[1:]) == {"*"}
        arg_type_list = list(arg_type)
        cls = self._get_type(sig, pointers=False)
        special_pointer_types = {None: c_void_p, c_char: c_char_p, c_wchar: c_wchar_p}
        if cls in special_pointer_types:
            cls = special_pointer_types[cls]
            del arg_type_list[1]
        for pointer_decl in arg_type_list[1:-1]:
            cls = POINTER(cls)
        return pointer(cls())

    def _cast_to(self, obj, typ):
        """Cast an object to a new type (new type must be a pointer)."""
        if not isinstance(typ, type):
            typ = self._get_type((typ,))

        return cast(obj, typ)

    def _get_array(self, typ, size, vals):
        """Build an array."""
        if not isinstance(typ, type):
            typ = self._get_type((typ,))

        if not isinstance(size, tuple):
            size = (size,)

        new = typ
        for s in size[::-1]:
            new *= s

        if vals:
            return new(*vals)
        else:
            return new()

    def _init_function(self, function):
        """Overrided here to declare the arguments types and return type."""
        function.func.argtypes = function.arg_types
        function.func.restype = function.res_type


if sys.platform == "win32":
    WIN_TYPES = {
        "__int64": c_longlong,
        "unsigned __int64": c_ulonglong,
        "HRESULT": HRESULT,
    }


def init_clibrary(extra_types={}):
    # First load all standard types
    CTypesCLibrary._types_ = {
        "bool": c_bool,
        "char": c_char,
        "wchar": c_wchar,
        "wchar_t": c_wchar,
        "unsigned char": c_ubyte,
        "short": c_short,
        "short int": c_short,
        "unsigned short": c_ushort,
        "unsigned short int": c_ushort,
        "int": c_int,
        "unsigned": c_uint,
        "unsigned int": c_uint,
        "long": c_long,
        "long int": c_long,
        "unsigned long": c_ulong,
        "unsigned long int": c_ulong,
        "long unsigned int": c_ulong,
        "long long": c_longlong,
        "long long int": c_longlong,
        "unsigned long long": c_ulonglong,
        "unsigned long long int": c_ulonglong,
        "float": c_float,
        "double": c_double,
        "long double": c_longdouble,
        "uint8_t": c_uint8,
        "int8_t": c_int8,
        "uint16_t": c_uint16,
        "int16_t": c_int16,
        "uint32_t": c_uint32,
        "int32_t": c_int32,
        "uint64_t": c_uint64,
        "int64_t": c_int64,
        "size_t": c_size_t,
        "ssize_t": c_ssize_t,
    }

    if sys.platform == "win32":
        for k in extra_types:
            if k in WIN_TYPES:
                extra_types[k] = WIN_TYPES[k]

    if sys.version_info >= (3, 12):
        extra_types["time_t"] = c_time_t

    # Now complete the list with some more exotic types
    CTypesCLibrary._types_.update(extra_types)


def identify_library(lib):
    return isinstance(lib, CDLL)


def get_library_path(lib):
    if os.path.isfile(lib._name):
        return lib._name
    else:
        return find_library(lib._name).path
