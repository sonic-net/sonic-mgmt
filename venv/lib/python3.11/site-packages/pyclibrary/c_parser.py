# -----------------------------------------------------------------------------
# Copyright 2015-2022 by PyCLibrary Authors, see AUTHORS for more details.
#
# Distributed under the terms of the MIT/X11 license.
#
# The full license is in the file LICENCE, distributed with this software.
# -----------------------------------------------------------------------------
"""
Used for extracting data such as macro definitions, variables, typedefs, and
function signatures from C header files.

"""

import logging
import os
import re
import sys
from inspect import cleandoc
from traceback import format_exc

# Import parsing elements
from pyparsing import (
    Forward,
    Group,
    Keyword,
    LineEnd,
    Literal,
    OneOrMore,
    Optional,
    ParserElement,
    ParseResults,
    Regex,
    SkipTo,
    Suppress,
    Word,
    WordEnd,
    WordStart,
    ZeroOrMore,
    alphanums,
    alphas,
    cStyleComment,
    delimitedList,
    hexnums,
    lineno,
    nestedExpr,
    oneOf,
    quotedString,
    restOfLine,
)

from .errors import DefinitionError
from .utils import find_header

ParserElement.enablePackrat()

logger = logging.getLogger(__name__)


__all__ = ["CParser", "win_defs"]


class Type(tuple):
    """
    Representation of a C type. CParser uses this class to store the parsed
    typedefs and the types of variable/func.

    **ATTENTION:** Due to compatibility issues with 0.1.0 this class derives
    from tuple and can be seen as the tuples from 0.1.0. In future this might
    change to a tuple-like object!!!

    Parameters
    ----------
    type_spec : str
        a string referring the base type of this type defintion. This may
        either be a fundametal type (i.e. 'int', 'enum x') or a type definition
        made by a typedef-statement

    declarators : str or list of tuple
        all following parameters are deriving a type from the type defined
        until now. Types can be derived by:

        - The string '*': define a pointer to the base type
          (i.E. Type('int', '*'))
        - The string '&': a reference. T.B.D.
        - A list of integers of len 1: define an array with N elements
          (N is the first and single entry in the list of integers). If N is
          -1, the array definition is seen as 'int x[]'
          (i.E. Type('int', [1])
        - a N-tuple of 3-tuples: defines a function of N parameters. Every
          parameter is a 3 tuple of the form:
          (<parameter-name-or-None>, <param-type>, None).
          Due to compatibility reasons the return value of the function is
          stored in Type.type_spec parameter
          (This is **not** the case for function pointers):
          (i.E. Type(Type('int', '*'), ( ('param1', Type('int'), None), ) ) )

    type_quals : dict of int to list of str (optional)
        this optional (keyword-)argument allows to optionally add type
        qualifiers for every declarator level. The key 0 refers the type
        qualifier of type_spec, while 1 refers to declarators[0], 2 refers to
        declarators[1] and so on.

    To build more complex types any number of declarators can be combined. i.E.

    >>> int * (*a[2])(char *, signed c[]);

    if represented as:

    >>> Type('int', '*',
    >>>      ( (None, Type('char', '*'), None),
    >>>        ('c', Type('signed', [-1]), None) )),
    >>>      '*', [2])

    """

    # Cannot slot a subclass of tuple.
    def __new__(cls, type_spec, *declarators, **argv):
        return super(Type, cls).__new__(cls, (type_spec, *declarators))

    def __init__(self, type_spec, *declarators, **argv):
        super(Type, self).__init__()
        self.type_quals = argv.pop("type_quals", None) or ((),) * (1 + len(declarators))
        if len(self.type_quals) != 1 + len(declarators):
            raise ValueError("wrong number of type qualifiers")
        assert len(argv) == 0, "Invalid Parameter"

    def __eq__(self, other):
        if isinstance(other, Type):
            if self.type_quals != other.type_quals:
                return False
        return super(Type, self).__eq__(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def declarators(self):
        """Return a tuple of all declarators."""
        return tuple(self[1:])

    @property
    def type_spec(self):
        """Return the base type of this type."""
        return self[0]

    def is_fund_type(self):
        """Returns True, if this type is a fundamental type.
        Fundamental types are all types, that are not defined via typedef

        """

        if (
            self[0].startswith("struct ")
            or self[0].startswith("union ")
            or self[0].startswith("enum ")
        ):
            return True

        names = (
            num_types + nonnum_types + size_modifiers + sign_modifiers + extra_type_list
        )
        for w in self[0].split():
            if w not in names:
                return False
        return True

    def eval(self, type_map, used=None):
        """Resolves the type_spec of this type recursively if it is referring
        to a typedef. For resolving the type type_map is used for lookup.
        Returns a new Type object.

        Parameters
        ----------
        type_map : dict of str to Type
            All typedefs that shall be resolved have to be stored in this
            type_map.

        used : list of str
            For internal use only to prevent circular typedefs

        """
        used = used or []

        if self.is_fund_type():
            # Remove 'signed' before returning evaluated type
            return Type(
                re.sub(r"\bsigned\b", "", self.type_spec).strip(),
                *self.declarators,
                type_quals=self.type_quals,
            )

        parent = self.type_spec
        if parent in used:
            m = "Recursive loop while evaluating types. (typedefs are {})"
            raise DefinitionError(m.format(" -> ".join([*used, parent])))

        used.append(parent)
        if parent not in type_map:
            m = 'Unknown type "{}" (typedefs are {})'
            raise DefinitionError(m.format(parent, " -> ".join(used)))

        pt = type_map[parent]
        evaled_type = Type(
            pt.type_spec,
            *(pt.declarators + self.declarators),
            type_quals=(
                (
                    *pt.type_quals[:-1],
                    pt.type_quals[-1] + self.type_quals[0],
                    *self.type_quals[1:],
                )
            ),
        )

        return evaled_type.eval(type_map, used)

    def add_compatibility_hack(self):
        """If This Type is refering to a function (**not** a function pointer)
        a new type is returned, that matches the hack from version 0.1.0.
        This hack enforces the return value be encapsulated in a separated Type
        object:

            Type('int', '*', ())

        is converted to

            Type(Type('int', '*'), ())
        """
        if type(self[-1]) is tuple:
            return Type(
                Type(*self[:-1], type_quals=self.type_quals[:-1]),
                self[-1],
                type_quals=((), self.type_quals[-1]),
            )
        else:
            return self

    def remove_compatibility_hack(self):
        """Returns a Type object, where the hack from .add_compatibility_hack()
        is removed

        """
        if len(self) == 2 and isinstance(self[0], Type):
            return Type(*(self[0] + (self[1],)))
        else:
            return self

    def __repr__(self):
        type_qual_str = (
            "" if not any(self.type_quals) else ", type_quals=" + repr(self.type_quals)
        )
        return (
            type(self).__name__ + "(" + ", ".join(map(repr, self)) + type_qual_str + ")"
        )

    def __getnewargs__(self):
        return (self.type_spec, *self.declarators)


class Compound(dict):
    """Base class for representing object using a dict-like interface."""

    __slots__ = ()

    def __init__(self, *members, **argv):
        members = list(members)
        pack = argv.pop("pack", None)
        assert len(argv) == 0

        super(Compound, self).__init__({"members": members, "pack": pack})

    def __repr__(self):
        packParam = ", pack=" + repr(self.pack) if self.pack is not None else ""
        return (
            type(self).__name__
            + "("
            + ", ".join(map(repr, self.members))
            + packParam
            + ")"
        )

    @property
    def members(self):
        return self["members"]

    @property
    def pack(self):
        return self["pack"]


class Struct(Compound):
    """Representation of a C struct. CParser uses this class to store the parsed
    structs.

    **ATTENTION:** Due to compatibility issues with 0.1.0 this class derives
    from dict and can be seen as the dicts from 0.1.0. In future this might
    change to a dict-like object!!!
    """

    __slots__ = ()


class Union(Compound):
    """Representation of a C union. CParser uses this class to store the parsed
    unions.

    **ATTENTION:** Due to compatibility issues with 0.1.0 this class derives
    from dict and can be seen as the dicts from 0.1.0. In future this might
    change to a dict-like object!!!
    """

    __slots__ = ()


class Enum(dict):
    """Representation of a C enum. CParser uses this class to store the parsed
    enums.

    **ATTENTION:** Due to compatibility issues with 0.1.0 this class derives
    from dict and can be seen as the dicts from 0.1.0. In future this might
    change to a dict-like object!!!
    """

    __slots__ = ()

    def __init__(self, **args):
        super(Enum, self).__init__(args)

    def __repr__(self):
        return (
            type(self).__name__
            + "("
            + ", ".join(nm + "=" + repr(val) for nm, val in sorted(self.items()))
            + ")"
        )


def win_defs(version="1500"):
    """Loads selection of windows headers included with PyCLibrary.

    These definitions can either be accessed directly or included before
    parsing another file like this:
    >>> windefs = c_parser.win_defs()
    >>> p = c_parser.CParser("headerFile.h", copy_from=windefs)

    Definitions are pulled from a selection of header files included in Visual
    Studio (possibly not legal to distribute? Who knows.), some of which have
    been abridged because they take so long to parse.

    Parameters
    ----------
    version : unicode
        Version of the MSVC to consider when parsing.

    Returns
    -------
    parser : CParser
        CParser containing all the infos from te windows headers.

    """
    header_files = [
        "WinNt.h",
        "WinDef.h",
        "WinBase.h",
        "BaseTsd.h",
        "WTypes.h",
        "WinUser.h",
    ]
    if not CParser._init:
        logger.info("Automatic initialisation : OS is assumed to be win32")
        from .init import auto_init

        auto_init()
    d = os.path.dirname(__file__)
    p = CParser(
        header_files,
        macros={
            "_WIN32": "",
            "_MSC_VER": version,
            "CONST": "const",
            "NO_STRICT": None,
            "MS_WIN32": "",
        },
        process_all=False,
    )

    p.process_all(cache=os.path.join(d, "headers", "WinDefs.cache"))

    return p


class CParser(object):
    """Class for parsing C code to extract variable, struct, enum, and function
    declarations as well as preprocessor macros.

    This is not a complete C parser; instead, it is meant to simplify the
    process of extracting definitions from header files in the absence of a
    complete build system. Many files will require some amount of manual
    intervention to parse properly (see 'replace' and extra arguments)

    Parameters
    ----------
    files : str or iterable, optional
        File or files which should be parsed.

    copy_from : CParser or iterable of CParser, optional
        CParser whose definitions should be included.

    replace : dict, optional
        Specify som string replacements to perform before parsing. Format is
        {'searchStr': 'replaceStr', ...}

    process_all : bool, optional
        Flag indicating whether files should be parsed immediatly. True by
        default.

    cache : unicode, optional
        Path of the cache file from which to load definitions/to which save
        definitions as parsing is an expensive operation.

    check_cache_validity : bool, optional
        Flag indicating whether to perform validity checking when using a cache file. This is useful
        in a scenario where the python wrapper needs to be used without access to the headers

    encoding : str, optional
        The encoding to use for reading the file. Default is 'utf-8'.

    kwargs :
        Extra parameters may be used to specify the starting state of the
        parser. For example, one could provide a set of missing type
        declarations by types={'UINT': ('unsigned int'), 'STRING': ('char', 1)}
        Similarly, preprocessor macros can be specified: macros={'WINAPI': ''}

    Example
    -------
    Create parser object, load two files

    >>> p = CParser(['header1.h', 'header2.h'])

    Remove comments, preprocess, and search for declarations

    >>> p.process_ all()

    Just to see what was successfully parsed from the files

    >>> p.print_all()

    Access parsed declarations

    >>> all_values = p.defs['values']
    >>> functionSignatures = p.defs['functions']

    To see what was not successfully parsed

    >>> unp = p.process_all(return_unparsed=True)
    >>> for s in unp:
            print s

    """

    #: Increment every time cache structure or parsing changes to invalidate
    #: old cache files.
    # 2 : add C99 integers
    cache_version = 2

    #: Private flag allowing to know if the parser has been initiliased.
    _init = False

    def __init__(
        self,
        files=None,
        copy_from=None,
        replace=None,
        process_all=True,
        cache=None,
        check_cache_validity=True,
        encoding="utf-8",
        **kwargs,
    ):
        if not self._init:
            logger.info("Automatic initialisation based on OS detection")
            from .init import auto_init

            auto_init()

        # Holds all definitions
        self.defs = {}
        # Holds definitions grouped by the file they came from
        self.file_defs = {}
        # Description of the struct packing rules as defined by #pragma pack
        self.pack_list = {}

        self.init_opts = kwargs.copy()
        self.init_opts["files"] = []
        self.init_opts["replace"] = {}

        self.data_list = [
            "types",
            "variables",
            "fnmacros",
            "macros",
            "structs",
            "unions",
            "enums",
            "functions",
            "values",
        ]

        self.file_order = []
        self.files = {}

        self.default_encoding = encoding

        if files is not None:
            if isinstance(files, str):
                files = [files]
            for f in self.find_headers(files):
                self.load_file(f, replace, encoding)

        # Initialize empty definition lists
        for k in self.data_list:
            self.defs[k] = {}

        # Holds translations from typedefs/structs/unions to fundamental types
        self.compiled_types = {}

        self.current_file = None

        # Import extra arguments if specified
        for t in kwargs:
            for k in kwargs[t].keys():
                self.add_def(t, k, kwargs[t][k])

        # Import from other CParsers if specified
        if copy_from is not None:
            if not isinstance(copy_from, (list, tuple)):
                copy_from = [copy_from]
            for p in copy_from:
                self.import_dict(p.file_defs)

        if process_all:
            self.process_all(cache=cache, check_cache_validity=check_cache_validity)

    def process_all(
        self,
        cache=None,
        return_unparsed=False,
        print_after_preprocess=False,
        check_cache_validity=True,
    ):
        """Remove comments, preprocess, and parse declarations from all files.

        This operates in memory, and thus does not alter the original files.

        Parameters
        ----------
        cache : unicode, optional
            File path where cached results are be stored or retrieved. The
            cache is automatically invalidated if any of the arguments to
            __init__ are changed, or if the C files are newer than the cache.
        return_unparsed : bool, optional
           Passed directly to parse_defs.

        print_after_preprocess : bool, optional
            If true prints the result of preprocessing each file.

        Returns
        -------
        results : list
            List of the results from parse_defs.

        """
        if cache is not None and self.load_cache(
            cache, check_validity=check_cache_validity
        ):
            logger.debug("Loaded cached definitions; will skip parsing.")
            # Cached values loaded successfully, nothing left to do here
            return

        results = []
        logger.debug(
            cleandoc("""Parsing C header files (no valid cache found).
                              This could take several minutes...""")
        )
        for f in self.file_order:
            if self.files[f] is None:
                # This means the file could not be loaded and there was no
                # cache.
                mess = 'Could not find header file "{}" or a cache file.'
                raise IOError(mess.format(f))

            logger.debug("Removing comments from file '{}'...".format(f))
            self.remove_comments(f)

            logger.debug("Preprocessing file '{}'...".format(f))
            self.preprocess(f)

            if print_after_preprocess:
                print("===== PREPROCSSED {} =======".format(f))
                print(self.files[f])

            logger.debug("Parsing definitions in file '{}'...".format(f))

            results.append(self.parse_defs(f, return_unparsed))

        if cache is not None:
            logger.debug("Writing cache file '{}'".format(cache))
            self.write_cache(cache)

        return results

    def load_cache(self, cache_file, check_validity=False):
        """Load a cache file.

        Used internally if cache is specified in process_all().

        Parameters
        ----------
        cache_file : unicode
            Path of the file from which the cache should be loaded.

        check_validity : bool, optional
            If True, then run several checks before loading the cache:
              - cache file must not be older than any source files
              - cache file must not be older than this library file
              - options recorded in cache must match options used to initialize
                CParser

        Returns
        -------
        result : bool
            Did the loading succeeded.

        """

        # Make sure cache file exists
        if not isinstance(cache_file, str):
            raise ValueError("Cache file option must be a str.")
        if not os.path.isfile(cache_file):
            # If file doesn't exist, search for it in this module's path
            d = os.path.dirname(__file__)
            cache_file = os.path.join(d, "headers", cache_file)
            if not os.path.isfile(cache_file):
                logger.debug("Can't find requested cache file.")
                return False

        # Make sure cache is newer than all input files
        if check_validity:
            mtime = os.stat(cache_file).st_mtime
            for f in self.file_order:
                # If file does not exist, then it does not count against the
                # validity of the cache.
                if os.path.isfile(f) and os.stat(f).st_mtime > mtime:
                    logger.debug("Cache file is out of date.")
                    return False

        try:
            # Read cache file
            import pickle

            cache = pickle.load(open(cache_file, "rb"))

            # Make sure __init__ options match
            if check_validity:
                if cache["opts"] != self.init_opts:
                    db = logger.debug
                    db("Cache file is not valid")
                    db("It was created using different initialization options")
                    db("{}".format(cache["opts"]))
                    db("{}".format(self.init_opts))
                    return False

                else:
                    logger.debug("Cache init opts are OK:")
                    logger.debug("{}".format(cache["opts"]))

                if cache["version"] < self.cache_version:
                    mess = "Cache file is not valid--cache format has changed."
                    logger.debug(mess)
                    return False

            # Import all parse results
            self.import_dict(cache["file_defs"])
            return True

        except Exception:
            logger.exception("Warning--cache read failed:")
            return False

    def import_dict(self, data):
        """Import definitions from a dictionary.

        The dict format should be the same as CParser.file_defs.
        Used internally; does not need to be called manually.

        """
        for f in data.keys():
            self.current_file = f
            for k in self.data_list:
                for n in data[f][k]:
                    self.add_def(k, n, data[f][k][n])

    def write_cache(self, cache_file):
        """Store all parsed declarations to cache. Used internally."""
        cache = {}
        cache["opts"] = self.init_opts
        cache["file_defs"] = self.file_defs
        cache["version"] = self.cache_version
        import pickle

        with open(cache_file, "wb") as f:
            pickle.dump(cache, f)

    def find_headers(self, headers):
        """Try to find the specified headers."""
        hs = []
        for header in headers:
            if os.path.isfile(header):
                hs.append(header)
            else:
                h = find_header(header)
                if not h:
                    raise OSError("Cannot find header: {}".format(header))
                hs.append(h)

        return hs

    def load_file(self, path, replace=None, encoding=None):
        """Read a file, make replacements if requested.

        Called by __init__, should not be called manually.

        Parameters
        ----------
        path : unicode
            Path of the file to load.

        replace : dict, optional
            Dictionary containing strings to replace by the associated value
            when loading the file.

        encoding : str, optional
            String with encoding options for the file to be opened. The default
            is the value specified during the construction of the instance.
        """
        if encoding is None:
            encoding = self.default_encoding

        if not os.path.isfile(path):
            # Not a fatal error since we might be able to function properly if
            # there is a cache file.
            mess = "Warning: C header '{}' is missing, this may cause trouble."
            logger.warning(mess.format(path))
            self.files[path] = None
            return False

        with open(path, "r", encoding=encoding) as fd:
            self.files[path] = fd.read()

        if replace is not None:
            for s in replace:
                self.files[path] = re.sub(s, replace[s], self.files[path])

        self.file_order.append(path)
        bn = os.path.basename(path)
        self.init_opts["replace"][bn] = replace
        # Only interested in the file names, the directory may change between
        # systems.
        self.init_opts["files"].append(bn)
        return True

    def _format_parsed_file(self, filename=None):
        from pprint import pformat

        s = ""
        for k in self.data_list:
            s += "============== {} ==================\n".format(k)
            if filename is None:
                s += pformat(self.defs[k], indent=4) + "\n"
            else:
                s += pformat(self.file_defs[filename][k]) + "\n"
        return s

    def print_all(self, filename=None):
        """Print everything parsed from files. Useful for debugging.

        Parameters
        ----------
        filename : unicode, optional
            Name of the file whose definition should be printed.

        """
        print(self._format_parsed_file(filename))

    def __str__(self):
        return self._format_parsed_file()

    # =========================================================================
    # --- Processing functions
    # =========================================================================

    def remove_comments(self, path):
        """Remove all comments from file.

        Operates in memory, does not alter the original files.

        """
        text = self.files[path]
        cplusplus_line_comment = Literal("//") + restOfLine
        # match quoted strings first to prevent matching comments inside quotes
        comment_remover = (
            quotedString | cStyleComment.suppress() | cplusplus_line_comment.suppress()
        )
        self.files[path] = comment_remover.transformString(text)

    # --- Pre processing

    def preprocess(self, path):  # noqa
        """Scan named file for preprocessor directives, removing them while
        expanding macros.

        Operates in memory, does not alter the original files.

        Currently support :
        - conditionals : ifdef, ifndef, if, elif, else (defined can be used
        in a if statement).
        - definition : define, undef
        - pragmas : pragma

        """
        # We need this so that eval_expr works properly
        self.build_parser()
        self.current_file = path

        # Stack for #pragma pack push/pop
        pack_stack = [(None, None)]
        self.pack_list[path] = [(0, None)]
        packing = None  # Current packing value

        text = self.files[path]

        # First join together lines split by \\n
        text = Literal("\\\n").suppress().transformString(text)

        # Define the structure of a macro definition
        name = Word(alphas + "_", alphanums + "_")("name")
        deli_list = Optional(lparen + delimitedList(name) + rparen)
        self.pp_define = (
            name.setWhitespaceChars(" \t")("macro")
            + deli_list.setWhitespaceChars(" \t")("args")
            + SkipTo(LineEnd())("value")
        )
        self.pp_define.setParseAction(self.process_macro_defn)

        # Comb through lines, process all directives
        lines = text.split("\n")

        result = []

        directive = re.compile(r"\s*#\s*([a-zA-Z]+)(.*)$")
        if_true = [True]
        if_hit = []
        for i, line in enumerate(lines):
            new_line = ""
            m = directive.match(line)

            # Regular code line
            if m is None:
                # Only include if we are inside the correct section of an IF
                # block
                if if_true[-1]:
                    new_line = self.expand_macros(line)

            # Macro line
            else:
                d = m.groups()[0]
                rest = m.groups()[1]

                if d == "ifdef":
                    d = "if"
                    rest = "defined " + rest
                elif d == "ifndef":
                    d = "if"
                    rest = "!defined " + rest

                # Evaluate 'defined' operator before expanding macros
                if d in ["if", "elif"]:

                    def pa(t):
                        is_macro = t["name"] in self.defs["macros"]
                        is_macro_func = t["name"] in self.defs["fnmacros"]
                        return ["0", "1"][is_macro or is_macro_func]

                    rest = (
                        (Keyword("defined") + (name | lparen + name + rparen))
                        .setParseAction(pa)
                        .transformString(rest)
                    )

                elif d in ["define", "undef"]:
                    match = re.match(r"\s*([a-zA-Z_][a-zA-Z0-9_]*)(.*)$", rest)
                    macroName, rest = match.groups()

                # Expand macros if needed
                if rest is not None and (all(if_true) or d in ["if", "elif"]):
                    rest = self.expand_macros(rest)

                if d == "elif":
                    if if_hit[-1] or not all(if_true[:-1]):
                        ev = False
                    else:
                        ev = self.eval_preprocessor_expr(rest)

                    logger.debug(
                        "  " * (len(if_true) - 2) + line + "{}, {}".format(rest, ev)
                    )

                    if_true[-1] = ev
                    if_hit[-1] = if_hit[-1] or ev

                elif d == "else":
                    logger.debug(
                        "  " * (len(if_true) - 2) + line + "{}".format(not if_hit[-1])
                    )
                    if_true[-1] = (not if_hit[-1]) and all(if_true[:-1])
                    if_hit[-1] = True

                elif d == "endif":
                    if_true.pop()
                    if_hit.pop()
                    logger.debug("  " * (len(if_true) - 1) + line)

                elif d == "if":
                    if all(if_true):
                        ev = self.eval_preprocessor_expr(rest)
                    else:
                        ev = False
                    logger.debug(
                        "  " * (len(if_true) - 1) + line + "{}, {}".format(rest, ev)
                    )
                    if_true.append(ev)
                    if_hit.append(ev)

                elif d == "define":
                    if not if_true[-1]:
                        continue
                    logger.debug(
                        "  " * (len(if_true) - 1)
                        + "define: "
                        + "{}, {}".format(macroName, rest)
                    )
                    try:
                        # Macro is registered here
                        self.pp_define.parseString(macroName + " " + rest)
                    except Exception:
                        logger.exception(
                            "Error processing macro definition:"
                            + "{}, {}".format(macroName, rest)
                        )

                elif d == "undef":
                    if not if_true[-1]:
                        continue
                    try:
                        self.rem_def("macros", macroName.strip())
                    except Exception:
                        if sys.exc_info()[0] is not KeyError:
                            mess = "Error removing macro definition '{}'"
                            logger.exception(mess.format(macroName.strip()))

                # Check for changes in structure packing
                # Support only for #pragme pack (with all its variants
                # save show), None is used to signal that the default packing
                # is used.
                # Those two definition disagree :
                # https://gcc.gnu.org/onlinedocs/gcc/Structure-Packing-Pragmas.html
                # http://msdn.microsoft.com/fr-fr/library/2e70t5y1.aspx
                # The current implementation follows the MSVC doc.
                elif d == "pragma":
                    if not if_true[-1]:
                        continue
                    m = re.match(r"\s+pack\s*\(([^\)]*)\)", rest)
                    if not m:
                        continue
                    if m.groups():
                        opts = [s.strip() for s in m.groups()[0].split(",")]

                    pushpop = id = val = None
                    for o in opts:
                        if o in ["push", "pop"]:
                            pushpop = o
                        elif o.isdigit():
                            val = int(o)
                        else:
                            id = o

                    packing = val

                    if pushpop == "push":
                        pack_stack.append((packing, id))
                    elif opts[0] == "pop":
                        if id is None:
                            pack_stack.pop()
                        else:
                            ind = None
                            for j, s in enumerate(pack_stack):
                                if s[1] == id:
                                    ind = j
                                    break
                            if ind is not None:
                                pack_stack = pack_stack[:ind]
                        if val is None:
                            packing = pack_stack[-1][0]

                    mess = ">> Packing changed to {} at line {}"
                    logger.debug(mess.format(str(packing), i))
                    self.pack_list[path].append((i, packing))
                else:
                    # Ignore any other directives
                    mess = "Ignored directive {} at line {}"
                    logger.debug(mess.format(d, i))

            result.append(new_line)
        self.files[path] = "\n".join(result)

    def eval_preprocessor_expr(self, expr):
        # Make a few alterations so the expression can be eval'd
        macro_diffs = (
            Literal("!").setParseAction(lambda: " not ")
            | Literal("&&").setParseAction(lambda: " and ")
            | Literal("||").setParseAction(lambda: " or ")
            | Word(alphas + "_", alphanums + "_").setParseAction(lambda: "0")
        )
        expr2 = macro_diffs.transformString(expr).strip()

        try:
            ev = bool(eval(expr2))
        except Exception:
            mess = "Error evaluating preprocessor expression: {} [{}]\n{}"
            logger.debug(mess.format(expr, repr(expr2), format_exc()))
            ev = False
        return ev

    def process_macro_defn(self, t):
        """Parse a #define macro and register the definition."""
        logger.debug("Processing MACRO: {}".format(t))
        macro_val = t.value.strip()
        if macro_val in self.defs["fnmacros"]:
            self.add_def("fnmacros", t.macro, self.defs["fnmacros"][macro_val])
            logger.debug("  Copy fn macro {} => {}".format(macro_val, t.macro))

        else:
            if t.args == "":
                val = self.eval_expr(macro_val)
                self.add_def("macros", t.macro, macro_val)
                self.add_def("values", t.macro, val)
                mess = "  Add macro: {} ({}); {}"
                logger.debug(mess.format(t.macro, val, self.defs["macros"][t.macro]))

            else:
                self.add_def(
                    "fnmacros",
                    t.macro,
                    self.compile_fn_macro(macro_val, list(t.args)),
                )
                mess = "  Add fn macro: {} ({}); {}"
                logger.debug(
                    mess.format(t.macro, t.args, self.defs["fnmacros"][t.macro])
                )

        return "#define " + t.macro + " " + macro_val

    def compile_fn_macro(self, text, args):
        """Turn a function macro spec into a compiled description."""
        # Find all instances of each arg in text.
        args_str = "|".join(args)
        arg_regex = re.compile(r'("(\\"|[^"])*")|(\b({})\b)'.format(args_str))
        start = 0
        parts = []
        arg_order = []
        # The group number to check for macro names
        N = 3
        for m in arg_regex.finditer(text):
            arg = m.groups()[N]
            if arg is not None:
                parts.append(text[start : m.start(N)] + "{}")
                start = m.end(N)
                arg_order.append(args.index(arg))
        parts.append(text[start:])
        return ("".join(parts), arg_order)

    def expand_macros(self, line):
        """Expand all the macro expressions in a string.

        Faulty calls to macro function are left untouched.

        """
        reg = re.compile(r'("(\\"|[^"])*")|(\b(\w+)\b)')
        parts = []
        # The group number to check for macro names
        N = 3
        macros = self.defs["macros"]
        fnmacros = self.defs["fnmacros"]
        while True:
            m = reg.search(line)
            if not m:
                break
            name = m.groups()[N]
            if name in macros:
                parts.append(line[: m.start(N)])
                line = line[m.end(N) :]
                parts.append(macros[name])

            elif name in fnmacros:
                # If function macro expansion fails, just ignore it.
                try:
                    exp, end = self.expand_fn_macro(name, line[m.end(N) :])
                except Exception:
                    exp = name
                    end = line[m.end(N) :]
                    mess = "Function macro expansion failed: {}, {}\n {}"
                    logger.error(mess.format(name, line[m.end(N) :], format_exc()))

                parts.append(line[: m.start(N)])
                line = end
                parts.append(exp)

            else:
                start = m.end(N)
                parts.append(line[:start])
                line = line[start:]

        parts.append(line)
        return "".join(parts)

    def expand_fn_macro(self, name, text):
        """Replace a function macro."""
        # defn looks like ('%s + %s / %s', (0, 0, 1))
        defn = self.defs["fnmacros"][name]

        try:
            args, end = text.split(")", 1)
            _, args = args.split("(", 1)
            args = [a.strip() for a in args.split(",")]
        except Exception:
            mess = "Function macro {} argument analysis failed :\n{}"
            raise DefinitionError(0, mess.format(name, format_exc()))

        args = [self.expand_macros(arg) for arg in args]
        new_str = defn[0].format(*[args[i] for i in defn[1]])

        return (new_str, end)

    # --- Compilation functions

    def parse_defs(self, path, return_unparsed=False):
        """Scan through the named file for variable, struct, enum, and function
        declarations.

        Parameters
        ----------
        path : unicode
            Path of the file to parse for definitions.

        return_unparsed : bool, optional
            If true, return a string of all lines that failed to match (for
            debugging purposes).

        Returns
        -------
        tokens : list
            Entire tree of successfully parsed tokens.

        """
        self.current_file = path

        parser = self.build_parser()
        if return_unparsed:
            text = parser.suppress().transformString(self.files[path])
            return re.sub(r"\n\s*\n", "\n", text)
        else:
            return [x[0] for x in parser.scanString(self.files[path])]

    def build_parser(self):
        """Builds the entire tree of parser elements for the C language (the
        bits we support, anyway).

        """
        if hasattr(self, "parser"):
            return self.parser

        self.struct_type = Forward()
        self.enum_type = Forward()
        type_ = (
            fund_type
            | Optional(kwl(size_modifiers + sign_modifiers)) + ident
            | self.struct_type
            | self.enum_type
        )
        if extra_modifier is not None:
            type_ += extra_modifier
        type_.setParseAction(recombine)
        self.type_spec = Group(type_qualifier("pre_qual") + type_("name"))

        # --- Abstract declarators for use in function pointer arguments
        #   Thus begins the extremely hairy business of parsing C declarators.
        #   Whomever decided this was a reasonable syntax should probably never
        #   breed.
        #   The following parsers combined with the process_declarator function
        #   allow us to turn a nest of type modifiers into a correctly
        #   ordered list of modifiers.

        self.declarator = Forward()
        self.abstract_declarator = Forward()

        #  Abstract declarators look like:
        #     <empty string>
        #     *
        #     **[num]
        #     (*)(int, int)
        #     *( )(int, int)[10]
        #     ...etc...
        self.abstract_declarator << Group(
            type_qualifier("first_typequal")
            + Group(ZeroOrMore(Group(Suppress("*") + type_qualifier)))("ptrs")
            + (
                (Optional("&")("ref"))
                | (lparen + self.abstract_declarator + rparen)("center")
            )
            + Optional(
                lparen
                + Optional(
                    delimitedList(
                        Group(
                            self.type_spec("type")
                            + self.abstract_declarator("decl")
                            + Optional(
                                Literal("=").suppress() + expression, default=None
                            )("val")
                        )
                    ),
                    default=None,
                )
                + rparen
            )("args")
            + Group(ZeroOrMore(lbrack + Optional(expression, default="-1") + rbrack))(
                "arrays"
            )
        )

        # Declarators look like:
        #     varName
        #     *varName
        #     **varName[num]
        #     (*fnName)(int, int)
        #     * fnName(int arg1=0)[10]
        #     ...etc...
        self.declarator << Group(
            type_qualifier("first_typequal")
            + call_conv
            + Group(ZeroOrMore(Group(Suppress("*") + type_qualifier)))("ptrs")
            + (
                (Optional("&")("ref") + ident("name"))
                | (lparen + self.declarator + rparen)("center")
            )
            + Optional(
                lparen
                + Optional(
                    delimitedList(
                        Group(
                            self.type_spec("type")
                            + (self.declarator | self.abstract_declarator)("decl")
                            + Optional(
                                Literal("=").suppress() + expression, default=None
                            )("val")
                        )
                    ),
                    default=None,
                )
                + rparen
            )("args")
            + Group(ZeroOrMore(lbrack + Optional(expression, default="-1") + rbrack))(
                "arrays"
            )
        )
        self.declarator_list = Group(delimitedList(self.declarator))

        # Typedef
        self.type_decl = (
            Keyword("typedef")
            + self.type_spec("type")
            + self.declarator_list("decl_list")
            + semi
        )
        self.type_decl.setParseAction(self.process_typedef)

        # Variable declaration
        self.variable_decl = (
            Group(
                storage_class_spec
                + self.type_spec("type")
                + Optional(self.declarator_list("decl_list"))
                + Optional(
                    Literal("=").suppress()
                    + (
                        expression("value")
                        | (
                            lbrace
                            + Group(delimitedList(expression))("array_values")
                            + rbrace
                        )
                    )
                )
            )
            + semi
        )
        self.variable_decl.setParseAction(self.process_variable)

        # Function definition
        self.typeless_function_decl = (
            self.declarator("decl") + nestedExpr("{", "}").suppress()
        )
        self.function_decl = (
            storage_class_spec
            + self.type_spec("type")
            + self.declarator("decl")
            + nestedExpr("{", "}").suppress()
        )
        self.function_decl.setParseAction(self.process_function)

        # Struct definition
        self.struct_decl = Forward()
        struct_kw = Keyword("struct") | Keyword("union")
        self.struct_member = (
            Group(self.variable_decl.copy().setParseAction(lambda: None))
            |
            # Hack to handle bit width specification.
            Group(
                Group(
                    self.type_spec("type")
                    + Optional(self.declarator_list("decl_list"))
                    + colon
                    + integer("bit")
                    + semi
                )
            )
            | (self.type_spec + self.declarator + nestedExpr("{", "}")).suppress()
            | (self.declarator + nestedExpr("{", "}")).suppress()
        )

        self.decl_list = (
            lbrace + Group(OneOrMore(self.struct_member))("members") + rbrace
        )
        self.struct_type << (
            struct_kw("struct_type")
            + ((Optional(ident)("name") + self.decl_list) | ident("name"))
        )
        self.struct_type.setParseAction(self.process_struct)

        self.struct_decl = self.struct_type + semi

        # Enum definition
        enum_var_decl = Group(
            ident("name") + Optional(Literal("=").suppress() + expression("value"))
        )

        self.enum_type << (
            Keyword("enum")
            + (
                Optional(ident)("name")
                + lbrace
                + Group(delimitedList(enum_var_decl))("members")
                + Optional(comma)
                + rbrace
                | ident("name")
            )
        )
        self.enum_type.setParseAction(self.process_enum)
        self.enum_decl = self.enum_type + semi

        self.parser = self.type_decl | self.variable_decl | self.function_decl
        return self.parser

    def process_declarator(self, decl):
        """Process a declarator (without base type) and return a tuple
        (name, [modifiers])

        See process_type(...) for more information.

        """
        toks = []
        quals = [tuple(decl.get("first_typequal", []))]
        name = None
        logger.debug("DECL: {}".format(decl))

        if "call_conv" in decl and len(decl["call_conv"]) > 0:
            toks.append(decl["call_conv"])
            quals.append(None)

        if "ptrs" in decl and len(decl["ptrs"]) > 0:
            toks += ("*",) * len(decl["ptrs"])
            quals += map(tuple, decl["ptrs"])

        if "arrays" in decl and len(decl["arrays"]) > 0:
            toks.extend([self.eval_expr(x)] for x in decl["arrays"])
            quals += [()] * len(decl["arrays"])

        if "args" in decl and len(decl["args"]) > 0:
            if decl["args"][0] is None:
                toks.append(())
            else:
                ex = lambda x: (x[0],) if len(x) != 0 else (None,)  # noqa
                toks.append(
                    tuple(
                        [
                            self.process_type(a["type"], a["decl"][0]) + ex(a["val"])
                            for a in decl["args"]
                        ]
                    )
                )
            quals.append(())
        if "ref" in decl:
            toks.append("&")
            quals.append(())

        if "center" in decl:
            (n, t, q) = self.process_declarator(decl["center"][0])
            if n is not None:
                name = n
            toks.extend(t)
            quals = [*quals[:-1], quals[-1] + q[0], *list(q[1:])]

        if "name" in decl:
            name = decl["name"]

        return (name, toks, tuple(quals))

    def process_type(self, typ, decl):
        """Take a declarator + base type and return a serialized name/type
        description.

        The description will be a list of elements (name, [basetype, modifier,
        modifier, ...]):

        - name is the string name of the declarator or None for an abstract
          declarator
        - basetype is the string representing the base type
        - modifiers can be:

            - `*`    : pointer (multiple pointers `***` allowed)
            - `&`    : reference
            - `__X`  : calling convention (windows only). X can be `cdecl` or
              `stdcall`
            - list   : array. Value(s) indicate the length of each array, -1
              for incomplete type.
            - tuple  : function, items are the output of processType for each
              function argument.

        Examples:
          - int *x[10]               =>  ('x', ['int', [10], '*'])
          - char fn(int x)           =>  ('fn', ['char', [('x', ['int'])]])
          - struct s (*)(int, int*)  =>
            (None, ["struct s", ((None, ['int']), (None, ['int', '*'])), '*'])

        """
        logger.debug("PROCESS TYPE/DECL: {}/{}".format(typ["name"], decl))
        (name, decl, quals) = self.process_declarator(decl)
        pre_typequal = tuple(typ.get("pre_qual", []))
        return (
            name,
            Type(typ["name"], *decl, type_quals=(pre_typequal + quals[0], *quals[1:])),
        )

    def process_enum(self, s, line, t):
        """ """
        try:
            logger.debug("ENUM: {}".format(t))
            if t.name == "":
                n = 0
                while True:
                    name = "anon_enum{}".format(n)
                    if name not in self.defs["enums"]:
                        break
                    n += 1
            else:
                if isinstance(t.name, str):
                    name = t.name
                else:
                    name = t.name[0]

            logger.debug("  name: {}".format(name))

            if name not in self.defs["enums"]:
                i = 0
                enum = {}
                for v in t.members:
                    if v.value != "":
                        try:
                            i = self.eval_expr(v.value)
                        except Exception:
                            pass
                    enum[v.name] = i
                    self.add_def("values", v.name, i)
                    i += 1
                logger.debug("  members: {}".format(enum))
                self.add_def("enums", name, enum)
                self.add_def("types", "enum " + name, Type("enum", name))
            return "enum " + name
        except Exception:
            logger.exception("Error processing enum: {}".format(t))

    def process_function(self, s, line, t):
        """Build a function definition from the parsing tokens."""
        logger.debug("FUNCTION {} : {}".format(t, t.keys()))

        try:
            name, decl = self.process_type(t.type, t.decl[0])
            if len(decl) == 0 or type(decl[-1]) is not tuple:
                logger.error("{}".format(t))
                mess = "Incorrect declarator type for function definition."
                raise DefinitionError(mess)
            logger.debug("  name: {}".format(name))
            logger.debug("  sig: {}".format(decl))
            self.add_def("functions", name, decl.add_compatibility_hack())

        except Exception:
            logger.exception("Error processing function: {}".format(t))

    def packing_at(self, line):
        """Return the structure packing value at the given line number."""
        packing = None
        for p in self.pack_list[self.current_file]:
            if p[0] <= line:
                packing = p[1]
            else:
                break
        return packing

    def process_struct(self, s, line, t):
        """ """
        try:
            str_typ = t.struct_type  # struct or union

            # Check for extra packing rules
            packing = self.packing_at(lineno(line, s))

            logger.debug("{} {} {}".format(str_typ.upper(), t.name, t))
            if t.name == "":
                n = 0
                while True:
                    sname = "anon_{}{}".format(str_typ, n)
                    if sname not in self.defs[str_typ + "s"]:
                        break
                    n += 1
            else:
                if isinstance(t.name, str):
                    sname = t.name
                else:
                    sname = t.name[0]

            logger.debug("  NAME: {}".format(sname))
            if (
                len(t.members) > 0
                or sname not in self.defs[str_typ + "s"]
                or self.defs[str_typ + "s"][sname] == {}
            ):
                logger.debug("  NEW " + str_typ.upper())
                struct = []
                for m in t.members:
                    typ = m[0].type
                    val = self.eval_expr(m[0].value)
                    logger.debug(
                        "    member: {}, {}, {}".format(m, m[0].keys(), m[0].decl_list)
                    )

                    if len(m[0].decl_list) == 0:  # anonymous member
                        member = [None, Type(typ[0]), None]
                        if m[0].bit:
                            member.append(int(m[0].bit))
                        struct.append(tuple(member))

                    for d in m[0].decl_list:
                        (name, decl) = self.process_type(typ, d)
                        member = [name, decl, val]
                        if m[0].bit:
                            member.append(int(m[0].bit))
                        struct.append(tuple(member))
                        logger.debug(
                            "      {} {} {} {}".format(name, decl, val, m[0].bit)
                        )

                str_cls = Struct if str_typ == "struct" else Union
                self.add_def(str_typ + "s", sname, str_cls(*struct, pack=packing))
                self.add_def("types", str_typ + " " + sname, Type(str_typ, sname))
            return str_typ + " " + sname

        except Exception:
            logger.exception("Error processing struct: {}".format(t))

    def process_variable(self, s, line, t):
        """ """
        logger.debug("VARIABLE: {}".format(t))
        try:
            val = self.eval_expr(t[0])
            for d in t[0].decl_list:
                (name, typ) = self.process_type(t[0].type, d)
                # This is a function prototype
                if type(typ[-1]) is tuple:
                    logger.debug(
                        "  Add function prototype: {} {} {}".format(name, typ, val)
                    )
                    self.add_def("functions", name, typ.add_compatibility_hack())
                # This is a variable
                else:
                    logger.debug("  Add variable: {} {} {}".format(name, typ, val))
                    self.add_def("variables", name, (val, typ))
                    self.add_def("values", name, val)

        except Exception:
            logger.exception("Error processing variable: {}".format(t))

    def process_typedef(self, s, line, t):
        """ """
        logger.debug("TYPE: {}".format(t))
        typ = t.type
        for d in t.decl_list:
            (name, decl) = self.process_type(typ, d)
            logger.debug("  {} {}".format(name, decl))
            self.add_def("types", name, decl)

    # --- Utility methods

    def eval_expr(self, toks):
        """Evaluates expressions.

        Currently only works for expressions that also happen to be valid
        python expressions.

        """
        logger.debug("Eval: {}".format(toks))
        try:
            if isinstance(toks, str):
                val = self.eval(toks, None, self.defs["values"])
            elif toks.array_values != "":
                val = [
                    self.eval(x, None, self.defs["values"]) for x in toks.array_values
                ]
            elif toks.value != "":
                val = self.eval(toks.value, None, self.defs["values"])
            else:
                val = None
            return val

        except Exception:
            logger.debug("    failed eval {} : {}".format(toks, format_exc()))
            return None

    def eval(self, expr, *args):
        """Just eval with a little extra robustness."""
        expr = expr.strip()
        cast = (lparen + self.type_spec + self.abstract_declarator + rparen).suppress()
        expr = (quotedString | number | cast).transformString(expr)
        if expr == "":
            return None
        return eval(expr, *args)

    def add_def(self, typ, name, val):
        """Add a definition of a specific type to both the definition set for
        the current file and the global definition set.

        """
        self.defs[typ][name] = val
        if self.current_file is None:
            base_name = None
        else:
            base_name = os.path.basename(self.current_file)
        if base_name not in self.file_defs:
            self.file_defs[base_name] = {}
            for k in self.data_list:
                self.file_defs[base_name][k] = {}
        self.file_defs[base_name][typ][name] = val

    def rem_def(self, typ, name):
        """Remove a definition of a specific type to both the definition set
        for the current file and the global definition set.

        """
        if self.current_file is None:
            base_name = None
        else:
            base_name = os.path.basename(self.current_file)
        del self.defs[typ][name]
        del self.file_defs[base_name][typ][name]

    def is_fund_type(self, typ):
        """Return True if this type is a fundamental C type, struct, or
        union.

        **ATTENTION: This function is legacy and should be replaced by
        Type.is_fund_type()**

        """
        return Type(typ).is_fund_type()

    def eval_type(self, typ):
        """Evaluate a named type into its fundamental type.

        **ATTENTION: This function is legacy and should be replaced by
        Type.eval()**

        """
        if not isinstance(typ, Type):
            typ = Type(*typ)
        return typ.eval(self.defs["types"])

    def find(self, name):
        """Search all definitions for the given name."""
        res = []
        for f in self.file_defs:
            fd = self.file_defs[f]
            for t in fd:
                typ = fd[t]
                for k in typ:
                    if isinstance(name, str):
                        if k == name:
                            res.append((f, t))
                    else:
                        if re.match(name, k):
                            res.append((f, t, k))
        return res

    def find_text(self, text):
        """Search all file strings for text, return matching lines."""
        res = []
        for f in self.files:
            lines = self.files[f].split("\n")
            for i, line in enumerate(lines):
                if text in line:
                    res.append((f, i, line))
        return res


# --- Basic parsing elements.


def kwl(strs):
    """Generate a match-first list of keywords given a list of strings."""
    return Regex(r"\b({})\b".format("|".join(strs)))


def flatten(lst):
    res = []
    for i in lst:
        if isinstance(i, (list, tuple)):
            res.extend(flatten(i))
        else:
            res.append(str(i))
    return res


def recombine(tok):
    """Flattens a tree of tokens and joins into one big string."""
    return " ".join(flatten(tok.asList()))


def print_parse_results(pr, depth=0, name=""):
    """For debugging; pretty-prints parse result objects."""
    start = name + " " * (20 - len(name)) + ":" + ".." * depth
    if isinstance(pr, ParseResults):
        print(start)
        for i in pr:
            name = ""
            for k in pr.keys():
                if pr[k] is i:
                    name = k
                    break
            print_parse_results(i, depth + 1, name)
    else:
        print(start + str(pr))


# Syntatic delimiters
comma = Literal(",").ignore(quotedString).suppress()
colon = Literal(":").ignore(quotedString).suppress()
semi = Literal(";").ignore(quotedString).suppress()
lbrace = Literal("{").ignore(quotedString).suppress()
rbrace = Literal("}").ignore(quotedString).suppress()
lbrack = Literal("[").ignore(quotedString).suppress()
rbrack = Literal("]").ignore(quotedString).suppress()
lparen = Literal("(").ignore(quotedString).suppress()
rparen = Literal(")").ignore(quotedString).suppress()

# Numbers
int_strip = lambda t: t[0].rstrip("UL")  # noqa
hexint = Regex(r"[+-]?\s*0[xX][{}]+[UL]*".format(hexnums)).setParseAction(int_strip)
decint = Regex(r"[+-]?\s*[0-9]+[UL]*").setParseAction(int_strip)
integer = hexint | decint
# The floating regex is ugly but it is because we do not want to match
# integer to it.
floating = Regex(r"[+-]?\s*((((\d(\.\d*)?)|(\.\d+))[eE][+-]?\d+)|((\d\.\d*)|(\.\d+)))")
number = floating | integer

# Miscelaneous
bi_operator = oneOf("+ - / * | & || && ! ~ ^ % == != > < >= <= -> . :: << >> = ? :")
uni_right_operator = oneOf("++ --")
uni_left_operator = oneOf("++ -- - + * sizeof new")
wordchars = alphanums + "_$"
name = WordStart(wordchars) + Word(alphas + "_", alphanums + "_$") + WordEnd(wordchars)
size_modifiers = ["short", "long"]
sign_modifiers = ["signed", "unsigned"]

# Syntax elements defined by _init_parser.
expression = Forward()
array_op = lbrack + expression + rbrack
base_types = None
ident = None
call_conv = None
type_qualifier = None
storage_class_spec = None
extra_modifier = None
fund_type = None
extra_type_list = []

c99_int_types = [
    "int8_t",
    "uint8_t",
    "int16_t",
    "uint16_t",
    "int32_t",
    "uint32_t",
    "int64_t",
    "uint64_t",
]
stddef_int_types = ["size_t", "ssize_t"]
num_types = ["int", "float", "double", *c99_int_types, *stddef_int_types]
nonnum_types = ["char", "wchar", "wchar_t", "bool", "void"]

if sys.version_info >= (3, 12):
    num_types.append("time_t")

if sys.platform == "win32":
    num_types.append("__int64")


# Define some common language elements when initialising.
def _init_cparser(extra_types=None, extra_modifiers=None):
    global expression
    global call_conv, ident
    global base_types
    global type_qualifier, storage_class_spec, extra_modifier
    global fund_type
    global extra_type_list

    # Some basic definitions
    extra_type_list = [] if extra_types is None else list(extra_types)
    base_types = nonnum_types + num_types + extra_type_list
    storage_classes = ["inline", "static", "extern"]
    qualifiers = ["const", "volatile", "restrict", "near", "far"]

    keywords = [
        "struct",
        "enum",
        "union",
        "__stdcall",
        "__cdecl",
        *qualifiers,
        *base_types,
        *size_modifiers,
        *sign_modifiers,
    ]

    keyword = kwl(keywords)
    wordchars = alphanums + "_$"
    ident = (
        WordStart(wordchars)
        + ~keyword
        + Word(alphas + "_", alphanums + "_$")
        + WordEnd(wordchars)
    ).setParseAction(lambda t: t[0])

    call_conv = Optional(Keyword("__cdecl") | Keyword("__stdcall"))("call_conv")

    # Removes '__name' from all type specs. may cause trouble.
    underscore_2_ident = (
        WordStart(wordchars)
        + ~keyword
        + "__"
        + Word(alphanums, alphanums + "_$")
        + WordEnd(wordchars)
    ).setParseAction(lambda t: t[0])
    type_qualifier = ZeroOrMore(
        (underscore_2_ident + Optional(nestedExpr())) | kwl(qualifiers)
    )

    storage_class_spec = Optional(kwl(storage_classes))

    if extra_modifiers:
        extra_modifier = ZeroOrMore(
            kwl(extra_modifiers) + Optional(nestedExpr())
        ).suppress()

    else:
        extra_modifier = None

    # Language elements
    fund_type = OneOrMore(
        kwl(sign_modifiers + size_modifiers + base_types)
    ).setParseAction(lambda t: " ".join(t))

    # Is there a better way to process expressions with cast operators??
    cast_atom = (
        ZeroOrMore(uni_left_operator)
        + Optional("(" + ident + ")").suppress()
        + (
            (
                ident + "(" + Optional(delimitedList(expression)) + ")"
                | ident + OneOrMore("[" + expression + "]")
                | ident
                | number
                | quotedString
            )
            | ("(" + expression + ")")
        )
        + ZeroOrMore(uni_right_operator)
    )

    uncast_atom = (
        ZeroOrMore(uni_left_operator)
        + (
            (
                ident + "(" + Optional(delimitedList(expression)) + ")"
                | ident + OneOrMore("[" + expression + "]")
                | ident
                | number
                | quotedString
            )
            | ("(" + expression + ")")
        )
        + ZeroOrMore(uni_right_operator)
    )

    atom = cast_atom | uncast_atom

    expression << Group(atom + ZeroOrMore(bi_operator + atom))
    expression.setParseAction(recombine)
