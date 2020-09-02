#!/bin/sh

dir=$(dirname $0)
dir=$(cd $dir;pwd -P)
ddir=$(cd $dir/..;pwd -P)

IGNORE1=""
IGNORE2=""

IGNORE1="$IGNORE1 --disable=W0311" #bad-indentation

IGNORE1="$IGNORE1 --disable=C0103" #invalid-name
IGNORE1="$IGNORE1 --disable=C0111" #missing-docstring
IGNORE1="$IGNORE1 --disable=C0305" #trailing-newlines
IGNORE1="$IGNORE1 --disable=C0325" #superfluous-parens
IGNORE1="$IGNORE1 --disable=C0326" #bad-whitespace
IGNORE1="$IGNORE1 --disable=C0410" #multiple-imports
IGNORE1="$IGNORE1 --disable=C0413" #wrong-import-position

IGNORE2="$IGNORE2 --disable=W0102" #dangerous-default-value
IGNORE2="$IGNORE2 --disable=W0105" #pointless-string-statement
IGNORE2="$IGNORE2 --disable=W0107" #unnecessary-pass
IGNORE2="$IGNORE2 --disable=W0201" #attribute-defined-outside-init
IGNORE2="$IGNORE2 --disable=W0212" #protected-access
IGNORE2="$IGNORE2 --disable=W0232" #no-init
IGNORE2="$IGNORE2 --disable=W0301" #unnecessary-semicolon
IGNORE2="$IGNORE2 --disable=W0312" #mixed-indentation
IGNORE2="$IGNORE2 --disable=W0401" #wildcard-import
IGNORE2="$IGNORE2 --disable=W0404" #reimported
IGNORE2="$IGNORE2 --disable=W0511" #fixme
IGNORE2="$IGNORE2 --disable=W0601" #global-variable-undefined
IGNORE2="$IGNORE2 --disable=W0603" #global-statement
IGNORE2="$IGNORE2 --disable=W0604" #global-at-module-level
#IGNORE2="$IGNORE2 --disable=W0611" #unused-import
IGNORE2="$IGNORE2 --disable=W0612" #unused-variable
IGNORE2="$IGNORE2 --disable=W0613" #unused-argument
IGNORE2="$IGNORE2 --disable=W0614" #unused-wildcard-import
IGNORE2="$IGNORE2 --disable=W0621" #redefined-outer-name
IGNORE2="$IGNORE2 --disable=W0622" #redefined-builtin
IGNORE2="$IGNORE2 --disable=W0702" #bare-except
IGNORE2="$IGNORE2 --disable=W0703" #broad-except

IGNORE2="$IGNORE2 --disable=C0112" #empty-docstring
IGNORE2="$IGNORE2 --disable=C0113" #unneeded-not
IGNORE2="$IGNORE2 --disable=C0121" #singleton-comparison
IGNORE2="$IGNORE2 --disable=C0123" #unidiomatic-typecheck
IGNORE2="$IGNORE2 --disable=C0200" #consider-using-enumerate
IGNORE2="$IGNORE2 --disable=C0201" #consider-iterating-dictionary
IGNORE2="$IGNORE2 --disable=C0301" #line-too-long
IGNORE2="$IGNORE2 --disable=C0302" #too-many-lines
IGNORE2="$IGNORE2 --disable=C0303" #trailing-whitespace
IGNORE2="$IGNORE2 --disable=C0304" #missing-final-newline
IGNORE2="$IGNORE2 --disable=C0321" #multiple-statements
IGNORE2="$IGNORE2 --disable=C0330" #bad-continuation
IGNORE2="$IGNORE2 --disable=C0411" #wrong-import-order
IGNORE2="$IGNORE2 --disable=C0412" #ungrouped-imports
IGNORE2="$IGNORE2 --disable=C1001" #old-style-class
IGNORE2="$IGNORE2 --disable=C1801" #len-as-condition

IGNORE2="$IGNORE2 --disable=E0632" #unbalanced-tuple-unpacking
IGNORE2="$IGNORE2 --disable=E1305" #too-many-format-args

IGNORE2="$IGNORE2 --disable=R0101" #too-many-nested-blocks
IGNORE2="$IGNORE2 --disable=R0102" #simplifiable-if-statement
IGNORE2="$IGNORE2 --disable=R0201" #no-self-use
IGNORE2="$IGNORE2 --disable=R0205" #useless-object-inheritance
IGNORE2="$IGNORE2 --disable=R0902" #too-many-instance-attributes
IGNORE2="$IGNORE2 --disable=R0903" #too-few-public-methods
IGNORE2="$IGNORE2 --disable=R0904" #too-many-public-methods
IGNORE2="$IGNORE2 --disable=R0911" #too-many-return-statements
IGNORE2="$IGNORE2 --disable=R0912" #too-many-branches
IGNORE2="$IGNORE2 --disable=R0913" #too-many-arguments
IGNORE2="$IGNORE2 --disable=R0914" #too-many-locals
IGNORE2="$IGNORE2 --disable=R0915" #too-many-statements
IGNORE2="$IGNORE2 --disable=R0916" #too-many-boolean-expressions
IGNORE2="$IGNORE2 --disable=R1705" #no-else-return
IGNORE2="$IGNORE2 --disable=R1710" #inconsistent-return-statements
IGNORE2="$IGNORE2 --disable=R1710" #useless-return

IGNORE="$IGNORE1"
IGNORE="$IGNORE1 $IGNORE2"

LINT="$dir/python3 -m pylint --rcfile=$dir/.pylintrc $IGNORE"
LINT="$dir/python -m pylint --rcfile=$dir/.pylintrc $IGNORE"
LINT2="$dir/python -m pyflakes"
LINT3="$dir/python -m flake8 --select F --ignore=F401,F841"

if [ $# -eq 0 ]; then
  files1=$(find $ddir/spytest/ -name "*.py" | grep -v __init__.py | grep -v $ddir/spytest/ddm | grep -v $ddir/spytest/tg)
  files2=$(find $ddir/scheduler/ -name "*.py" | grep -v __init__.py)
  files3=$(find $ddir/apis/ -name "*.py" | grep -v __init__.py)
  files4=$(find $ddir/utilities/ -name "*.py" | grep -v __init__.py | grep -v ipaddress.py)
  files5=$(find $ddir/tests/ -name "*.py" | grep -v __init__.py | grep -v $ddir/tests/ddm)
  files="$files1 $files2 $files3 $files4 $files5"
else
  files=""
  for arg in $*; do
    [ -f $arg ] && files="$files $arg"
    [ -d $arg ] && files="$files $(find $arg -name '*.py' | grep -v __init__.py)"
  done
fi

rm -f errors.log
for f in $files;do
  #echo    ================== FLAKES8 $f  | tee -a errors.log
  #$LINT3 $f 2>&1 | tee -a errors.log
  #echo    ================== PYFLAKES $f  | tee -a errors.log
  #$LINT2 $f 2>&1 | tee -a errors.log
  echo    ================== PYLINT $f  | tee -a errors.log
  $LINT $f 2>&1 | grep -v "Using config file " | tee -a errors.log
done

