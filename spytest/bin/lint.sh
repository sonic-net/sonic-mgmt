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
IGNORE1="$IGNORE1 --disable=C0415" #import-outside-toplevel

IGNORE2="$IGNORE2 --disable=W0102" #dangerous-default-value
IGNORE2="$IGNORE2 --disable=W0105" #pointless-string-statement
#IGNORE2="$IGNORE2 --disable=W0106" #expression-not-assigned
IGNORE2="$IGNORE2 --disable=W0107" #unnecessary-pass
IGNORE2="$IGNORE2 --disable=W0122" #exec-used
IGNORE2="$IGNORE2 --disable=W0123" #eval-used
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
#IGNORE2="$IGNORE2 --disable=W0612" #unused-variable
IGNORE2="$IGNORE2 --disable=W0613" #unused-argument
IGNORE2="$IGNORE2 --disable=W0614" #unused-wildcard-import
IGNORE2="$IGNORE2 --disable=W0621" #redefined-outer-name
IGNORE2="$IGNORE2 --disable=W0622" #redefined-builtin
IGNORE2="$IGNORE2 --disable=W0702" #bare-except
IGNORE2="$IGNORE2 --disable=W0703" #broad-except

IGNORE2="$IGNORE2 --disable=C0112" #empty-docstring
IGNORE2="$IGNORE2 --disable=C0113" #unneeded-not
#IGNORE2="$IGNORE2 --disable=C0121" #singleton-comparison
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

#IGNORE2="$IGNORE2 --disable=E0102" #function-redefined
IGNORE2="$IGNORE2 --disable=E0632" #unbalanced-tuple-unpacking
IGNORE2="$IGNORE2 --disable=E1128" #assignment-from-none
#IGNORE2="$IGNORE2 --disable=E1305" #too-many-format-args

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
IGNORE2="$IGNORE2 --disable=R1711" #useless-return

IGNORE2="$IGNORE2 --disable=R1714" #consider-using-in
IGNORE2="$IGNORE2 --disable=R1716" #chained-comparison
IGNORE2="$IGNORE2 --disable=R1719" #simplifiable-if-expression
IGNORE2="$IGNORE2 --disable=R1720" #no-else-raise
IGNORE2="$IGNORE2 --disable=R1723" #no-else-break
IGNORE2="$IGNORE2 --disable=R1724" #no-else-continue

exclude="__init__.py scheduler/"
LINT_PYVER=0
ERR_TEMP=$(mktemp)
REPORT=lint_report.log
ERR_FILE=lint_errors.log

if [ "$LINT_DAILY" == "1" ]; then
  REPORT=daily_lint_report.log
  ERR_FILE=daily_lint_errors.log
  #IGNORE2="$IGNORE2 --disable=W0611" #unused-import
  #IGNORE2="$IGNORE2 --disable=W0612" #unused-variable
  IGNORE2="$IGNORE2 --disable=W0106" #expression-not-assigned
  exclude="__init__.py ddm/ tests/ut/ tests/systb/ scheduler/ tests/dell"
fi

IGNORE="$IGNORE1"
IGNORE="$IGNORE1 $IGNORE2"

LINT2="$dir/python -m pylint --rcfile=$dir/.pylintrc $IGNORE"
LINT3="$dir/python3 -m pylint --rcfile=$dir/.pylintrc $IGNORE"
#PYFLAKES="$dir/python -m pyflakes"
#FLAKE8="$dir/python -m flake8 --select F --ignore=F401,F841"
#FLAKE8="$dir/python -m flake8 --select F"

if [ $# -eq 0 ]; then
  files1=$(find $ddir/spytest/ -name "*.py")
  if [ -d $ddir/scheduler ]; then
    files2=$(find $ddir/scheduler/ -name "*.py")
  fi
  files3=$(find $ddir/apis/ -name "*.py")
  files4=$(find $ddir/utilities/ -name "*.py")
  files5=$(find $ddir/tests/ -name "*.py")
  files="$files1 $files2 $files3 $files4 $files5"
else
  files=""
  for arg in $*; do
    if [ -f $arg ]; then
      files="$files $arg"
    elif [ -d $arg ]; then
      files="$files $(find $arg -name '*.py')"
    fi
  done
fi

files2=""
for f in $files;do
    skip=0
    for ex in $exclude; do
        if grep -q $ex <<< $f; then
            skip=1
            break
        fi
    done
    [ $skip -eq 1 ] || files2="$files2 $f"
done

rm -f $REPORT $ERR_FILE $ERR_TEMP
line="\--------------------------------------------------------------------"
score="Your code has been rated at 10.00"
using="Using config file "
date | tee -a $REPORT | tee -a $ERR_FILE
for f in $files2;do
  if [ -n "$FLAKE8" ]; then
    echo ================== FLAKES8 $f  | tee -a $REPORT
    $FLAKE8 $f 2>&1 | tee -a $REPORT
  fi
  if [ -n "$PYFLAKES" ]; then
    echo ================== PYFLAKES $f  | tee -a $REPORT
    $PYFLAKES $f 2>&1 | tee -a $REPORT
  fi
  if [ -z "$LINT2" -a -z "$LINT3" ]; then
    continue
  fi
  if [ $LINT_PYVER -eq 2 ]; then
    echo ================== PYLINT2 $f  | tee -a $REPORT
    $LINT2 $f 2>&1 | grep -v "$using" | tee -a $REPORT
    continue
  fi
  if [ $LINT_PYVER -eq 3 ]; then
    echo ================== PYLINT3 $f  | tee -a $REPORT
    $LINT3 $f 2>&1 | grep -v "$using" | tee -a $REPORT
    continue
  fi

  $LINT3 $f 2>&1 | grep -v "$using" | grep -v $line > $ERR_TEMP
  grep -q "$score" $ERR_TEMP >/dev/null
  if [ $? -ne 0 ]; then
    echo ================== PYLINT3 $f  | tee -a $REPORT
    echo ================== PYLINT3 $f  | tee -a $ERR_FILE
    cat $ERR_TEMP | tee -a $REPORT $ERR_FILE
    continue
  fi

  $LINT2 $f 2>&1 | grep -v "$using" | grep -v $line > $ERR_TEMP
  grep -q "$score" $ERR_TEMP >/dev/null
  if [ $? -ne 0 ]; then
    echo ================== PYLINT2 $f  | tee -a $REPORT
    echo ================== PYLINT2 $f  | tee -a $ERR_FILE
    cat $ERR_TEMP | tee -a $REPORT $ERR_FILE
    continue
  fi
  echo ================== PYLINT $f  | tee -a $REPORT
done

