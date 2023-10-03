#!/bin/bash

dir=$(dirname $0)
dir=$(cd $dir;pwd -P)
ddir=$(cd $dir/..;pwd -P)

IGNORE1=""
INGORE2=""
INGORE3=""

IGNORE1="$IGNORE1 --disable=W0311" #bad-indentation

IGNORE1="$IGNORE1 --disable=C0103" #invalid-name
IGNORE1="$IGNORE1 --disable=C0111" #missing-docstring
IGNORE1="$IGNORE1 --disable=C0305" #trailing-newlines
IGNORE1="$IGNORE1 --disable=C0325" #superfluous-parens
IGNORE2="$IGNORE2 --disable=C0326" #bad-whitespace
IGNORE1="$IGNORE1 --disable=C0410" #multiple-imports
IGNORE1="$IGNORE1 --disable=C0413" #wrong-import-position
IGNORE1="$IGNORE1 --disable=C0415" #import-outside-toplevel

IGNORE1="$IGNORE1 --disable=W0102" #dangerous-default-value
IGNORE1="$IGNORE1 --disable=W0105" #pointless-string-statement
#IGNORE1="$IGNORE1 --disable=W0106" #expression-not-assigned
IGNORE1="$IGNORE1 --disable=W0107" #unnecessary-pass
IGNORE1="$IGNORE1 --disable=W0122" #exec-used
IGNORE1="$IGNORE1 --disable=W0123" #eval-used
IGNORE1="$IGNORE1 --disable=W0201" #attribute-defined-outside-init
IGNORE1="$IGNORE1 --disable=W0212" #protected-access
IGNORE2="$IGNORE2 --disable=W0232" #no-init
IGNORE1="$IGNORE1 --disable=W0237" #arguments-renamed
IGNORE1="$IGNORE1 --disable=W0301" #unnecessary-semicolon
IGNORE2="$IGNORE2 --disable=W0312" #mixed-indentation
IGNORE1="$IGNORE1 --disable=W0401" #wildcard-import
#IGNORE1="$IGNORE1 --disable=W0404" #reimported
IGNORE1="$IGNORE1 --disable=W0511" #fixme
IGNORE1="$IGNORE1 --disable=W0601" #global-variable-undefined
IGNORE1="$IGNORE1 --disable=W0602" #global-variable-not-assigned
IGNORE1="$IGNORE1 --disable=W0603" #global-statement
IGNORE1="$IGNORE1 --disable=W0604" #global-at-module-level
#IGNORE1="$IGNORE1 --disable=W0611" #unused-import
#IGNORE1="$IGNORE1 --disable=W0612" #unused-variable
IGNORE1="$IGNORE1 --disable=W0613" #unused-argument
IGNORE1="$IGNORE1 --disable=W0614" #unused-wildcard-import
IGNORE1="$IGNORE1 --disable=W0621" #redefined-outer-name
IGNORE1="$IGNORE1 --disable=W0622" #redefined-builtin
IGNORE1="$IGNORE1 --disable=W0702" #bare-except
IGNORE1="$IGNORE1 --disable=W0703" #broad-except
IGNORE3="$IGNORE3 --disable=W0707" #raise-missing-from

IGNORE1="$IGNORE1 --disable=C0112" #empty-docstring
#IGNORE1="$IGNORE1 --disable=C0113" #unneeded-not
#IGNORE1="$IGNORE1 --disable=C0121" #singleton-comparison
IGNORE1="$IGNORE1 --disable=C0123" #unidiomatic-typecheck
IGNORE1="$IGNORE1 --disable=C0200" #consider-using-enumerate
IGNORE1="$IGNORE1 --disable=C0201" #consider-iterating-dictionary
IGNORE1="$IGNORE1 --disable=C0301" #line-too-long
IGNORE1="$IGNORE1 --disable=C0302" #too-many-lines
IGNORE1="$IGNORE1 --disable=C0303" #trailing-whitespace
IGNORE1="$IGNORE1 --disable=C0304" #missing-final-newline
IGNORE1="$IGNORE1 --disable=C0321" #multiple-statements
IGNORE2="$IGNORE2 --disable=C0330" #bad-continuation
IGNORE1="$IGNORE1 --disable=C0411" #wrong-import-order
IGNORE1="$IGNORE1 --disable=C0412" #ungrouped-imports
IGNORE2="$IGNORE2 --disable=C1001" #old-style-class
IGNORE1="$IGNORE1 --disable=C1801" #len-as-condition

#IGNORE1="$IGNORE1 --disable=E0102" #function-redefined
IGNORE1="$IGNORE1 --disable=E0632" #unbalanced-tuple-unpacking
IGNORE1="$IGNORE1 --disable=E1128" #assignment-from-none
#IGNORE1="$IGNORE1 --disable=E1305" #too-many-format-args

IGNORE1="$IGNORE1 --disable=R0022" #useless-option-value
IGNORE1="$IGNORE1 --disable=R0101" #too-many-nested-blocks
IGNORE1="$IGNORE1 --disable=R0102" #simplifiable-if-statement
IGNORE1="$IGNORE1 --disable=R0201" #no-self-use
IGNORE1="$IGNORE1 --disable=R0205" #useless-object-inheritance
IGNORE1="$IGNORE1 --disable=R0902" #too-many-instance-attributes
IGNORE1="$IGNORE1 --disable=R0903" #too-few-public-methods
IGNORE1="$IGNORE1 --disable=R0904" #too-many-public-methods
IGNORE1="$IGNORE1 --disable=R0911" #too-many-return-statements
IGNORE1="$IGNORE1 --disable=R0912" #too-many-branches
IGNORE1="$IGNORE1 --disable=R0913" #too-many-arguments
IGNORE1="$IGNORE1 --disable=R0914" #too-many-locals
IGNORE1="$IGNORE1 --disable=R0915" #too-many-statements
IGNORE1="$IGNORE1 --disable=R0916" #too-many-boolean-expressions
IGNORE1="$IGNORE1 --disable=R1705" #no-else-return
IGNORE1="$IGNORE1 --disable=R1710" #inconsistent-return-statements
IGNORE1="$IGNORE1 --disable=R1711" #useless-return
IGNORE1="$IGNORE1 --disable=R1714" #consider-using-in
IGNORE1="$IGNORE1 --disable=R1716" #chained-comparison
IGNORE1="$IGNORE1 --disable=R1719" #simplifiable-if-expression
IGNORE1="$IGNORE1 --disable=R1720" #no-else-raise
IGNORE1="$IGNORE1 --disable=R1723" #no-else-break
IGNORE1="$IGNORE1 --disable=R1724" #no-else-continue
IGNORE3="$IGNORE3 --disable=R1725" #super-with-arguments
IGNORE3="$IGNORE3 --disable=R1732" #consider-using-with

if [ "$LINT_IGNORE_UNUSED" == "1" ]; then
  IGNORE1="$IGNORE1 --disable=W0611" #unused-import
  IGNORE1="$IGNORE1 --disable=W0612" #unused-variable
fi

IGNORE2="$IGNORE2 --disable=C0122" #misplaced-comparison-constant
IGNORE1="$IGNORE1 --disable=W1308" #duplicate-string-formatting-argument
IGNORE1="$IGNORE1 --disable=W1309" #f-string-without-interpolation
IGNORE1="$IGNORE1 --disable=R1715" #consider-using-get
IGNORE1="$IGNORE1 --disable=R1718" #consider-using-set-comprehension
IGNORE1="$IGNORE1 --disable=R1721" #unnecessary-comprehension
IGNORE1="$IGNORE1 --disable=R1728" #consider-using-generator
IGNORE1="$IGNORE1 --disable=W1401" #anomalous-backslash-in-string

IGNORE3="$IGNORE3 --disable=W1514" #unspecified-encoding
IGNORE3="$IGNORE3 --disable=R1734" #use-list-literal
IGNORE3="$IGNORE3 --disable=R1735" #use-dict-literal
IGNORE3="$IGNORE3 --disable=C0206" #consider-using-dict-items
IGNORE3="$IGNORE3 --disable=C0209" #consider-using-f-string
IGNORE3="$IGNORE3 --disable=C0207" #use-maxsplit-arg
IGNORE3="$IGNORE3 --disable=R0402" #consider-using-from-import
IGNORE3="$IGNORE3 --disable=W1406" #redundant-u-string-prefix
IGNORE3="$IGNORE3 --disable=R1729" #use-a-generator

IGNORE3="$IGNORE3 --disable=C3001" #unnecessary-lambda-assignment

exclude="apis/gnmi/openconfig apis/gnmi unused/"
exclude="$exclude apis/yang/autogen/bindings"
exclude="$exclude apis/yang/codegen/bindings"
exclude="$exclude apis/yang/codegen/test.py"
exclude="$exclude apis/yang/codegen/gnoi_bindings"
exclude="$exclude spytest/ddm/third-party"
exclude="$exclude tests/dell/infra/bgpcfgd_test.py"

if [ "$LINT_EXCLUDE_KNOWN_FAILS" == "1" ]; then
  exclude="$exclude apis/yang/codegen"
  exclude="$exclude tests/dell"
  exclude="$exclude tests/ut/acl_fbs"
  exclude="$exclude tests/infra_ut/data_driven"
  exclude="$exclude tests/systb"
fi

LINT_PYVER=${LINT_PYVER:=3}
TMP_FOLD=$(mktemp -d)
trap "rm -rf $TMP_FOLD" EXIT
ERR_TEMP=$TMP_FOLD/err
DBG_FILE=lint_debug.log
ERR_FILE=lint_errors.log
REP_FILE=lint_report.log

if [ "$LINT_MODIFIED" == "1" ]; then
  DBG_FILE=modified_lint_debug.log
  ERR_FILE=modified_lint_errors.log
  REP_FILE=modified_lint_report.log
  #exclude=""
  exclude="$exclude __init__.py"
fi

#IGNORE1="$IGNORE1 --disable=W0612" #unused-variable

if [ "$LINT_DAILY" == "1" ]; then
  DBG_FILE=daily_lint_debug.log
  ERR_FILE=daily_lint_errors.log
  REP_FILE=daily_lint_report.log
  #IGNORE1="$IGNORE1 --disable=W0612" #unused-variable
fi
IGNORE1="$IGNORE1 --disable=W0106" #expression-not-assigned
IGNORE1="$IGNORE1 --disable=W0631" #undefined-loop-variable
IGNORE1="$IGNORE1 --disable=R1704" #redefined-argument-from-local

RUFF_OPTS="$RUFF_OPTS --ignore E401" #multiple-imports-on-one-line
RUFF_OPTS="$RUFF_OPTS --ignore E401" #multiple-imports-on-one-line
RUFF_OPTS="$RUFF_OPTS --ignore E402" #module-import-not-at-top-of-file
RUFF_OPTS="$RUFF_OPTS --ignore E501" #line-too-long
RUFF_OPTS="$RUFF_OPTS --ignore E701" #multiple-statements
RUFF_OPTS="$RUFF_OPTS --ignore E702" #multiple-statements-on-one-line-semicolon
RUFF_OPTS="$RUFF_OPTS --ignore E703" #useless-semicolon
RUFF_OPTS="$RUFF_OPTS --ignore E713" #not-in-test
RUFF_OPTS="$RUFF_OPTS --ignore E722" #bare-except
RUFF_OPTS="$RUFF_OPTS --ignore E731" #lambda-assignment
RUFF_OPTS="$RUFF_OPTS --ignore E741" #ambiguous-variable-name
RUFF_OPTS="$RUFF_OPTS --ignore F541" #f-string-missing-placeholders
RUFF_OPTS="$RUFF_OPTS --ignore W191" #Indentation contains tabs
RUFF_OPTS="$RUFF_OPTS --ignore W292" #No newline at end of file
RUFF_OPTS="$RUFF_OPTS --ignore W191" #Indentation contains tabs
RUFF_OPTS="$RUFF_OPTS --ignore W291" #Trailing whitespace
RUFF_OPTS="$RUFF_OPTS --ignore W293" #Blank line contains whitespace
RUFF_OPTS="$RUFF_OPTS --ignore PLW2901"
RUFF_OPTS="$RUFF_OPTS --ignore PLW0603"
RUFF_OPTS="$RUFF_OPTS --ignore PLC1901"

LINT_TOOL="${LINT_TOOL:-ruff}"
if [ "$LINT_TOOL" = "pylint" ]; then
  LINT_PYVER=3
elif [ "$LINT_TOOL" = "pylint2" ]; then
  LINT_PYVER=2
elif [ "$LINT_TOOL" = "pylint3" ]; then
  LINT_PYVER=3
elif [ "$LINT_TOOL" = "pyflakes" ]; then
  PYFLAKES="$dir/python -m pyflakes"
  LINT2=""; LINT3=""
elif [ "$LINT_TOOL" = "ruff" -o "$LINT_TOOL" = "ruff-only" ]; then
  RUFF="$dir/python -m ruff --select=F,E,W,PLE,PLW,PLC"
fi

if [ "$LINT_TOOL" != "pyflakes" ]; then
  RCFILE=$dir/.pylintrc$LINT_PYVER
  if [ ! -f $RCFILE ]; then
    RCFILE=$TMP_FOLD/.pylintrc
    touch $RCFILE
  fi

  LINT2="timeout 300 $dir/python2 -m pylint --max-parents=8 --rcfile=$RCFILE $IGNORE1 $IGNORE2"
  LINT3="timeout 300 $dir/python3 -m pylint --rcfile=$RCFILE $IGNORE1 $IGNORE3"
  #LINT3="$LINT3 --load-plugins perflint --disable=W8205" #dotted-import-in-loop
  #FLAKE8="$dir/python -m flake8 --select F --ignore=F401,F841"
  #FLAKE8="$dir/python -m flake8 --select F"
fi

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

cmd="grep -q"
for ex in $exclude; do
  cmd="$cmd -e $ex"
done
files2=""
for f in $files;do
  if [ -z "$exclude" ]; then
    files2="$files2 $f"
  elif ! $cmd <<< $f; then
    files2="$files2 $f"
  fi
done

rm -f $DBG_FILE $ERR_FILE $REP_FILE $ERR_TEMP $REP_FILE.err
line="\--------------------------------------------------------------------"
score="Your code has been rated at 10.00"
using="Using config file "

print()
{
  echo $(date +'%Y-%d-%m %H:%M:%S') $*
}

print "Start...." | tee -a $DBG_FILE | tee -a $ERR_FILE
for f in $files2;do
  OPT_LINT_PYVER=${LINT_PYVER:=3}

  OPTS=""; OPTS2=""; OPTS3=""
  if [[ $f == *utilities/common.py ]]; then
    OPTS3="$OPTS3 --disable=W1515"
  fi

  if [[ $f == */yang/* || $f == */infra_ut/data_driven/* ]]; then
    OPT_LINT_PYVER=3
  fi

  if [[ $f == */test_ut_boot_time.py ]]; then
    OPT_LINT_PYVER=3
  fi

  if [[ $f == */ut/acl_fbs/* || $f == */ut/flexDpb/* || $f == */ut/gnmi/* ]]; then
    OPT_LINT_PYVER=3
  fi

  if [[ $f == */yang/codegen/* || $f == */yang/autogen/* ]]; then
    OPTS3="$OPTS3 --disable=E0401"
    OPTS3="$OPTS3 --disable=W0404" #reimported
    OPTS3="$OPTS3 --disable=W0611" #unused-import
    OPTS3="$OPTS3 --disable=R1706"
    OPTS3="$OPTS3 --disable=W0127"
    RUFF_OPTS="$RUFF_OPTS --ignore F401" #unused-import
    RUFF_OPTS="$RUFF_OPTS --ignore E101" #mixed indentation
    RUFF_OPTS="$RUFF_OPTS --ignore W191" #Indentation contains tabs
    RUFF_OPTS="$RUFF_OPTS --ignore W291" #Trailing whitespace
    RUFF_OPTS="$RUFF_OPTS --ignore W293" #Blank line contains whitespace
    RUFF_OPTS="$RUFF_OPTS --ignore F811" #reimported
  fi

  if [[ $f == */dell/* ]]; then
    export SPYLINT_PYTHONPATH=$ddir/tests/dell/platform
    OPTS2="$OPTS2 --disable=W0403" #relative-import
    OPTS="$OPTS --disable=W0611" #unused-import
    OPTS="$OPTS --disable=W0612" #unused-variable
    OPTS="$OPTS --disable=W0404" #reimported
    OPTS="$OPTS --disable=C0121" #singleton-comparison
    OPTS="$OPTS --disable=R0123" #literal-comparison
    OPTS="$OPTS --disable=E1305" #too-many-format-args
    OPTS="$OPTS --disable=C0113" #unneeded-not
    RUFF_OPTS="$RUFF_OPTS --ignore E101" #mixed indentation
    RUFF_OPTS="$RUFF_OPTS --ignore F401" #unused-import
    RUFF_OPTS="$RUFF_OPTS --ignore F841" #unused-variable
    RUFF_OPTS="$RUFF_OPTS --ignore E711" #none-comparison
    RUFF_OPTS="$RUFF_OPTS --ignore E712" #true-false-comparison
    RUFF_OPTS="$RUFF_OPTS --ignore E714" #true-false-comparison
    RUFF_OPTS="$RUFF_OPTS --ignore F632" #literal-comparison
    RUFF_OPTS="$RUFF_OPTS --ignore PLW0602"
  fi

  if [[ $f == */systb/campus/* ]]; then
    export SPYLINT_PYTHONPATH=$ddir/tests/systb/campus
    basef=$(basename $f)
    if [[ $basef != test_* ]]; then
      continue
    fi
    OPTS2="$OPTS2 --disable=W0403" #relative-import
    OPTS="$OPTS --disable=W0611" #unused-import
    OPTS="$OPTS --disable=W0612" #unused-variable
    OPTS="$OPTS --disable=W0404" #reimported
  elif [[ $f == */systb/* ]]; then
    basef=$(basename $f)
    if [[ $basef != test_* ]]; then
      continue
    fi
    if [[ $f == */systb/dc/vxlan/* ]]; then
        systb_dc=$ddir/tests/systb/dc
        systb_vxlan=$systb_dc/vxlan
        export SPYLINT_PYTHONPATH=$systb_dc:$systb_vxlan
    fi
    #dirf1=$(cd $(dirname $f);pwd -P)
    #dirf2=$(cd $(dirname $f)/..;pwd -P)
    #export SPYLINT_PYTHONPATH=$dirf1:$dirf2:$dirf1/st_common:$dirf2/st_common
    OPT_LINT_PYVER=3
    OPTS="$OPTS --disable=E0611" #no-name-in-module
    OPTS2="$OPTS2 --disable=W0403" #relative-import
    OPTS="$OPTS --disable=W0611" #unused-import
    OPTS="$OPTS --disable=W0612" #unused-variable
    OPTS="$OPTS --disable=W0404" #reimported
  fi

  if [[ $f == */ddm/* ]]; then
    OPTS="$OPTS --disable=C0121" #singleton-comparison
    OPTS="$OPTS --disable=R0123" #literal-comparison
    OPTS="$OPTS --disable=W0611" #unused-import
    OPTS="$OPTS --disable=W0612" #unused-variable
    OPTS="$OPTS --disable=W0404" #reimported
    RUFF_OPTS="$RUFF_OPTS --ignore E101" #mixed indentation
    RUFF_OPTS="$RUFF_OPTS --ignore E711" #none-comparison
    RUFF_OPTS="$RUFF_OPTS --ignore E712" #true-false-comparison
    RUFF_OPTS="$RUFF_OPTS --ignore F632" #literal-comparison
    RUFF_OPTS="$RUFF_OPTS --ignore F401" #unused-import
    RUFF_OPTS="$RUFF_OPTS --ignore F841" #unused-variable
    RUFF_OPTS="$RUFF_OPTS --ignore F811" #reimported
  fi

  if [ -n "$RUFF" ]; then
    $RUFF $RUFF_OPTS $f 2>&1 > $ERR_TEMP
    grep -q "may be undefined, or defined from star imports" $ERR_TEMP >/dev/null
    if [ $? -ne 0 ]; then
        print ================== RUFF $f  | tee -a $DBG_FILE
        lc=$(wc -l < $ERR_TEMP)
        if [ $lc -gt 0 ]; then
            print ================== RUFF $f  | tee -a $ERR_FILE
            cat $ERR_TEMP | tee -a $DBG_FILE $ERR_FILE
            print $lc $f | tee -a $REP_FILE
        fi
        continue
    elif [ "$LINT_TOOL" = "ruff-only" ]; then
        echo "Try with pylint $f" | tee -a $REP_FILE.err
        continue
    else
        echo "Using pylint $f"
    fi
  fi

  if [ -n "$FLAKE8" ]; then
    print ================== FLAKES8 $f  | tee -a $DBG_FILE
    $FLAKE8 $f 2>&1 | tee -a $DBG_FILE
  fi
  if [ -n "$PYFLAKES" ]; then
    print ================== PYFLAKES $f  | tee -a $DBG_FILE
    $PYFLAKES $f 2>&1 | tee -a $DBG_FILE
  fi
  if [ -z "$LINT2" -a -z "$LINT3" ]; then
    continue
  fi

  if [ $OPT_LINT_PYVER -eq 3 -o $OPT_LINT_PYVER -eq 0 ]; then
    #echo $LINT3 $OPTS $OPTS3 $f
    $LINT3 $OPTS $OPTS3 $f 2>&1 | grep -v "$using" | grep -v $line > $ERR_TEMP
    lc=$(wc -l < $ERR_TEMP)
    grep -q "$score" $ERR_TEMP >/dev/null
    if [ $? -ne 0 -a $lc -gt 0 ]; then
      print ================== PYLINT3 $f  | tee -a $DBG_FILE >/dev/null
      print ================== PYLINT3 $f  | tee -a $ERR_FILE
      cat $ERR_TEMP | tee -a $DBG_FILE $ERR_FILE
      print $lc $f | tee -a $REP_FILE
      continue
    fi
  fi

  if [ $OPT_LINT_PYVER -eq 2 -o $OPT_LINT_PYVER -eq 0 ]; then
    #echo $LINT2 $OPTS $OPTS2 $f
    $LINT2 $OPTS $OPTS2 $f 2>&1 | grep -v "$using" | grep -v $line > $ERR_TEMP
    lc=$(wc -l < $ERR_TEMP)
    grep -q "$score" $ERR_TEMP >/dev/null
    if [ $? -ne 0 -a $lc -gt 0 ]; then
      print ================== PYLINT2 $f  | tee -a $DBG_FILE >/dev/null
      print ================== PYLINT2 $f  | tee -a $ERR_FILE
      cat $ERR_TEMP | tee -a $DBG_FILE $ERR_FILE
      print $lc $f | tee -a $REP_FILE
      continue
    fi
  fi
  print ================== PYLINT $f  | tee -a $DBG_FILE
done

if [ -f $REP_FILE ]; then
    mv $REP_FILE $ERR_TEMP
    sort -rnk3 $ERR_TEMP > $REP_FILE
    err_count=$(awk -F" " '{x+=$3}END{print x}' $REP_FILE)
fi
print "================ COMPLETED $err_count ==================" >> $DBG_FILE
print "================ COMPLETED $err_count ==================" >> $ERR_FILE
