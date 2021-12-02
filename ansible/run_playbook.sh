#!/bin/bash

basedir=`dirname $0`

function usage
{
  echo "run_playbook.sh - Run a playbook"
  echo "Usage: "
  echo "   $0 -p yaml_playbook -t target_box [-s <sonic_user>]"
  echo "   yaml_playbook - path to ansible playbook to run from the same directory where run_playbook.sh is"
  echo "   target_box - one of the boxes defined in westford_hw_inv.yaml file in $basedir"
  echo "   sonic_user - optional, and defaults to admin"
  echo "  "
  echo "   Example:"
  echo "     ./run_playbook.sh -p healthcheck.yml -t ixr_7250_x_pizza1"
  echo "     ./run_playbook.sh -p healthcheck.yml -t ixr_7250_x_pizza1 -s carl"
}


playbook=''
target_box=''
sonic_user="admin"
playbook_args=''

while getopts "e:p:s:t:" OPTION; do
    case $OPTION in
    e)
        playbook_args="${playbook_args} -e $OPTARG"
        ;;
    p)
        playbook=$OPTARG
        ;;
    s)
        playbook_args="${playbook_args} -e sonic_user=$OPTARG"
        ;;
    t) 
        target_box=$OPTARG
        ;;
    *)
        usage
    esac
done

if [[ "$playbook" == "" ]];
then
    echo "No playbook defined with -p"
    usage
    exit
fi

if [[ "$target_box" == "" ]];
then
    echo "No target box defined with -t"
    usage
    exit
fi


ansible_cmd="ansible-playbook -i $basedir/westford_hw_inventory $basedir/$playbook -l $target_box $playbook_args"
echo "Executing '$ansible_cmd'"

ansible-playbook -i $basedir/westford_hw_inventory $basedir/$playbook -l $target_box $playbook_args | tee /tmp/run_playbook_log 

result_line=`grep -n "PLAY RECAP" /tmp/run_playbook_log | awk -F : '{print $1}'`
#echo "result_line '$result_line"
# Get all the lines with results
result=`tail --lines=+$result_line /tmp/run_playbook_log | sed -e '/^$/,$d' | grep -v "PLAY RECAP"`
#echo "result '$result'"
failed=0
unreachable=0
# Iterate over each result line
while IFS= read -r line; do
  a_failed=`echo $line | awk -F : '{print $2}' | awk '{print $4}' | awk -F = '{print $2}'`
  a_unreachable=`echo $line | awk -F : '{print $2}' | awk '{print $3}' | awk -F = '{print $2}'`
  failed=$(($failed+$a_failed))
  unreachable=$(($unreachable+$a_unreachable))  
done <<< "$result"

#echo "failed: '$failed'"
#echo "unreachable: '$unreachable'"

if [[ "$failed" != "0" ]]; then
   echo "Playbook '$playbook' had '$failed' failures"
   exit 1
fi

if [[ "$unreachable" != "0" ]]; then
   echo "Playbook '$playbook' had '$unreachable' unreachable failures"
   exit 1
fi


echo "No failures found in playbook '$playbook'"
   
   

