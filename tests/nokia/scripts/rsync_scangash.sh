#!/bin/sh

rsync -P --recursive -e 'ssh -i /home/minion/.ssh/id_rsa_ci_srlinux -l ci' /home/minion/scangash/ anpyshl1.ipd.be.alcatel-lucent.com:/var/www/scangash
