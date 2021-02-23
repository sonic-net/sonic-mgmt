#!/bin/bash

for ((i=1;i<=48;i++)); do
  sudo accton_as5712_util.py set sfp $i 0
done

