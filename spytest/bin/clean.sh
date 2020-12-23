#!/bin/bash

cd $(dirname $0)/..

find . -name __pycache__ | xargs rm -rf
find . -name .pytest_cache | xargs rm -rf
find . -name "*.pyc" | xargs rm -f

