#!/bin/bash
PROJECT="iottly_core"

# If the script moves this must be changed!
ROOT="$(dirname $0)"

SCRIPTS_DIR=$ROOT

PYTHON="/usr/bin/python"

PYTHONPATH=$ROOT:$ROOT/$PROJECT; export PYTHONPATH

script_name=$1
shift 1;
args=$@

$PYTHON $SCRIPTS_DIR/$script_name $args
