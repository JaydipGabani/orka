#!/bin/sh
set -eu
exec /usr/bin/python3 /checks/scenario.py "$1"
