#!/bin/bash

rm -rf .pytest_cache

readlink=$(which greadlink 2>/dev/null) || readlink=$(which readlink)
base_dir=$(cd $(dirname $(${readlink} -f "$0")); pwd)

echo "Cleaning *.pyc files ..."
find $base_dir -name \*.pyc | xargs rm 2>/dev/null

echo "Running PEP8 checks (flake8) ..."
flake8 r2flutch
flake8_ecode=$?

echo "Running pylint ..."
pylint r2flutch
pylint_ecode=$?

python -m coverage run --source=r2flutch -m pytest test/ -v -rsx -k "test_"
ecode=$?
coverage report -m --omit="*/venv/*"

if [ $flake8_ecode -ne 0 ]; then
    echo ".-----------------------------------------------------------------------."
    echo "|  ERROR: flake8 found PEP8 violations                                 |"
    echo "'-----------------------------------------------------------------------'"
    exit $flake8_ecode
fi

if [ $pylint_ecode -ne 0 ]; then
    echo ".-----------------------------------------------------------------------."
    echo "|  ERROR: pylint found issues                                           |"
    echo "'-----------------------------------------------------------------------'"
    exit $pylint_ecode
fi

if [ $ecode -eq 5 ]; then
    echo ".-----------------------------------------------------------------------."
    echo "|  WARNING: No tests found!                                             |"
    echo "'-----------------------------------------------------------------------'"
    exit 0
fi
exit $ecode