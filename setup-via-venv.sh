#!/bin/env bash
# https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/
# setup venv (if not existing), activate, update, and ensure requirements are met

_PWD="$(dirname $(realpath -s "$0"))"
_FNAME="$(basename "$0")"
_VENV="$_PWD/.venv"

if [[ -n $1 ]]; then
  cat<<EOF
usage: ${_FNAME}

simply running ${_FNAME} will install a new local venv to ./.venv if missing,
  update pip and ensure that all requirements are satisfied

to activate the new venv run:
  $_VENV/bin/activate
or alias
  $_PWD/venv-activate
EOF
  exit 1
fi

if [[ ! -d "$_PWD"/.venv ]]; then
  echo "> no .venv directory found in [$_PWD], setting up new local venv"
  python3 -m venv "$_VENV"
  chmod +x "$_VENV"/bin/activate
  ln -sf "$_VENV"/bin/activate "$_PWD"/venv-activate
fi

echo "> activating venv"
source "$_VENV"/bin/activate

echo "> updating pip"
python3 -m pip install --upgrade pip
echo "> ensuring that all requirements are setisfied"
python3 -m pip install -r "$_PWD"/requirements.txt

