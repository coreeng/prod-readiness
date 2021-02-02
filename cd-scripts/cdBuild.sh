#!/usr/bin/env bash
set -eu

script_dir="$(cd "$(dirname "$0")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

export PATH=${PATH}:${GOPATH}/bin
echo "GOPATH: $GOPATH"
echo "PATH: $PATH"

make -C ${project_dir} setup docker