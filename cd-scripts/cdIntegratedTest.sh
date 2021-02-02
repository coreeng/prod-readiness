#!/usr/bin/env bash
set -eu

script_dir="$(cd "$(dirname "$0")" && pwd)"
project_dir="$(cd "${script_dir}/.." && pwd)"

export PATH=${PATH}:${GOPATH}/bin

function cleanup(){
    kind delete cluster --name kind-production-readiness
}

trap cleanup EXIT

make setup
kind create cluster --name kind-production-readiness --kubeconfig ${HOME}/.kube/kind-production-readiness
make -C ${project_dir} integrated-test