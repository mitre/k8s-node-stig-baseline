#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE="${1:?usage: $0 <suite>}"
KIND_CLUSTER_NAME="k8s-node-stig-${SUITE}"
KUBECONFIG_PATH="${ROOT_DIR}/.kitchen/kind/${KIND_CLUSTER_NAME}.kubeconfig"

if command -v kind >/dev/null && kind get clusters | grep -Fxq "${KIND_CLUSTER_NAME}"; then
  kind delete cluster --name "${KIND_CLUSTER_NAME}"
fi

rm -f "${KUBECONFIG_PATH}"
rmdir "${ROOT_DIR}/.kitchen/kind" 2>/dev/null || true

rm -rf "${ROOT_DIR}/.kitchen/kind/${KIND_CLUSTER_NAME}-files"
