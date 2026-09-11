#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE="${1:?usage: $0 <suite>}"
KIND_CLUSTER_NAME="k8s-node-stig-${SUITE}"
KIND_NODE_CONTAINER="${KIND_CLUSTER_NAME}-control-plane"
KUBECONFIG_PATH="${ROOT_DIR}/.kitchen/kind/${KIND_CLUSTER_NAME}.kubeconfig"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.32.2}"

require_command() {
  command -v "$1" >/dev/null || { echo "Required command not found: $1" >&2; exit 127; }
}

wait_for_cluster() {
  local attempt
  for attempt in $(seq 1 24); do
    if kubectl wait --for=condition=Ready nodes --all --timeout=10s; then
      return 0
    fi
    sleep 5
  done

  echo "Kind cluster did not become Ready within two minutes" >&2
  return 1
}

add_manifest_argument() {
  local manifest_path="$1"
  local component="$2"
  local argument="$3"

  if ! docker exec "${KIND_NODE_CONTAINER}" grep -Fq -- "    - --${argument}" "${manifest_path}"; then
    docker exec "${KIND_NODE_CONTAINER}" \
      sed -i "/^    - ${component}$/a\\    - --${argument}" "${manifest_path}"
  fi
}

configure_hardened_node() {
  local api_manifest controller_manifest scheduler_manifest etcd_manifest kubelet_config
  api_manifest='/etc/kubernetes/manifests/kube-apiserver.yaml'
  controller_manifest='/etc/kubernetes/manifests/kube-controller-manager.yaml'
  scheduler_manifest='/etc/kubernetes/manifests/kube-scheduler.yaml'
  etcd_manifest='/etc/kubernetes/manifests/etcd.yaml'
  kubelet_config='/var/lib/kubelet/config.yaml'

  docker cp "${ROOT_DIR}/provisioning/kind/hardened/audit-policy.yaml" \
    "${KIND_NODE_CONTAINER}:/etc/kubernetes/audit-policy.yaml"
  docker exec "${KIND_NODE_CONTAINER}" mkdir -p /var/log/kubernetes/audit
  docker exec "${KIND_NODE_CONTAINER}" chmod 0600 /etc/kubernetes/audit-policy.yaml

  add_manifest_argument "${api_manifest}" kube-apiserver 'audit-log-path=/var/log/kubernetes/audit/audit.log'
  add_manifest_argument "${api_manifest}" kube-apiserver 'audit-policy-file=/etc/kubernetes/audit-policy.yaml'
  add_manifest_argument "${api_manifest}" kube-apiserver 'audit-log-maxage=30'
  add_manifest_argument "${api_manifest}" kube-apiserver 'audit-log-maxbackup=10'
  add_manifest_argument "${api_manifest}" kube-apiserver 'audit-log-maxsize=100'
  add_manifest_argument "${api_manifest}" kube-apiserver 'request-timeout=1m'
  add_manifest_argument "${api_manifest}" kube-apiserver 'tls-min-version=VersionTLS12'
  add_manifest_argument "${api_manifest}" kube-apiserver 'tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
  add_manifest_argument "${controller_manifest}" kube-controller-manager 'profiling=false'
  add_manifest_argument "${controller_manifest}" kube-controller-manager 'tls-min-version=VersionTLS12'
  add_manifest_argument "${scheduler_manifest}" kube-scheduler 'tls-min-version=VersionTLS12'
  add_manifest_argument "${etcd_manifest}" etcd 'tls-min-version=TLS1.2'

  if ! docker exec "${KIND_NODE_CONTAINER}" grep -Fq -- 'mountPath: /etc/kubernetes/audit-policy.yaml' "${api_manifest}"; then
    docker exec "${KIND_NODE_CONTAINER}" sed -i "/^    volumeMounts:/a\\    - mountPath: /etc/kubernetes/audit-policy.yaml\\n      name: audit-policy\\n      readOnly: true\\n    - mountPath: /var/log/kubernetes/audit\\n      name: audit-log" "${api_manifest}"
  fi

  if ! docker exec "${KIND_NODE_CONTAINER}" grep -Fq -- 'path: /etc/kubernetes/audit-policy.yaml' "${api_manifest}"; then
    docker exec "${KIND_NODE_CONTAINER}" sed -i "/^  volumes:/a\\  - hostPath:\\n      path: /etc/kubernetes/audit-policy.yaml\\n      type: File\\n    name: audit-policy\\n  - hostPath:\\n      path: /var/log/kubernetes/audit\\n      type: DirectoryOrCreate\\n    name: audit-log" "${api_manifest}"
  fi

  docker exec "${KIND_NODE_CONTAINER}" \
    sed -i 's/^streamingConnectionIdleTimeout:.*/streamingConnectionIdleTimeout: 5m0s/' "${kubelet_config}"
  if docker exec "${KIND_NODE_CONTAINER}" grep -Eq '^protectKernelDefaults:' "${kubelet_config}"; then
    docker exec "${KIND_NODE_CONTAINER}" \
      sed -i 's/^protectKernelDefaults:.*/protectKernelDefaults: true/' "${kubelet_config}"
  else
    docker exec "${KIND_NODE_CONTAINER}" sh -c \
      "printf '\nprotectKernelDefaults: true\n' >> '${kubelet_config}'"
  fi

  docker exec "${KIND_NODE_CONTAINER}" systemctl restart kubelet
}

for command_name in kind kubectl docker; do require_command "${command_name}"; done

case "${SUITE}" in
  vanilla|hardened) ;;
  *)
    echo "Unknown Kind suite: ${SUITE}. Expected vanilla or hardened." >&2
    exit 2
    ;;
esac

KIND_CONFIG_FILE="${ROOT_DIR}/provisioning/kind/cluster.yaml"
[[ -f "${KIND_CONFIG_FILE}" ]] || { echo "Kind config not found: ${KIND_CONFIG_FILE}" >&2; exit 2; }

mkdir -p "$(dirname "${KUBECONFIG_PATH}")"
if ! kind get clusters | grep -Fxq "${KIND_CLUSTER_NAME}"; then
  kind create cluster --name "${KIND_CLUSTER_NAME}" --config "${KIND_CONFIG_FILE}" --image "${KIND_NODE_IMAGE}"
fi

kind export kubeconfig --name "${KIND_CLUSTER_NAME}" --kubeconfig "${KUBECONFIG_PATH}"
export KUBECONFIG="${KUBECONFIG_PATH}"
if [[ "${SUITE}" == 'hardened' ]]; then
  configure_hardened_node
fi
wait_for_cluster
kubectl cluster-info
