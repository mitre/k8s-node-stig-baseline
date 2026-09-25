#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE="${1:?usage: $0 <suite>}"
KIND_CLUSTER_NAME="k8s-node-stig-${SUITE}"
KUBECONFIG_PATH="${ROOT_DIR}/.kitchen/kind/${KIND_CLUSTER_NAME}.kubeconfig"
RESULTS_DIR="${ROOT_DIR}/results"

# One scan per node role: <role> <container suffix> <inputs file> <result file>
SCAN_TARGETS=(
  "control-plane control-plane kind.${SUITE}.inputs.yml        kind_${SUITE}.json"
  "worker        worker         kind.${SUITE}.worker.inputs.yml kind_${SUITE}_worker.json"
)

[[ -f "${KUBECONFIG_PATH}" ]] || { echo "Cluster kubeconfig not found; run kitchen create ${SUITE} first" >&2; exit 2; }

export KUBECONFIG="${KUBECONFIG_PATH}"
# Train's Docker transport does not automatically follow non-default Docker
# contexts (for example Docker Desktop on macOS), so pass the active endpoint.
if [[ -z "${DOCKER_HOST:-}" ]]; then
  DOCKER_HOST="$(docker context inspect --format '{{.Endpoints.docker.Host}}' "$(docker context show)")"
  export DOCKER_HOST
fi
mkdir -p "${RESULTS_DIR}"
kubectl wait --for=condition=Ready nodes --all --timeout=2m

overall_status=0
for target in "${SCAN_TARGETS[@]}"; do
  read -r role container_suffix inputs_name result_name <<<"${target}"
  node_container="${KIND_CLUSTER_NAME}-${container_suffix}"
  input_file="${ROOT_DIR}/${inputs_name}"
  result_file="${RESULTS_DIR}/${result_name}"

  [[ -f "${input_file}" ]] || { echo "Missing suite inputs: ${input_file}" >&2; exit 2; }
  docker inspect "${node_container}" >/dev/null 2>&1 || { echo "Kind node container not found: ${node_container}" >&2; exit 2; }

  echo "==> Scanning ${role} node ${node_container} with ${inputs_name}"
  rm -f "${result_file}"
  set +e
  bundle exec cinc-auditor exec "${ROOT_DIR}" \
    --target "docker://${node_container}" \
    --no-distinct-exit \
    --input-file "${input_file}" \
    --reporter cli "json:${result_file}"
  cinc_status=$?
  set -e

  # Cinc exits nonzero when controls fail. A complete JSON report is successful
  # suite execution; the later SAF threshold step decides whether its findings
  # are acceptable. Missing, malformed, or empty reports remain infrastructure
  # failures and stop Kitchen here.
  if [[ ! -s "${result_file}" ]]; then
    echo "Cinc Auditor did not create a result for the ${role} node: ${result_file}" >&2
    (( cinc_status == 0 )) && exit 1
    exit "${cinc_status}"
  fi
  bundle exec ruby -rjson -e \
    'report = JSON.parse(File.read(ARGV.fetch(0))); exit(report.fetch("profiles").flat_map { |profile| profile.fetch("controls", []) }.empty? ? 1 : 0)' \
    "${result_file}"

  (( cinc_status != 0 )) && overall_status=1
done

if (( overall_status != 0 )); then
  echo "Cinc Auditor reported control findings; SAF will enforce the suite thresholds."
fi
