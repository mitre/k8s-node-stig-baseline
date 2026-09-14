#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SUITE="${1:?usage: $0 <suite>}"
INPUT_FILE="${ROOT_DIR}/kind.${SUITE}.inputs.yml"
KIND_CLUSTER_NAME="k8s-node-stig-${SUITE}"
KIND_NODE_CONTAINER="${KIND_CLUSTER_NAME}-control-plane"
KUBECONFIG_PATH="${ROOT_DIR}/.kitchen/kind/${KIND_CLUSTER_NAME}.kubeconfig"
RESULTS_DIR="${ROOT_DIR}/results"
RESULT_FILE="${RESULTS_DIR}/kind_${SUITE}.json"

[[ -f "${INPUT_FILE}" ]] || { echo "Missing suite inputs: ${INPUT_FILE}" >&2; exit 2; }
[[ -f "${KUBECONFIG_PATH}" ]] || { echo "Cluster kubeconfig not found; run kitchen create ${SUITE} first" >&2; exit 2; }
docker inspect "${KIND_NODE_CONTAINER}" >/dev/null 2>&1 || { echo "Kind node container not found: ${KIND_NODE_CONTAINER}" >&2; exit 2; }

export KUBECONFIG="${KUBECONFIG_PATH}"
# Train's Docker transport does not automatically follow non-default Docker
# contexts (for example Docker Desktop on macOS), so pass the active endpoint.
if [[ -z "${DOCKER_HOST:-}" ]]; then
  DOCKER_HOST="$(docker context inspect --format '{{.Endpoints.docker.Host}}' "$(docker context show)")"
  export DOCKER_HOST
fi
mkdir -p "${RESULTS_DIR}"
kubectl wait --for=condition=Ready nodes --all --timeout=2m

rm -f "${RESULT_FILE}"
set +e
bundle exec cinc-auditor exec "${ROOT_DIR}" \
  --target "docker://${KIND_NODE_CONTAINER}" \
  --no-distinct-exit \
  --input-file "${INPUT_FILE}" \
  --reporter cli "json:${RESULT_FILE}"
cinc_status=$?
set -e

# Cinc exits nonzero when controls fail. A complete JSON report is successful
# suite execution; the later SAF threshold step decides whether its findings
# are acceptable. Missing, malformed, or empty reports remain infrastructure
# failures and stop Kitchen here.
if [[ ! -s "${RESULT_FILE}" ]]; then
  echo "Cinc Auditor did not create a result: ${RESULT_FILE}" >&2
  (( cinc_status == 0 )) && exit 1
  exit "${cinc_status}"
fi
bundle exec ruby -rjson -e \
  'report = JSON.parse(File.read(ARGV.fetch(0))); exit(report.fetch("profiles").flat_map { |profile| profile.fetch("controls", []) }.empty? ? 1 : 0)' \
  "${RESULT_FILE}"

if (( cinc_status != 0 )); then
  echo "Cinc Auditor reported control findings (exit ${cinc_status}); SAF will enforce the suite threshold."
fi
