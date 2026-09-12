#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/cyber-sentinel/Cyber-Sentinel-Atlas"
RUNNER_NAME="ATLAS-CI-LNX01"
RUNNER_VERSION="2.337.0"
RUNNER_ARCHIVE="actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
RUNNER_URL="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${RUNNER_ARCHIVE}"
RUNNER_SHA256="70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613"
RUNNER_ROOT="/opt/atlas-runner"
RUNNER_USER="atlasrunner"
RUNNER_LABELS="atlas-ci,atlas-linux"

if [[ ${EUID} -ne 0 ]]; then
  echo "ERROR: run this script as root (sudo)." >&2
  exit 1
fi

if [[ -z "${GITHUB_RUNNER_TOKEN:-}" ]]; then
  echo "ERROR: set GITHUB_RUNNER_TOKEN to a fresh repository-scoped runner registration token." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl git jq tar gzip unzip \
  python3 python-is-python3 python3-venv python3-pip sqlite3 build-essential

if ! id "${RUNNER_USER}" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "${RUNNER_USER}"
fi

install -d -m 0750 -o "${RUNNER_USER}" -g "${RUNNER_USER}" "${RUNNER_ROOT}"

if [[ -e "${RUNNER_ROOT}/config.sh" ]]; then
  echo "ERROR: ${RUNNER_ROOT} already contains a runner installation. Decommission it before re-bootstrap." >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

curl --fail --location --proto '=https' --tlsv1.2 \
  --retry 8 --retry-delay 3 --retry-all-errors --connect-timeout 20 \
  --output "${tmpdir}/${RUNNER_ARCHIVE}" \
  "${RUNNER_URL}"

echo "${RUNNER_SHA256}  ${tmpdir}/${RUNNER_ARCHIVE}" | sha256sum --check --strict

tar -xzf "${tmpdir}/${RUNNER_ARCHIVE}" -C "${RUNNER_ROOT}"
chown -R "${RUNNER_USER}:${RUNNER_USER}" "${RUNNER_ROOT}"

cd "${RUNNER_ROOT}"

# Install OS dependencies recommended by the runner package.
./bin/installdependencies.sh

# Configure as the dedicated non-root account. The registration token is not persisted
# by this script and must be supplied through the environment only for bootstrap.
su -s /bin/bash -c "./config.sh --unattended --replace \
  --url '${REPO_URL}' \
  --token '${GITHUB_RUNNER_TOKEN}' \
  --name '${RUNNER_NAME}' \
  --labels '${RUNNER_LABELS}' \
  --work '_work'" "${RUNNER_USER}"

# Install and start the system service under the dedicated account.
./svc.sh install "${RUNNER_USER}"
./svc.sh start

unset GITHUB_RUNNER_TOKEN

echo "Runner bootstrap complete: ${RUNNER_NAME}"
echo "Expected labels: self-hosted, linux, x64, atlas-ci, atlas-linux"
echo "Verify it is Idle in GitHub repository Settings -> Actions -> Runners."
