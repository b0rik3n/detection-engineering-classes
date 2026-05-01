#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/b0rik3n/detection-engineering-classes.git}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/detection-engineering-classes}"
BRANCH="${BRANCH:-main}"
PRELOAD_LABS="${PRELOAD_LABS:-true}"
START_SPLUNK="${START_SPLUNK:-false}"
MIN_MEM_GB="${MIN_MEM_GB:-6}"
MIN_DISK_GB="${MIN_DISK_GB:-25}"
MIN_CPU_CORES="${MIN_CPU_CORES:-2}"

log() { printf '\n[+] %s\n' "$*"; }
warn() { printf '\n[!] %s\n' "$*" >&2; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

if [[ ! -r /etc/os-release ]]; then
  echo "Unsupported Linux: /etc/os-release not found" >&2
  exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release
OS_ID="${ID,,}"
OS_LIKE="${ID_LIKE,,}"

check_minimum_requirements() {
  log "Checking minimum requirements"

  local mem_kb mem_gb disk_kb disk_gb cpu_cores
  mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
  mem_gb=$((mem_kb / 1024 / 1024))
  disk_kb=$(df -Pk "$HOME" | awk 'NR==2 {print $4}')
  disk_gb=$((disk_kb / 1024 / 1024))
  cpu_cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc)

  echo "Detected: ${cpu_cores} CPU cores, ${mem_gb}GB RAM, ${disk_gb}GB free under $HOME"
  echo "Minimum: ${MIN_CPU_CORES} CPU cores, ${MIN_MEM_GB}GB RAM, ${MIN_DISK_GB}GB free disk"

  local failed=false
  if (( cpu_cores < MIN_CPU_CORES )); then
    warn "CPU cores below minimum. Mucaro Scout may run slowly."
    failed=true
  fi
  if (( mem_gb < MIN_MEM_GB )); then
    warn "RAM below minimum. OpenSearch Dashboards may be unstable."
    failed=true
  fi
  if (( disk_gb < MIN_DISK_GB )); then
    warn "Free disk below minimum. Docker image pulls may fail."
    failed=true
  fi

  if [[ "${failed}" == "true" ]]; then
    warn "Continuing anyway. Set MIN_MEM_GB/MIN_DISK_GB/MIN_CPU_CORES lower if this is intentional."
  fi
}

install_base_packages_debian() {
  log "Installing base packages with apt"
  ${SUDO} apt-get update
  ${SUDO} apt-get install -y ca-certificates curl git gnupg lsb-release make python3
}

install_base_packages_rhel() {
  log "Installing base packages with dnf/yum"
  if need_cmd dnf; then
    ${SUDO} dnf install -y ca-certificates curl git make python3 yum-utils
  else
    ${SUDO} yum install -y ca-certificates curl git make python3 yum-utils
  fi
}

install_docker_debian() {
  if need_cmd docker && docker compose version >/dev/null 2>&1; then
    log "Docker and Docker Compose plugin already installed"
    return
  fi

  install_base_packages_debian
  log "Installing Docker from Docker's apt repository"
  ${SUDO} install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" | ${SUDO} gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  ${SUDO} chmod a+r /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${OS_ID} ${VERSION_CODENAME} stable" \
    | ${SUDO} tee /etc/apt/sources.list.d/docker.list >/dev/null
  ${SUDO} apt-get update
  ${SUDO} apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

install_docker_rhel() {
  if need_cmd docker && docker compose version >/dev/null 2>&1; then
    log "Docker and Docker Compose plugin already installed"
    return
  fi

  install_base_packages_rhel
  log "Installing Docker from Docker's yum repository"
  if need_cmd dnf; then
    ${SUDO} dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    ${SUDO} dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  else
    ${SUDO} yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    ${SUDO} yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  fi
}

install_docker() {
  case "${OS_ID}:${OS_LIKE}" in
    ubuntu:*|debian:*|*:debian*) install_docker_debian ;;
    rhel:*|centos:*|rocky:*|almalinux:*|fedora:*|*:rhel*|*:fedora*) install_docker_rhel ;;
    *)
      echo "Unsupported distro: ID=${ID} ID_LIKE=${ID_LIKE:-}" >&2
      echo "Install Docker manually, then rerun this script." >&2
      exit 1
      ;;
  esac

  log "Enabling Docker service"
  ${SUDO} systemctl enable --now docker

  if [[ -n "${SUDO}" ]]; then
    if ! id -nG "${USER}" | grep -qw docker; then
      log "Adding ${USER} to docker group"
      ${SUDO} usermod -aG docker "${USER}"
      warn "You may need to log out and back in before running docker without sudo. This script will use sudo when needed."
    fi
  fi
}

docker_cmd() {
  if docker ps >/dev/null 2>&1; then
    docker "$@"
  else
    ${SUDO} docker "$@"
  fi
}

clone_or_update_repo() {
  if [[ -d "${INSTALL_DIR}/.git" ]]; then
    log "Updating existing repo at ${INSTALL_DIR}"
    git -C "${INSTALL_DIR}" fetch origin "${BRANCH}"
    git -C "${INSTALL_DIR}" checkout "${BRANCH}"
    git -C "${INSTALL_DIR}" pull --ff-only origin "${BRANCH}"
  else
    log "Cloning labs repo to ${INSTALL_DIR}"
    git clone --branch "${BRANCH}" "${REPO_URL}" "${INSTALL_DIR}"
  fi
}

start_scout() {
  local scout_dir="${INSTALL_DIR}/labs/mucaro-scout"
  if [[ ! -f "${scout_dir}/docker-compose.yml" ]]; then
    echo "Mucaro Scout compose file not found at ${scout_dir}/docker-compose.yml" >&2
    exit 1
  fi

  log "Starting Mucaro Scout"
  (cd "${scout_dir}" && docker_cmd compose up -d --build)

  log "Waiting for Scout API"
  for _ in {1..60}; do
    if curl -fsS http://localhost:8000/health >/dev/null 2>&1; then
      echo "Scout API is ready."
      return
    fi
    sleep 2
  done
  echo "Scout API did not become ready within 120 seconds" >&2
  exit 1
}

preload_labs() {
  if [[ "${PRELOAD_LABS}" != "true" ]]; then
    log "Skipping lab preload because PRELOAD_LABS=${PRELOAD_LABS}"
    return
  fi
  log "Preloading lab data into Scout SQLite"
  (cd "${INSTALL_DIR}" && ./scripts/preload-scout-labs.sh)
}

start_splunk_optional() {
  if [[ "${START_SPLUNK}" != "true" ]]; then
    return
  fi
  log "Starting optional Splunk lab container"
  curl -fsS -X POST http://localhost:8000/integrations/splunk/start || true
  echo
  warn "Splunk first boot can take several minutes. Open http://localhost:8001 when ready."
}

main() {
  log "Mucaro Scout installer"
  check_minimum_requirements
  install_docker
  clone_or_update_repo
  start_scout
  preload_labs
  start_splunk_optional

  cat <<EOF

Mucaro Scout is ready.

Open:
  Scout UI:        http://localhost:5173
  Scout API:       http://localhost:8000/health
  SQLite health:   http://localhost:8000/health/sqlite
  Dashboards:      http://localhost:5601

Optional Splunk:
  START_SPLUNK=true $0
  Splunk UI:       http://localhost:8001
  Splunk login:    admin / admin1234

Useful overrides:
  INSTALL_DIR=$HOME/detection-engineering-classes PRELOAD_LABS=true $0
  PRELOAD_LABS=false $0

EOF
}

main "$@"
