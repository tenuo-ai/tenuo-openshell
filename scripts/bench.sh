#!/usr/bin/env bash
# Reproduce docs/performance.md.
#
#   scripts/bench.sh [extra tenuo-openshell-bench arguments]
#
# Builds the release binaries, starts two throwaway Redis containers (plain
# and TLS) on loopback, records the machine, and runs every scenario at
# concurrency 1, 8, and 64. Results go to target/bench/<timestamp>.{txt,jsonl}.
#
# Environment:
#   BENCH_REDIS_PORT    plain Redis host port (default 6390)
#   BENCH_REDISS_PORT   TLS Redis host port (default 6391)
#   BENCH_REDIS_IMAGE   Redis image (default redis:7.4-alpine)
#   BENCH_SKIP_REDIS=1  run only the scenarios that need no Redis
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

redis_port="${BENCH_REDIS_PORT:-6390}"
rediss_port="${BENCH_REDISS_PORT:-6391}"
image="${BENCH_REDIS_IMAGE:-redis:7.4-alpine}"
plain="tenuo-bench-redis-$$"
tls="tenuo-bench-rediss-$$"
work="$(mktemp -d)"
out="$ROOT/target/bench"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out"

cleanup() {
  if [ "${BENCH_SKIP_REDIS:-0}" != 1 ]; then
    docker rm -f "$plain" "$tls" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

cargo build --release --locked --bin tenuo-openshell-middleware --bin tenuo-openshell-bench

redis_args=()
if [ "${BENCH_SKIP_REDIS:-0}" != 1 ]; then
  command -v docker >/dev/null || { echo "docker is required; set BENCH_SKIP_REDIS=1 to skip Redis" >&2; exit 2; }
  # A throwaway CA and a server certificate for 127.0.0.1. The middleware
  # verifies it the way it would in production: SSL_CERT_FILE replaces the
  # native root store for this run only.
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=tenuo-bench-ca" \
    -keyout "$work/ca.key" -out "$work/ca.crt" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" \
    -keyout "$work/redis.key" -out "$work/redis.csr" >/dev/null 2>&1
  printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' >"$work/redis.ext"
  openssl x509 -req -days 1 -in "$work/redis.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
    -CAcreateserial -extfile "$work/redis.ext" -out "$work/redis.crt" >/dev/null 2>&1
  chmod 644 "$work/redis.key" "$work/redis.crt" "$work/ca.crt"
  # No RDB snapshots or AOF: replay claims live for minutes, and a snapshot
  # fork mid-run would show up as latency that is not the middleware's.
  docker run -d --rm --name "$plain" -p "127.0.0.1:$redis_port:6379" "$image" \
    redis-server --save '' --appendonly no >/dev/null
  docker run -d --rm --name "$tls" -p "127.0.0.1:$rediss_port:6379" -v "$work:/tls:ro" "$image" \
    redis-server --save '' --appendonly no --port 0 --tls-port 6379 \
    --tls-cert-file /tls/redis.crt --tls-key-file /tls/redis.key \
    --tls-ca-cert-file /tls/ca.crt --tls-auth-clients no >/dev/null
  for _ in $(seq 1 50); do
    if docker exec "$plain" redis-cli ping >/dev/null 2>&1 &&
      docker exec "$tls" redis-cli --tls --cacert /tls/ca.crt ping >/dev/null 2>&1; then
      break
    fi
    sleep 0.2
  done
  docker exec "$plain" redis-cli ping >/dev/null
  docker exec "$tls" redis-cli --tls --cacert /tls/ca.crt ping >/dev/null
  redis_args=(--redis-url "redis://127.0.0.1:$redis_port/" --rediss-url "rediss://127.0.0.1:$rediss_port/")
  export SSL_CERT_FILE="$work/ca.crt"
fi

{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit: $(git rev-parse --short HEAD)$(git diff --quiet HEAD -- src Cargo.toml Cargo.lock || echo ' (dirty)')"
  case "$(uname -s)" in
    Darwin)
      echo "cpu: $(sysctl -n machdep.cpu.brand_string)"
      echo "cores: $(sysctl -n hw.ncpu) ($(sysctl -n hw.perflevel0.physicalcpu 2>/dev/null || echo ?) performance, $(sysctl -n hw.perflevel1.physicalcpu 2>/dev/null || echo ?) efficiency)"
      echo "memory: $(($(sysctl -n hw.memsize) / 1073741824)) GiB"
      echo "os: macOS $(sw_vers -productVersion) $(uname -m)"
      ;;
    *)
      echo "cpu: $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ //' || uname -m)"
      echo "cores: $(nproc)"
      echo "memory: $(awk '/MemTotal/ {printf "%d GiB", $2/1048576}' /proc/meminfo)"
      echo "os: $(uname -sr) $(uname -m)"
      ;;
  esac
  echo "load average at start: $(uptime | sed 's/.*load averages*: //')"
  echo "rustc: $(rustc --version)"
  if [ "${BENCH_SKIP_REDIS:-0}" != 1 ]; then
    echo "docker: $(docker version --format '{{.Server.Version}}' 2>/dev/null) ($(docker info --format '{{.OperatingSystem}}' 2>/dev/null))"
    echo "redis: $(docker exec "$plain" redis-server --version | sed 's/ sha=.*//')"
  fi
  echo
  target/release/tenuo-openshell-bench "${redis_args[@]}" --json "$out/$stamp.jsonl" "$@"
  echo
  echo "load average at end: $(uptime | sed 's/.*load averages*: //')"
} 2>&1 | tee "$out/$stamp.txt"

echo "results: $out/$stamp.txt"
