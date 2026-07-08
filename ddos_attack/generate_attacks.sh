#!/usr/bin/env bash
#
# Generate per-source DoS pcap dataset using tshark + hping3.
#
# For each attack class:
#   1. Start tshark on the loopback interface, auto-stops after DURATION seconds.
#   2. Start hping3 in background with one fixed source IP and a paced rate
#      (-i u500 ≈ ~2000 pps from this single "bot").
#   3. When tshark finishes, kill hping3 and move on.
#
# The output is one pcap per attack class in $OUTPUT_DIR.
# Run as root (tshark + hping3 both need raw socket access).
#
# Configurable via env vars:
#   TARGET_IP, TARGET_PORT, INTERFACE, DURATION, PACE, OUTPUT_DIR
#
# Notes / gotchas:
#   - On loopback, the kernel may drop "martian" sources if rp_filter is strict.
#     If pcaps come out empty, try:
#       sudo sysctl -w net.ipv4.conf.lo.rp_filter=0
#       sudo sysctl -w net.ipv4.conf.all.rp_filter=0
#   - Capturing is unfiltered, so other lo traffic (postgres, dev servers) ends
#     up in the pcap too. Filter at analysis time if needed.
#   - The pcap covers BOTH directions: attack packets AND kernel responses
#     (SYN-ACK / RST / ICMP echo-reply / ICMP unreachable). That is intentional
#     — it mirrors what a victim-side sensor sees in production.
#   - dumpcap (forked by tshark) drops ALL Linux capabilities to zero right after
#     opening the raw socket — including CAP_DAC_OVERRIDE. That means the pcap
#     write step runs with euid=0 but no DAC bypass, so it cannot traverse a
#     0750 home directory like /home/ivan/. We work around this by writing
#     pcaps to a world-traversable staging dir (/tmp by default) and moving
#     them to OUTPUT_DIR afterwards under the still-fully-privileged shell.

set -euo pipefail

# ---- Configuration -----------------------------------------------------------

TARGET_IP="${TARGET_IP:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-80}"
INTERFACE="${INTERFACE:-lo}"
DURATION="${DURATION:-60}"            # seconds of capture per attack class
PACE="${PACE:-u500}"                  # hping3 -i: u500 ≈ ~2000 pps
OUTPUT_DIR="${OUTPUT_DIR:-$(dirname "$(readlink -f "$0")")/pcap}"
# Staging dir must be world-traversable, otherwise the capability-dropped
# dumpcap child cannot openat() the pcap file. /tmp is 1777, which fits.
STAGING_DIR="${STAGING_DIR:-/tmp/generate_attacks.$$}"

# Per-class single "bot" src IP. One bot per class for now; extend later
# by running the script multiple times with different SRC_IP[*] values.
declare -A SRC_IP=(
  [syn]=10.0.0.42
  [ack]=10.0.0.43
  [fin]=10.0.0.44
  [push]=10.0.0.45
  [rst]=10.0.0.46
  [udp]=10.0.0.47
  [icmp]=10.0.0.48
)

# Per-class hping3 flags (everything except -a, -i, target).
declare -A HPING_FLAGS=(
  [syn]="--syn -p ${TARGET_PORT}"
  [ack]="-A   -p ${TARGET_PORT}"
  [fin]="-F   -p ${TARGET_PORT}"
  [push]="-P  -p ${TARGET_PORT}"
  [rst]="-R   -p ${TARGET_PORT}"
  [udp]="--udp -p ${TARGET_PORT}"
  [icmp]="--icmp"
)

ATTACK_CLASSES=(syn ack fin push rst udp icmp)

# ---- Sanity checks -----------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: must run as root (tshark + hping3 need raw socket access)." >&2
  echo "Try: sudo $0" >&2
  exit 1
fi

for bin in tshark hping3; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "ERROR: '$bin' not found in PATH. Install it and retry." >&2
    exit 1
  fi
done

mkdir -p "$OUTPUT_DIR" "$STAGING_DIR"

# ---- Cleanup hook ------------------------------------------------------------

TSHARK_PID=""
HPING_PID=""

cleanup() {
  if [[ -n "${HPING_PID:-}" ]]; then
    kill "${HPING_PID}" 2>/dev/null || true
  fi
  if [[ -n "${TSHARK_PID:-}" ]]; then
    kill "${TSHARK_PID}" 2>/dev/null || true
  fi
  wait 2>/dev/null || true
  rm -rf "${STAGING_DIR}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ---- Single attack run -------------------------------------------------------

run_attack() {
  local label=$1
  local src=${SRC_IP[$label]}
  local flags=${HPING_FLAGS[$label]}
  local staged="${STAGING_DIR}/${label}.pcap"
  local final="${OUTPUT_DIR}/${label}.pcap"

  echo "=== [${label}] ${DURATION}s | src=${src} → ${TARGET_IP} | ${flags} | -i ${PACE}"
  echo "    staged: ${staged}"
  echo "    final:  ${final}"

  # shellcheck disable=SC2086
  hping3 ${flags} -a "${src}" -i "${PACE}" "${TARGET_IP}" \
    >/dev/null 2>&1 &
  HPING_PID=$!

  # Foreground tshark blocks for DURATION seconds, then exits cleanly.
  # No `wait $PID` needed → no race with bash's auto-reaping.
  # Write to STAGING_DIR (1777) because dumpcap drops caps before opening
  # the pcap and cannot traverse a 0750 home directory anymore.
  tshark -i "${INTERFACE}" -a duration:"${DURATION}" -w "${staged}" -q \
    >/dev/null || true

  kill "${HPING_PID}" 2>/dev/null || true
  wait "${HPING_PID}" 2>/dev/null || true
  HPING_PID=""

  # Promote the staged pcap into the project directory while we still hold
  # full root + capabilities (mv is run by the parent shell, not dumpcap).
  if [[ -s "${staged}" ]]; then
    mv -f "${staged}" "${final}"
  else
    echo "    WARNING: staged pcap missing or empty, skipping move." >&2
    rm -f "${staged}" 2>/dev/null || true
  fi

  if [[ -f "${final}" ]] && command -v capinfos >/dev/null 2>&1; then
    local n_pkts size
    n_pkts=$(capinfos -c "${final}" 2>/dev/null \
      | awk -F: '/Number of packets/ {gsub(/[^0-9]/, "", $2); print $2}')
    size=$(du -h "${final}" | cut -f1)
    echo "    captured: ${n_pkts:-?} packets, ${size}"
  fi
  echo ""
}

# ---- Main --------------------------------------------------------------------

echo "Output dir:        ${OUTPUT_DIR}"
echo "Staging dir:       ${STAGING_DIR}"
echo "Capture interface: ${INTERFACE}"
echo "Target:            ${TARGET_IP}:${TARGET_PORT}"
echo "Duration / class:  ${DURATION}s"
echo "Pace (-i):         ${PACE}"
echo "Classes:           ${ATTACK_CLASSES[*]}"
echo ""

for label in "${ATTACK_CLASSES[@]}"; do
  run_attack "$label"
done

echo "Done."
ls -lh "${OUTPUT_DIR}/"
