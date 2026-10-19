#!/usr/bin/env bash
# Install the root service that caps battery charging.
#   sudo deploy/install-charge-limit.sh [LIMIT]   (default 85)
# Writes /usr/local/sbin/charge-limit and /etc/systemd/system/charge-limit.service.
# Undo: sudo systemctl disable --now charge-limit
#       sudo rm -f /etc/systemd/system/charge-limit.service /usr/local/sbin/charge-limit

set -euo pipefail

limit="${1:-85}"
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
helper_source="${project_dir}/deploy/charge-limit.sh"
unit_source="${project_dir}/deploy/charge-limit.service"
helper_target="/usr/local/sbin/charge-limit"
unit_target="/etc/systemd/system/charge-limit.service"

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: this needs root. Run it as: sudo $0 ${limit}" >&2
  exit 1
fi

if ! [[ "${limit}" =~ ^[0-9]+$ ]] || (( limit < 1 || limit > 100 )); then
  echo "error: LIMIT must be a whole number between 1 and 100, got '${limit}'" >&2
  exit 1
fi

for source in "${helper_source}" "${unit_source}"; do
  if [[ ! -f "${source}" ]]; then
    echo "error: ${source} is missing." >&2
    exit 1
  fi
done

install -d -m 0755 "$(dirname "${helper_target}")"
sed -e "s|__LIMIT__|${limit}|g" "${helper_source}" > "${helper_target}"
chmod 0755 "${helper_target}"
chown root:root "${helper_target}"

sed -e "s|__LIMIT__|${limit}|g" "${unit_source}" > "${unit_target}"
chmod 0644 "${unit_target}"
chown root:root "${unit_target}"

echo "Installed ${helper_target} and ${unit_target} (limit ${limit}%)"

systemctl daemon-reload
systemctl enable --now charge-limit.service

echo
echo "Applied now:"
for attribute in /sys/class/power_supply/BAT*/charge_control_end_threshold; do
  [[ -e "${attribute}" ]] || continue
  echo "  ${attribute} = $(cat "${attribute}")"
done
echo
echo "It will re-apply on every boot and after every resume."
echo "Check it with:  systemctl status charge-limit.service"
echo "Remove it with: sudo systemctl disable --now charge-limit"
