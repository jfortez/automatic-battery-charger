#!/usr/bin/env bash
# Install the systemd user unit. Idempotent; never uses sudo and never
# enables or starts the service.

set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
abc_bin="${project_dir}/.venv/bin/abc"
template="${project_dir}/deploy/battery-charger.service"
unit_dir="${XDG_CONFIG_HOME:-${HOME}/.config}/systemd/user"
unit_path="${unit_dir}/battery-charger.service"

if [[ ! -x "${abc_bin}" ]]; then
  echo "error: ${abc_bin} is missing or not executable." >&2
  echo "Run 'uv sync' in ${project_dir} first, then re-run this script." >&2
  exit 1
fi

if [[ ! -f "${template}" ]]; then
  echo "error: ${template} is missing." >&2
  exit 1
fi

mkdir -p "${unit_dir}"

temporary="$(mktemp "${unit_dir}/.battery-charger.service.XXXXXX")"
trap 'rm -f "${temporary}"' EXIT
sed -e "s|__PROJECT_DIR__|${project_dir//|/\\|}|g" \
    -e "s|__ABC__|${abc_bin//|/\\|}|g" \
    "${template}" > "${temporary}"
chmod 0644 "${temporary}"
mv "${temporary}" "${unit_path}"
trap - EXIT

echo "Installed ${unit_path}"

if systemctl --user daemon-reload 2>/dev/null; then
  echo "Reloaded the systemd user manager."
else
  echo "note: 'systemctl --user daemon-reload' did not run (no user session?);"
  echo "      run it once a user session is available."
fi

cat <<EOF

Nothing was enabled or started. To do that:

  systemctl --user enable battery-charger.service
  systemctl --user start battery-charger.service

To watch the log:

  journalctl --user -u battery-charger.service -f

To stop it (the unit switches the plug OFF on stop):

  systemctl --user stop battery-charger.service
EOF
