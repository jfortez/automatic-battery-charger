#!/bin/sh
# Cap battery charging at LIMIT percent.
# Best effort: a missing or read-only attribute is ignored, and the value is
# only written when it differs.

LIMIT=__LIMIT__

for attribute in /sys/class/power_supply/BAT*/charge_control_end_threshold; do
    [ -w "$attribute" ] || continue
    current=$(cat "$attribute" 2>/dev/null) || continue
    [ "$current" = "$LIMIT" ] && continue
    echo "$LIMIT" >"$attribute" 2>/dev/null || true
done

exit 0
