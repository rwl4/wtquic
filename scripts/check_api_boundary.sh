#!/usr/bin/env bash
#
# API boundary check.
#
# The public surface (installed headers, examples, user-facing README) must
# speak WebTransport concepts — sessions, streams, datagrams, subprotocols —
# never H3/QPACK wire internals. Internal design docs, tests, and src/ are
# deliberately EXEMPT: this pins the public surface, it does not ban
# vocabulary.
#
# Escape hatch: a line containing `api-boundary-exempt` is skipped.
#
# Usage: check_api_boundary.sh <repo-root>

set -u

ROOT="${1:?usage: check_api_boundary.sh <repo-root>}"
cd "$ROOT" || exit 2

FORBIDDEN='qpack|huffman|varint|h3_frame|SETTINGS_|0x2843|0x78ae|quarter.?stream|preamble|field.section'

# Public surface only.
SURFACE=()
while IFS= read -r f; do SURFACE+=("$f"); done < <(
    find include/wtquic -name '*.h' -o -name '*.h.in' 2>/dev/null | sort
)
[ -f README.md ] && SURFACE+=(README.md)
while IFS= read -r f; do SURFACE+=("$f"); done < <(
    find examples -name '*.c' -o -name '*.h' 2>/dev/null | sort
)

failures=0
for f in "${SURFACE[@]}"; do
    hits=$(grep -inE "$FORBIDDEN" "$f" 2>/dev/null | grep -v 'api-boundary-exempt')
    if [ -n "$hits" ]; then
        echo "BOUNDARY VIOLATION in $f:"
        echo "$hits"
        failures=$((failures + 1))
    fi
done

if [ "$failures" -ne 0 ]; then
    echo "FAIL: $failures public-surface file(s) leak wire internals"
    exit 1
fi
echo "PASS: api_boundary (${#SURFACE[@]} public-surface files clean)"
exit 0
