#!/usr/bin/env bash
#
# Backend-leak check.
#
# The core public headers must stay transport-agnostic: they may not name
# MsQuic types (HQUIC, QUIC_*) or pull in a backend/transport header. Only
# the backend-specific headers (wtquic_msquic.h, …) are allowed to. This
# keeps <wtquic/wtquic.h> and everything it includes free of any transport
# dependency.
#
# Usage: check_no_backend_leak.sh <repo-root>

set -u

ROOT="${1:?usage: check_no_backend_leak.sh <repo-root>}"
cd "$ROOT" || exit 2

# Naming a MsQuic handle/type, or including a transport header.
FORBIDDEN='\bHQUIC\b|\bQUIC_[A-Za-z0-9_]+|include[[:space:]]*[<"][^>"]*msquic'

failures=0
while IFS= read -r f; do
    case "$f" in
        # Backend headers legitimately speak MsQuic.
        */wtquic_msquic.h) continue ;;
    esac
    hits=$(grep -nE "$FORBIDDEN" "$f" 2>/dev/null)
    if [ -n "$hits" ]; then
        echo "BACKEND LEAK in $f:"
        echo "$hits"
        failures=$((failures + 1))
    fi
done < <(find include/wtquic -name '*.h' -o -name '*.h.in' 2>/dev/null | sort)

if [ "$failures" -ne 0 ]; then
    echo "FAIL: $failures core public header(s) expose a transport backend"
    exit 1
fi
echo "PASS: consumer_no_backend_leak (core headers transport-agnostic)"
exit 0
