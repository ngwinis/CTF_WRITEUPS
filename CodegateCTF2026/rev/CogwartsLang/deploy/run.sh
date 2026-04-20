#!/bin/sh
set -eu
umask 077

TMP="$(mktemp /tmp/solve.XXXXXX.grim)"
trap 'rm -f "$TMP"' EXIT

# Read the submitted Grimoire source from stdin.
# Limit: 64 KiB max, 10 second timeout.
echo "Input Grimoire source:"
if ! timeout 10 head -c 65536 > "$TMP"; then
  echo "Input timeout or read error"
  exit 1
fi

if [ ! -s "$TMP" ]; then
  echo "No input"
  exit 1
fi

# Basic resource limits to avoid runaway submissions.
ulimit -t 5
ulimit -v 524288

exec /home/cogwarts/bin/harness "$TMP" \
  --host /home/cogwarts/bin/liboracle_host.so \
  --host /home/cogwarts/bin/libstdlib_host.so
