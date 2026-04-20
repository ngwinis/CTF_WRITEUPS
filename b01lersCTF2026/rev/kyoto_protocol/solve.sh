#!/usr/bin/env bash
set -euo pipefail

cp chall.sh chall.sh.bak 2>/dev/null || true
chmod +x chall chall.sh

for i in $(seq 1 1000); do
  echo "[*] round $i"

  timeout 5s bash -lc "printf 'aaa\n' | bash ./chall.sh | /usr/bin/head -n 2" >/dev/null 2>/dev/null || true

  if [[ -f flag.txt ]]; then
    echo "[+] flag.txt found"
    cat flag.txt
    exit 0
  fi

  if grep -a -q 'cat flag.txt' chall.sh 2>/dev/null; then
    echo "[+] flag-printer state reached"
    timeout 5s bash ./chall.sh >/dev/null 2>/dev/null || true
    [[ -f flag.txt ]] && cat flag.txt
    exit 0
  fi

  echo "    lines: $(wc -l < chall.sh)"
  tail -n 3 chall.sh | sed 's/[[:space:]]*$//'
done

echo "[-] not reached yet"
