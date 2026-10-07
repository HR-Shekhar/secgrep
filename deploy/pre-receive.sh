#!/bin/sh
# secgrep server-side pre-receive hook (self-hosted Git only).
#
# Install on the Git server (not available on github.com):
#   1. Put `secgrep` on the server PATH (or set SECGREP_BIN)
#   2. Copy this script to: <repo.git>/hooks/pre-receive
#   3. chmod +x <repo.git>/hooks/pre-receive
#
# Developers cannot bypass this with --no-verify.

set -eu

SECGREP_BIN="${SECGREP_BIN:-secgrep}"
zero=0000000000000000000000000000000000000000
# Git empty tree — used when a brand-new branch is pushed
empty=4b825dc642cb6eb9a060e54bf8d6927bbc6d1b78

while read oldrev newrev refname
do
  if [ "$newrev" = "$zero" ]; then
    continue
  fi

  if [ "$oldrev" = "$zero" ]; then
    range="${empty}..${newrev}"
  else
    range="${oldrev}..${newrev}"
  fi

  if ! "$SECGREP_BIN" scan --diff "$range" --format text; then
    echo "secgrep: rejecting push to $refname (secret policy)" >&2
    echo "Rotate the credential. Deleting the line is not enough." >&2
    exit 1
  fi
done

exit 0
