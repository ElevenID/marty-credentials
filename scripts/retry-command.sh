#!/usr/bin/env bash
set -euo pipefail

max_attempts="${MARTY_CI_RETRY_ATTEMPTS:-3}"
delay_seconds="${MARTY_CI_RETRY_DELAY_SECONDS:-5}"

if ! [[ "$max_attempts" =~ ^[1-9][0-9]*$ ]]; then
  echo "MARTY_CI_RETRY_ATTEMPTS must be a positive integer" >&2
  exit 2
fi
if ! [[ "$delay_seconds" =~ ^[0-9]+$ ]]; then
  echo "MARTY_CI_RETRY_DELAY_SECONDS must be a non-negative integer" >&2
  exit 2
fi
if [ "$#" -eq 0 ]; then
  echo "usage: retry-command.sh COMMAND [ARG ...]" >&2
  exit 2
fi

attempt=1
while true; do
  if "$@"; then
    exit 0
  else
    status=$?
  fi

  if [ "$attempt" -ge "$max_attempts" ]; then
    echo "command failed after $attempt attempt(s) with exit status $status" >&2
    exit "$status"
  fi

  echo "command failed on attempt $attempt/$max_attempts; retrying in ${delay_seconds}s" >&2
  sleep "$delay_seconds"
  attempt=$((attempt + 1))
done
