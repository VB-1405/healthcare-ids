#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

while inotifywait -r -e modify,create,delete,move .; do
  git add -A
  if git diff --cached --quiet; then
    continue
  fi
  git commit -m "auto update $(date '+%Y-%m-%d %H:%M:%S')" || true
  git push
done

