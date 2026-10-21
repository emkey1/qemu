#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Checks each commit in BASE..HEAD against QEMU's coding style with checkpatch:
# an error fails the commit, a warning is only shown.
#   ci-checkpatch.sh BASE HEAD
#
set -euo pipefail
status=0

# meson-buildoptions.sh is generated, with lines as long as meson makes them.
paths=(. ':(exclude)scripts/meson-buildoptions.sh')

for c in $(git rev-list --reverse --no-merges "$1..$2"); do
  echo "=== $(git log -1 --format='%h %s' "$c")"
  if git diff --quiet "$c^" "$c" -- "${paths[@]}"; then
    continue
  fi
  git show --format=email "$c" -- "${paths[@]}" |
    scripts/checkpatch.pl --no-signoff - || status=1
done

exit $status
