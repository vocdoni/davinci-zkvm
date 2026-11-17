#!/usr/bin/env bash
# Assign the BUSL-1.1 version and Change Date for a new release.
#
#   scripts/license/busl-release.sh <version> [<published YYYY-MM-DD>]
#
# <version> is the release version without the "v" (0.6.0). <published>
# defaults to today's UTC date and must be the day the release is pushed:
# never later than that (it would extend the restricted period), never in
# the future. The script:
#
#   1. computes Change Date = published + 3 calendar years;
#   2. appends "version,published,change_date" to licensing/busl-versions.csv;
#   3. writes the version and Change Date into LICENSE-BUSL and its copies;
#   4. runs scripts/license/check.sh.
#
# Commit the result, push it and create the v<version> tag on that commit
# the same day. See "Releasing" in CONTRIBUTING.md.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=scripts/license/common.sh
source scripts/license/common.sh

if [[ $# -lt 1 || $# -gt 2 ]]; then
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
version=$1
published=${2:-$(date -u +%F)}
today=$(date -u +%F)

die() { echo "error: $*" >&2; exit 1; }

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "bad version '$version' (expected X.Y.Z)"
valid_date "$published" || die "bad date '$published' (expected YYYY-MM-DD)"
if [[ "$published" > "$today" ]]; then die "published date $published is in the future (today is $today UTC)"; fi
if grep -qx "v$version" "$AGPL_VERSIONS"; then die "v$version was published under AGPL only"; fi
if ledger_rows "$LEDGER" | grep -q "^$version,"; then die "$version is already in $LEDGER (rows are never changed)"; fi
if git rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
  die "tag v$version already exists; a published version keeps its original terms"
fi
last=$(ledger_rows "$LEDGER" | tail -n 1)
if [[ -n "$last" ]]; then
  last_ver=$(cut -d, -f1 <<<"$last")
  last_pub=$(cut -d, -f2 <<<"$last")
  if [[ "$published" < "$last_pub" ]]; then die "published date is before the previous version's ($last)"; fi
  if [[ "$(printf '%s\n%s\n' "$last_ver" "$version" | sort -V | tail -n 1)" != "$version" ]]; then
    die "$version does not follow the last version $last_ver"
  fi
fi

change=$(change_date_for "$published")

# Roll every file back if anything below fails.
files=("$LEDGER" "$BUSL_FILE")
for d in "${BUSL_COPIES[@]}"; do files+=("$d/LICENSE-BUSL"); done
backup=$(mktemp -d)
for f in "${files[@]}"; do mkdir -p "$backup/$(dirname "$f")"; cp "$f" "$backup/$f"; done
restore() { for f in "${files[@]}"; do cp "$backup/$f" "$f"; done; echo "error: rolled back, nothing changed" >&2; }
trap 'restore' ERR

printf '%s,%s,%s\n' "$version" "$published" "$change" >> "$LEDGER"
sed -i \
  -e "s/^Licensed Work:        davinci-zkvm .*$/Licensed Work:        davinci-zkvm $version/" \
  -e "s/^Change Date:          .*$/Change Date:          $change/" \
  "$BUSL_FILE"
for d in "${BUSL_COPIES[@]}"; do cp "$BUSL_FILE" "$d/LICENSE-BUSL"; done

scripts/license/check.sh
trap - ERR
rm -rf "$backup"
echo
echo "BUSL-1.1 parameters set: davinci-zkvm $version, published $published, Change Date $change."
echo "Next: commit, push and tag v$version today (UTC)."
