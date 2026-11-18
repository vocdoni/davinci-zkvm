#!/usr/bin/env bash
# Validate the repository's license metadata. Run from anywhere:
#
#   scripts/license/check.sh                      # Change Date must be set
#   scripts/license/check.sh --base origin/main   # also: ledger is append-only
#   scripts/license/check.sh --tag v0.6.0         # also: tag matches its ledger row
#   scripts/license/check.sh --allow-unset        # local only: accept "[NOT SET]"
#
# CI never passes --allow-unset: nothing may be published with LICENSE-BUSL
# parameters unset. See "Releasing" in CONTRIBUTING.md.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
# shellcheck source=scripts/license/common.sh
source scripts/license/common.sh

base="" tag="" allow_unset=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --base) base="$2"; shift 2 ;;
    --tag) tag="$2"; shift 2 ;;
    --allow-unset) allow_unset=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

errors=0
fail() { echo "error: $*" >&2; errors=$((errors + 1)); }
today=$(date -u +%F)

# 1. License files.
for f in LICENSE LICENSE-AGPL LICENSE-BUSL LICENSE-GPL LICENSING.md NOTICE \
         "$LEDGER" "$AGPL_VERSIONS" go-sdk/LICENSE; do
  [[ -f "$f" ]] || fail "missing $f"
done

# 2. LICENSE-BUSL carries the official terms verbatim.
terms_sha=$(sed -n "/^${SEPARATOR}\$/,\$p" "$BUSL_FILE" | tail -n +3 | sha256sum | cut -d' ' -f1)
[[ "$terms_sha" == "$BUSL_TERMS_SHA256" ]] ||
  fail "$BUSL_FILE: the text after the parameter block is not the official BUSL-1.1 text"

# 3. Parameters.
[[ "$(busl_param Licensor)" == "$LICENSOR" ]] || fail "$BUSL_FILE: Licensor must be '$LICENSOR'"
# Any Additional Use Grant other than "None" must be added here together with
# the change to LICENSE-BUSL.
[[ "$(busl_param 'Additional Use Grant')" == "None" ]] ||
  fail "$BUSL_FILE: Additional Use Grant must be 'None' until a grant is approved"
{ grep -q '^Change License:       GNU Affero General Public License, version 3 or (at$' "$BUSL_FILE" &&
  grep -q '^                      your option) any later version (AGPL-3.0-or-later)$' "$BUSL_FILE"; } ||
  fail "$BUSL_FILE: Change License must be AGPL-3.0-or-later"
grep -q '^                      The Licensed Work is (c) [0-9]\{4\}\(-[0-9]\{4\}\)\{0,1\} Synergize S\.L\.$' "$BUSL_FILE" ||
  fail "$BUSL_FILE: missing the Licensed Work copyright line"

work=$(busl_param 'Licensed Work')
change=$(busl_param 'Change Date')
version="${work#davinci-zkvm }"
last_row=$(ledger_rows "$LEDGER" | tail -n 1)
if [[ "$version" == "[VERSION NOT SET]" || "$change" == "[NOT SET]" ]]; then
  if [[ "$version" != "[VERSION NOT SET]" || "$change" != "[NOT SET]" ]]; then
    fail "$BUSL_FILE: version and Change Date must be set together"
  elif [[ -n "$last_row" ]]; then
    fail "$BUSL_FILE: parameters unset although $LEDGER has versions"
  elif [[ $allow_unset -eq 0 ]]; then
    fail "$BUSL_FILE: version and Change Date are not set. Run scripts/license/busl-release.sh <version> on the day of the first BUSL publication (see \"Releasing\" in CONTRIBUTING.md)"
  fi
  version="" change=""
else
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || fail "$BUSL_FILE: bad version '$version'"
  valid_date "$change" || fail "$BUSL_FILE: bad Change Date '$change'"
  [[ "$last_row" == "$version,"*",$change" ]] ||
    fail "$BUSL_FILE: version $version / Change Date $change do not match the last $LEDGER row (${last_row:-none})"
fi

# 4. Ledger rules.
prev_pub="" prev_ver=""
declare -A seen=()
while IFS=, read -r v pub cd extra; do
  [[ -z "$extra" ]] || fail "$LEDGER: extra columns in row $v"
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || fail "$LEDGER: bad version '$v'"
  [[ -z "${seen[$v]:-}" ]] || fail "$LEDGER: duplicate version $v"
  seen[$v]=1
  if grep -qx "v$v" "$AGPL_VERSIONS"; then fail "$LEDGER: v$v was published under AGPL only"; fi
  valid_date "$pub" || fail "$LEDGER: $v: bad published date '$pub'"
  valid_date "$cd" || fail "$LEDGER: $v: bad change date '$cd'"
  [[ "$cd" == "$(change_date_for "$pub")" ]] ||
    fail "$LEDGER: $v: change date $cd is not published + 3 years ($(change_date_for "$pub"))"
  if [[ "$pub" > "$today" ]]; then fail "$LEDGER: $v: published date $pub is in the future"; fi
  if [[ -n "$prev_pub" ]]; then
    if [[ "$pub" < "$prev_pub" ]]; then fail "$LEDGER: $v published before the previous row"; fi
    [[ "$v" != "$prev_ver" && "$(printf '%s\n%s\n' "$prev_ver" "$v" | sort -V | tail -n 1)" == "$v" ]] ||
      fail "$LEDGER: $v does not follow $prev_ver"
  fi
  prev_pub=$pub prev_ver=$v
done < <(ledger_rows "$LEDGER")

# 5. Append-only against a base revision.
if [[ -n "$base" ]] && git cat-file -e "$base:$LEDGER" 2>/dev/null; then
  old=$(git show "$base:$LEDGER" | grep -v -e '^#' -e '^version,' -e '^[[:space:]]*$' || true)
  if [[ -n "$old" ]]; then
    n=$(printf '%s\n' "$old" | wc -l)
    [[ "$(ledger_rows "$LEDGER" | head -n "$n")" == "$old" ]] ||
      fail "$LEDGER: rows published on $base were changed or removed (the ledger is append-only)"
  fi
fi

# 6. Release tag: LICENSE-BUSL at the tag names the tagged version, and the
#    ledger date is not later than the tagged commit (a version cannot be
#    published before its commit exists, so the Change Date is never more
#    than three years after the real publication).
if [[ -n "$tag" ]]; then
  if grep -qx "$tag" "$AGPL_VERSIONS"; then
    : # historical AGPL-only tag
  elif [[ "$tag" == "v$version" ]]; then
    commit_date=$(TZ=UTC git log -1 --format=%cd --date=format-local:%F "$tag^{commit}")
    pub=$(ledger_rows "$LEDGER" | grep "^$version," | cut -d, -f2)
    if [[ "$pub" > "$commit_date" ]]; then
      fail "$tag: ledger published date $pub is after the tagged commit ($commit_date)"
    fi
  else
    fail "$tag: LICENSE-BUSL names version '${version:-unset}'; run scripts/license/busl-release.sh ${tag#v} before tagging"
  fi
fi

# 7. Copies of the license texts.
for d in "${BUSL_COPIES[@]}"; do
  cmp -s "$BUSL_FILE" "$d/LICENSE-BUSL" || fail "$d/LICENSE-BUSL differs from $BUSL_FILE"
done
cmp -s LICENSE-AGPL go-sdk/LICENSE || fail "go-sdk/LICENSE differs from LICENSE-AGPL"

# 8. Cargo manifests: every Rust package is BUSL-1.1. A package that must
#    carry another license has to be classified in LICENSING.md and here.
ws_license=$(sed -n '/^\[workspace.package\]/,/^\[/s/^license = "\(.*\)"$/\1/p' Cargo.toml)
[[ "$ws_license" == "BUSL-1.1" ]] || fail "Cargo.toml: workspace license is '$ws_license', expected BUSL-1.1"
while read -r manifest; do
  [[ "$manifest" == "Cargo.toml" ]] && continue
  lic=$(sed -n '/^\[package\]/,/^\[/{s/^license = "\(.*\)"$/\1/p;s/^license\.workspace = true$/WORKSPACE/p;}' "$manifest")
  [[ "$lic" == "WORKSPACE" ]] && lic=$ws_license
  [[ "$lic" == "BUSL-1.1" ]] || fail "$manifest: license is '${lic:-missing}', expected BUSL-1.1"
done < <(git ls-files -co --exclude-standard -- '*Cargo.toml')

# 9. Solidity keeps its upstream notices; new contracts must be classified.
declare -A sol=(
  [solidity/PlonkVerifier.sol]="// SPDX-License-Identifier: GPL-3.0"
  [solidity/ZiskVerifier.sol]="// SPDX-License-Identifier: AGPL-3.0"
  [solidity/IZiskVerifier.sol]="// SPDX-License-Identifier: AGPL-3.0"
  [solidity/DavinciSettlement.sol]="// SPDX-License-Identifier: AGPL-3.0"
)
while read -r f; do
  [[ -n "${sol[$f]:-}" ]] || fail "$f: unclassified Solidity file (add it to LICENSING.md and this check)"
done < <(git ls-files -co --exclude-standard -- 'solidity/*.sol')
for f in "${!sol[@]}"; do
  [[ "$(head -n 1 "$f")" == "${sol[$f]}" ]] || fail "$f: SPDX header changed (expected '${sol[$f]}')"
done
grep -q 'Copyright 2021 0KIMS association\.' solidity/PlonkVerifier.sol ||
  fail "solidity/PlonkVerifier.sol: the snarkJS / 0KIMS notice was removed"

# 10. No BUSL marking inside the AGPL / per-file areas.
if git grep -q -I -e 'BUSL' -- go-sdk solidity; then
  fail "BUSL referenced inside go-sdk/ or solidity/: $(git grep -l -I -e 'BUSL' -- go-sdk solidity | tr '\n' ' ')"
fi

if [[ $errors -gt 0 ]]; then
  echo "license check: $errors error(s)" >&2
  exit 1
fi
if [[ -n "$version" ]]; then
  echo "license check: ok (BUSL-1.1 version $version, Change Date $change)"
else
  echo "license check: ok (BUSL-1.1 parameters not set yet: nothing may be published)"
fi
