# shellcheck shell=bash disable=SC2034
# Shared definitions for the BUSL-1.1 tooling. Sourced, not executed.
# Needs GNU date (Linux, CI); on macOS use gdate from coreutils.

LICENSOR="Synergize S.L."
BUSL_FILE="LICENSE-BUSL"
LEDGER="licensing/busl-versions.csv"
AGPL_VERSIONS="licensing/agpl-versions.txt"
# Directories carrying a byte-identical copy of LICENSE-BUSL (crates that
# can be consumed outside the repository through cargo).
BUSL_COPIES=(service input-gen rust-sdk)
# sha256 of the official SPDX BUSL-1.1 text (spdx/license-list-data
# text/BUSL-1.1.txt), which LICENSE-BUSL must carry verbatim after its
# parameter block. Never change this to make a modified text pass.
BUSL_TERMS_SHA256="d90560217049db1d6020ec7cf482da4198bfa372dffd22270ba08fd8088cd93b"
SEPARATOR="-----------------------------------------------------------------------------"

# valid_date YYYY-MM-DD: true if it is a real calendar date.
valid_date() {
  [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || return 1
  [[ "$(date -u -d "$1" +%F 2>/dev/null)" == "$1" ]]
}

# change_date_for YYYY-MM-DD: the same day four calendar years later. A
# 29 February with no counterpart (e.g. in 2100) maps to 28 February, so the
# interval never exceeds four years.
change_date_for() {
  local d
  d=$(printf '%04d-%s' $((10#${1:0:4} + 4)) "${1:5:5}")
  valid_date "$d" || d="${d:0:4}-02-28"
  printf '%s\n' "$d"
}

# ledger_rows FILE: the data rows of a ledger (no comments, no header).
ledger_rows() {
  grep -v -e '^#' -e '^version,' -e '^[[:space:]]*$' "$1" || true
}

# busl_param NAME: the first line value of a LICENSE-BUSL parameter.
busl_param() {
  sed -n "s/^$1:[[:space:]]*//p" "${2:-$BUSL_FILE}" | head -n 1
}
