#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$REPO_ROOT/install.sh"

assert_eq() {
  local got="$1"
  local want="$2"
  local msg="$3"
  if [[ "$got" != "$want" ]]; then
    echo "assertion failed: $msg: got [$got] want [$want]" >&2
    exit 1
  fi
}

test_missing_apt_packages_reports_unknown_package() {
  local out
  out="$(missing_apt_packages definitely-not-a-real-package-name)"
  assert_eq "$out" "definitely-not-a-real-package-name" "missing package detection"
}

test_is_ubuntu_host_matches_os_release() {
  local expected=1
  if [[ -r /etc/os-release ]] && grep -q '^ID=ubuntu$' /etc/os-release; then
    expected=0
  fi
  if is_ubuntu_host; then
    assert_eq "0" "$expected" "ubuntu host detection true path"
  else
    assert_eq "1" "$expected" "ubuntu host detection false path"
  fi
}

test_missing_apt_packages_reports_unknown_package
test_is_ubuntu_host_matches_os_release
echo "install logic tests passed"
