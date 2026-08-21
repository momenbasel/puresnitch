#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd "$script_dir/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/puresnitch-hardening.XXXXXX")

cleanup() {
  if [[ -n "$test_dir" && -d "$test_dir" ]]; then
    rm -rf -- "$test_dir"
  fi
}
trap cleanup EXIT

if [[ $(uname -s) != Darwin ]]; then
  echo "Hardening regression tests require macOS." >&2
  exit 1
fi

machine_arch=$(uname -m)
case "$machine_arch" in
  arm64|x86_64) ;;
  *)
    echo "Unsupported macOS architecture: $machine_arch" >&2
    exit 1
    ;;
esac

xcrun --sdk macosx swiftc \
  -swift-version 5 \
  -parse-as-library \
  -target "${machine_arch}-apple-macos13.0" \
  "$repo_dir/Sources/Shared/Models.swift" \
  "$repo_dir/Sources/Shared/RuleMatcher.swift" \
  "$repo_dir/Sources/Shared/Logger.swift" \
  "$repo_dir/Sources/Shared/RuleStore.swift" \
  "$repo_dir/Sources/Helper/HelperSecurityState.swift" \
  "$repo_dir/Sources/Helper/PendingDNSAsks.swift" \
  "$repo_dir/Sources/Helper/NetMonitor.swift" \
  "$repo_dir/Sources/Helper/PFManager.swift" \
  "$repo_dir/Sources/Helper/DNSProxy.swift" \
  "$repo_dir/Tests/ConnectionHistoryRegression.swift" \
  "$repo_dir/Tests/HardeningRegression.swift" \
  -lsqlite3 \
  -o "$test_dir/hardening-regression"

PURESNITCH_REPO_DIR="$repo_dir" "$test_dir/hardening-regression"
