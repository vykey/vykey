#!/usr/bin/env bash
# Prints `version=<v>` for $GITHUB_OUTPUT: the tag without its "v" on a tag
# push (checked against Cargo.toml), otherwise "<Cargo version>-dev+<sha>".
set -euo pipefail

cargo_version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)

if [[ "${GITHUB_REF:-}" == refs/tags/v* ]]; then
  tag=${GITHUB_REF#refs/tags/v}
  if [[ "$tag" != "$cargo_version" ]]; then
    echo "tag v$tag does not match version $cargo_version in Cargo.toml" >&2
    exit 1
  fi
  echo "version=$tag"
else
  echo "version=$cargo_version-dev+${GITHUB_SHA:0:7}"
fi
