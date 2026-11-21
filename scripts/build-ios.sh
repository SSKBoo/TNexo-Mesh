#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/rust-core"

cargo build --target aarch64-apple-ios --release

# Create XCFramework (requires Xcode)
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libnexomesh_core.a \
  -output ../apple-ios/NexoMesh.xcframework
