#!/usr/bin/env bash
set -euo pipefail

swiftly_toolchain="${SWIFTLY_TOOLCHAIN:-+6.3.1}"
swift_sdk="${SWIFT_WASM_SDK:-swift-6.3.1-RELEASE_wasm}"

if command -v swiftly >/dev/null 2>&1; then
  swift_command=(swiftly run "${swiftly_toolchain}" swift)
else
  swift_command=(swift)
fi

"${swift_command[@]}" build \
  --swift-sdk "${swift_sdk}" \
  --target DNSWire \
  -c release \
  --scratch-path .build/wasm-dnswire-verify

"${swift_command[@]}" build \
  --swift-sdk "${swift_sdk}" \
  --target MDNS \
  -c release \
  --scratch-path .build/wasm-mdns-verify
