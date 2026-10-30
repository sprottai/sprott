#!/bin/sh
# Build the wasm the console loads: the release .wasm, then the wasm-bindgen
# glue for the browser (pkg/web) and for Node (pkg/node: the console's verify
# scripts and smoke.mjs). Needs the wasm32-unknown-unknown target and
# wasm-bindgen-cli at the version Cargo.toml pins. Honors CARGO_TARGET_DIR.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
want=$(sed -n 's/^wasm-bindgen = "=\(.*\)"$/\1/p' "$here/Cargo.toml")
have=$(wasm-bindgen --version | awk '{print $2}')
if [ "$have" != "$want" ]; then
    echo "wasm-bindgen-cli $have; the crate pins $want (cargo install wasm-bindgen-cli --version $want)" >&2
    exit 1
fi
cd "$root"
cargo build -p sprott-trust-wasm --target wasm32-unknown-unknown --release
target_dir=${CARGO_TARGET_DIR:-$root/target}
wasm="$target_dir/wasm32-unknown-unknown/release/sprott_trust_wasm.wasm"
rm -rf "$here/pkg"
wasm-bindgen --target web --out-dir "$here/pkg/web" "$wasm"
wasm-bindgen --target nodejs --out-dir "$here/pkg/node" "$wasm"
out="$here/pkg/web/sprott_trust_wasm_bg.wasm"
echo "$out: $(wc -c < "$out") bytes, $(gzip -9 -c "$out" | wc -c) gzipped"
