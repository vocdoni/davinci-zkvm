#!/bin/sh
set -e

# v0.17.0: constant trees are built on-demand during prove (prover.setup()).
# check-setup validates the proving key and warms up the runtime.
echo "Validating proving key..."
cargo-zisk check-setup --proving-key "$PROVING_KEY_PATH"

exec /app/davinci-zkvm
