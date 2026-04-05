#!/bin/sh
# Generate roff man pages from scdoc sources.
# Requires: scdoc (https://git.sr.ht/~sircmpwn/scdoc)
set -e

cd "$(dirname "$0")"

scdoc < pnut.1.scd > pnut.1
scdoc < pnut.toml.5.scd > pnut.toml.5

echo "Generated pnut.1 and pnut.toml.5"
