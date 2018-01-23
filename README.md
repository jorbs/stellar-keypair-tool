# Stellar Keypair Tool
A tool to generate custom Stellar public keys with suffixes.

# Installation
1. Install `libsodium` (http://libsodium.org)
2. `make`

# Usage
`./keypair <suffix>`

`suffix` must be upper case. There isn't string case modification in the code in order to reduce the number of CPU instructions.
