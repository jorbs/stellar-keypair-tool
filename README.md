# Stellar Keypair Tool
A tool to generate vanity Stellar public address. It was implemented in C++ in order to use the NaCl `EdDSA25519` implementation (https://nacl.cr.yp.to/sign.html), available throught `libsodium`.

# Installation
1. Install `libsodium` (http://libsodium.org)
2. `make`

# Usage
`./keypair [-p|-m|-s] <term>`

It searches `term` for `prefix`, `middle` or `suffix` positions. `term` can have down case chars.
