# BLAKE3 test vectors

`test_vectors.json` is the official BLAKE3 test-vector file, copied unchanged from
https://github.com/BLAKE3-team/BLAKE3/blob/657284b1fa4c4378aa7422b4450dcb5c2c9052fc/test_vectors/test_vectors.json

The BLAKE3 repository is dedicated to the public domain under CC0 1.0 and is
also available under the Apache License 2.0 (and Apache 2.0 with LLVM
exceptions); see https://github.com/BLAKE3-team/BLAKE3#license.

Only the `hash` outputs are checked (the default hash mode, full extended
length); this package does not implement `keyed_hash` or `derive_key`.
