# mlkem-cli

A tiny Rust CLI demonstrating how to use the `libcrux-ml-kem` crate (ML-KEM / Kyber) to

- generate a key pair
- encapsulate a shared secret to the public key
- decapsulate the shared secret with the private key

It supports the 512, 768, and 1024 parameter sets.

## Prerequisites

- Rust toolchain (stable). Install via <https://rustup.rs>
- macOS, Linux, or Windows (the crate auto-selects optimized backends at runtime)
- Optional: set `LIBCRUX_ENABLE_SIMD128=1` or `LIBCRUX_ENABLE_SIMD256=1` to force NEON/AVX2 builds

## How it works

This example follows the crate docs and uses the serialized key API:

- `mlkem{512,768,1024}::generate_key_pair(seed)`
- `mlkem{512,768,1024}::encapsulate(public_key, seed)`
- `mlkem{512,768,1024}::decapsulate(private_key, &ciphertext)`
- `validate_public_key` and `validate_private_key` before use

Seeds are sourced from `OsRng` for demo purposes. For production, use a DRBG per NIST guidance.

## Build and run

```bash
# Build
cargo build

# Run with default (ML-KEM-768)
cargo run --

# Run with a specific parameter set and print materials in hex
cargo run -- --param 512 --verbose
cargo run -- --param 768 --verbose
cargo run -- --param 1024 --verbose
```

## Tests

```bash
cargo test
```

## Performance notes

The crate auto-selects portable/optimized backends based on the target and CPU features. You can force
SIMD with:

```bash
LIBCRUX_ENABLE_SIMD128=1 cargo run --release -- --param 768
LIBCRUX_ENABLE_SIMD256=1 cargo run --release -- --param 768
```

## Related repositories and docs

- Implementation used here: <https://github.com/pq-code-package/rust-libcrux>
- Crate API docs: <https://docs.rs/libcrux-ml-kem/latest/libcrux_ml_kem/>
- Upstream libcrux (formally verified crypto): <https://github.com/cryspen/libcrux>
- Verification status for ML-KEM: <https://github.com/cryspen/libcrux/blob/main/libcrux-ml-kem/proofs/verification_status.md>
- Benchmarks dashboard: <https://libcrux.cryspen.com>

## References

- Repo: <https://github.com/pq-code-package/rust-libcrux>
- Docs: <https://docs.rs/libcrux-ml-kem/latest/libcrux_ml_kem/>
