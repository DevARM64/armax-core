# ARMax ($ARM)

A mobile-first Layer 1 blockchain with ARM-friendly proof of work and a 100% fair launch:
**no premine, no presale, no team allocation.**

> **Status: public testnet stage. Not audited. $ARM has no market value.**
> Do not treat this software as an investment, and do not use it to protect value you cannot afford to lose.
> Consensus rules, parameters and the wire protocol can still change.

## Design

| | |
|---|---|
| Block time | 300 s |
| Max supply | 21,000,000 ARM |
| Block reward | 25 ARM, halving every 420,000 blocks (~4 years) |
| Decimals | 8 |
| Proof of work | Memory-hungry VM (384 MiB per mining thread, AES/NEON instructions) |
| Per-address damper | Rewards above 40 H/s per address are reduced |
| Pool | Optional P2Pool-style sharechain (no pool operator) |
| Network | Encrypted P2P (X25519 + ChaCha20-Poly1305), optional pinned node keys |

Honest notes:

* The per-address damper is an **economic barrier, not a guarantee**: anyone can create many addresses.
* The design targets phones, but nothing prevents mining on a PC.
* There has been **no independent security audit** yet.

## Repository layout

* `crates/` — the Rust core: `armax-vm`, `armax-pow`, `armax-chain`, `armax-ledger`, `armax-keys`, `armax-store`,
  `armax-mempool`, `armax-net`, `armax-share`, `armax-thermal`, `armax-node`, `armax-ffi`.
* `armax-android/` — the Android app (Kotlin + Jetpack Compose), see its own README.
* `deploy/` — files to run a public seed node on a Linux server.

The Rust workspace has no external crates.

## Build and test

```
cargo test --workspace --release
cargo build --release -p armax-node
```

## Run a node

Networks: `testnet` (public test network, real consensus parameters), `devnet` (same parameters, private use)
and `fast` (reduced proof of work, only to try the software).

```
armax-node new-wallet --wallet ./wallet.dat
armax-node run --network testnet --data ./data --wallet ./wallet.dat \
  --connect 2.29.163.248:8333 \
  --pin 2.29.163.248:8333=dcff449ee769c49700e21e4b3a066ca471d3098cec29523fb24624de51d1c617 \
  --mine --pool
```

Useful options: `--threads N`, `--listen 0.0.0.0:8333` (accept incoming connections), `--no-governor`,
`--min-battery N`. In the console: `status`, `balance`, `send ADDRESS AMOUNT`, `quit`.
The wallet file is a development wallet and is **not encrypted**. Never reuse a testnet wallet for real funds.

The public seed node above is run by the project and may change during the testing phase.
The testnet can be reset while consensus parameters are still being calibrated; coins on it have no value.

### Minimum hardware

The real proof of work needs about 384 MiB of RAM per mining thread and verifying blocks and shares is also costly.
Tested so far:

* 64-bit ARM phone (Motorola moto g53 5G): syncs, mines (~5 H/s per thread), about 5 minutes per block with one miner.
* 32-bit ARM phone with little RAM (Termux, `--no-governor`): works but is slow. Initial sync is painful (about 4 s to verify each block,
  ~10 minutes for the first 25 blocks, with some disconnects), then it keeps up at ~0.2-0.3 H/s.

A 64-bit device with enough free RAM is strongly recommended.

## Android app

See `armax-android/README.md`. Build the native library with `cargo ndk` and then the app with Gradle.
The app is restricted to arm64 devices.

## Reporting security issues

Please do **not** open a public issue. Use GitHub's private reporting (Security tab → *Report a vulnerability*). See `SECURITY.md`.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.
