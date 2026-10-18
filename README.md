# Outis recovery

An offline Rust command that reconstructs account keys, addresses and deployment parameters
from an Outis 12-word recovery phrase. It supports ordinary and agent accounts, the vault
wallet key and pool viewing keys. It makes no network calls and uses no Outis runtime packages.

## Build and run

From this directory, with Rust and Cargo installed:

```sh
cargo build --release --locked
./target/release/outis-recovery --network SN_SEPOLIA --index 0
```

Copy the executable to an offline machine with the same operating system and architecture.
No Node.js, Rust installation or package installation is needed to run it. On Windows the
executable is `outis-recovery.exe`. Building requires the locked crates to be downloaded;
`cargo build --release --locked --offline` works once they are cached.

Enter the phrase at the hidden prompt. It is never a command-line argument or written to a
file by the tool. Output is JSON containing private keys: keep it secret.

- `--network SN_MAIN` selects mainnet; `SN_SEPOLIA` selects testnet. Other Outis chain names work.
- `--index 0` selects the first account; indices range from 0 through 999.
- `--kind agent` selects an agent account.
- `--pool 0xADDRESS` includes the viewing key for that pool and the derived account address.
- `--stdin` reads the phrase from a trusted input stream for automation.

## Using the result

`address` is the derived address. The tool does not check deployment, balances or broadcast
transactions. For an undeployed account, use the emitted deployment parameters. Preserve the
original parameters after a contract upgrade.

For an ordinary account with its original Stark owner and no guardian, a standard Starknet
signer can use `owner.privateKey` at `address`. The account accepts both `[r, s]` and
`[1, 0, publicKey, r, s]` signatures. Owner changes, guardians or contract upgrades may require
additional recovery information. Agent owner recovery does not restore sessions. Viewing keys
still need the privacy protocol's tooling to discover notes and generate proofs.

## Verification

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
python3 tests/verify_vectors.py
```

Rust tests check the [published vectors](tests/fixtures/recovery-v1-vectors.json), phrase handling,
invalid inputs and the executable. The Python verifier independently checks the public vectors.
