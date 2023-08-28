<p align="center">
  <img src="https://raw.githubusercontent.com/firstbatchxyz/hollowdb/master/logo.svg" alt="logo" width="142">
</p>

<p align="center">
  <h1 align="center">
    HollowDB Prover
  </h1>
  <p align="center">
    <i>Proof generator crate for HollowDB.</i>
  </p>
</p>

<p align="center">
    <a href="https://opensource.org/licenses/MIT" target="_blank">
        <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-yellow.svg">
    </a>
    <a href="https://docs.hollowdb.xyz/zero-knowledge-proofs/hollowdb-prover" target="_blank">
        <img alt="Docs" src="https://img.shields.io/badge/docs-hollowdb-3884FF.svg?logo=gitbook">
    </a>
    <a href="https://github.com/firstbatchxyz/hollowdb" target="_blank">
        <img alt="GitHub: HollowDB" src="https://img.shields.io/badge/github-hollowdb-5C3EFE?logo=github">
    </a>
    <a href="https://discord.gg/2wuU9ym6fq" target="_blank">
        <img alt="Discord" src="https://dcbadge.vercel.app/api/server/2wuU9ym6fq?style=flat">
    </a>
</p>

TODOS:

-   Return `Result`s instead of unwrapping everywhere

## Usage

Using [ark_circom](https://crates.io/crates/ark-circom), we can generate proofs for HollowDB. Only Groth16 is supported as of yet.

## Testing

You can test via:

```sh
cargo test --release

# see println's in there
cargo test --release -- --nocapture
```

Note that due to an [issue](https://github.com/arkworks-rs/circom-compat/issues/27) in `ark-circom` we have to run in release mode, otherwise it hangs.
