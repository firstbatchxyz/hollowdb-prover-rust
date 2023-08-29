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

## Usage

We use [ark_circom](https://crates.io/crates/ark-circom) to generate Groth16 proofs for HollowDB. PLONK is not supported as of yet.

### Generating Proofs

To create a prover:

```rs
let prover = HollowProver::new(
    wasmPath,
    r1csPath,
    proverKeyPath,
)?;
```

The `prove` function accepts any type for the current value and next value, where the inputs will be stringified and then hashed. The resulting string should match that of `JSON.stringify` in JavaScript. Here is an example of creating a proof:

```rs
#[derive(Serialize)]
struct MyStruct {
    foo: i32,
    bar: bool,
    baz: String,
}

let preimage = BigUint::from_str("123456789")?;
let cur_value = MyStruct {
    foo: 123,
    bar: true,
    baz: "zab".to_owned(),
};
let next_value = MyStruct {
    foo: 789,
    bar: false,
    baz: "baz".to_owned(),
};

let (proof, public_signals) = prover.prove(preimage, cur_value, next_value)?;
```

Note that if you are using the value at both JS and Rust, you need to ensure that keys are ordered the same so that the resulting hashes match.

### Computing Key

To compute the key (i.e. the Poseidon hash of your preimage) without generating a proof, you can use the `ComputeKey` function.

```rs
let preimage = BigUint::from_str("123456789")?;
let key = compute_key(preimage)?;
```

### Hashing to Group

If you would like to compute the hashes manually, you can use `hash_to_group` function. It accepts any argument that is serializable.

## Testing

Running the tests will generate a proof and public signals under out folder, which can be verified using SnarkJS. You can run all tests with:

```sh
yarn test
```

which will run all tests, and then run SnarkJS to verify the resulting proofs. To verify generated proofs you can also type `yarn verify`. To run tests without SnarkJS, you can do:

```sh
cargo test --release
```

Note that due to an [issue](https://github.com/arkworks-rs/circom-compat/issues/27) in `ark-circom` we have to run in release mode, otherwise it hangs.

## See Also

We have prover implementations in Go and JavaScript as well:

-   [Go](https://github.com/firstbatchxyz/hollowdb-prover-go)
-   [JavaScript](https://github.com/firstbatchxyz/hollowdb-prover)
