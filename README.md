# SAFE API – Sponge API for Field Elements

> ⚠️ **Disclaimer:** This implementation is experimental and designed for use in Noir-based ZK circuits. It has not been audited. Use in production at your own risk.

## Overview

This crate implements the **SAFE API (Sponge API for Field Elements)** using the **Poseidon permutation** over a finite field. It is designed for use in zero-knowledge proof systems written in [Noir](https://noir-lang.org/), where efficient hash-based commitments and PRFs over field elements are essential.

The SAFE API offers:

- Absorption of field element messages
- Squeezing output elements from a sponge
- Compatibility with ZK circuits written in Noir
- Domain separation for input consistency

---

## Why SAFE?

SAFE provides an abstraction over cryptographic sponge constructions specifically tailored for finite field inputs—ideal for ZK circuits. It enables:

- Commitment schemes
- Fiat-Shamir transformations
- Merkle-tree-compatible hashing
- PRF derivation from structured inputs
