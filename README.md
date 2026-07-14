# SHA-3 (Keccak) Implementation in C

## Overview

This repository contains a C implementation of the SHA-3 family of cryptographic hash functions, based on the Keccak sponge construction defined in **NIST FIPS 202**.

The project implements the Keccak-f[1600] permutation, sponge construction, multi-rate padding, and the SHA3-224, SHA3-256, SHA3-384, and SHA3-512 hash functions from scratch using only the C standard library.

---

## Features

* Keccak-f[1600] permutation
* Sponge construction
* Multi-rate (pad10*1) padding
* SHA3-224
* SHA3-256
* SHA3-384
* SHA3-512
* Clean and modular C implementation
* Official FIPS 202 compatible output
* Comprehensive inline documentation

---

## Project Structure

```text
SHA3/
│
├── src/
│   ├── main.c
│   ├── sha3.c
│   ├── sponge.c
│   ├── keccak.c
│   ├── padding.c
│   ├── state.c
│   └── utils.c
│
├── include/
│   ├── sha3.h
│   ├── sponge.h
│   ├── keccak.h
│   ├── padding.h
│   ├── state.h
│   └── utils.h
│
├── tests/
│
└── README.md
```

---

## Building

This project is written in standard C and can be built with any modern C compiler.

### Microsoft Visual Studio

1. Open the solution.
2. Build the project.
3. Run the executable.

### GCC

```bash
gcc src/*.c -Iinclude -o sha3
```

---

## Verification

The implementation is verified against the official test vectors published in **NIST FIPS 202** to ensure standards compliance.

---

## Standards

This implementation follows:

* **NIST FIPS 202** — SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions

---

## Future Development

Planned improvements include:

* SHAKE128
* SHAKE256
* cSHAKE
* KMAC
* Performance optimizations
* Additional test coverage
* Cross-platform support

---

## License

This project is licensed under the MIT License.
