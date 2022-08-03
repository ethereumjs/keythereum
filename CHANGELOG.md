# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
(modification: no type change headlines) and this project adheres to
[Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2022-08-03

Maintenance release with various library updates and dependency simplifications.

Note that this version now uses the native JS [BigInt](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt) datatype, which is not supported in some older versions of browsers and dev/build tools!

Following Updates:

1. Replaced `crypto-browserify` with `browserify-aes`, which is a dependency of crypto-browserify; without all the unnecessary modules. We are still using `browserify-aes` because the keythereum's related api methods are synchronous - ethereum-cryptography/aes exposes async-only methods.
2. Replaced `keccak` with `ethereum-cryptography/keccak`
3. Replaced `scrypt-js` with `ethereum-cryptography/scrypt`
4. Replaced `secp256k1` with `ethereum-cryptography/secp256k1-compat`
5. Removed `sjcl` which had pbkdf2 implementation
6. Updated `uuid` from 3.0.0 to 8.3.2
7. The package versions are exact, like before - no version ranges

`wc < dist/keythereum.js` output:
- before `31994  118030  921363`
- after `15243   63140  484003`

Backwards incompatibilities:

- BigInt support is now required
- `keythereum.crypto` is now an emulated object instead of `crypto-browserify` stuff

[2.0.0]: https://github.com/ethereumjs/keythereum/compare/v1.2.0...v2.0.0

## [1.2.0] - 2020-09-29

This is a maintenance release after a longer period with no releases.
See PR [#81](https://github.com/ethereumjs/keythereum/pull/81) for implementation
details.

**Changes**

- `scrypt` to [`scrypt-js`](https://github.com/ricmoo/scrypt-js) for a pure js implementation (simplifies some code)
- `keccak` from `1.4.0` to `3.1.0` for node 12 and n-api support
- `secp256k1` from `3.5.0` to `4.0.2` for node 12 and n-api support
- travis ci node versions from `[4, 5, 6, 7, 8]` to `[8, 10, 12, 13, 14]`
- uglify-js to [`terser`](https://github.com/terser/terser) (build was having some trouble with es6 in node_modules)
- browserify from `16.2.2` to `16.5.2` for misc. bug fixes and upgrades.

[1.2.0]: https://github.com/ethereumjs/keythereum/compare/v1.0.4...v1.2.0

## [1.0.4]

TODO

## Older releases:

- [1.x.x](https://github.com/ethereumjs/keythereum/compare/v1.x.x...v1.y.y) - 20xx-xx-xx
- ...
