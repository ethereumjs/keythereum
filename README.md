keythereum
==========

[![Build Status](https://travis-ci.org/AugurProject/keythereum.svg?branch=master)](https://travis-ci.org/AugurProject/keythereum)
[![Coverage Status](https://coveralls.io/repos/AugurProject/keythereum/badge.svg?branch=master&service=github)](https://coveralls.io/github/AugurProject/keythereum?branch=master)

[![NPM](https://nodei.co/npm/keythereum.png)](https://nodei.co/npm/keythereum/)

Keythereum is a JavaScript tool to generate, import and export Ethereum keys.  This provides a simple way to use the same account locally and in web wallets.  It can be used for verifiable cold storage wallets.

Keythereum uses the same key derivation functions (PBKDF2-SHA256 or scrypt), symmetric ciphers (AES-128-CTR or AES-128-CBC), and message authentication codes as [geth](https://github.com/ethereum/go-ethereum).  You can export your generated key to file, copy it to your data directory's keystore, and immediately start using it in your local Ethereum client.

Note: key import is not yet implemented.

Installation
------------

    $ npm install keythereum

Usage
-----

To use keythereum, just `require` it:
```javascript
var keythereum = require("keythereum");
```
Generate a new random private key (256 bit), as well as the salt (256 bit) used by the key derivation function, and the initialization vector (128 bit) used to AES-128-CTR encrypt the key.  `create` is synchronous if no arguments are provided, and asynchronous if a callback function provided:
```javascript
// synchronous
var dk = keythereum.create();
// dk:
{
    privateKey: <Buffer ...>,
    iv: <Buffer ...>,
    salt: <Buffer ...>
}

// asynchronous
keythereum.create(function (dk) {
    // do stuff!
});
```
Next, specify a password and (optionally) a key derivation function.  If unspecified, PBKDF2-SHA256 will be used to derive the AES secret key.
```javascript
var password = "wheethereum";
var kdf = "pbkdf2"; // or "scrypt" to use the scrypt kdf
```
The `dump` function is used to export key info to keystore ["secret-storage" format](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition).  If a callback function is supplied as the sixth parameter to `dump`, it will run asynchronously (for PBKDF2; scrypt is synchronous-only for now):
```javascript
// synchronous
var keyObject = keythereum.dump(password, dk.privateKey, dk.salt, dk.iv, kdf);
// keyObject:
{
    address: '008aeeda4d805471df9b2a5b0f38a0c3bcba786b',
    Crypto: {
        cipher: 'aes-128-ctr',
        ciphertext: '5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46',
        cipherparams: {
            iv: '6087dab2f9fdbbfaddc31a909735c1e6'
        },
        mac: '517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2',
        kdf: 'pbkdf2',
        kdfparams: {
            c: 262144,
            dklen: 32,
            prf: 'hmac-sha256',
            salt: 'ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd'
        }
    },
    id: 'e13b209c-3b2f-4327-bab0-3bef2e51630d',
    version: 3
}

// asynchronous
keythereum.dump(password, dk.privateKey, dk.salt, dk.iv, kdf, function (keyObject) {
    // do stuff!
});

```
Note that this creates an object and not a JSON string.  In Node, the `exportToFile` method provides an easy way to export this formatted key object to file.  It creates a JSON file in the `keystore` sub-directory, and uses geth's current file-naming convention (ISO timestamp concatenated with the key's derived Ethereum address).
```
keythereum.exportToFile(keyObject);
```
After successful key export, you will see a message like:
```
Saved to file:
keystore/UTC--2015-08-11T06:13:53.359Z--008aeeda4d805471df9b2a5b0f38a0c3bcba786b

To use with geth, copy this file to your Ethereum keystore folder
(usually ~/.ethereum/keystore).
```
Note: by default, keythereum uses 65536 hashing rounds in its key derivation functions, compared to the 262144 geth uses by default.  (Keythereum's JSON output files are still compatible with geth, however, since they tell geth how many rounds to use.)  These values are user-editable: `keythereum.constants.pbkdf2.c` is the number of rounds for PBKDF2, and `keythereum.constants.scrypt.n` is the number of rounds for scrypt.

Tests
-----

Unit tests are in the `test` directory, and should be run with mocha:

    $ npm test
