keythereum
==========

[![Build Status](https://travis-ci.org/AugurProject/keythereum.svg?branch=master)](https://travis-ci.org/AugurProject/keythereum)
[![Coverage Status](https://coveralls.io/repos/AugurProject/keythereum/badge.svg?branch=master&service=github)](https://coveralls.io/github/AugurProject/keythereum?branch=master)

[![NPM](https://nodei.co/npm/keythereum.png)](https://nodei.co/npm/keythereum/)

Generate, import and export Ethereum private keys.  Uses PBKDF2 or scrypt key derivation functions.

Installation
------------

    $ npm install keythereum

Usage
-----

```javascript
var keythereum = require("keythereum");
```
Generate a new secp256k1 ECDSA private key (256 bit), as well as the salt (256 bit) used by the key derivation function, and the initialization vector (128 bit) used to AES-128-CTR encrypt the key:
```javascript
var dk = keythereum.create();
// dk:
{
    privateKey: <Buffer ...>,
    iv: <Buffer ...>,
    salt: <Buffer ...>
}
```
Next, specify a password and (optionally) a key derivation function.  If unspecified, PBKDF2-SHA256 will be used to derive the AES secret key.
```javascript
var password = "wheethereum";
var kdf = "pbkdf2"; // or "scrypt" to use the scrypt kdf
```
Export key info to keystore ["secret-storage" format](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition):
```javascript
var json = keythereum.dump(password, dk.privateKey, dk.salt, dk.iv, kdf);
// json:
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
```
In Node, the `exportToFile` method provides an easy way to export this formatted key object to file.  It creates a JSON file in the `keystore` sub-directory, and uses geth's current file-naming convention (ISO timestamp concatenated with the key's derived Ethereum address).
```
keythereum.exportToFile(json);
```
After successful key export, you will see a message like:
```
Saved to file:
keystore/UTC--2015-08-11T06:13:53.359Z--008aeeda4d805471df9b2a5b0f38a0c3bcba786b

To use with geth, copy this file to your Ethereum keystore folder
(usually ~/.ethereum/keystore).
```

Tests
-----

Unit tests are in the `test` directory, and are run with mocha.

    $ npm test
