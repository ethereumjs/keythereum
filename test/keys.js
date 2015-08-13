/**
 * keythereum unit tests
 * @author Jack Peterson (jack@tinybike.net)
 */

"use strict";

var crypto = require("crypto");
var assert = require("chai").assert;
var validator = require("validator");
var pubToAddress = require("ethereumjs-util").pubToAddress;
var ecdsa = new (require("elliptic").ec)("secp256k1");
var keythereum = require("../");

// change hashing rounds to match geth's default
keythereum.constants.pbkdf2.c = 262144;
keythereum.constants.scrypt.n = 262144;

// create private key
var privateKey = crypto.randomBytes(32);

// timeout for asynchronous unit tests
var TIMEOUT = 48000;

keythereum.create();

describe("Crypto", function () {

    // derive secp256k1 ECDSA public key and address from private key
    var publicKey = new Buffer(ecdsa.keyFromPrivate(privateKey).getPublic("arr"));
    var address = pubToAddress(publicKey).toString("hex");

    // user specified password
    var password = "wheethereum";

    // password used as secret key for aes-256 cipher
    var secret = crypto.createHash("sha256").update(password).digest("hex");
    var cipher = crypto.createCipher("aes-256-cbc", secret);
    var encryptedPrivateKey = cipher.update(privateKey, "hex", "base64");
    encryptedPrivateKey += cipher.final("base64");

    // verify private key is recovered by decryption
    it("private key should be recovered using the password to decrypt", function () {
        var decipher = crypto.createDecipher("aes-256-cbc", secret);
        var decryptedPrivateKey = decipher.update(encryptedPrivateKey, "base64", "hex");
        decryptedPrivateKey += decipher.final("hex");
        assert.strictEqual(decryptedPrivateKey, privateKey.toString("hex"));
    });

    it("derive address from private key", function () {
        assert.strictEqual(
            keythereum.privateKeyToAddress(privateKey),
            "0x" + address
        );
    });

    it("generate random 256-bit private key & salt, 128-bit initialization vector", function () {
        var plaintext = keythereum.create();
        assert.property(plaintext, "privateKey");
        assert.isNotNull(plaintext.privateKey);
        assert.property(plaintext, "iv");
        assert.isNotNull(plaintext.iv);
        assert.property(plaintext, "salt");
        assert.isNotNull(plaintext.salt);
    });

});

// describe("Import key from keystore file", function () {

//     var test = function (t) {
//         it("import " + t.address, function (done) {

//         });
//     };

//     test({
//         input: {
//             address: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
//             datadir: null
//         },
//         expected: {

//         }
//     });

// });

// Test vectors:
// https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition

describe("Key derivation", function () {

    var test = function (t) {
        it("[sync] " + t.input.kdf, function () {
            this.timeout(TIMEOUT);
            var derivedKey = keythereum.deriveKey(
                t.input.password,
                t.input.salt,
                t.input.kdf
            );
            assert.strictEqual(derivedKey.toString("hex"), t.expected);
        });
        if (t.input.kdf !== "scrypt") {
            it("[async] " + t.input.kdf, function (done) {
                this.timeout(TIMEOUT);
                keythereum.deriveKey(
                    t.input.password,
                    t.input.salt,
                    t.input.kdf,
                    function (derivedKey) {
                        if (derivedKey.error) {
                            done(derivedKey);
                        } else {
                            assert.strictEqual(derivedKey.toString("hex"), t.expected);
                            done();
                        }
                    }
                );
            });
        }
    };

    test({
        input: {
            password: "testpassword",
            salt: "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd",
            kdf: "pbkdf2-sha256"
        },
        expected: "f06d69cdc7da0faffb1008270bca38f5e31891a3a773950e6d0fea48a7188551"
    });

    if (!process.env.CONTINUOUS_INTEGRATION) {
        test({
            input: {
                password: "testpassword",
                salt: "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19",
                kdf: "scrypt"
            },
            expected: "fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd"
        });
    }

});

describe("Message authentication code", function () {

    var test = function (t) {
        it("convert " + JSON.stringify(t.input) + " -> " + t.output, function () {
            var mac = keythereum.getMAC(t.input.derivedKey, t.input.ciphertext);
            assert.strictEqual(mac, t.output);
        });
    };

    test({
        input: {
            derivedKey: "f06d69cdc7da0faffb1008270bca38f5e31891a3a773950e6d0fea48a7188551",
            ciphertext: "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46"
        },
        output: "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
    });

    test({
        input: {
            derivedKey: "fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd",
            ciphertext: "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c"
        },
        output: "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
    });

});

describe("Dump private key", function () {

    function check_structure(json) {
        assert.instanceOf(json, Object);
        assert.property(json, "address");
        assert.property(json, "Crypto");
        assert.instanceOf(json.Crypto, Object);
        assert.property(json.Crypto, "cipher");
        assert(
            json.Crypto.cipher === "aes-128-ctr" ||
            json.Crypto.cipher === "aes-128-cbc"
        );
        assert.property(json.Crypto, "cipherparams");
        assert.instanceOf(json.Crypto.cipherparams, Object);
        assert.property(json.Crypto.cipherparams, "iv");
        assert.strictEqual(json.Crypto.cipherparams.iv.length, 32);
        assert.property(json.Crypto, "ciphertext");
        assert.strictEqual(json.Crypto.ciphertext.length, 64);
        assert.isTrue(validator.isHexadecimal(json.Crypto.ciphertext));
        assert.property(json.Crypto, "kdf");
        assert(json.Crypto.kdf === "pbkdf2" || json.Crypto.kdf === "scrypt");
        assert.property(json.Crypto, "kdfparams");
        assert.instanceOf(json.Crypto.kdfparams, Object);
        if (json.Crypto.kdf === "pbkdf2") {
            assert.property(json.Crypto.kdfparams, "c");
            assert.property(json.Crypto.kdfparams, "prf");
            assert.strictEqual(json.Crypto.kdfparams.c, 262144);
            assert.strictEqual(json.Crypto.kdfparams.prf, "hmac-sha256");
        } else {
            assert.property(json.Crypto.kdfparams, "n");
            assert.property(json.Crypto.kdfparams, "r");
            assert.property(json.Crypto.kdfparams, "p");
            assert.strictEqual(json.Crypto.kdfparams.n, 262144);
            assert.strictEqual(json.Crypto.kdfparams.r, 1);
            assert.strictEqual(json.Crypto.kdfparams.p, 8);
        }
        assert.property(json.Crypto.kdfparams, "dklen");
        assert.isNumber(json.Crypto.kdfparams.dklen);
        assert(json.Crypto.kdfparams.dklen >= 32);
        assert.property(json.Crypto.kdfparams, "salt");
        assert(json.Crypto.kdfparams.salt.length >= 32);
        assert.isTrue(validator.isHexadecimal(json.Crypto.kdfparams.salt));
        assert.property(json.Crypto, "mac");
        assert.strictEqual(json.Crypto.mac.length, 64);
        assert.isTrue(validator.isHexadecimal(json.Crypto.mac));
        assert.property(json, "id");
        assert.strictEqual(json.id.length, 36);
        assert.isTrue(validator.isUUID(json.id));
        assert.property(json, "version");
        assert.strictEqual(json.version, 3);
    }

    function check_values(t, json) {
        assert.strictEqual(json.address, t.expected.address);
        assert.strictEqual(
            json.Crypto.cipher,
            keythereum.constants.cipher
        );
        assert.strictEqual(
            json.Crypto.cipher,
            t.expected.Crypto.cipher
        );
        assert.strictEqual(
            json.Crypto.cipherparams.iv,
            t.input.iv.toString("hex")
        );
        assert.strictEqual(
            json.Crypto.cipherparams.iv,
            t.expected.Crypto.cipherparams.iv
        );
        assert.strictEqual(
            json.Crypto.ciphertext,
            t.expected.Crypto.ciphertext
        );
        assert.strictEqual(
            json.Crypto.kdf,
            t.expected.Crypto.kdf
        );
        if (t.input.kdf === "scrypt") {
            assert.strictEqual(
                json.Crypto.kdfparams.n,
                t.expected.Crypto.kdfparams.n
            );
            assert.strictEqual(
                json.Crypto.kdfparams.n,
                keythereum.constants.scrypt.n
            );
            assert.strictEqual(
                json.Crypto.kdfparams.r,
                t.expected.Crypto.kdfparams.r
            );
            assert.strictEqual(
                json.Crypto.kdfparams.r,
                keythereum.constants.scrypt.r
            );
            assert.strictEqual(
                json.Crypto.kdfparams.p,
                t.expected.Crypto.kdfparams.p
            );
            assert.strictEqual(
                json.Crypto.kdfparams.p,
                keythereum.constants.scrypt.p
            );
        } else {
            assert.strictEqual(
                json.Crypto.kdfparams.c,
                t.expected.Crypto.kdfparams.c
            );
            assert.strictEqual(
                json.Crypto.kdfparams.c,
                keythereum.constants.pbkdf2.c
            );
            assert.strictEqual(
                json.Crypto.kdfparams.prf,
                t.expected.Crypto.kdfparams.prf
            );
            assert.strictEqual(
                json.Crypto.kdfparams.prf,
                keythereum.constants.pbkdf2.prf
            );
        }
        assert.strictEqual(
            json.Crypto.kdfparams.dklen,
            t.expected.Crypto.kdfparams.dklen
        );
        assert.strictEqual(
            json.Crypto.kdfparams.dklen,
            keythereum.constants.pbkdf2.dklen
        );
        assert.strictEqual(
            json.Crypto.kdfparams.salt,
            t.expected.Crypto.kdfparams.salt
        );
        assert.strictEqual(
            json.Crypto.mac,
            t.expected.Crypto.mac
        );
        assert.strictEqual(
            json.version,
            t.expected.version
        );
    }

    var test = function (t) {

        it("[sync] " + t.input.kdf, function () {
            this.timeout(TIMEOUT);
            var json = keythereum.dump(
                t.input.password,
                t.input.privateKey,
                t.input.salt,
                t.input.iv,
                t.input.kdf
            );
            if (json.error) throw json;
            check_structure(json);
            check_values(t, json);            
        });

        if (t.input.kdf !== "scrypt") {
            it("[async] " + t.input.kdf, function (done) {
                this.timeout(TIMEOUT);                
                keythereum.dump(
                    t.input.password,
                    t.input.privateKey,
                    t.input.salt,
                    t.input.iv,
                    t.input.kdf,
                    function (json) {
                        if (json.error) {
                            done(json);
                        } else {
                            check_structure(json);
                            check_values(t, json);
                            done();
                        }
                    }
                );
            });
        }
    };

    test({
        input: {
            password: "testpassword",
            privateKey: new Buffer(
                "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
                "hex"
            ),
            salt: "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd",
            iv: new Buffer("6087dab2f9fdbbfaddc31a909735c1e6", "hex"),
            kdf: "pbkdf2-sha256"
        },
        expected: {
            address: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
            Crypto: {
                cipher: "aes-128-ctr",
                cipherparams: {
                    iv: "6087dab2f9fdbbfaddc31a909735c1e6"
                },
                ciphertext: "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
                kdf: "pbkdf2",
                kdfparams: {
                    c: 262144,
                    dklen: 32,
                    prf: "hmac-sha256",
                    salt: "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
                },
                mac: "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
            },
            version: 3
        }
    });

    if (!process.env.CONTINUOUS_INTEGRATION) {
        test({
            input: {
                password: "testpassword",
                privateKey: "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
                salt: "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19",
                iv: "83dbcc02d8ccb40e466191a123791e0e",
                kdf: "scrypt"
            },
            expected: {
                address: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
                Crypto: {
                    cipher: "aes-128-ctr",
                    cipherparams: {
                        iv: "83dbcc02d8ccb40e466191a123791e0e"
                    },
                    ciphertext: "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
                    kdf: "scrypt",
                    kdfparams: {
                        dklen: 32,
                        n: 262144,
                        r: 1,
                        p: 8,
                        salt: "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
                    },
                    mac: "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
                },
                version: 3
            }
        });
    }

});

describe("Export to file", function () {

    var json = {
        address: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
        Crypto: {
            cipher: "aes-128-ctr",
            ciphertext: "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
            cipherparams: {
                iv: "6087dab2f9fdbbfaddc31a909735c1e6"
            },
            mac: "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2",
            kdf: "pbkdf2",
            kdfparams: {
                c: 262144,
                dklen: 32,
                prf: "hmac-sha256",
                salt: "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
            }
        },
        id: "e13b209c-3b2f-4327-bab0-3bef2e51630d",
        version: 3
    };

    it("export key to json file", function (done) {
        keythereum.exportToFile(json, function (outfile) {
            assert.strictEqual(outfile.slice(0, 5), "UTC--");
            assert.isAbove(outfile.indexOf(json.address), -1);
            done();
        });
    });

});
