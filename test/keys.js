/**
 * ethereumjs-keys tests
 * @author Jack Peterson (jack@tinybike.net)
 */

"use strict";

var crypto = require("crypto");
var assert = require("chai").assert;
var validator = require("validator");
var pubToAddress = require("ethereumjs-util").pubToAddress;
var ecdsa = new (require("elliptic").ec)("secp256k1");
var EthKeys = require("../");
var log = console.log;

// create private key, get public key and address
var privateKey = crypto.randomBytes(32);

// timeout for asynchronous unit tests
var TIMEOUT = 120000;

describe("Crypto", function () {
    var publicKey = new Buffer(ecdsa.keyFromPrivate(privateKey).getPublic("arr"));
    var address = pubToAddress(publicKey).toString("hex");

    // user specified handle and password
    var handle = "tinybike";
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
        assert.strictEqual(EthKeys.privateKeyToAddress(privateKey), "0x" + address);
    });

    it("generate random 256-bit private key & salt, 128-bit initialization vector", function () {
        var plaintext = EthKeys.create();
        assert.property(plaintext, "privateKey");
        assert.isNotNull(plaintext.privateKey);
        assert.property(plaintext, "iv");
        assert.isNotNull(plaintext.iv);
        assert.property(plaintext, "salt");
        assert.isNotNull(plaintext.salt);
    });

});

// Test vectors:
// https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition

describe("Key derivation", function () {

    var test = function (t) {
        it("[sync] " + t.input.kdf, function () {
            this.timeout(TIMEOUT);
            var derivedKey = EthKeys.deriveKey(
                t.input.password,
                t.input.salt,
                t.input.kdf
            );
            assert.strictEqual(derivedKey.toString("hex"), t.expected);
        });
        if (t.input.kdf !== "scrypt") {
            it("[async] " + t.input.kdf, function (done) {
                this.timeout(TIMEOUT);
                EthKeys.deriveKey(
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

    test({
        input: {
            password: "testpassword",
            salt: "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19",
            kdf: "scrypt"
        },
        expected: "fac192ceb5fd772906bea3e118a69e8bbb5cc24229e20d8766fd298291bba6bd"
    });

});

describe("Message authentication code", function () {

    var test = function (t) {
        it("convert " + JSON.stringify(t.input) + " -> " + t.output, function () {
            var mac = EthKeys.getMAC(t.input.derivedKey, t.input.ciphertext);
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

    function validate(json) {
        assert.instanceOf(json, Object);
        assert.property(json, "crypto");
        assert.instanceOf(json.crypto, Object);
        assert.property(json.crypto, "cipher");
        assert(json.crypto.cipher === "aes-128-ctr"
            || json.crypto.cipher === "aes-128-cbc");
        assert.property(json.crypto, "cipherparams");
        assert.instanceOf(json.crypto.cipherparams, Object);
        assert.property(json.crypto.cipherparams, "iv");
        assert.strictEqual(json.crypto.cipherparams.iv.length, 32);
        assert.property(json.crypto, "ciphertext");
        assert.strictEqual(json.crypto.ciphertext.length, 64);
        assert.isTrue(validator.isHexadecimal(json.crypto.ciphertext));
        assert.property(json.crypto, "kdf");
        assert(json.crypto.kdf === "pbkdf2" || json.crypto.kdf === "scrypt");
        assert.property(json.crypto, "kdfparams");
        assert.instanceOf(json.crypto.kdfparams, Object);
        if (json.crypto.kdf === "pbkdf2") {
            assert.property(json.crypto.kdfparams, "c");
            assert.property(json.crypto.kdfparams, "prf");
            assert.strictEqual(json.crypto.kdfparams.c, 262144);
            assert.strictEqual(json.crypto.kdfparams.prf, "hmac-sha256");
        } else {
            assert.property(json.crypto.kdfparams, "n");
            assert.property(json.crypto.kdfparams, "r");
            assert.property(json.crypto.kdfparams, "p");
            assert.strictEqual(json.crypto.kdfparams.n, 262144);
            assert.strictEqual(json.crypto.kdfparams.r, 1);
            assert.strictEqual(json.crypto.kdfparams.p, 8);
        }
        assert.property(json.crypto.kdfparams, "dklen");
        assert.isNumber(json.crypto.kdfparams.dklen);
        assert(json.crypto.kdfparams.dklen >= 32);
        assert.property(json.crypto.kdfparams, "salt");
        assert(json.crypto.kdfparams.salt.length >= 32);
        assert.isTrue(validator.isHexadecimal(json.crypto.kdfparams.salt));
        assert.property(json.crypto, "mac");
        assert.strictEqual(json.crypto.mac.length, 64);
        assert.isTrue(validator.isHexadecimal(json.crypto.mac));
        assert.property(json, "id");
        assert.strictEqual(json.id.length, 36);
        assert.isTrue(validator.isUUID(json.id));
        assert.property(json, "version");
        assert.strictEqual(json.version, 3);
    }

    var test = function (t) {
        it(t.input.kdf, function (done) {
            this.timeout(TIMEOUT);
            EthKeys.dumpPrivateKey(
                t.input.password,
                t.input.privateKey,
                t.input.salt,
                t.input.iv,
                t.input.kdf,
                function (json) {
                    if (json.error) {
                        done(json);
                    } else {
                        validate(json);
                        assert.strictEqual(
                            json.crypto.cipher,
                            EthKeys.constants.cipher
                        );
                        assert.strictEqual(
                            json.crypto.cipher,
                            t.expected.crypto.cipher
                        );
                        assert.strictEqual(
                            json.crypto.cipherparams.iv,
                            t.input.iv.toString("hex")
                        );
                        assert.strictEqual(
                            json.crypto.cipherparams.iv,
                            t.expected.crypto.cipherparams.iv
                        );
                        assert.strictEqual(
                            json.crypto.ciphertext,
                            t.expected.crypto.ciphertext
                        );
                        assert.strictEqual(
                            json.crypto.kdf,
                            t.expected.crypto.kdf
                        );
                        if (t.input.kdf === "scrypt") {
                            assert.strictEqual(
                                json.crypto.kdfparams.n,
                                t.expected.crypto.kdfparams.n
                            );
                            assert.strictEqual(
                                json.crypto.kdfparams.n,
                                EthKeys.constants.scrypt.n
                            );
                            assert.strictEqual(
                                json.crypto.kdfparams.r,
                                t.expected.crypto.kdfparams.r
                            );
                            assert.strictEqual(
                                json.crypto.kdfparams.r,
                                EthKeys.constants.scrypt.r
                            );
                            assert.strictEqual(
                                json.crypto.kdfparams.p,
                                t.expected.crypto.kdfparams.p
                            );
                            assert.strictEqual(
                                json.crypto.kdfparams.p,
                                EthKeys.constants.scrypt.p
                            );
                        } else {
                            assert.strictEqual(
                                json.crypto.kdfparams.c,
                                t.expected.crypto.kdfparams.c
                            );
                            assert.strictEqual(
                                json.crypto.kdfparams.c,
                                EthKeys.constants.pbkdf2.c
                            );
                            assert.strictEqual(
                                json.crypto.kdfparams.prf,
                                t.expected.crypto.kdfparams.prf
                            );
                            assert.strictEqual(
                                json.crypto.kdfparams.prf,
                                EthKeys.constants.pbkdf2.prf
                            );
                        }
                        assert.strictEqual(
                            json.crypto.kdfparams.dklen,
                            t.expected.crypto.kdfparams.dklen
                        );
                        assert.strictEqual(
                            json.crypto.kdfparams.dklen,
                            EthKeys.constants.pbkdf2.dklen
                        );
                        assert.strictEqual(
                            json.crypto.kdfparams.salt,
                            t.expected.crypto.kdfparams.salt
                        );
                        assert.strictEqual(
                            json.crypto.mac,
                            t.expected.crypto.mac
                        );
                        assert.strictEqual(
                            json.version,
                            t.expected.version
                        );
                        done();
                    }
                }
            );
        });
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
            crypto: {
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

    test({
        input: {
            password: "testpassword",
            privateKey: "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
            salt: "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19",
            iv: "83dbcc02d8ccb40e466191a123791e0e",
            kdf: "scrypt"
        },
        expected: {
            crypto: {
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

});
