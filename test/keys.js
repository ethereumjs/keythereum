/**
 * keythereum unit tests
 * @author Jack Peterson (jack@tinybike.net)
 */

"use strict";

var path = require("path");
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

function check_structure(keyObject) {
    assert.instanceOf(keyObject, Object);
    assert.property(keyObject, "address");
    assert.property(keyObject, "Crypto");
    assert.instanceOf(keyObject.Crypto, Object);
    assert.property(keyObject.Crypto, "cipher");
    assert(
        keyObject.Crypto.cipher === "aes-128-ctr" ||
        keyObject.Crypto.cipher === "aes-128-cbc"
    );
    assert.property(keyObject.Crypto, "cipherparams");
    assert.instanceOf(keyObject.Crypto.cipherparams, Object);
    assert.property(keyObject.Crypto.cipherparams, "iv");
    assert.strictEqual(keyObject.Crypto.cipherparams.iv.length, 32);
    assert.property(keyObject.Crypto, "ciphertext");
    assert(keyObject.Crypto.ciphertext.length >= 64);
    assert.isTrue(validator.isHexadecimal(keyObject.Crypto.ciphertext));
    assert.property(keyObject.Crypto, "kdf");
    assert(keyObject.Crypto.kdf === "pbkdf2" || keyObject.Crypto.kdf === "scrypt");
    assert.property(keyObject.Crypto, "kdfparams");
    assert.instanceOf(keyObject.Crypto.kdfparams, Object);
    if (keyObject.Crypto.kdf === "pbkdf2") {
        assert.property(keyObject.Crypto.kdfparams, "c");
        assert.property(keyObject.Crypto.kdfparams, "prf");
        assert.strictEqual(keyObject.Crypto.kdfparams.prf, "hmac-sha256");
    } else {
        assert.property(keyObject.Crypto.kdfparams, "n");
        assert.property(keyObject.Crypto.kdfparams, "r");
        assert.property(keyObject.Crypto.kdfparams, "p");
    }
    assert.property(keyObject.Crypto.kdfparams, "dklen");
    assert.isNumber(keyObject.Crypto.kdfparams.dklen);
    assert(keyObject.Crypto.kdfparams.dklen >= 32);
    assert.property(keyObject.Crypto.kdfparams, "salt");
    assert(keyObject.Crypto.kdfparams.salt.length >= 32);
    assert.isTrue(validator.isHexadecimal(keyObject.Crypto.kdfparams.salt));
    assert.property(keyObject.Crypto, "mac");
    assert.strictEqual(keyObject.Crypto.mac.length, 64);
    assert.isTrue(validator.isHexadecimal(keyObject.Crypto.mac));
    assert.property(keyObject, "id");
    assert.strictEqual(keyObject.id.length, 36);
    assert.isTrue(validator.isUUID(keyObject.id));
    assert.property(keyObject, "version");
    assert(keyObject.version === "1" || keyObject.version === 3);
}

function check_values(t, keyObject) {
    assert.strictEqual(keyObject.address, t.expected.address);
    assert.strictEqual(
        keyObject.Crypto.cipher,
        t.expected.Crypto.cipher
    );
    if (t.input.iv) {
        assert.strictEqual(
            keyObject.Crypto.cipherparams.iv,
            t.input.iv.toString("hex")
        );
    }
    assert.strictEqual(
        keyObject.Crypto.cipherparams.iv,
        t.expected.Crypto.cipherparams.iv
    );
    assert.strictEqual(
        keyObject.Crypto.ciphertext,
        t.expected.Crypto.ciphertext
    );
    assert.strictEqual(
        keyObject.Crypto.kdf,
        t.expected.Crypto.kdf
    );
    if (t.input.kdf) {
        if (t.input.kdf === "scrypt") {
            assert.strictEqual(
                keyObject.Crypto.kdfparams.n,
                t.expected.Crypto.kdfparams.n
            );
            assert.strictEqual(
                keyObject.Crypto.kdfparams.n,
                keythereum.constants.scrypt.n
            );
            assert.strictEqual(
                keyObject.Crypto.kdfparams.r,
                t.expected.Crypto.kdfparams.r
            );
            assert.strictEqual(
                keyObject.Crypto.kdfparams.r,
                keythereum.constants.scrypt.r
            );
            assert.strictEqual(
                keyObject.Crypto.kdfparams.p,
                t.expected.Crypto.kdfparams.p
            );
            assert.strictEqual(
                keyObject.Crypto.kdfparams.p,
                keythereum.constants.scrypt.p
            );
        } else {
            assert.strictEqual(
                keyObject.Crypto.kdfparams.c,
                t.expected.Crypto.kdfparams.c
            );
            assert.strictEqual(
                keyObject.Crypto.kdfparams.c,
                keythereum.constants.pbkdf2.c
            );
            assert.strictEqual(
                keyObject.Crypto.kdfparams.prf,
                t.expected.Crypto.kdfparams.prf
            );
            assert.strictEqual(
                keyObject.Crypto.kdfparams.prf,
                keythereum.constants.pbkdf2.prf
            );
        }
        assert.strictEqual(
            keyObject.Crypto.kdfparams.dklen,
            t.expected.Crypto.kdfparams.dklen
        );
        assert.strictEqual(
            keyObject.Crypto.kdfparams.dklen,
            keythereum.constants.pbkdf2.dklen
        );
        assert.strictEqual(
            keyObject.Crypto.kdfparams.salt,
            t.expected.Crypto.kdfparams.salt
        );
    }
    assert.strictEqual(
        keyObject.Crypto.mac,
        t.expected.Crypto.mac
    );
    assert.strictEqual(
        keyObject.version,
        t.expected.version
    );
}

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

describe("Import from keystore file", function () {

    var test = function (t) {

        it("[sync]  " + t.expected.Crypto.kdf + " import " + t.input.address + " from file", function () {
            this.timeout(TIMEOUT);
            var keyObject = keythereum.importFromFile(t.input.address, t.input.datadir);
            check_structure(keyObject);
            check_values(t, keyObject);
        });

        it("[async] " + t.expected.Crypto.kdf + " import " + t.input.address + " from file", function (done) {
            this.timeout(TIMEOUT);
            keythereum.importFromFile(t.input.address, t.input.datadir, function (keyObject) {
                check_structure(keyObject);
                check_values(t, keyObject);
                done();
            });
        });

    };

    describe("Version 3", function () {

        test({
            input: {
                address: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
                datadir: path.join(__dirname, "fixtures")
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
                id: "e13b209c-3b2f-4327-bab0-3bef2e51630d",
                version: 3
            }
        });

        test({
            input: {
                address: "c9a9adc70a9cbf077ae4bd0a170d88592914e0cc",
                datadir: path.join(__dirname, "fixtures")
            },
            expected: {
                address: "c9a9adc70a9cbf077ae4bd0a170d88592914e0cc",
                Crypto: {
                    cipher: "aes-128-ctr",
                    ciphertext: "92d71fb22fd51f54837c61ba3c03a511d26505dfdc72fc6425deaead0103ec5b",
                    cipherparams: {
                        iv: "306e7a27057d7d3f350de0aa90239ca9"
                    },
                    mac: "833a5d2de213523b87b3303799f7a5d74a3dba7158bb4669d1761b473ef67fc1",
                    kdf: "pbkdf2",
                    kdfparams: {
                        c: 65536,
                        dklen: 32,
                        prf: "hmac-sha256",
                        salt: "c91893bdae79b1115405e3a546718227a2cc61a1528e5b53e467ad29a8225a7a"
                    }
                },
                id: "b34cf55b-4781-48f6-a321-6b1388aa5a4d",
                version: 3
            }
        });

        test({
            input: {
                address: "c9a9adc70a9cbf077ae4bd0a170d88592914e0cc",
                datadir: path.join(__dirname, "fixtures")
            },
            expected: {
                address: "c9a9adc70a9cbf077ae4bd0a170d88592914e0cc",
                Crypto: {
                    cipher: "aes-128-ctr",
                    ciphertext: "92d71fb22fd51f54837c61ba3c03a511d26505dfdc72fc6425deaead0103ec5b",
                    cipherparams: {
                        iv: "306e7a27057d7d3f350de0aa90239ca9"
                    },
                    mac: "833a5d2de213523b87b3303799f7a5d74a3dba7158bb4669d1761b473ef67fc1",
                    kdf: "pbkdf2",
                    kdfparams: {
                        c: 65536,
                        dklen: 32,
                        prf: "hmac-sha256",
                        salt: "c91893bdae79b1115405e3a546718227a2cc61a1528e5b53e467ad29a8225a7a"
                    }
                },
                id: "b34cf55b-4781-48f6-a321-6b1388aa5a4d",
                version: 3
            }
        });

        if (!process.env.CONTINUOUS_INTEGRATION) {
            test({
                input: {
                    address: "00efeeb535b1b1c408cca2ffd55b2b233269728c",
                    datadir: path.join(__dirname, "fixtures")
                },
                expected: {
                    address: "00efeeb535b1b1c408cca2ffd55b2b233269728c",
                    Crypto: {
                        cipher: "aes-128-ctr",
                        ciphertext: "8da6723594a551ca467d24fdfc92e9948505eb97e07be43564e61f9152ca3089",
                        cipherparams: {
                            iv: "22a4c940f804e32a8dbd9ff4c90c913b"
                        },
                        kdf: "scrypt",
                        kdfparams: {
                            dklen: 32,
                            n: 262144,
                            p: 1,
                            r: 8,
                            salt: "b55a4440b57210c0bafdcc5422c9b9d04e9bd7ab1e3dccaf51be838e6aa7c037"
                        },
                        mac: "57d910c27c3ae13957062b8a3ac620cdbe27ed4e69292a852e072a4926e2eacf"
                    },
                    id: "2a60191c-b718-4522-b487-fb7de1ad021f",
                    version: 3
                }
            });

            test({
                input: {
                    address: "5a79b93487966d0eafb5264ca0408e66b7db9269",
                    datadir: path.join(__dirname, "fixtures")
                },
                expected: {
                    address: "5a79b93487966d0eafb5264ca0408e66b7db9269",
                    Crypto: {
                        cipher: "aes-128-ctr",
                        ciphertext: "07f5ba9d3a90b8c33f57e903bba7541d42ccc1676a38195c65ff936e2437e7d9",
                        cipherparams: {
                            iv: "5b65c6eb075c37685c08169b5a4d89d6"
                        },
                        kdf: "scrypt",
                        kdfparams: {
                            dklen: 32,
                            n: 262144,
                            p: 1,
                            r: 8,
                            salt: "ff3c29472b4cc9e6e35ffa983fd0cfed6260a373ec9eb3b9ad1a9285a4067d88"
                        },
                        mac: "aee429e0286079e5081ab4ec3040bfbf88aa38245bfbe9796405d3e1d376398b"
                    },
                    id: "aa84e172-a45a-4084-ab85-796b04bb719d",
                    version: 3
                }
            });
        }

    });

    // TODO get some version 2 keys to test with

    describe("Version 1", function () {

        if (!process.env.CONTINUOUS_INTEGRATION) {
            test({
                input: {
                    address: "ebb117ef11769e675e0245062a8e6296dfe42da4",
                    datadir: path.join(__dirname, "fixtures")
                },
                expected: {
                    address: "ebb117ef11769e675e0245062a8e6296dfe42da4",
                    Crypto: {
                        cipher: "aes-128-cbc",
                        ciphertext: "edfa88ba7e67f26dd846e17fe5f1cabc0ef618949a5150287ac86b19dade146fb93df12716ae7e1b881f844738d60404",
                        cipherparams: {
                            iv: "5d99a672d1ecc115671b75f4e852f573"
                        },
                        kdf: "scrypt",
                        kdfparams: {
                            n: 262144,
                            r: 8,
                            p: 1,
                            dklen: 32,
                            salt: "231d12dd08d728db6705a73f460eaa61650c39fc12ac266f6ccd577bd3f7cc74"
                        },
                        mac: "ebe0dcc2e12a28a0b4a6040ec0198ed856ccf9f82718b989faee1e22626c36df",
                        version: "1"
                    },
                    id: "294724c7-8508-496d-8fdf-eef62872bc10",
                    version: "1"
                }
            });

            test({
                input: {
                    address: "f0c4ee355432a7c7da12bdef04543723d110d591",
                    datadir: path.join(__dirname, "fixtures")
                },
                expected: {
                    address: "f0c4ee355432a7c7da12bdef04543723d110d591",
                    Crypto: {
                        cipher: "aes-128-cbc",
                        ciphertext: "5dcd8d2678a492a88a5d4929e51016accf8cd5d3831989a85011642a463e24656c41e43159e9a35e978b79355dcb052c",
                        cipherparams: {
                            iv: "bda427191686ac4455142bc449543129"
                        },
                        kdf: "scrypt",
                        kdfparams: {
                            n: 262144,
                            r: 8,
                            p: 1,
                            dklen: 32,
                            salt: "98e3f47b814f5a55a2298cf92a2572a047c31d30c6b8bb4d1e5f60cc4a437653"
                        },
                        mac: "b2d8ef9d23fae559257bb52205b490776de6c94465d8947ecfbab9807604fb07",
                        version: "1"
                    },
                    id: "b5d5ef3a-d42e-4eeb-86ae-51a89131e38e",
                    version: "1"
                }
            });

            test({
                input: {
                    address: "2c97f31d2db40aa57d0e6ca5fa8aedf7d99592db",
                    datadir: path.join(__dirname, "fixtures")
                },
                expected: {
                    address: "2c97f31d2db40aa57d0e6ca5fa8aedf7d99592db",
                    Crypto: {
                        cipher: "aes-128-cbc",
                        ciphertext: "b0d4523d2c49dcb0134fc5cd341e46099af70c32dbec776bf2d9665b8a5b1539ada61d1fe4962f4f536e1b980928e462",
                        cipherparams: {
                            iv: "e00bc9b2a963b7491a8fb6bb2750bea0"
                        },
                        kdf: "scrypt",
                        kdfparams: {
                            n: 262144,
                            r: 8,
                            p: 1,
                            dklen: 32,
                            salt: "ea373fd764ef47f9ae28ea59824000e9d4f4dab89fa52502ee3c1cfe03582c87"
                        },
                        mac: "3bfb8637cec761c2d7dd96f09d7eafaa39120360932cee9e2f6701efbe6426fb",
                        version: "1"
                    },
                    id: "5790f0a7-56ae-44b5-9b75-9fe694d6bc54",
                    version: "1"
                }
            });
        }
    
    });

});

describe("Recover plaintext private key from key object", function () {

    var test = function (t) {

        it("[sync]  recover key for " + t.input.keyObject.address, function () {
            this.timeout(TIMEOUT);
            var dk = keythereum.recover(t.input.password, t.input.keyObject);
            assert.strictEqual(dk.toString("hex"), t.expected);
        });

        it("[async] recover key for " + t.input.keyObject.address, function (done) {
            this.timeout(TIMEOUT);
            keythereum.recover(t.input.password, t.input.keyObject, function (dk) {
                assert.strictEqual(dk.toString("hex"), t.expected);
                done();
            });
        });

    };

    test({
        input: {
            password: "testpassword",
            keyObject: {
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
                id: "e13b209c-3b2f-4327-bab0-3bef2e51630d",
                version: 3
            }
        },
        expected: "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"
    });

    test({
        input: {
            password: "testpassword",
            keyObject: {
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
        },
        expected: "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"
    });

});
