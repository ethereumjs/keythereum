"use strict";

var assert = require("chai").assert;
var validator = require("validator");

module.exports = {

    structure: function (keythereum, keyObject) {
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
    },

    values: function (keythereum, t, keyObject) {
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
};
