"use strict";

var assert = require("chai").assert;
var isUUID = require("validator").isUUID;
var isHex = require("../").isHex;

module.exports = {

  structure: function (keythereum, keyObject) {
    var keyObjectCrypto = keyObject.Crypto || keyObject.crypto;
    assert.instanceOf(keyObject, Object);
    assert.property(keyObject, "address");
    assert(keyObject.Crypto || keyObject.crypto);
    assert.instanceOf(keyObjectCrypto, Object);
    assert.property(keyObjectCrypto, "cipher");
    assert(
      keyObjectCrypto.cipher === "aes-128-ctr" ||
      keyObjectCrypto.cipher === "aes-128-cbc"
    );
    assert.property(keyObjectCrypto, "cipherparams");
    assert.instanceOf(keyObjectCrypto.cipherparams, Object);
    assert.property(keyObjectCrypto.cipherparams, "iv");
    assert.strictEqual(keyObjectCrypto.cipherparams.iv.length, 32);
    assert.property(keyObjectCrypto, "ciphertext");
    assert(keyObjectCrypto.ciphertext.length >= 64);
    assert.isTrue(isHex(keyObjectCrypto.ciphertext));
    assert.property(keyObjectCrypto, "kdf");
    assert(keyObjectCrypto.kdf === "pbkdf2" || keyObjectCrypto.kdf === "scrypt");
    assert.property(keyObjectCrypto, "kdfparams");
    assert.instanceOf(keyObjectCrypto.kdfparams, Object);
    if (keyObjectCrypto.kdf === "pbkdf2") {
      assert.property(keyObjectCrypto.kdfparams, "c");
      assert.property(keyObjectCrypto.kdfparams, "prf");
      assert.strictEqual(keyObjectCrypto.kdfparams.prf, "hmac-sha256");
    } else {
      assert.property(keyObjectCrypto.kdfparams, "n");
      assert.property(keyObjectCrypto.kdfparams, "r");
      assert.property(keyObjectCrypto.kdfparams, "p");
    }
    assert.property(keyObjectCrypto.kdfparams, "dklen");
    assert.isNumber(keyObjectCrypto.kdfparams.dklen);
    assert(keyObjectCrypto.kdfparams.dklen >= 32);
    assert.property(keyObjectCrypto.kdfparams, "salt");
    assert(keyObjectCrypto.kdfparams.salt.length >= 32);
    assert.isTrue(isHex(keyObjectCrypto.kdfparams.salt));
    assert.property(keyObjectCrypto, "mac");
    assert.strictEqual(keyObjectCrypto.mac.length, 64);
    assert.isTrue(isHex(keyObjectCrypto.mac));
    assert.property(keyObject, "id");
    assert.strictEqual(keyObject.id.length, 36);
    assert.isTrue(isUUID(keyObject.id));
    assert.property(keyObject, "version");
    assert(keyObject.version === "1" || keyObject.version === 3);
  },

  values: function (keythereum, t, keyObject) {
    var keyObjectCrypto = keyObject.Crypto || keyObject.crypto;
    assert.strictEqual(keyObject.address, t.expected.address);
    assert.strictEqual(
      keyObjectCrypto.cipher,
      t.expected.crypto.cipher
    );
    if (t.input.iv) {
      assert.strictEqual(
        keyObjectCrypto.cipherparams.iv,
        t.input.iv.toString("hex")
      );
    }
    assert.strictEqual(
      keyObjectCrypto.cipherparams.iv,
      t.expected.crypto.cipherparams.iv
    );
    assert.strictEqual(
      keyObjectCrypto.ciphertext,
      t.expected.crypto.ciphertext
    );
    assert.strictEqual(
      keyObjectCrypto.kdf,
      t.expected.crypto.kdf
    );
    if (t.input.kdf) {
      if (t.input.kdf === "scrypt") {
        assert.strictEqual(
          keyObjectCrypto.kdfparams.n,
          t.expected.crypto.kdfparams.n
        );
        assert.strictEqual(
          keyObjectCrypto.kdfparams.n,
          keythereum.constants.scrypt.n
        );
        assert.strictEqual(
          keyObjectCrypto.kdfparams.r,
          t.expected.crypto.kdfparams.r
        );
        assert.strictEqual(
          keyObjectCrypto.kdfparams.r,
          keythereum.constants.scrypt.r
        );
        assert.strictEqual(
          keyObjectCrypto.kdfparams.p,
          t.expected.crypto.kdfparams.p
        );
        assert.strictEqual(
          keyObjectCrypto.kdfparams.p,
          keythereum.constants.scrypt.p
        );
      } else {
        assert.strictEqual(
          keyObjectCrypto.kdfparams.c,
          t.expected.crypto.kdfparams.c
        );
        assert.strictEqual(
          keyObjectCrypto.kdfparams.c,
          keythereum.constants.pbkdf2.c
        );
        assert.strictEqual(
          keyObjectCrypto.kdfparams.prf,
          t.expected.crypto.kdfparams.prf
        );
        assert.strictEqual(
          keyObjectCrypto.kdfparams.prf,
          keythereum.constants.pbkdf2.prf
        );
      }
      assert.strictEqual(
        keyObjectCrypto.kdfparams.dklen,
        t.expected.crypto.kdfparams.dklen
      );
      assert.strictEqual(
        keyObjectCrypto.kdfparams.dklen,
        keythereum.constants.pbkdf2.dklen
      );
      assert.strictEqual(
        keyObjectCrypto.kdfparams.salt,
        t.expected.crypto.kdfparams.salt
      );
    }
    assert.strictEqual(
      keyObjectCrypto.mac,
      t.expected.crypto.mac
    );
    assert.strictEqual(
      keyObject.version,
      t.expected.version
    );
  }
};
