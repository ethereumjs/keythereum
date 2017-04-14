/* eslint-env node, mocha */

"use strict";

var fs = require("fs");
var path = require("path");
var crypto = require("crypto");
var assert = require("chai").assert;
var keythereum = require("../");
var checkKeyObj = require("./checkKeyObj");
var DEBUG = false;

// timeout for asynchronous unit tests
var TIMEOUT = 120000;

// create private key
var privateKey = crypto.randomBytes(32);

// suppress logging
keythereum.constants.quiet = !DEBUG;

describe("Check if valid hex-encoded string", function () {
  var test = function (t) {
    it(t.description, function () {
      t.assertions(keythereum.isHex(t.s));
    });
  };
  test({
    description: "deadbeef -> true",
    s: "deadbeef",
    assertions: function (isHex) {
      assert.isTrue(isHex);
    }
  });
  test({
    description: "deadbee -> false",
    s: "deadbee",
    assertions: function (isHex) {
      assert.isFalse(isHex);
    }
  });
  test({
    description: "dEaDbEeF -> true",
    s: "dEaDbEeF",
    assertions: function (isHex) {
      assert.isTrue(isHex);
    }
  });
  test({
    description: "123456 -> true",
    s: "123456",
    assertions: function (isHex) {
      assert.isTrue(isHex);
    }
  });
  test({
    description: "00aa33 -> true",
    s: "00aa33",
    assertions: function (isHex) {
      assert.isTrue(isHex);
    }
  });
  test({
    description: "0xdEaDbEeF -> false",
    s: "0xdEaDbEeF",
    assertions: function (isHex) {
      assert.isFalse(isHex);
    }
  });
  test({
    description: ".. -> false",
    s: "..",
    assertions: function (isHex) {
      assert.isFalse(isHex);
    }
  });
});

describe("Check if valid base64-encoded string", function () {
  var test = function (t) {
    it(t.description, function () {
      t.assertions(keythereum.isBase64(t.s));
    });
  };
  // test cases: https://github.com/chriso/validator.js/blob/master/test/validators.js
  [
    "aGVsbG8gd29ybGQ=",
    "ZGVhZGIwYg==",
    "YWxpdmViZWVm",
    "Zg==",
    "Zm8=",
    "Zm9v",
    "Zm9vYg==",
    "Zm9vYmE=",
    "Zm9vYmFy",
    "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4=",
    "Vml2YW11cyBmZXJtZW50dW0gc2VtcGVyIHBvcnRhLg==",
    "U3VzcGVuZGlzc2UgbGVjdHVzIGxlbw==",
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuMPNS1Ufof9EW/M98FNw" +
      "UAKrwflsqVxaxQjBQnHQmiI7Vac40t8x7pIb8gLGV6wL7sBTJiPovJ0V7y7oc0Ye" +
      "rhKh0Rm4skP2z/jHwwZICgGzBvA0rH8xlhUiTvcwDCJ0kc+fh35hNt8srZQM4619" +
      "FTgB66Xmp4EtVyhpQV+t02g6NzK72oZI0vnAvqhpkxLeLiMCyrI416wHm5Tkukhx" +
      "QmcL2a6hNOyu0ixX/x2kSFXApEnVrJ+/IxGyfyw8kf4N2IZpW5nEP847lpfj0SZZ" +
      "Fwrd1mnfnDbYohX2zRptLy2ZUn06Qo9pkG5ntvFEPo9bfZeULtjYzIl6K8gJ2uGZ" +
      "HQIDAQAB"
  ].forEach(function (s) {
    test({
      description: s + " -> true",
      s: s,
      assertions: function (isBase64) {
        assert.isTrue(isBase64);
      }
    });
  });
  [
    "12345",
    "",
    "Vml2YW11cyBmZXJtZtesting123",
    "Zg=",
    "Z===",
    "Zm=8",
    "=m9vYg==",
    "Zm9vYmFy===="
  ].forEach(function (s) {
    test({
      description: s + " -> false",
      s: "s",
      assertions: function (isBase64) {
        assert.isFalse(isBase64);
      }
    });
  });
});

describe("Convert a string to a Buffer", function () {
  var test = function (t) {
    it(t.description, function () {
      t.assertions(keythereum.str2buf(t.params.str, t.params.enc));
    });
  };
  test({
    description: "[ascii] hello world",
    params: {
      str: "hello world",
      enc: "ascii"
    },
    assertions: function (output) {
      assert.strictEqual(output.toString("utf8"), "hello world");
    }
  });
  test({
    description: "[utf8] hello world",
    params: {
      str: "hello world",
      enc: "utf8"
    },
    assertions: function (output) {
      assert.strictEqual(output.toString("utf8"), "hello world");
    }
  });
  test({
    description: "[hex] 68656c6c6f20776f726c64",
    params: {
      str: "68656c6c6f20776f726c64",
      enc: "hex"
    },
    assertions: function (output) {
      assert.strictEqual(output.toString("utf8"), "hello world");
    }
  });
  test({
    description: "[inferred hex] 68656c6c6f20776f726c64",
    params: {
      str: "68656c6c6f20776f726c64"
    },
    assertions: function (output) {
      assert.strictEqual(output.toString("utf8"), "hello world");
    }
  });
  test({
    description: "[inferred utf8] hello world",
    params: {
      str: "hello world"
    },
    assertions: function (output) {
      assert.strictEqual(output.toString("utf8"), "hello world");
    }
  });
  test({
    description: "[inferred utf8] hello",
    params: {
      str: "hello"
    },
    assertions: function (output) {
      assert.strictEqual(output.toString("utf8"), "hello");
    }
  });
  test({
    description: "[inferred base64] aGVsbG8gd29ybGQ=",
    params: {
      str: "aGVsbG8gd29ybGQ="
    },
    assertions: function (output) {
      assert.strictEqual(output.toString("utf8"), "hello world");
    }
  });
  test({
    description: "[inferred base64] ZGVhZGIwYg==",
    params: {
      str: "ZGVhZGIwYg=="
    },
    assertions: function (output) {
      assert.strictEqual(output.toString("utf8"), "deadb0b");
    }
  });
  test({
    description: "[inferred base64] aGVsbG8gd29ybGQ=",
    params: {
      str: "aGVsbG8gd29ybGQ="
    },
    assertions: function (output) {
      assert.strictEqual(output.toString("utf8"), "hello world");
    }
  });
  test({
    description: "[inferred base64] YWxpdmViZWVm",
    params: {
      str: "YWxpdmViZWVm"
    },
    assertions: function (output) {
      assert.strictEqual(output.toString("utf8"), "alivebeef");
    }
  });
});

describe("Check if selected cipher is available", function () {
  var test = function (t) {
    it(t.description, function () {
      t.assertions(keythereum.isCipherAvailable(t.cipher));
    });
  };
  test({
    description: "aes-128-ctr should be available",
    cipher: "aes-128-ctr",
    assertions: function (isAvailable) {
      assert.isTrue(isAvailable);
    }
  });
  test({
    description: "aes-128-cbc should be available",
    cipher: "aes-128-cbc",
    assertions: function (isAvailable) {
      assert.isTrue(isAvailable);
    }
  });
  test({
    description: "roflcipher should not be available",
    cipher: "roflcipher",
    assertions: function (isAvailable) {
      assert.isFalse(isAvailable);
    }
  });
});

describe("Private key recovery", function () {

  // password used as secret key for aes-256 cipher
  var password = "wheethereum";
  var secret = crypto.createHash("sha256").update(password).digest("hex");
  var cipher = crypto.createCipher("aes-256-cbc", secret);
  var encryptedPrivateKey = cipher.update(privateKey, "hex", "base64");
  encryptedPrivateKey += cipher.final("base64");

  // verify private key is recovered by decryption
  it(encryptedPrivateKey + " -> " + privateKey.toString("hex"), function () {
    var decipher = crypto.createDecipher("aes-256-cbc", secret);
    var decryptedPrivateKey = decipher.update(encryptedPrivateKey, "base64", "hex");
    decryptedPrivateKey += decipher.final("hex");
    assert.strictEqual(decryptedPrivateKey, privateKey.toString("hex"));
  });
});

describe("Derive Ethereum address from private key", function () {
  var test = function (t) {
    it(t.description + ": " + t.privateKey, function () {
      t.assertions(keythereum.privateKeyToAddress(t.privateKey));
      t.assertions(keythereum.privateKeyToAddress(Buffer.from(t.privateKey, "hex")));
      t.assertions(keythereum.privateKeyToAddress(Buffer.from(t.privateKey, "hex").toString("base64")));
    });
  };
  test({
    description: "32-byte private key",
    privateKey: "d1b1178d3529626a1a93e073f65028370d14c7eb0936eb42abef05db6f37ad7d",
    assertions: function (address) {
      assert.strictEqual(address, "0xcb61d5a9c4896fb9658090b597ef0e7be6f7b67e");
    }
  });
  test({
    description: "32-byte private key",
    privateKey: "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
    assertions: function (address) {
      assert.strictEqual(address, "0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b");
    }
  });
  test({
    description: "32-byte private key",
    privateKey: "6445042b8e8cc121fb6a8985606a84b4cb07dac6dfb3633e769ec27dd2370984",
    assertions: function (address) {
      assert.strictEqual(address, "0xe1e212c353f7a682693c198ba5ff85849f8300cc");
    }
  });
  test({
    description: "32-byte private key",
    privateKey: "490127c2782fb55943beeb31943ec26f48a9a5121cd7e91799eb354d30d46529",
    assertions: function (address) {
      assert.strictEqual(address, "0xf0c4ee355432a7c7da12bdef04543723d110d591");
    }
  });
  test({
    description: "31-byte private key",
    privateKey: "fa7b3db73dc7dfdf8c5fbdb796d741e4488628c41fc4febd9160a866ba0f35",
    assertions: function (address) {
      assert.strictEqual(address, "0xd1e64e5480bfaf733ba7d48712decb8227797a4e");
    }
  });
  test({
    description: "30-byte private key",
    privateKey: "81c29e8142bb6a81bef5a92bda7a8328a5c85bb2f9542e76f9b0f94fc018",
    assertions: function (address) {
      assert.strictEqual(address, "0x31e9d1e6d844bd3a536800ef8d8be6a9975db509");
    }
  });
});

describe("Create random private key, salt and initialization vector", function () {

  var test = function (dk, params) {
    assert.property(dk, "privateKey");
    assert.isNotNull(dk.privateKey);
    assert.instanceOf(dk.privateKey, Buffer);
    assert.strictEqual(dk.privateKey.length, params.keyBytes);

    assert.property(dk, "iv");
    assert.isNotNull(dk.iv);
    assert.instanceOf(dk.iv, Buffer);
    assert.strictEqual(dk.iv.length, params.ivBytes);

    assert.property(dk, "salt");
    assert.isNotNull(dk.salt);
    assert.instanceOf(dk.salt, Buffer);
    assert.strictEqual(dk.salt.length, params.keyBytes);
  };

  var runtests = function (i) {
    var runtest = function (params) {
      it("create key " + i + ": " + JSON.stringify(params), function (done) {

        // synchronous
        test(keythereum.create(), keythereum.constants);
        test(keythereum.create(params), params);

        // asynchronous
        keythereum.create(null, function (dk) {
          test(dk, keythereum.constants);
          keythereum.create(params, function (dk) {
            test(dk, params);
            done();
          });
        });
      });
    };

    runtest(keythereum.constants);
    runtest({ keyBytes: 16, ivBytes: 16 });
    runtest({ keyBytes: 32, ivBytes: 16 });
    runtest({ keyBytes: 64, ivBytes: 16 });
    runtest({ keyBytes: 128, ivBytes: 16 });
    runtest({ keyBytes: 256, ivBytes: 16 });
  };

  var i;
  for (i = 0; i < 25; ++i) runtests(i);
});

describe("Encryption", function () {

  var test = function (t) {
    var label = t.input.cipher + ": " + JSON.stringify(t.input.plaintext)+
      " -> " + t.expected.ciphertext;
    it(label, function () {
      var oldCipher = keythereum.constants.cipher;
      keythereum.constants.cipher = t.input.cipher;
      assert.strictEqual(
        keythereum.encrypt(t.input.plaintext, t.input.key, t.input.iv).toString("base64"),
        t.expected.ciphertext
      );
      keythereum.constants.cipher = oldCipher;
    });
  };

  var runtests = function (t) {
    test({
      input: {
        plaintext: t.plaintext,
        key: t.key,
        iv: t.iv,
        cipher: "aes-128-ctr"
      },
      expected: {
        ciphertext: t.ciphertext.toString("base64")
      }
    });
    test({
      input: {
        plaintext: t.plaintext.toString("hex"),
        key: t.key.toString("hex"),
        iv: t.iv.toString("hex"),
        cipher: "aes-128-ctr"
      },
      expected: {
        ciphertext: t.ciphertext.toString("base64")
      }
    });
    test({
      input: {
        plaintext: t.plaintext.toString("base64"),
        key: t.key.toString("base64"),
        iv: t.iv.toString("base64"),
        cipher: "aes-128-ctr"
      },
      expected: {
        ciphertext: t.ciphertext.toString("base64")
      }
    });
  };

  runtests({
    plaintext: Buffer.from(
      "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
      "hex"
    ),
    ciphertext: Buffer.from(
      "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
      "hex"
    ),
    key: Buffer.from("f06d69cdc7da0faffb1008270bca38f5", "hex"),
    iv: Buffer.from("6087dab2f9fdbbfaddc31a909735c1e6", "hex")
  });
  runtests({
    plaintext: Buffer.from(
      "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
      "hex"
    ),
    ciphertext: Buffer.from(
      "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
      "hex"
    ),
    key: Buffer.from("fac192ceb5fd772906bea3e118a69e8b", "hex"),
    iv: Buffer.from("83dbcc02d8ccb40e466191a123791e0e", "hex")
  });
});

describe("Decryption", function () {

  var test = function (t) {
    var label = t.input.cipher + ": " + JSON.stringify(t.input.ciphertext) + " -> " + t.expected.plaintext;
    it(label, function () {
      var oldCipher = keythereum.constants.cipher;
      keythereum.constants.cipher = t.input.cipher;
      assert.strictEqual(
        keythereum.decrypt(t.input.ciphertext, t.input.key, t.input.iv).toString("hex"),
        t.expected.plaintext
      );
      keythereum.constants.cipher = oldCipher;
    });
  };

  var runtests = function (t) {
    test({
      input: {
        ciphertext: t.ciphertext,
        key: t.key,
        iv: t.iv,
        cipher: "aes-128-ctr"
      },
      expected: {
        plaintext: t.plaintext.toString("hex")
      }
    });
    test({
      input: {
        ciphertext: t.ciphertext.toString("hex"),
        key: t.key.toString("hex"),
        iv: t.iv.toString("hex"),
        cipher: "aes-128-ctr"
      },
      expected: {
        plaintext: t.plaintext.toString("hex")
      }
    });
    test({
      input: {
        ciphertext: t.ciphertext.toString("base64"),
        key: t.key.toString("base64"),
        iv: t.iv.toString("base64"),
        cipher: "aes-128-ctr"
      },
      expected: {
        plaintext: t.plaintext.toString("hex")
      }
    });
  };
  runtests({
    plaintext: Buffer.from(
      "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
      "hex"
    ),
    ciphertext: Buffer.from(
      "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
      "hex"
    ),
    key: Buffer.from("f06d69cdc7da0faffb1008270bca38f5", "hex"),
    iv: Buffer.from("6087dab2f9fdbbfaddc31a909735c1e6", "hex")
  });
  runtests({
    plaintext: Buffer.from(
      "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
      "hex"
    ),
    ciphertext: Buffer.from(
      "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
      "hex"
    ),
    key: Buffer.from("fac192ceb5fd772906bea3e118a69e8b", "hex"),
    iv: Buffer.from("83dbcc02d8ccb40e466191a123791e0e", "hex")
  });
});

// Test vectors:
// https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition

describe("Key derivation", function () {

  var test = function (t) {
    var pbkdf2, pbkdf2Sync;

    before(function () {
      pbkdf2 = keythereum.crypto.pbkdf2;
      pbkdf2Sync = keythereum.crypto.pbkdf2Sync;
    });

    after(function () {
      keythereum.crypto.pbkdf2 = pbkdf2;
      keythereum.crypto.pbkdf2Sync = pbkdf2Sync;
    });

    it("using crypto: " + t.input.kdf, function (done) {
      var derivedKey;
      this.timeout(TIMEOUT);
      keythereum.crypto.pbkdf2 = pbkdf2;
      keythereum.crypto.pbkdf2Sync = pbkdf2Sync;

      // synchronous
      derivedKey = keythereum.deriveKey(
        t.input.password,
        t.input.salt,
        { kdf: t.input.kdf }
      );
      if (derivedKey.error) return done(derivedKey);
      assert.strictEqual(derivedKey.toString("hex"), t.expected);

      // asynchronous
      keythereum.deriveKey(
        t.input.password,
        t.input.salt,
        { kdf: t.input.kdf },
        function (derivedKey) {
          if (derivedKey.error) return done(derivedKey);
          assert.strictEqual(derivedKey.toString("hex"), t.expected);
          done();
        }
      );
    });
    it("using sjcl: " + t.input.kdf, function (done) {
      var derivedKey;
      this.timeout(TIMEOUT);
      keythereum.crypto.pbkdf2 = undefined;
      keythereum.crypto.pbkdf2Sync = undefined;

      // synchronous
      derivedKey = keythereum.deriveKey(
        t.input.password,
        t.input.salt,
        { kdf: t.input.kdf }
      );
      if (derivedKey.error) return done(derivedKey);
      assert.strictEqual(derivedKey.toString("hex"), t.expected);

      // asynchronous
      keythereum.deriveKey(
        t.input.password,
        t.input.salt,
        { kdf: t.input.kdf },
        function (derivedKey) {
          if (derivedKey.error) return done(derivedKey);
          assert.strictEqual(derivedKey.toString("hex"), t.expected);
          done();
        }
      );
    });
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

    it(t.input.kdf, function (done) {
      var keyObject;
      this.timeout(TIMEOUT);

      // synchronous
      keyObject = keythereum.dump(
        t.input.password,
        t.input.privateKey,
        t.input.salt,
        t.input.iv,
        { kdf: t.input.kdf }
      );
      if (keyObject.error) return done(keyObject);
      checkKeyObj.structure(keythereum, keyObject);
      checkKeyObj.values(keythereum, t, keyObject);

      // asynchronous
      keythereum.dump(
        t.input.password,
        t.input.privateKey,
        t.input.salt,
        t.input.iv,
        { kdf: t.input.kdf },
        function (keyObj) {
          if (keyObj.error) return done(keyObj);
          checkKeyObj.structure(keythereum, keyObj);
          checkKeyObj.values(keythereum, t, keyObj);
          done();
        }
      );
    });
  };
  test({
    input: {
      password: "testpassword",
      privateKey: Buffer.from(
        "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
        "hex"
      ),
      salt: "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd",
      iv: Buffer.from("6087dab2f9fdbbfaddc31a909735c1e6", "hex"),
      kdf: "pbkdf2-sha256"
    },
    expected: {
      address: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
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
      address: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
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

describe("Generate keystore filename", function () {
  var test = function (t) {
    it(t.address, function () {
      t.assertions(keythereum.generateKeystoreFilename(t.address));
    });
  };
  test({
    address: "0000000000000000000000000000000000000b0b",
    assertions: function (filename) {
      var splitFilename = filename.split("--");
      assert.strictEqual(splitFilename.length, 3);
      assert.strictEqual(splitFilename[0], "UTC");
      assert.strictEqual(splitFilename[2], "0000000000000000000000000000000000000b0b");
    }
  });
  test({
    address: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
    assertions: function (filename) {
      var splitFilename = filename.split("--");
      assert.strictEqual(splitFilename.length, 3);
      assert.strictEqual(splitFilename[0], "UTC");
      assert.strictEqual(splitFilename[2], "008aeeda4d805471df9b2a5b0f38a0c3bcba786b");
    }
  });
  test({
    address: "c9a9adc70a9cbf077ae4bd0a170d88592914e0cc",
    assertions: function (filename) {
      var splitFilename = filename.split("--");
      assert.strictEqual(splitFilename.length, 3);
      assert.strictEqual(splitFilename[0], "UTC");
      assert.strictEqual(splitFilename[2], "c9a9adc70a9cbf077ae4bd0a170d88592914e0cc");
    }
  });
});

describe("Export to file", function () {

  var keyObj = {
    address: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
    crypto: {
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
    var keypath, outfile;
    this.timeout(TIMEOUT);

    // synchronous
    keypath = keythereum.exportToFile(keyObj);
    outfile = keypath.split("/");
    assert.isArray(outfile);
    outfile = outfile[outfile.length - 1];
    assert.strictEqual(outfile.slice(0, 5), "UTC--");
    assert.isAbove(outfile.indexOf(keyObj.address), -1);
    fs.unlinkSync(keypath);

    // asynchronous
    keythereum.exportToFile(keyObj, null, function (keyPath) {
      var outFile = keyPath.split("/");
      assert.isArray(outFile);
      outFile = outFile[outFile.length - 1];
      assert.strictEqual(outFile.slice(0, 5), "UTC--");
      assert.isAbove(outFile.indexOf(keyObj.address), -1);
      fs.unlink(keyPath, function (exc) {
        if (exc) return done(exc);
        done();
      });
    });
  });
  it("export key to json (browser)", function (done) {
    var json;
    this.timeout(TIMEOUT);
    keythereum.browser = true;

    // synchronous
    json = keythereum.exportToFile(keyObj);
    assert.strictEqual(json, JSON.stringify(keyObj));

    // asynchronous
    keythereum.exportToFile(keyObj, null, function (json) {
      assert.strictEqual(json, JSON.stringify(keyObj));
      keythereum.browser = false;
      done();
    });
  });
});

describe("Import from keystore file", function () {

  var test = function (t) {
    var label = "[" + t.expected.crypto.kdf + "] import " + t.input.address + " from file";
    it(label, function (done) {
      var keyObject;
      this.timeout(TIMEOUT);
      keyObject = keythereum.importFromFile(t.input.address, t.input.datadir);
      checkKeyObj.structure(keythereum, keyObject);
      checkKeyObj.values(keythereum, t, keyObject);
      keythereum.importFromFile(t.input.address, t.input.datadir, function (keyObj) {
        checkKeyObj.structure(keythereum, keyObj);
        checkKeyObj.values(keythereum, t, keyObj);
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
        crypto: {
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
        crypto: {
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
        address: "00efeeb535b1b1c408cca2ffd55b2b233269728c",
        datadir: path.join(__dirname, "fixtures")
      },
      expected: {
        address: "00efeeb535b1b1c408cca2ffd55b2b233269728c",
        crypto: {
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
        crypto: {
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
  });

  describe("Version 1", function () {
    test({
      input: {
        address: "ebb117ef11769e675e0245062a8e6296dfe42da4",
        datadir: path.join(__dirname, "fixtures")
      },
      expected: {
        address: "ebb117ef11769e675e0245062a8e6296dfe42da4",
        crypto: {
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
        crypto: {
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
        crypto: {
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
  });
});

describe("Recover plaintext private key from key object", function () {

  var test = function (t) {
    var keyObjectCrypto = t.input.keyObject.Crypto || t.input.keyObject.crypto;
    var label = "[" + keyObjectCrypto.kdf + "] "+ "recover key for " + t.input.keyObject.address;
    it(label, function (done) {
      var dk;
      this.timeout(TIMEOUT);

      // synchronous
      dk = keythereum.recover(t.input.password, t.input.keyObject);
      assert.strictEqual(dk.toString("hex"), t.expected);

      // asynchronous
      keythereum.recover(t.input.password, t.input.keyObject, function (dk) {
        assert.strictEqual(dk.toString("hex"), t.expected);
        done();
      });
    });
  };

  test({
    input: {
      password: "foobar",
      keyObject: {
        address: "7ef5a6135f1fd6a02593eedc869c6d41d934aef8",
        crypto: {
          cipher: "aes-128-ctr",
          ciphertext: "1d0839166e7a15b9c1333fc865d69858b22df26815ccf601b28219b6192974e1",
          cipherparams: {
            iv: "8df6caa7ff1b00c4e871f002cb7921ed"
          },
          kdf: "scrypt",
          kdfparams: {
            dklen: 32,
            n: 8,
            p: 16,
            r: 8,
            salt: "e5e6ef3f4ea695f496b643ebd3f75c0aa58ef4070e90c80c5d3fb0241bf1595c"
          },
          mac: "6d16dfde774845e4585357f24bce530528bc69f4f84e1e22880d34fa45c273e5"
        },
        id: "950077c7-71e3-4c44-a4a1-143919141ed4",
        version: 3
      }
    },
    expected: "976f9f7772781ff6d1c93941129d417c49a209c674056a3cf5e27e225ee55fa8"
  });
  test({
    input: {
      password: "foobar",
      keyObject: {
        address: "f466859ead1932d743d622cb74fc058882e8648a",
        crypto: {
          cipher: "aes-128-ctr",
          ciphertext: "cb664472deacb41a2e995fa7f96fe29ce744471deb8d146a0e43c7898c9ddd4d",
          cipherparams: {
            iv: "dfd9ee70812add5f4b8f89d0811c9158"
          },
          kdf: "scrypt",
          kdfparams: {
            dklen: 32,
            n: 8,
            p: 16,
            r: 8,
            salt: "0d6769bf016d45c479213990d6a08d938469c4adad8a02ce507b4a4e7b7739f1"
          },
          mac: "bac9af994b15a45dd39669fc66f9aa8a3b9dd8c22cb16e4d8d7ea089d0f1a1a9"
        },
        id: "472e8b3d-afb6-45b5-8111-72c89895099a",
        version: 3
      }
    },
    expected: "539f9b4106fb452408e1ee43d177077f057a8fdc1e1fad92c61e68982b4e3c4b"
  });
  test({
    input: {
      password: "g",
      keyObject: {
        address: "cb61d5a9c4896fb9658090b597ef0e7be6f7b67e",
        Crypto: {
          cipher: "aes-128-cbc",
          ciphertext: "6143d3192db8b66eabd693d9c4e414dcfaee52abda451af79ccf474dafb35f1bfc7ea013aa9d2ee35969a1a2e8d752d0",
          cipherparams: {
            iv: "35337770fc2117994ecdcad026bccff4"
          },
          kdf: "scrypt",
          kdfparams: {
            n: 262144,
            r: 8,
            p: 1,
            dklen: 32,
            salt: "9afcddebca541253a2f4053391c673ff9fe23097cd8555d149d929e4ccf1257f"
          },
          mac: "3f3d5af884b17a100b0b3232c0636c230a54dc2ac8d986227219b0dd89197644",
          version: "1"
        },
        id: "e25f7c1f-d318-4f29-b62c-687190d4d299",
        version: "1"
      }
    },
    expected: "d1b1178d3529626a1a93e073f65028370d14c7eb0936eb42abef05db6f37ad7d"
  });
  test({
    input: {
      password: "foo",
      keyObject: {
        address: "d1e64e5480bfaf733ba7d48712decb8227797a4e",
        crypto: {
          cipher: "aes-128-ctr",
          cipherparams: {
            iv: "e0c41130a323adc1446fc82f724bca2f"
          },
          ciphertext: "9517cd5bdbe69076f9bf5057248c6c050141e970efa36ce53692d5d59a3984",
          kdf: "scrypt",
          kdfparams: {
            dklen: 32,
            n: 2,
            r: 8,
            p: 1,
            salt: "711f816911c92d649fb4c84b047915679933555030b3552c1212609b38208c63"
          },
          mac: "d5e116151c6aa71470e67a7d42c9620c75c4d23229847dcc127794f0732b0db5"
        },
        id: "fecfc4ce-e956-48fd-953b-30f8b52ed66c",
        version: 3
      }
    },
    expected: "fa7b3db73dc7dfdf8c5fbdb796d741e4488628c41fc4febd9160a866ba0f35"
  });
  test({
    input: {
      password: "foo",
      keyObject: {
        address: "31e9d1e6d844bd3a536800ef8d8be6a9975db509",
        crypto: {
          cipher: "aes-128-ctr",
          cipherparams: {
            iv: "3ca92af36ad7c2cd92454c59cea5ef00"
          },
          ciphertext: "108b7d34f3442fc26ab1ab90ca91476ba6bfa8c00975a49ef9051dc675aa",
          kdf: "scrypt",
          kdfparams: {
            dklen: 32,
            n: 2,
            r: 8,
            p: 1,
            salt: "d0769e608fb86cda848065642a9c6fa046845c928175662b8e356c77f914cd3b"
          },
          mac: "75d0e6759f7b3cefa319c3be41680ab6beea7d8328653474bd06706d4cc67420"
        },
        id: "a37e1559-5955-450d-8075-7b8931b392b2",
        version: 3
      }
    },
    expected: "81c29e8142bb6a81bef5a92bda7a8328a5c85bb2f9542e76f9b0f94fc018"
  });
  test({
    input: {
      password: "foobar",
      keyObject: {
        address: "289d485d9771714cce91d3393d764e1311907acc",
        crypto: {
          cipher: "aes-128-ctr",
          ciphertext: "faf32ca89d286b107f5e6d842802e05263c49b78d46eac74e6109e9a963378ab",
          cipherparams: {
            iv: "558833eec4a665a8c55608d7d503407d"
          },
          kdf: "scrypt",
          kdfparams: {
            dklen: 32,
            n: 8,
            p: 16,
            r: 8,
            salt: "d571fff447ffb24314f9513f5160246f09997b857ac71348b73e785aab40dc04"
          },
          mac: "21edb85ff7d0dab1767b9bf498f2c3cb7be7609490756bd32300bb213b59effe"
        },
        id: "3279afcf-55ba-43ff-8997-02dcc46a6525",
        version: 3
      }
    },
    expected: "14a447d8d4c69714f8750e1688feb98857925e1fec6dee7c75f0079d10519d25"
  });
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
  test({
    input: {
      password: "testpassword",
      keyObject: {
        address: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
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
    },
    expected: "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"
  });
  test({
    input: {
      password: "testpass",
      keyObject: {
        address: "e1e212c353f7a682693c198ba5ff85849f8300cc",
        Crypto: {
          cipher: "aes-128-ctr",
          ciphertext: "008baf806bb0f855fbc35fcf22cab732315a368e6e6d529b50dcbc60c955d349",
          cipherparams: {iv: "92a01f397d5c2ce4c2964c36a9754f69"},
          kdf: "scrypt",
          kdfparams: {
            dklen: 32,
            n: 262144,
            p: 1,
            r: 8,
            salt: "7deda03653eb9d767a7feb7ab7ae82a17559954f7ae62fef93f7bc25813c3ccf"
          },
          mac: "2ff9d7b27b57b856f92b5396819ba18144e434665f945295d2ea3e354c4f6093"
        },
        id: "64c495d9-05ca-4d3b-8c95-94060df83544",
        version: 3
      }
    },
    expected: "6445042b8e8cc121fb6a8985606a84b4cb07dac6dfb3633e769ec27dd2370984"
  });
  test({
    input: {
      password: "testpassword",
      keyObject: {
        address: "f0c4ee355432a7c7da12bdef04543723d110d591",
        Crypto: {
          cipher: "aes-128-cbc",
          cipherparams: {iv: "bda427191686ac4455142bc449543129"},
          ciphertext: "097cc168892c41872ba92af7a359708f2e9f2f420465684cf84bb2d1a7351e37a7746607d3845ab91ce82cbf9ba54c69",
          kdf: "scrypt",
          kdfparams: {
            n: 262144,
            r: 8,
            p: 1,
            dklen: 32,
            salt: "98e3f47b814f5a55a2298cf92a2572a047c31d30c6b8bb4d1e5f60cc4a437653"
          },
          mac: "4c5d82b039d482b51d2f6ca09f1ff9b44f6e4a35f5bf0155cb1a163c75742278",
          version: "1"
        },
        id: "efe9ba02-56a3-42f5-9fb3-10059629c7bf",
        version: "1"
      }
    },
    expected: "490127c2782fb55943beeb31943ec26f48a9a5121cd7e91799eb354d30d46529"
  });
  test({
    input: {
      password: "correcthorsebatterystaple",
      keyObject: {
        address: "f0c4ee355432a7c7da12bdef04543723d110d591",
        Crypto: {
          cipher: "aes-128-cbc",
          cipherparams: {iv: "bda427191686ac4455142bc449543129"},
          ciphertext: "fc221520b157d08bd51e1b220a188e36b2f53a783ed5777e4438951349dd80b33089a18f493a84f279f376edc42a370d",
          kdf: "scrypt",
          kdfparams: {
            n: 262144,
            r: 8,
            p: 1,
            dklen: 32,
            salt: "98e3f47b814f5a55a2298cf92a2572a047c31d30c6b8bb4d1e5f60cc4a437653"
          },
          mac: "f4f15a66f99a87923cc8d8fcbf2fd5d3c2f2de238d87b024113f97a37778210a",
          version: "1"
        },
        id: "efe9ba02-56a3-42f5-9fb3-10059629c7bf",
        version: "1"
      }
    },
    expected: "490127c2782fb55943beeb31943ec26f48a9a5121cd7e91799eb354d30d46529"
  });
});
