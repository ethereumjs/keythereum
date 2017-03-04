/**
 * keythereum unit tests
 * @author Jack Peterson (jack@tinybike.net)
 */

"use strict";

var fs = require("fs");
var path = require("path");
var crypto = require("crypto");
var assert = require("chai").assert;
var pubToAddress = require("ethereumjs-util").pubToAddress;
var ecdsa = new (require("elliptic").ec)("secp256k1");
var keythereum = require("../");
var checkKeyObj = require("./checkKeyObj");

// suppress logging
keythereum.constants.quiet = true;

// change hashing rounds to match geth's default
keythereum.constants.pbkdf2.c = 262144;
keythereum.constants.scrypt.n = 262144;

// timeout for asynchronous unit tests
var TIMEOUT = 120000;

// create private key
var privateKey = crypto.randomBytes(32);

// derive secp256k1 ECDSA public key and address from private key
var publicKey = new Buffer(ecdsa.keyFromPrivate(privateKey).getPublic("arr"));
var address = pubToAddress(publicKey, true).toString("hex");

describe("Private key recovery", function () {

  // password used as secret key for aes-256 cipher
  var password = "wheethereum";
  var secret = crypto.createHash("sha256").update(password).digest("hex");
  var cipher = crypto.createCipher("aes-256-cbc", secret);
  var encryptedPrivateKey = cipher.update(privateKey, "hex", "base64");
  encryptedPrivateKey += cipher.final("base64");

  it(encryptedPrivateKey + " -> " + privateKey.toString("hex"), function () {

    // verify private key is recovered by decryption
    var decipher = crypto.createDecipher("aes-256-cbc", secret);
    var decryptedPrivateKey = decipher.update(encryptedPrivateKey, "base64", "hex");
    decryptedPrivateKey += decipher.final("hex");
    assert.strictEqual(decryptedPrivateKey, privateKey.toString("hex"));
  });

});

describe("Derive Ethereum address from private key", function () {

  var test = function (t) {
    it(JSON.stringify(t.privateKey) + " -> " + t.address, function () {
      assert.strictEqual(
        keythereum.privateKeyToAddress(t.privateKey),
        "0x" + t.address
      );
    });
  };

  var runtests = function (t) {

    test({
      privateKey: t.privateKey,
      address: t.address
    });

    test({
      privateKey: t.privateKey.toString("hex"),
      address: t.address
    });

    test({
      privateKey: t.privateKey.toString("base64"),
      address: t.address
    });
  };

  runtests({
    privateKey: new Buffer(privateKey, "hex"),
    address: address
  });

  runtests({
    privateKey: new Buffer(
      "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
      "hex"
    ),
    address: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b"
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

  for (var i = 0; i < 25; ++i) runtests(i);

});

describe("Encryption", function () {

  var test = function (t) {

    var label = t.input.cipher + ": " + JSON.stringify(t.input.plaintext)+
      " -> " + t.expected.ciphertext;

    it(label, function () {
      var oldCipher = keythereum.constants.cipher;
      keythereum.constants.cipher = t.input.cipher;
      assert.strictEqual(
        keythereum.encrypt(t.input.plaintext, t.input.key, t.input.iv),
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
    plaintext: new Buffer(
      "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
      "hex"
    ),
    ciphertext: new Buffer(
      "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
      "hex"
    ),
    key: new Buffer("f06d69cdc7da0faffb1008270bca38f5", "hex"),
    iv: new Buffer("6087dab2f9fdbbfaddc31a909735c1e6", "hex")
  });

  runtests({
    plaintext: new Buffer(
      "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
      "hex"
    ),
    ciphertext: new Buffer(
      "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
      "hex"
    ),
    key: new Buffer("fac192ceb5fd772906bea3e118a69e8b", "hex"),
    iv: new Buffer("83dbcc02d8ccb40e466191a123791e0e", "hex")
  });

});

describe("Decryption", function () {

  var test = function (t) {

    var label = t.input.cipher + ": " + JSON.stringify(t.input.ciphertext)+
      " -> " + t.expected.plaintext;

    it(label, function () {
      var oldCipher = keythereum.constants.cipher;
      keythereum.constants.cipher = t.input.cipher;
      assert.strictEqual(
        keythereum.decrypt(t.input.ciphertext, t.input.key, t.input.iv),
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
    plaintext: new Buffer(
      "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
      "hex"
    ),
    ciphertext: new Buffer(
      "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
      "hex"
    ),
    key: new Buffer("f06d69cdc7da0faffb1008270bca38f5", "hex"),
    iv: new Buffer("6087dab2f9fdbbfaddc31a909735c1e6", "hex")
  });

  runtests({
    plaintext: new Buffer(
      "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
      "hex"
    ),
    ciphertext: new Buffer(
      "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
      "hex"
    ),
    key: new Buffer("fac192ceb5fd772906bea3e118a69e8b", "hex"),
    iv: new Buffer("83dbcc02d8ccb40e466191a123791e0e", "hex")
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
      this.timeout(TIMEOUT);
      keythereum.crypto.pbkdf2 = pbkdf2;
      keythereum.crypto.pbkdf2Sync = pbkdf2Sync;

      // synchronous
      var derivedKey = keythereum.deriveKey(
        t.input.password,
        t.input.salt,
        { kdf: t.input.kdf }
      );
      if (derivedKey.error) {
        done(derivedKey);
      } else {
        assert.strictEqual(derivedKey.toString("hex"), t.expected);

        // asynchronous
        keythereum.deriveKey(
          t.input.password,
          t.input.salt,
          { kdf: t.input.kdf },
          function (derivedKey) {
            if (derivedKey.error) {
              done(derivedKey);
            } else {
              assert.strictEqual(derivedKey.toString("hex"), t.expected);
              done();
            }
          }
        );
      }
    });
    it("using sjcl: " + t.input.kdf, function (done) {
      this.timeout(TIMEOUT);
      keythereum.crypto.pbkdf2 = undefined;
      keythereum.crypto.pbkdf2Sync = undefined;

      // synchronous
      var derivedKey = keythereum.deriveKey(
        t.input.password,
        t.input.salt,
        { kdf: t.input.kdf }
      );
      if (derivedKey.error) {
        done(derivedKey);
      } else {
        assert.strictEqual(derivedKey.toString("hex"), t.expected);

        // asynchronous
        keythereum.deriveKey(
          t.input.password,
          t.input.salt,
          { kdf: t.input.kdf },
          function (derivedKey) {
            if (derivedKey.error) {
              done(derivedKey);
            } else {
              assert.strictEqual(derivedKey.toString("hex"), t.expected);
              done();
            }
          }
        );
      }
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
      this.timeout(TIMEOUT);

      // synchronous
      var keyObject = keythereum.dump(
        t.input.password,
        t.input.privateKey,
        t.input.salt,
        t.input.iv,
        { kdf: t.input.kdf }
      );
      if (keyObject.error) {
        done(keyObject);
      } else {
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
            if (keyObj.error) {
              done(keyObj);
            } else {
              checkKeyObj.structure(keythereum, keyObj);
              checkKeyObj.values(keythereum, t, keyObj);
              done();
            }
          }
        );
      }
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
    this.timeout(TIMEOUT);

    // synchronous
    var keypath = keythereum.exportToFile(keyObj);
    var outfile = keypath.split('/');
    assert.isArray(outfile);

    outfile = outfile[outfile.length - 1];
    assert.strictEqual(outfile.slice(0, 5), "UTC--");
    assert.isAbove(outfile.indexOf(keyObj.address), -1);

    fs.unlinkSync(keypath);

    // asynchronous
    keythereum.exportToFile(keyObj, null, function (keyPath) {
      var outFile = keyPath.split('/');
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
    this.timeout(TIMEOUT);
    keythereum.browser = true;

    // synchronous
    var json = keythereum.exportToFile(keyObj);
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
      this.timeout(TIMEOUT);

      var keyObject = keythereum.importFromFile(t.input.address, t.input.datadir);
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

  // TODO get some version 2 keys to test with

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
      this.timeout(TIMEOUT);

      // synchronous
      var dk = keythereum.recover(t.input.password, t.input.keyObject);
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

});
