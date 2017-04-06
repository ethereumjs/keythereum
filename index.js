/**
 * keythereum: create/import/export ethereum keys
 * @author Jack Peterson (jack@tinybike.net)
 */

"use strict";

var NODE_JS = (typeof module !== "undefined") && process && !process.browser;

var path = (NODE_JS) ? require("path") : null;
var fs = (NODE_JS) ? require("fs") : null;
var crypto = require("crypto");
var sjcl = require("sjcl");
var uuid = require("uuid");
var validator = require("validator");
var privateToAddress = require("ethereumjs-util").privateToAddress;
var keccak = require("./lib/keccak");
var scrypt = require("./lib/scrypt");

// convert string to buffer
function str2buf(str, enc) {
  if (str && str.constructor === String) {
    if (enc) {
      str = new Buffer(str, enc);
    } else {
      if (validator.isHexadecimal(str)) {
        str = new Buffer(str, "hex");
      } else if (validator.isBase64(str)) {
        str = new Buffer(str, "base64");
      } else {
        str = new Buffer(str);
      }
    }
  }
  return str;
}

// convert hex to UTF-16LE
function hex2utf16le(input) {
  if (input.length % 4 !== 0) {
    throw new Error("Can't convert input to utf16 - invalid length");
  }
  return new Buffer(input, "hex").toString("utf16le");
}

function isFunction(f) {
  return typeof f === "function";
}

module.exports = {

  browser: !NODE_JS,

  crypto: crypto,

  constants: {

    // Suppress logging
    quiet: false,

    // Symmetric cipher for private key encryption
    cipher: "aes-128-ctr",

    // Initialization vector size in bytes
    ivBytes: 16,

    // ECDSA private key size in bytes
    keyBytes: 32,

    // Key derivation function parameters
    pbkdf2: {
      c: 65536,
      dklen: 32,
      hash: "sha256",
      prf: "hmac-sha256"
    },
    scrypt: {
      memory: 280000000,
      dklen: 32,
      n: 65536,
      r: 1,
      p: 8
    }
  },

  /**
   * Check if the selected cipher is available.
   * @param {string} algo Encryption algorithm.
   * @return {boolean} If available true, otherwise false.
   */
  isCipherAvailable: function (cipher) {
    return crypto.getCiphers().some(function (name) { return name === cipher });
  },

  /**
   * Symmetric private key encryption using secret (derived) key.
   * @param {buffer|string} plaintext Text to be encrypted.
   * @param {buffer|string} key Secret key.
   * @param {buffer|string} iv Initialization vector.
   * @param {string=} algo Encryption algorithm (default: constants.cipher).
   * @return {string} Base64 encrypted text.
   */
  encrypt: function (plaintext, key, iv, algo) {
    var cipher, ciphertext;
    algo = algo || this.constants.cipher;
    if (!this.isCipherAvailable(algo)) throw new Error(algo + " is not available");

    plaintext = str2buf(plaintext);
    key = str2buf(key);
    iv = str2buf(iv);

    cipher = crypto.createCipheriv(algo, key, iv);
    ciphertext = cipher.update(plaintext.toString("hex"), "hex", "base64");
    return ciphertext + cipher.final("base64");
  },

  /**
   * Symmetric private key decryption using secret (derived) key.
   * @param {buffer|string} ciphertext Text to be decrypted.
   * @param {buffer|string} key Secret key.
   * @param {buffer|string} iv Initialization vector.
   * @param {string=} algo Encryption algorithm (default: constants.cipher).
   * @return {string} Hex decryped text.
   */
  decrypt: function (ciphertext, key, iv, algo) {
    var decipher, plaintext;
    algo = algo || this.constants.cipher;
    if (!this.isCipherAvailable(algo)) throw new Error(algo + " is not available");

    ciphertext = str2buf(ciphertext);
    key = str2buf(key);
    iv = str2buf(iv);

    decipher = crypto.createDecipheriv(algo, key, iv);
    plaintext = decipher.update(ciphertext.toString("base64"), "base64", "hex");
    return plaintext + decipher.final("hex");
  },

  /**
   * Derive Ethereum address from private key.
   * @param {buffer|string} privateKey ECDSA private key.
   * @return {string} Hex-encoded Ethereum address.
   */
  privateKeyToAddress: function (privateKey) {
    return "0x" + privateToAddress(str2buf(privateKey)).toString("hex");
  },

  /**
   * Calculate message authentication code from secret (derived) key and
   * encrypted text.  The MAC is the keccak-256 hash of the byte array
   * formed by concatenating the second 16 bytes of the derived key with
   * the ciphertext key's contents.
   * @param {buffer|string} derivedKey Secret key derived from password.
   * @param {buffer|string} ciphertext Text encrypted with secret key.
   * @return {string} Hex-encoded MAC.
   */
  getMAC: function (derivedKey, ciphertext) {
    if (derivedKey !== undefined && derivedKey !== null && ciphertext !== undefined && ciphertext !== null) {
      if (Buffer.isBuffer(derivedKey)) derivedKey = derivedKey.toString("hex");
      if (Buffer.isBuffer(ciphertext)) ciphertext = ciphertext.toString("hex");
      return keccak(hex2utf16le(derivedKey.slice(32, 64) + ciphertext));
    }
  },

  /**
   * Derive secret key from password with key dervation function.
   * @param {string|buffer} password User-supplied password.
   * @param {string|buffer} salt Randomly generated salt.
   * @param {Object=} options Encryption parameters.
   * @param {string=} options.kdf Key derivation function (default: pbkdf2).
   * @param {string=} options.cipher Symmetric cipher (default: constants.cipher).
   * @param {Object=} options.kdfparams KDF parameters (default: constants.<kdf>).
   * @param {function=} cb Callback function (optional).
   * @return {buffer} Secret key derived from password.
   */
  deriveKey: function (password, salt, options, cb) {
    var prf, self = this;
    if (typeof password === "undefined" || password === null || !salt) {
      throw new Error("Must provide password and salt to derive a key");
    }

    options = options || {};
    options.kdfparams = options.kdfparams || {};

    // convert strings to buffers
    password = str2buf(password, "utf8");
    salt = str2buf(salt);

    // use scrypt as key derivation function
    if (options.kdf === "scrypt") {
      if (isFunction(scrypt)) {
        scrypt = scrypt(options.kdfparams.memory || self.constants.scrypt.memory);
      }
      if (isFunction(cb)) {
        setTimeout(function () {
          cb(new Buffer(scrypt.to_hex(scrypt.crypto_scrypt(
            password,
            salt,
            options.kdfparams.n || self.constants.scrypt.n,
            options.kdfparams.r || self.constants.scrypt.r,
            options.kdfparams.p || self.constants.scrypt.p,
            options.kdfparams.dklen || self.constants.scrypt.dklen
          )), "hex"));
        }, 0);
      } else {
        return new Buffer(scrypt.to_hex(scrypt.crypto_scrypt(
          password,
          salt,
          options.kdfparams.n || this.constants.scrypt.n,
          options.kdfparams.r || this.constants.scrypt.r,
          options.kdfparams.p || this.constants.scrypt.p,
          options.kdfparams.dklen || this.constants.scrypt.dklen
        )), "hex");
      }

    // use default key derivation function (PBKDF2)
    } else {
      prf = options.kdfparams.prf || this.constants.pbkdf2.prf;
      if (prf === "hmac-sha256") prf = "sha256";
      if (!isFunction(cb)) {
        if (!this.crypto.pbkdf2Sync) {
          return new Buffer(sjcl.codec.hex.fromBits(sjcl.misc.pbkdf2(
            password.toString("utf8"),
            sjcl.codec.hex.toBits(salt.toString("hex")),
            options.kdfparams.c || self.constants.pbkdf2.c,
            (options.kdfparams.dklen || self.constants.pbkdf2.dklen)*8
          )), "hex");
        }
        return crypto.pbkdf2Sync(
          password,
          salt,
          options.kdfparams.c || this.constants.pbkdf2.c,
          options.kdfparams.dklen || this.constants.pbkdf2.dklen,
          prf
        );
      }
      if (!this.crypto.pbkdf2) {
        setTimeout(function () {
          cb(new Buffer(sjcl.codec.hex.fromBits(sjcl.misc.pbkdf2(
            password.toString("utf8"),
            sjcl.codec.hex.toBits(salt.toString("hex")),
            options.kdfparams.c || self.constants.pbkdf2.c,
            (options.kdfparams.dklen || self.constants.pbkdf2.dklen)*8
          )), "hex"));
        }, 0);
      } else {
        crypto.pbkdf2(
          password,
          salt,
          options.kdfparams.c || this.constants.pbkdf2.c,
          options.kdfparams.dklen || this.constants.pbkdf2.dklen,
          prf,
          function (ex, derivedKey) {
            if (ex) return cb(ex);
            cb(derivedKey);
          }
        );
      }
    }
  },

  /**
   * Generate random numbers for private key, initialization vector,
   * and salt (for key derivation).
   * @param {Object=} params Encryption options (defaults: constants).
   * @param {string=} params.keyBytes Private key size in bytes.
   * @param {string=} params.ivBytes Initialization vector size in bytes.
   * @param {function=} cb Callback function (optional).
   * @return {Object<string,buffer>} Private key, IV and salt.
   */
  create: function (params, cb) {
    var keyBytes, ivBytes;
    params = params || {};
    keyBytes = params.keyBytes || this.constants.keyBytes;
    ivBytes = params.ivBytes || this.constants.ivBytes;

    // synchronous key generation if callback not provided
    if (!isFunction(cb)) {
      return {
        privateKey: crypto.randomBytes(keyBytes),
        iv: crypto.randomBytes(ivBytes),
        salt: crypto.randomBytes(keyBytes)
      };
    }

    // asynchronous key generation
    // generate private key
    crypto.randomBytes(keyBytes, function (ex, privateKey) {
      if (ex) return cb(ex);

      // generate random initialization vector
      crypto.randomBytes(ivBytes, function (ex, iv) {
        if (ex) return cb(ex);

        // generate random salt
        crypto.randomBytes(keyBytes, function (ex, salt) {
          if (ex) return cb(ex);
          cb({
            privateKey: privateKey,
            iv: iv,
            salt: salt
          });
        });
      });
    });
  },

  /**
   * Assemble key data object in secret-storage format.
   * @param {buffer} derivedKey Password-derived secret key.
   * @param {buffer} privateKey Private key.
   * @param {buffer} salt Randomly generated salt.
   * @param {buffer} iv Initialization vector.
   * @param {Object=} options Encryption parameters.
   * @param {string=} options.kdf Key derivation function (default: pbkdf2).
   * @param {string=} options.cipher Symmetric cipher (default: constants.cipher).
   * @param {Object=} options.kdfparams KDF parameters (default: constants.<kdf>).
   * @return {Object}
   */
  marshal: function (derivedKey, privateKey, salt, iv, options) {
    var ciphertext, keyObject, algo;
    options = options || {};
    options.kdfparams = options.kdfparams || {};
    algo = options.cipher || this.constants.cipher;

    // encrypt using first 16 bytes of derived key
    ciphertext = new Buffer(this.encrypt(privateKey, derivedKey.slice(0, 16), iv, algo), "base64").toString("hex");

    keyObject = {
      address: this.privateKeyToAddress(privateKey).slice(2),
      crypto: {
        cipher: options.cipher || this.constants.cipher,
        ciphertext: ciphertext,
        cipherparams: { iv: iv.toString("hex") },
        mac: this.getMAC(derivedKey, ciphertext)
      },
      id: uuid.v4(), // random 128-bit UUID
      version: 3
    };

    if (options.kdf === "scrypt") {
      keyObject.crypto.kdf = "scrypt";
      keyObject.crypto.kdfparams = {
        dklen: options.kdfparams.dklen || this.constants.scrypt.dklen,
        n: options.kdfparams.n || this.constants.scrypt.n,
        r: options.kdfparams.r || this.constants.scrypt.r,
        p: options.kdfparams.p || this.constants.scrypt.p,
        salt: salt.toString("hex")
      };

    } else {
      keyObject.crypto.kdf = "pbkdf2";
      keyObject.crypto.kdfparams = {
        c: options.kdfparams.c || this.constants.pbkdf2.c,
        dklen: options.kdfparams.dklen || this.constants.pbkdf2.dklen,
        prf: options.kdfparams.prf || this.constants.pbkdf2.prf,
        salt: salt.toString("hex")
      };
    }

    return keyObject;
  },

  /**
   * Export private key to keystore secret-storage format.
   * @param {string|buffer} password User-supplied password.
   * @param {string|buffer} privateKey Private key.
   * @param {string|buffer} salt Randomly generated salt.
   * @param {string|buffer} iv Initialization vector.
   * @param {Object=} options Encryption parameters.
   * @param {string=} options.kdf Key derivation function (default: pbkdf2).
   * @param {string=} options.cipher Symmetric cipher (default: constants.cipher).
   * @param {Object=} options.kdfparams KDF parameters (default: constants.<kdf>).
   * @param {function=} cb Callback function (optional).
   * @return {Object}
   */
  dump: function (password, privateKey, salt, iv, options, cb) {
    options = options || {};
    iv = str2buf(iv);
    privateKey = str2buf(privateKey);

    // synchronous if no callback provided
    if (!isFunction(cb)) {
      return this.marshal(this.deriveKey(password, salt, options), privateKey, salt, iv, options);
    }

    // asynchronous if callback provided
    this.deriveKey(password, salt, options, function (derivedKey) {
      cb(this.marshal(derivedKey, privateKey, salt, iv, options));
    }.bind(this));
  },

  /**
   * Recover plaintext private key from secret-storage key object.
   * @param {Object} keyObject Keystore object.
   * @param {function=} cb Callback function (optional).
   * @return {buffer} Plaintext private key.
   */
  recover: function (password, keyObject, cb) {
    var keyObjectCrypto, iv, salt, ciphertext, algo, self = this;
    keyObjectCrypto = keyObject.Crypto || keyObject.crypto;

    // verify that message authentication codes match, then decrypt
    function verifyAndDecrypt(derivedKey, salt, iv, ciphertext, algo) {
      var key;
      if (self.getMAC(derivedKey, ciphertext) !== keyObjectCrypto.mac) {
        throw new Error("message authentication code mismatch");
      }
      if (keyObject.version === "1") {
        key = new Buffer(keccak(hex2utf16le(derivedKey.toString("hex").slice(0, 32))), "hex").slice(0, 16);
      } else {
        key = derivedKey.slice(0, 16);
      }
      return new Buffer(self.decrypt(ciphertext, key, iv, algo), "hex");
    }

    iv = keyObjectCrypto.cipherparams.iv;
    salt = keyObjectCrypto.kdfparams.salt;
    ciphertext = keyObjectCrypto.ciphertext;
    algo = keyObjectCrypto.cipher;

    iv = str2buf(iv);
    salt = str2buf(salt);
    ciphertext = str2buf(ciphertext);

    if (keyObjectCrypto.kdf === "scrypt") {
      this.constants.scrypt.n = keyObjectCrypto.kdfparams.n;
      this.constants.scrypt.r = keyObjectCrypto.kdfparams.r;
      this.constants.scrypt.p = keyObjectCrypto.kdfparams.p;
      this.constants.scrypt.dklen = keyObjectCrypto.kdfparams.dklen;
    } else {
      if (keyObjectCrypto.kdfparams.prf !== "hmac-sha256") {
        throw new Error("PBKDF2 only supported with HMAC-SHA256");
      }
      this.constants.pbkdf2.c = keyObjectCrypto.kdfparams.c;
      this.constants.pbkdf2.dklen = keyObjectCrypto.kdfparams.dklen;
    }

    // derive secret key from password
    if (!isFunction(cb)) {
      return verifyAndDecrypt(this.deriveKey(password, salt, keyObjectCrypto), salt, iv, ciphertext, algo);
    }
    this.deriveKey(password, salt, keyObjectCrypto, function (derivedKey) {
      cb(verifyAndDecrypt(derivedKey, salt, iv, ciphertext, algo));
    });
  },

  /**
   * Generate filename for a keystore file.
   * @param {string} address Ethereum address.
   * @return {string} Keystore filename.
   */
  generateKeystoreFilename: function (address) {
    var filename = "UTC--" + new Date().toISOString() + "--" + address;

    // Windows does not permit ":" in filenames, replace all with "-"
    if (process.platform === "win32") filename = filename.split(":").join("-");

    return filename;
  },

  /**
   * Export formatted JSON to keystore file.
   * @param {Object} keyObject Keystore object.
   * @param {string=} keystore Path to keystore folder (default: "keystore").
   * @param {function=} cb Callback function (optional).
   * @return {string} JSON filename (Node.js) or JSON string (browser).
   */
  exportToFile: function (keyObject, keystore, cb) {
    var self = this;
    var outfile, outpath, json;

    function instructions(outpath) {
      if (!self.constants.quiet) {
        console.log(
          "Saved to file:\n" + outpath + "\n"+
          "To use with geth, copy this file to your Ethereum "+
          "keystore folder (usually ~/.ethereum/keystore)."
        );
      }
    }

    keystore = keystore || "keystore";
    outfile = this.generateKeystoreFilename(keyObject.address);
    outpath = path.join(keystore, outfile);
    json = JSON.stringify(keyObject);

    if (this.browser) {
      if (!isFunction(cb)) return json;
      return cb(json);
    }
    if (!isFunction(cb)) {
      fs.writeFileSync(outpath, json);
      instructions(outpath);
      return outpath;
    }
    fs.writeFile(outpath, json, function (ex) {
      if (ex) throw ex;
      instructions(outpath);
      cb(outpath);
    });
  },

  /**
   * Import key data object from keystore JSON file.
   * (Note: Node.js only!)
   * @param {string} address Ethereum address to import.
   * @param {string=} datadir Ethereum data directory (default: ~/.ethereum).
   * @param {function=} cb Callback function (optional).
   * @return {Object} Keystore data file's contents.
   */
  importFromFile: function (address, datadir, cb) {
    var keystore, filepath;
    address = address.replace("0x", "");

    function findKeyfile(keystore, address, files) {
      var i, len, filepath = null;
      for (i = 0, len = files.length; i < len; ++i) {
        if (files[i].indexOf(address) > -1) {
          filepath = path.join(keystore, files[i]);
          if (fs.lstatSync(filepath).isDirectory()) {
            filepath = path.join(filepath, files[i]);
          }
          break;
        }
      }
      return filepath;
    }

    if (this.browser) throw new Error("method only available in Node.js");
    datadir = datadir || path.join(process.env.HOME, ".ethereum");
    keystore = path.join(datadir, "keystore");
    if (!isFunction(cb)) {
      filepath = findKeyfile(keystore, address, fs.readdirSync(keystore));
      if (!filepath) {
        throw new Error("could not find key file for address " + address);
      }
      return JSON.parse(fs.readFileSync(filepath));
    }
    fs.readdir(keystore, function (ex, files) {
      var filepath;
      if (ex) return cb(ex);
      filepath = findKeyfile(keystore, address, files);
      if (!filepath) {
        return new Error("could not find key file for address " + address);
      }
      return cb(JSON.parse(fs.readFileSync(filepath)));
    });
  }

};
