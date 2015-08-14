/**
 * keythereum: create/import/export ethereum keys
 * @author Jack Peterson (jack@tinybike.net)
 */

"use strict";

var crypto;
if ((typeof module !== "undefined") && process && !process.browser) {
    crypto = require("crypto");
} else {
    crypto = require("crypto-browserify");
}
var uuid = require("node-uuid");
var validator = require("validator");
var ecdsa = new (require("elliptic").ec)("secp256k1");
var pubToAddress = require("ethereumjs-util").pubToAddress;
var keccak = require("./lib/keccak");
var scrypt = require("./lib/scrypt")(67108864);

function FileNotFoundError(message) {
    this.message = "File Not Found: " + message;
}

FileNotFoundError.prototype = new Error();

function str2buf(str, enc) {
    if (str.constructor === String) {
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

function hex2utf16le(input) {
    var output = '';
    for (var i = 0, l = input.length; i < l; i += 4) {
        output += '\\u' + input.slice(i+2, i+4) + input.slice(i, i+2);
    }
    return JSON.parse('"' + output + '"');
}

module.exports = {

    constants: {

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
            dklen: 32,
            n: 65536,
            r: 1,
            p: 8
        }
    },

    /**
     * Symmetric private key encryption using secret (derived) key.
     * @param {string} plaintext Text to be encrypted.
     * @param {string|buffer} key Secret key.
     * @param {string|buffer} iv Initialization vector.
     * @return {string} Base64 encrypted text.
     */
    encrypt: function (plaintext, key, iv) {
        var cipher, ciphertext;

        if (key.constructor === String) key = str2buf(key);
        if (iv.constructor === String) iv = str2buf(iv);

        cipher = crypto.createCipheriv(this.constants.cipher, key, iv);
        ciphertext = cipher.update(plaintext, "hex", "base64");

        return ciphertext + cipher.final("base64");
    },

    /**
     * Symmetric private key decryption using secret (derived) key.
     * @param {string} ciphertext Text to be decrypted.
     * @param {string|buffer} key Secret key.
     * @param {string|buffer} iv Initialization vector.
     * @return {string} Hex decryped text.
     */
    decrypt: function (ciphertext, key, iv) {
        var decipher, plaintext;

        if (key.constructor === String) key = str2buf(key);
        if (iv.constructor === String) iv = str2buf(iv);

        decipher = crypto.createDecipheriv(this.constants.cipher, key, iv);
        plaintext = decipher.update(ciphertext, "base64", "hex");

        return plaintext + decipher.final("hex");
    },

    /**
     * Derive Ethereum address from private key.
     * @param {string|buffer} privateKey ECDSA private key.
     * @return {string} Hex-encoded Ethereum address.
     */
    privateKeyToAddress: function (privateKey) {

        if (privateKey.constructor === String)
            privateKey = str2buf(privateKey);

        return "0x" + pubToAddress(new Buffer(
            ecdsa.keyFromPrivate(privateKey).getPublic("arr")
        )).toString("hex");
    },

    /**
     * Calculate message authentication code from secret (derived) key and
     * encrypted text.  The MAC is the keccak-256 hash of the byte array
     * formed by concatenating the second 16 bytes of the derived key with
     * the ciphertext key's contents.
     * @param {string|buffer} derivedKey Secret key derived from password.
     * @param {string|buffer} ciphertext Text encrypted with secret key.
     * @return {string} Hex-encoded MAC.
     */
    getMAC: function (derivedKey, ciphertext) {
        if (derivedKey !== undefined && derivedKey !== null &&
            ciphertext !== undefined && ciphertext !== null)
        {
            if (derivedKey.constructor === Buffer)
                derivedKey = derivedKey.toString("hex");

            if (ciphertext.constructor === Buffer)
                ciphertext = ciphertext.toString("hex");

            return keccak(
                hex2utf16le(derivedKey.slice(32, 64) + ciphertext)
            );
        }
    },

    /**
     * Derive secret key from password with key dervation function.
     * @param {string|buffer} password User-supplied password.
     * @param {string|buffer} salt Randomly generated salt.
     * @param {string=} kdf Key derivation function (default: pbkdf2).
     * @param {function=} cb Callback function (optional).
     * @return {buffer} Secret key derived from password.
     */
    deriveKey: function (password, salt, kdf, cb) {
        if (password && salt) {

            // convert strings to buffers
            if (password.constructor === String) {
                password = new Buffer(password, "utf8");
            }
            if (salt.constructor === String) {
                if (validator.isHexadecimal(salt)) {
                    salt = new Buffer(salt, "hex");
                } else if (validator.isBase64(salt)) {
                    salt = new Buffer(salt, "base64");
                } else {
                    salt = new Buffer(salt);
                }
            }

            // use scrypt as key derivation function
            if (kdf === "scrypt") {

                try {
                    var derivedKey = new Buffer(
                        scrypt.to_hex(scrypt.crypto_scrypt(
                            password,
                            salt,
                            this.constants.scrypt.n,
                            this.constants.scrypt.r,
                            this.constants.scrypt.p,
                            this.constants.scrypt.dklen
                        )
                    ), "hex");

                    if (cb && cb.constructor === Function) {
                        cb(derivedKey);
                    } else {
                        return derivedKey; 
                    }

                } catch (ex) {
                    if (cb && cb.constructor === Function) {
                        cb(ex);
                    } else {
                        return ex;
                    }
                }

            // use default key derivation function (PBKDF2)
            } else {

                if (cb && cb.constructor === Function) {

                    crypto.pbkdf2(
                        password,
                        salt,
                        this.constants.pbkdf2.c,
                        this.constants.pbkdf2.dklen,
                        this.constants.pbkdf2.hash,
                        function (ex, derivedKey) {
                            if (ex) return ex;
                            cb(derivedKey);
                        }
                    );

                } else {
                    
                    try {
                        return crypto.pbkdf2Sync(
                            password,
                            salt,
                            this.constants.pbkdf2.c,
                            this.constants.pbkdf2.dklen,
                            this.constants.pbkdf2.hash
                        );

                    } catch (ex) {
                        return ex;
                    }
                }
            }
        }
    },

    /**
     * Generate random numbers for private key, initialization vector,
     * and salt (for key derivation).
     * @param {function=} cb Callback function (optional).
     * @return {Object<string,buffer>} Private key, IV and salt.
     */
    create: function (cb) {
        var self = this;

        // asynchronous key generation if callback is provided
        if (cb && cb.constructor === Function) {

            // generate private key
            crypto.randomBytes(this.constants.keyBytes, function (ex, privateKey) {
                if (ex) cb(ex);

                // generate random initialization vector
                crypto.randomBytes(self.constants.ivBytes, function (ex, iv) {
                    if (ex) cb(ex);

                    // generate random salt
                    crypto.randomBytes(self.constants.keyBytes, function (ex, salt) {
                        if (ex) cb(ex);
                        
                        cb({
                            privateKey: privateKey,
                            iv: iv,
                            salt: salt
                        });
                    });

                }); // crypto.randomBytes

            }); // crypto.randomBytes

        // synchronous key generation
        } else {

            try {
                return {
                    privateKey: crypto.randomBytes(this.constants.keyBytes),
                    iv: crypto.randomBytes(this.constants.ivBytes),
                    salt: crypto.randomBytes(this.constants.keyBytes)
                };

            // couldn't generate key: not enough entropy?
            } catch (ex) {
                return ex;
            }
        }
    },

    /**
     * Assemble key data object in secret-storage format.
     * @param {string|buffer} derivedKey Password-derived secret key.
     * @param {string|buffer} privateKey Private key.
     * @param {string|buffer} salt Randomly generated salt.
     * @param {string|buffer} iv Initialization vector.
     * @param {string=} kdf Key derivation function (default: pbkdf2).
     * @param {function=} cb Callback function (optional).
     * @return {Object}
     */
    marshal: function(derivedKey, privateKey, salt, iv, kdf) {
        var ciphertext, json;

        // encryption key: first 16 bytes of derived key
        ciphertext = new Buffer(this.encrypt(
            privateKey,
            derivedKey.slice(0, 16),
            iv
        ), "base64").toString("hex");

        json = {
            address: this.privateKeyToAddress(privateKey).slice(2),
            Crypto: {
                cipher: this.constants.cipher,
                ciphertext: ciphertext,
                cipherparams: { iv: iv.toString("hex") },
                mac: this.getMAC(derivedKey, ciphertext)
            },
            id: uuid.v4(), // random 128-bit UUID
            version: 3
        };

        if (kdf === "scrypt") {
            json.Crypto.kdf = "scrypt";
            json.Crypto.kdfparams = {
                dklen: this.constants.scrypt.dklen,
                n: this.constants.scrypt.n,
                r: this.constants.scrypt.r,
                p: this.constants.scrypt.p,
                salt: salt
            };

        } else {
            json.Crypto.kdf = "pbkdf2";
            json.Crypto.kdfparams = {
                c: this.constants.pbkdf2.c,
                dklen: this.constants.pbkdf2.dklen,
                prf: this.constants.pbkdf2.prf,
                salt: salt.toString("hex")
            };
        }

        return json;
    },

    /**
     * Export private key to keystore secret-storage format.
     * @param {string|buffer} password User-supplied password.
     * @param {string|buffer} privateKey Private key.
     * @param {string|buffer} salt Randomly generated salt.
     * @param {string|buffer} iv Initialization vector.
     * @param {string=} kdf Key derivation function (default: pbkdf2).
     * @param {function=} cb Callback function (optional).
     * @return {Object}
     */
    dump: function (password, privateKey, salt, iv, kdf, cb) {

        if (iv.constructor === String) iv = str2buf(iv);
        if (privateKey.constructor === String) privateKey = str2buf(privateKey);

        // asynchronous if callback provided
        if (cb && cb.constructor === Function) {

            this.deriveKey(password, salt, kdf, function (derivedKey) {
                cb(this.marshal(derivedKey, privateKey, salt, iv, kdf));
            }.bind(this));

        // synchronous if no callback
        } else {

            return this.marshal(
                this.deriveKey(password, salt, kdf),
                privateKey,
                salt,
                iv,
                kdf
            );
        }
    },

    /**
     * Recover plaintext private key from secret-storage key object.
     * @param {Object} keyObject Keystore object.
     * @param {function=} cb Callback function (optional).
     * @return {buffer} Plaintext private key.
     */
    recover: function (password, keyObject, cb) {

        function verifyAndDecrypt(derivedKey, salt, iv, ciphertext) {

            // verify that message authentication codes match
            var mac = self.getMAC(derivedKey, ciphertext);
            if (mac === keyObject.Crypto.mac) {

                return new Buffer(self.decrypt(
                    ciphertext,
                    derivedKey.slice(0, 16),
                    iv
                ), "hex");
            
            } else {
                throw new Error("message authentication code mismatch");
            }
        }

        var self = this;
        var iv = keyObject.Crypto.cipherparams.iv;
        var salt = keyObject.Crypto.kdfparams.salt;
        var ciphertext = keyObject.Crypto.ciphertext;

        if (iv && iv.constructor === String) iv = str2buf(iv);
        if (salt && salt.constructor === String) salt = str2buf(salt);
        if (ciphertext && ciphertext.constructor === String)
            ciphertext = str2buf(ciphertext);

        if (keyObject.Crypto.kdf === "scrypt") {
            this.constants.scrypt = {
                n: keyObject.Crypto.kdfparams.n,
                r: keyObject.Crypto.kdfparams.r,
                p: keyObject.Crypto.kdfparams.p,
                dklen: keyObject.Crypto.kdfparams.dklen
            };
        } else {
            if (keyObject.Crypto.kdfparams.prf !== "hmac-sha256") {
                throw new Error("PBKDF2 only supported with HMAC-SHA256");
            }
            this.constants.pbkdf2.c = keyObject.Crypto.kdfparams.c;
            this.constants.pbkdf2.dklen = keyObject.Crypto.kdfparams.dklen;
        }

        // derive secret key from password
        if (cb && cb.constructor === Function) {
            this.deriveKey(password, salt, keyObject.Crypto.kdf, function (derivedKey) {
                cb(verifyAndDecrypt(derivedKey, salt, iv, ciphertext));
            });
        } else {
            return verifyAndDecrypt(
                this.deriveKey(password, salt, keyObject.Crypto.kdf),
                salt,
                iv,
                ciphertext
            );
        }
    },

    /**
     * Export formatted JSON to keystore file.
     * (Note: Node.js only!)
     * @param {Object} keyObject Keystore object.
     * @param {function=} cb Callback function (optional).
     * @return {Object}
     */
    exportToFile: function (keyObject, cb) {
        var outfile = "UTC--" + new Date().toISOString() + "--" + keyObject.address;
        require("fs").writeFile(
            "keystore/" + outfile,
            JSON.stringify(keyObject),
            function (ex) {
                if (ex) throw ex;
                console.log("Saved to file:\nkeystore/" + outfile);
                console.log(
                    "\nTo use with geth, copy this file to your Ethereum "+
                    "keystore folder (usually ~/.ethereum/keystore)."
                );
                if (cb && cb.constructor === Function) cb(outfile);
            }
        );
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

        function findKeyfile(address, files) {
            var filepath = null;
            for (var i = 0, len = files.length; i < len; ++i) {
                if (files[i].indexOf(address) > -1) {
                    filepath = p.join(keystore, files[i]);
                    if (fs.lstatSync(filepath).isDirectory()) {
                        filepath = p.join(filepath, files[i]);
                    }
                    break;
                }
            }
            return filepath;
        }

        var p = require("path");
        var fs = require("fs");
        datadir = datadir || p.join(process.env.HOME, ".ethereum");
        var keystore = p.join(datadir, "keystore");

        if (cb && cb.constructor === Function) {
            fs.readdir(keystore, function (ex, files) {
                if (ex) throw ex;
                var filepath = findKeyfile(address, files);
                if (filepath) {
                    cb(JSON.parse(fs.readFileSync(filepath)));
                } else {
                    throw new FileNotFoundError(
                        "could not find key file for address " + address
                    );
                }
            });

        } else {
            var filepath = findKeyfile(address, fs.readdirSync(keystore));
            if (filepath) {
                return JSON.parse(fs.readFileSync(filepath));
            } else {
                throw new FileNotFoundError(
                    "could not find key file for address " + address
                );
            }
        }
    }

};
