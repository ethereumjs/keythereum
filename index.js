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
            c: 262144,
            dklen: 32,
            hash: "sha256",
            prf: "hmac-sha256"
        },
        scrypt: {
            dklen: 32,
            n: 262144,
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
     * Assemble JSON object in secret-storage format.
     * @param {string|buffer} derivedKey Password-derived secret key.
     * @param {string|buffer} privateKey Private key.
     * @param {string|buffer} salt Randomly generated salt.
     * @param {string|buffer} iv Initialization vector.
     * @param {string=} kdf Key derivation function (default: pbkdf2).
     * @param {function=} cb Callback function (optional).
     * @return {Object}
     */
    jsonMarshal: function(derivedKey, privateKey, salt, iv, kdf) {
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
                salt: salt
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
                cb(this.jsonMarshal(derivedKey, privateKey, salt, iv, kdf));
            }.bind(this));

        // synchronous if no callback
        } else {

            return this.jsonMarshal(
                this.deriveKey(password, salt, kdf),
                privateKey,
                salt,
                iv,
                kdf
            );
        }
    },

    /**
     * Import private key from keystore secret-storage format.
     * @param {Object} json Keystore object.
     * @param {function=} cb Callback function (optional).
     * @return {Object}
     */
    // load: function (json, cb) {

    // },

    /**
     * Import formatted JSON from keystore file.
     * (Note: Node.js only!)
     * @param {string} address Ethereum address to import.
     * @param {string=} datadir Ethereum data directory (default: ~/.ethereum).
     * @param {function=} cb Callback function (optional).
     * @return {Object} Keystore data file's contents.
     */
    // importFromFile: function (address, datadir, cb) {

    //     var p = require("path");
    //     var fs = require("fs");

    //     datadir = datadir || p.join(process.env.HOME, ".ethereum");

    //     fs.readdir(p.join(datadir), "keystore", function (ex, files) {
    //         if (ex) throw ex;
    //         console.log(files);
    //     });
    
    // },

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
    }

};
