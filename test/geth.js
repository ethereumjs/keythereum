/**
 * keythereum unit tests
 * @author Jack Peterson (jack@tinybike.net)
 */

"use strict";

var fs = require("fs");
var path = require("path");
var cp = require("child_process");
var crypto = require("crypto");
var assert = require("chai").assert;
var keythereum = require("../");
var checkKeyObj = require("./checkKeyObj");

var NUM_TESTS = 1000;
var TIMEOUT = 5000;
var DEBUG = false;

var GETH_BIN = "geth";
var GETH_PORT = "30304";
var GETH_RPCPORT = "8547";
var DATADIR = path.join(__dirname, "fixtures");
var NETWORK_ID = "10101";

var PASSFILE = path.join(DATADIR, ".password");
var GETH_FLAGS = [
    "--etherbase", null,
    "--unlock", null,
    "--nodiscover",
    "--networkid", NETWORK_ID,
    "--port", GETH_PORT,
    "--rpcport", GETH_RPCPORT,
    "--datadir", DATADIR,
    "--password", PASSFILE
];

function createEthereumKey(passphrase) {
    var dk = keythereum.create();
    var key = keythereum.dump(passphrase, dk.privateKey, dk.salt, dk.iv);
    return JSON.stringify(key);
}

keythereum.constants.quiet = true;

describe("Unlock randomly-generated accounts in geth", function () {

    var test = function (t) {

        var label = "[" + t.kdf + " | " + t.hashRounds + " rounds] "+
            "generate key file using password '" + t.password +"'";

        it(label, function (done) {
            this.timeout(TIMEOUT*2);

            var json = createEthereumKey(t.password);
            assert.isNotNull(json);

            var keyObject = JSON.parse(json);
            assert.isNotNull(keyObject);
            checkKeyObj.structure(keythereum, keyObject);

            keythereum.exportToFile(keyObject, path.join(DATADIR, "keystore"), function (keypath) {

                fs.writeFile(PASSFILE, t.password, function (ex) {
                    var failed = false;
                    if (ex) {
                        done(ex);
                    } else {
                        GETH_FLAGS[1] = keyObject.address;
                        GETH_FLAGS[3] = keyObject.address;

                        var geth = cp.spawn(GETH_BIN, GETH_FLAGS);
                        assert.isNotNull(geth);

                        geth.stdout.on("data", function (data) {
                            var unlocked = "Account '" + keyObject.address + "' unlocked.";
                            if (DEBUG) {
                                process.stdout.write(data.toString());
                            }
                            if (data.toString().indexOf(unlocked) > -1) {
                                if (geth) geth.kill();
                            }
                        });

                        geth.stderr.on("data", function (data) {
                            if (DEBUG) {
                                process.stdout.write(data.toString());
                            }
                        });

                        geth.on("close", function () {
                            if (geth) geth.kill();

                            fs.unlink(PASSFILE, function (exc) {
                                if (exc) {
                                    done(exc);
                                } else {

                                    fs.unlink(keypath, function (exc) {
                                        if (exc) {
                                            done(exc);
                                        } else {
                                            if (failed) {
                                                done(new Error(
                                                    "account not unlocked after "+
                                                    TIMEOUT / 1000 + " seconds"
                                                ));
                                            } else {
                                                done();
                                            }
                                        }
                                    });
                                }
                            });
                        });

                        // if not unlocked after 10 seconds, kill geth
                        setTimeout(function () {
                            failed = true;
                            if (geth) geth.kill();
                        }, TIMEOUT);

                    }
                });
            });
        });
    };

    var password, hashRounds;

    for (var i = 0; i < NUM_TESTS; ++i) {
        
        password = crypto.randomBytes(Math.ceil(Math.random()*100));
        hashRounds = Math.ceil(Math.random() * 300000);

        keythereum.constants.pbkdf2.c = hashRounds;
        keythereum.constants.scrypt.n = hashRounds;

        test({
            password: password.toString("hex"),
            hashRounds: hashRounds,
            kdf: "pbkdf2"
        });
        test({
            password: password.toString("base64"),
            hashRounds: hashRounds,
            kdf: "scrypt"
        });

        test({
            password: password.toString("hex"),
            hashRounds: hashRounds,
            kdf: "pbkdf2"
        });
        test({
            password: password.toString("base64"),
            hashRounds: hashRounds,
            kdf: "scrypt"
        });

    }

});
